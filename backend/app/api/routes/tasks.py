from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AttackTask, Report, SecurityEvent, User
from ...schemas.task import (
    AttackTaskBatchFromSamplesCreate,
    AttackTaskCreate,
    AttackTaskDispatchRequest,
    AttackTaskFromSampleCreate,
    AttackTaskRetryRequest,
)
from ...services.ai_endpoints import attach_ai_endpoint_selection, task_ai_endpoint_snapshot
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.event_status import EVENT_STATUS_SUSPICIOUS, normalize_event_status
from ...services.guard_trace import build_task_guard_trace
from ...services.report_export import resolve_report_path
from ...services.repository import contains_keyword, paginate
from ...services.sample_catalog import build_task_payload_from_sample, get_sample
from ...services.task_worker import (
    append_task_runtime_log,
    enqueue_attack_task,
    release_task_queue_slot,
    task_runtime_log_snapshot,
    task_worker_snapshot,
)
from ...services.time_utils import format_beijing, utc_now

router = APIRouter()
logger = logging.getLogger("app.api.tasks")
PAUSED_TASK_STATUS_MAP = {
    "ready": "paused_ready",
    "queued": "paused_queued",
    "scheduled": "paused_scheduled",
}
RESUMABLE_TASK_STATUS_MAP = {
    "paused_ready": "ready",
    "paused_queued": "queued",
    "paused_scheduled": "scheduled",
}


def _format_datetime(value: datetime | None) -> str | None:
    return format_beijing(value)


def _serialize_task(item: AttackTask) -> dict:
    return {
        "id": item.id,
        "task_name": item.task_name,
        "attack_type": item.attack_type,
        "target_agent": item.target_agent,
        "ai_endpoint": task_ai_endpoint_snapshot(item),
        "status": item.status,
        "source_type": item.source_type,
        "source_ref": item.source_ref,
        "execution_mode": item.execution_mode,
        "runtime_name": item.runtime_name,
        "runtime_task_ref": item.runtime_task_ref,
        "params_json": item.params,
        "raw_response": item.raw_response,
        "result_summary": item.result_summary,
        "latest_event_id": item.latest_event_id,
        "latest_report_id": item.latest_report_id,
        "created_by": item.created_by,
        "scheduled_at": _format_datetime(item.scheduled_at),
        "started_at": _format_datetime(item.started_at),
        "finished_at": _format_datetime(item.finished_at),
        "last_heartbeat_at": _format_datetime(item.last_heartbeat_at),
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
        "guard_trace": build_task_guard_trace(item),
    }


def _serialize_event(item: SecurityEvent | None, task: AttackTask | None = None) -> Optional[dict]:
    if item is None:
        return None

    return {
        "id": item.id,
        "task_id": item.task_id,
        "event_type": item.event_type,
        "event_level": item.event_level,
        "source": item.source,
        "target": item.target,
        "status": normalize_event_status(item.status, EVENT_STATUS_SUSPICIOUS),
        "detail": item.detail,
        "hit_rules": item.hit_rules,
        "raw_input": item.raw_input,
        "result": item.result,
        "operation_logs": item.operation_logs,
        "created_at": format_beijing(item.created_at) or "",
        "guard_trace": build_task_guard_trace(task),
    }


def _serialize_report(item: Report | None) -> Optional[dict]:
    if item is None:
        return None

    return {
        "id": item.id,
        "task_id": item.task_id,
        "report_name": item.report_name,
        "report_type": item.report_type,
        "file_path": item.file_path,
        "summary_text": item.summary_text,
        "download_url": f"/api/reports/{item.id}/download",
        "created_by": item.created_by,
        "created_at": format_beijing(item.created_at) or "",
    }


def _get_task_or_404(db: Session, task_id: int) -> AttackTask:
    item = db.get(AttackTask, task_id)
    if item is None:
        raise HTTPException(status_code=404, detail="attack task not found")
    return item


def _task_schedule_mode(schedule_at: datetime | None, auto_run: bool) -> tuple[str, datetime | None]:
    if not auto_run:
        return "ready", None
    if schedule_at is not None and schedule_at > utc_now():
        return "scheduled", schedule_at
    return "queued", None


def _reset_task_for_dispatch(task: AttackTask, schedule_at: datetime | None) -> None:
    status, normalized_schedule = _task_schedule_mode(schedule_at, auto_run=True)
    params = dict(task.params)
    params.pop("worker_retry", None)
    task.set_params(params)
    task.status = status
    task.scheduled_at = normalized_schedule
    task.started_at = None
    task.finished_at = None
    task.last_heartbeat_at = None
    task.result_summary = ""
    task.raw_response = ""
    task.latest_event_id = None
    task.latest_report_id = None
    task.runtime_name = None
    task.runtime_task_ref = None
    task.execution_mode = task.execution_mode or "worker"


def _cancel_task_before_execution(task: AttackTask) -> None:
    now = utc_now()
    task.status = "cancelled"
    task.scheduled_at = None
    task.started_at = None
    task.finished_at = now
    task.last_heartbeat_at = now
    task.result_summary = "Task was cancelled before execution."
    task.raw_response = json.dumps({"status": "cancelled", "reason": "cancelled_by_user"}, ensure_ascii=False)
    task.latest_event_id = None
    task.latest_report_id = None


def _pause_task_before_execution(task: AttackTask) -> None:
    paused_status = PAUSED_TASK_STATUS_MAP.get(task.status)
    if paused_status is None:
        raise ValueError(f"task in status {task.status} cannot be paused")

    task.status = paused_status
    task.finished_at = None
    task.last_heartbeat_at = utc_now()
    task.result_summary = "Task is paused before execution."
    task.raw_response = json.dumps({"status": "paused", "reason": "paused_by_user"}, ensure_ascii=False)


def _resume_paused_task(task: AttackTask) -> str:
    target_status = RESUMABLE_TASK_STATUS_MAP.get(task.status)
    if target_status is None:
        raise ValueError(f"task in status {task.status} cannot be resumed")

    if target_status == "scheduled":
        if task.scheduled_at is not None and task.scheduled_at > utc_now():
            task.status = "scheduled"
        else:
            task.status = "queued"
            task.scheduled_at = None
    else:
        task.status = target_status

    task.finished_at = None
    task.last_heartbeat_at = utc_now()
    task.result_summary = ""
    task.raw_response = ""
    return task.status


def _delete_report_artifact(report: Report) -> bool:
    if not report.file_path:
        return False

    try:
        artifact_path = resolve_report_path(report.file_path)
        if artifact_path.exists():
            artifact_path.unlink()
            return True
    except OSError:
        logger.warning("report artifact delete failed | report_id=%s file_path=%s", report.id, report.file_path)

    return False


def _create_sample_task(
    db: Session,
    *,
    sample: dict,
    target_agent: str,
    ai_endpoint_id: int | None,
    params_json: dict,
    current_user: User,
    task_name: str | None,
    auto_run: bool,
    schedule_at: datetime | None,
) -> AttackTask:
    status, normalized_schedule = _task_schedule_mode(schedule_at, auto_run=auto_run)
    params = build_task_payload_from_sample(sample, overrides=params_json)
    params, _endpoint = attach_ai_endpoint_selection(db, params, ai_endpoint_id=ai_endpoint_id)
    attack_type = str(sample.get("attack_family") or sample.get("mapped_section") or "dataset_sample")

    item = AttackTask(
        task_name=(task_name or str(sample.get("title") or sample.get("id") or "dataset-sample-task")).strip(),
        attack_type=attack_type,
        target_agent=target_agent,
        status=status,
        source_type="dataset_sample",
        source_ref=str(sample.get("id") or ""),
        execution_mode="worker",
        created_by=current_user.id,
        scheduled_at=normalized_schedule,
    )
    item.set_params(params)
    db.add(item)
    return item


@router.get("/worker/status")
def get_attack_worker_status(
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success(task_worker_snapshot())


@router.post("")
def create_attack_task(
    payload: AttackTaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    try:
        params_json, _endpoint = attach_ai_endpoint_selection(db, payload.params_json, ai_endpoint_id=payload.ai_endpoint_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    item = AttackTask(
        task_name=payload.task_name,
        attack_type=payload.attack_type,
        target_agent=payload.target_agent,
        status="ready" if str(params_json.get("execution_mode") or "worker") == "runtime_callback" else "queued",
        source_type=str(params_json.get("source_type") or "manual"),
        source_ref=str(params_json.get("source_ref") or ""),
        execution_mode=str(params_json.get("execution_mode") or "worker"),
        created_by=current_user.id,
    )
    item.set_params(params_json)
    db.add(item)
    append_audit_log(db, current_user, "attack-tasks", "create", f"created task {payload.task_name}")
    db.commit()
    db.refresh(item)
    logger.info(
        "task created | task_id=%s task_name=%s attack_type=%s user=%s",
        item.id,
        item.task_name,
        item.attack_type,
        current_user.username,
    )
    return success(_serialize_task(item), message="task created")


@router.post("/from-sample")
def create_attack_task_from_sample(
    payload: AttackTaskFromSampleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    sample = get_sample(payload.sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="sample not found")

    try:
        item = _create_sample_task(
            db,
            sample=sample,
            target_agent=payload.target_agent,
            ai_endpoint_id=payload.ai_endpoint_id,
            params_json=payload.params_json,
            current_user=current_user,
            task_name=payload.task_name,
            auto_run=payload.auto_run,
            schedule_at=payload.schedule_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    append_audit_log(
        db,
        current_user,
        "attack-tasks",
        "create-from-sample",
        f"created task from sample {payload.sample_id}",
    )
    db.commit()
    db.refresh(item)

    enqueued = False
    if item.status == "queued":
        enqueued = enqueue_attack_task(item.id)
        db.refresh(item)

    logger.info(
        "task created from sample | task_id=%s sample_id=%s status=%s enqueued=%s user=%s",
        item.id,
        payload.sample_id,
        item.status,
        enqueued,
        current_user.username,
    )
    return success(
        {
            "task": _serialize_task(item),
            "sample": sample,
            "enqueued": enqueued,
        },
        message="task created from sample",
    )


@router.post("/batch-from-samples")
def create_attack_tasks_from_samples(
    payload: AttackTaskBatchFromSamplesCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    sample_ids = [item.strip() for item in payload.sample_ids if item.strip()]
    if not sample_ids:
        raise HTTPException(status_code=400, detail="sample_ids is required")

    missing_ids = [sample_id for sample_id in sample_ids if get_sample(sample_id) is None]
    if missing_ids:
        raise HTTPException(status_code=404, detail=f"samples not found: {', '.join(missing_ids)}")

    items: list[AttackTask] = []
    for sample_id in sample_ids:
        sample = get_sample(sample_id)
        if sample is None:
            continue
        try:
            item = _create_sample_task(
                db,
                sample=sample,
                target_agent=payload.target_agent,
                ai_endpoint_id=payload.ai_endpoint_id,
                params_json=payload.params_json,
                current_user=current_user,
                task_name=None,
                auto_run=payload.auto_run,
                schedule_at=payload.schedule_at,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        items.append(item)

    append_audit_log(
        db,
        current_user,
        "attack-tasks",
        "batch-from-samples",
        f"created {len(items)} tasks from samples",
    )
    db.commit()
    for item in items:
        db.refresh(item)

    enqueued_task_ids: list[int] = []
    if payload.auto_run and payload.schedule_at is None:
        for item in items:
            if item.status == "queued" and enqueue_attack_task(item.id):
                enqueued_task_ids.append(item.id)
        for item in items:
            db.refresh(item)

    return success(
        {
            "items": [_serialize_task(item) for item in items],
            "created": len(items),
            "enqueued_task_ids": enqueued_task_ids,
            "scheduled": payload.schedule_at is not None,
        },
        message="tasks created from samples",
    )


@router.post("/dispatch")
def dispatch_attack_tasks(
    payload: AttackTaskDispatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    if not payload.task_ids:
        raise HTTPException(status_code=400, detail="task_ids is required")

    items = [_get_task_or_404(db, task_id) for task_id in payload.task_ids]
    for item in items:
        _reset_task_for_dispatch(item, payload.schedule_at)
        append_task_runtime_log(
            item.id,
            level="info",
            stage="control",
            message=f"Task was dispatched to status {item.status}.",
            metadata={"operator": current_user.username},
        )

    append_audit_log(
        db,
        current_user,
        "attack-tasks",
        "dispatch",
        f"dispatched {len(items)} tasks",
    )
    db.commit()
    for item in items:
        db.refresh(item)

    enqueued_task_ids: list[int] = []
    if payload.schedule_at is None or payload.schedule_at <= utc_now():
        for item in items:
            if item.status == "queued" and enqueue_attack_task(item.id):
                enqueued_task_ids.append(item.id)
        for item in items:
            db.refresh(item)

    return success(
        {
            "items": [_serialize_task(item) for item in items],
            "enqueued_task_ids": enqueued_task_ids,
            "scheduled_at": _format_datetime(payload.schedule_at),
        },
        message="tasks dispatched",
    )


@router.get("")
def list_attack_tasks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    source_type: Optional[str] = None,
    execution_mode: Optional[str] = None,
    ai_endpoint_id: Optional[int] = None,
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    items = [_serialize_task(item) for item in db.query(AttackTask).order_by(AttackTask.created_at.desc(), AttackTask.id.desc()).all()]

    if attack_type:
        items = [item for item in items if item["attack_type"] == attack_type]
    if status:
        items = [item for item in items if item["status"] == status]
    if source_type:
        items = [item for item in items if item["source_type"] == source_type]
    if execution_mode:
        items = [item for item in items if item["execution_mode"] == execution_mode]
    if ai_endpoint_id is not None:
        items = [item for item in items if (item.get("ai_endpoint") or {}).get("id") == ai_endpoint_id]
    if keyword:
        items = [
            item
            for item in items
            if contains_keyword(
                item,
                keyword,
                ["task_name", "attack_type", "target_agent", "status", "source_type", "source_ref", "runtime_name"],
            )
        ]

    return success(paginate(items, page=page, page_size=page_size))


@router.get("/{task_id}")
def get_attack_task(
    task_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)
    return success(_serialize_task(item))


@router.get("/{task_id}/live-log")
def get_attack_task_live_log(
    task_id: int,
    after: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)
    snapshot = task_runtime_log_snapshot(task_id, after=after, limit=limit)
    return success(
        {
            "task": _serialize_task(item),
            "live_log": snapshot,
        }
    )


@router.post("/{task_id}/pause")
def pause_attack_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)

    if item.status == "pause_requested":
        return success({"task": _serialize_task(item)}, message="pause already requested")
    if item.status == "running":
        item.status = "pause_requested"
        append_task_runtime_log(
            item.id,
            level="warn",
            stage="control",
            message="Pause was requested for a running task. The worker will stop at the next checkpoint.",
            metadata={"operator": current_user.username},
        )
        append_audit_log(db, current_user, "attack-tasks", "pause-request", f"pause requested for task {item.task_name}")
        db.commit()
        db.refresh(item)
        logger.info("task pause requested | task_id=%s user=%s", item.id, current_user.username)
        return success({"task": _serialize_task(item)}, message="task pause requested")
    if item.status in RESUMABLE_TASK_STATUS_MAP:
        return success({"task": _serialize_task(item)}, message="task already paused")
    if item.status not in PAUSED_TASK_STATUS_MAP:
        raise HTTPException(status_code=409, detail=f"task in status {item.status} cannot be paused")

    _pause_task_before_execution(item)
    release_task_queue_slot(item.id)
    append_task_runtime_log(
        item.id,
        level="info",
        stage="control",
        message="Task was paused before execution.",
        metadata={"operator": current_user.username},
    )
    append_audit_log(db, current_user, "attack-tasks", "pause", f"paused task {item.task_name}")
    db.commit()
    db.refresh(item)
    logger.info("task paused | task_id=%s user=%s", item.id, current_user.username)
    return success({"task": _serialize_task(item)}, message="task paused")


@router.post("/{task_id}/resume")
def resume_attack_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)

    if item.status not in RESUMABLE_TASK_STATUS_MAP:
        raise HTTPException(status_code=409, detail=f"task in status {item.status} cannot be resumed")

    resumed_status = _resume_paused_task(item)
    append_task_runtime_log(
        item.id,
        level="info",
        stage="control",
        message=f"Task was resumed to status {resumed_status}.",
        metadata={"operator": current_user.username},
    )
    append_audit_log(db, current_user, "attack-tasks", "resume", f"resumed task {item.task_name}")
    db.commit()
    db.refresh(item)

    enqueued = False
    if item.status == "queued":
        enqueued = enqueue_attack_task(item.id)
        db.refresh(item)

    logger.info(
        "task resumed | task_id=%s status=%s enqueued=%s user=%s",
        item.id,
        item.status,
        enqueued,
        current_user.username,
    )
    return success(
        {
            "task": _serialize_task(item),
            "enqueued": enqueued,
        },
        message="task resumed",
    )


@router.post("/{task_id}/cancel")
def cancel_attack_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)

    if item.status == "cancel_requested":
        return success({"task": _serialize_task(item)}, message="cancel already requested")
    if item.status == "running":
        item.status = "cancel_requested"
        append_task_runtime_log(
            item.id,
            level="warn",
            stage="control",
            message="Cancel was requested for a running task. The worker will stop at the next checkpoint.",
            metadata={"operator": current_user.username},
        )
        append_audit_log(db, current_user, "attack-tasks", "cancel-request", f"cancel requested for task {item.task_name}")
        db.commit()
        db.refresh(item)
        logger.info("task cancel requested | task_id=%s user=%s", item.id, current_user.username)
        return success({"task": _serialize_task(item)}, message="task cancel requested")
    if item.status == "cancelled":
        return success({"task": _serialize_task(item)}, message="task already cancelled")
    if item.status not in {"ready", "queued", "scheduled", *RESUMABLE_TASK_STATUS_MAP.keys()}:
        raise HTTPException(status_code=409, detail=f"task in status {item.status} cannot be cancelled")

    _cancel_task_before_execution(item)
    release_task_queue_slot(item.id)
    append_task_runtime_log(
        item.id,
        level="info",
        stage="control",
        message="Task was cancelled before execution.",
        metadata={"operator": current_user.username},
    )
    append_audit_log(db, current_user, "attack-tasks", "cancel", f"cancelled task {item.task_name}")
    db.commit()
    db.refresh(item)
    logger.info("task cancelled | task_id=%s user=%s", item.id, current_user.username)
    return success({"task": _serialize_task(item)}, message="task cancelled")


@router.post("/{task_id}/retry")
def retry_attack_task(
    task_id: int,
    payload: AttackTaskRetryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)

    if item.status == "running":
        raise HTTPException(status_code=409, detail="running task cannot be retried")
    if item.status not in {"failed", "done", "cancelled", "dead_letter"}:
        raise HTTPException(status_code=409, detail=f"task in status {item.status} cannot be retried")

    _reset_task_for_dispatch(item, payload.schedule_at)
    append_task_runtime_log(
        item.id,
        level="info",
        stage="control",
        message=f"Task was retried and reset to status {item.status}.",
        metadata={"operator": current_user.username},
    )
    append_audit_log(db, current_user, "attack-tasks", "retry", f"retried task {item.task_name}")
    db.commit()
    db.refresh(item)

    enqueued = False
    if item.status == "queued":
        enqueued = enqueue_attack_task(item.id)
        db.refresh(item)

    logger.info(
        "task retried | task_id=%s status=%s enqueued=%s user=%s",
        item.id,
        item.status,
        enqueued,
        current_user.username,
    )
    return success(
        {
            "task": _serialize_task(item),
            "enqueued": enqueued,
        },
        message="task retried",
    )


@router.post("/{task_id}/run")
def run_attack_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)

    if item.status == "done" and item.latest_event_id and item.latest_report_id:
        logger.info("task run skipped | task_id=%s reason=already_completed user=%s", item.id, current_user.username)
        event = db.get(SecurityEvent, item.latest_event_id)
        report = db.get(Report, item.latest_report_id)
        return success(
            {
                "task": _serialize_task(item),
                "event": _serialize_event(event, item),
                "report": _serialize_report(report),
            },
            message="task already completed",
        )

    if item.status not in {"queued", "running"}:
        _reset_task_for_dispatch(item, None)
        append_task_runtime_log(
            item.id,
            level="info",
            stage="control",
            message="Task was reset for immediate execution.",
            metadata={"operator": current_user.username},
        )
        append_audit_log(db, current_user, "attack-tasks", "run", f"queued task {item.task_name}")
        logger.info("task state reset for rerun | task_id=%s user=%s", item.id, current_user.username)
        db.commit()
    else:
        item.scheduled_at = None
        item.execution_mode = item.execution_mode or "worker"
        db.commit()

    enqueued = enqueue_attack_task(item.id)
    db.refresh(item)
    logger.info(
        "task run requested | task_id=%s enqueued=%s status=%s user=%s",
        item.id,
        enqueued,
        item.status,
        current_user.username,
    )

    return success(
        {
            "task": _serialize_task(item),
            "event": None,
            "report": None,
        },
        message="task queued" if enqueued else "task already queued",
    )


@router.delete("/{task_id}")
def delete_attack_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_task_or_404(db, task_id)

    if item.status == "running":
        raise HTTPException(status_code=409, detail="running task cannot be deleted")

    release_task_queue_slot(item.id)

    reports = db.query(Report).filter(Report.task_id == item.id).order_by(Report.id.asc()).all()
    deleted_report_files = 0
    for report in reports:
        if _delete_report_artifact(report):
            deleted_report_files += 1
        db.delete(report)

    deleted_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.task_id == item.id)
        .delete(synchronize_session=False)
    )

    task_id_value = item.id
    task_name = item.task_name
    deleted_reports = len(reports)
    db.delete(item)
    append_audit_log(db, current_user, "attack-tasks", "delete", f"deleted task {task_name}")
    db.commit()

    logger.info(
        "task deleted | task_id=%s reports=%s events=%s report_files=%s user=%s",
        task_id_value,
        deleted_reports,
        deleted_events,
        deleted_report_files,
        current_user.username,
    )
    return success(
        {
            "id": task_id_value,
            "task_name": task_name,
            "deleted_reports": deleted_reports,
            "deleted_events": deleted_events,
            "deleted_report_files": deleted_report_files,
        },
        message="task deleted",
    )
