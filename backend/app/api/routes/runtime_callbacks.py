from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AttackTask, Report, SecurityEvent, User
from ...schemas.task import RuntimeTaskAuthorizeRequest, RuntimeTaskComplete, RuntimeTaskHeartbeat
from ...services.authorization import get_current_user
from ...services.event_status import EVENT_STATUS_ALLOWED, EVENT_STATUS_SUSPICIOUS, normalize_event_status
from ...services.policy_enforcer import (
    append_task_authorization_snapshot,
    authorize_runtime_action,
    serialize_authorization_decision,
)
from ...services.task_runner import record_task_outcome
from ...services.time_utils import format_beijing, utc_now

router = APIRouter()


def _format_datetime(value: datetime | None) -> str | None:
    return format_beijing(value)


def _serialize_task(item: AttackTask) -> dict:
    return {
        "id": item.id,
        "task_name": item.task_name,
        "attack_type": item.attack_type,
        "target_agent": item.target_agent,
        "status": item.status,
        "source_type": item.source_type,
        "source_ref": item.source_ref,
        "execution_mode": item.execution_mode,
        "runtime_name": item.runtime_name,
        "runtime_task_ref": item.runtime_task_ref,
        "params_json": item.params,
        "result_summary": item.result_summary,
        "latest_event_id": item.latest_event_id,
        "latest_report_id": item.latest_report_id,
        "scheduled_at": _format_datetime(item.scheduled_at),
        "started_at": _format_datetime(item.started_at),
        "finished_at": _format_datetime(item.finished_at),
        "last_heartbeat_at": _format_datetime(item.last_heartbeat_at),
        "created_at": _format_datetime(item.created_at),
        "updated_at": _format_datetime(item.updated_at),
    }


def _serialize_event(item: SecurityEvent | None) -> dict | None:
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
        "created_at": _format_datetime(item.created_at),
    }


def _serialize_report(item: Report | None) -> dict | None:
    if item is None:
        return None
    return {
        "id": item.id,
        "task_id": item.task_id,
        "report_name": item.report_name,
        "report_type": item.report_type,
        "file_path": item.file_path,
        "download_url": f"/api/reports/{item.id}/download",
        "summary_text": item.summary_text,
        "created_by": item.created_by,
        "created_at": _format_datetime(item.created_at),
    }


def _get_task_or_404(db: Session, task_id: int) -> AttackTask:
    item = db.query(AttackTask).get(task_id)
    if item is None:
        raise HTTPException(status_code=404, detail="attack task not found")
    return item


def _merge_runtime_state(task: AttackTask, payload: dict) -> None:
    params = dict(task.params)
    runtime_state = dict(params.get("runtime") or {})
    runtime_state.update(payload)
    params["runtime"] = runtime_state
    task.set_params(params)


@router.post("/tasks/{task_id}/authorize")
def authorize_runtime_task(
    task_id: int,
    payload: RuntimeTaskAuthorizeRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    item = _get_task_or_404(db, task_id)
    if item.status in {"done", "failed"} and item.latest_report_id:
        raise HTTPException(status_code=409, detail="task already completed")

    now = utc_now()
    if payload.runtime_name:
        item.runtime_name = payload.runtime_name
    if payload.runtime_task_ref:
        item.runtime_task_ref = payload.runtime_task_ref
    item.execution_mode = "runtime_callback"
    item.last_heartbeat_at = now

    action = payload.model_dump()
    decision = authorize_runtime_action(db, item, action)
    append_task_authorization_snapshot(item, action=action, decision=decision)
    serialized_decision = serialize_authorization_decision(decision)
    _merge_runtime_state(
        item,
        {
            "authorization_at": format_beijing(now),
            "authorization_result": serialized_decision,
        },
    )

    db.commit()
    db.refresh(item)
    return success(
        {
            "task": _serialize_task(item),
            "authorization": serialized_decision,
        },
        message="runtime authorization evaluated",
    )


@router.post("/tasks/{task_id}/heartbeat")
def heartbeat_runtime_task(
    task_id: int,
    payload: RuntimeTaskHeartbeat,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    item = _get_task_or_404(db, task_id)
    if item.status in {"done", "failed"} and item.latest_report_id:
        raise HTTPException(status_code=409, detail="task already completed")

    now = utc_now()
    item.status = "running"
    item.execution_mode = "runtime_callback"
    item.runtime_name = payload.runtime_name
    item.runtime_task_ref = payload.runtime_task_ref or item.runtime_task_ref
    item.started_at = item.started_at or now
    item.last_heartbeat_at = now
    item.scheduled_at = None
    _merge_runtime_state(
        item,
        {
            "status": payload.status,
            "message": payload.message,
            "progress": payload.progress,
            "metadata": payload.metadata,
            "heartbeat_at": format_beijing(now),
        },
    )

    db.commit()
    db.refresh(item)
    return success(_serialize_task(item), message="heartbeat received")


@router.post("/tasks/{task_id}/complete")
def complete_runtime_task(
    task_id: int,
    payload: RuntimeTaskComplete,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    item = _get_task_or_404(db, task_id)
    if item.status in {"done", "failed"} and item.latest_report_id:
        event = db.query(SecurityEvent).get(item.latest_event_id) if item.latest_event_id else None
        report = db.query(Report).get(item.latest_report_id) if item.latest_report_id else None
        return success(
            {
                "task": _serialize_task(item),
                "event": _serialize_event(event),
                "report": _serialize_report(report),
            },
            message="task already completed",
        )

    now = utc_now()
    item.execution_mode = "runtime_callback"
    item.runtime_name = payload.runtime_name or item.runtime_name or "external-runtime"
    item.runtime_task_ref = payload.runtime_task_ref or item.runtime_task_ref
    item.started_at = item.started_at or now
    item.last_heartbeat_at = now
    item.scheduled_at = None
    _merge_runtime_state(
        item,
        {
            "status": payload.status,
            "metadata": payload.metadata,
            "completed_at": format_beijing(now),
        },
    )

    raw_response = payload.raw_response_text
    if not raw_response and payload.raw_response_json is not None:
        raw_response = json.dumps(payload.raw_response_json, ensure_ascii=False)
    if not raw_response:
        raw_response = json.dumps({"runtime_metadata": payload.metadata}, ensure_ascii=False)

    event_payload = payload.event
    default_event_source = f"runtime/{item.runtime_name or 'external-runtime'}"
    event_type = event_payload.event_type if event_payload is not None else (item.attack_type or "runtime_execution")
    event_level = event_payload.event_level if event_payload is not None else ("high" if payload.status == "failed" else "medium")
    event_status = event_payload.event_status if event_payload is not None else (
        EVENT_STATUS_SUSPICIOUS if payload.status == "failed" else EVENT_STATUS_ALLOWED
    )
    event_source = event_payload.source if event_payload is not None and event_payload.source else default_event_source
    event_detail = event_payload.detail if event_payload is not None else payload.summary
    hit_rules = event_payload.hit_rules if event_payload is not None else []
    operation_logs = event_payload.operation_logs if event_payload is not None else [
        {"operator": item.runtime_name or "external-runtime", "action": "runtime_complete", "time": format_beijing(now)}
    ]
    raw_input = event_payload.raw_input if event_payload is not None else json.dumps(item.params, ensure_ascii=False)
    result = event_payload.result if event_payload is not None and event_payload.result else payload.summary

    task, event, report = record_task_outcome(
        db,
        item,
        summary=payload.summary,
        raw_response=raw_response,
        task_status="failed" if payload.status == "failed" else "done",
        event_type=event_type,
        event_level=event_level,
        event_status=event_status,
        event_source=event_source,
        event_detail=event_detail,
        hit_rules=hit_rules,
        raw_input=raw_input,
        result=result,
        operation_logs=operation_logs,
        report_type=payload.report_type,
        created_by=item.created_by or 1,
        create_report=True,
    )

    db.commit()
    db.refresh(task)
    if event is not None:
        db.refresh(event)
    if report is not None:
        db.refresh(report)

    return success(
        {
            "task": _serialize_task(task),
            "event": _serialize_event(event),
            "report": _serialize_report(report),
        },
        message="runtime result ingested",
    )
