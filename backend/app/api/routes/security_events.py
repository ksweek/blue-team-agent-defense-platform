from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AttackTask, Report, SecurityEvent, User
from ...schemas.event import EventBatchHandle, EventStatusUpdate
from ...services.ai_endpoints import task_ai_endpoint_snapshot
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.event_status import EVENT_STATUS_SUSPICIOUS, normalize_event_status
from ...services.guard_trace import build_task_guard_trace
from ...services.repository import contains_keyword, paginate
from ...services.security_report_view import build_security_event_report_view
from ...services.security_taxonomy import (
    build_event_trigger_summary,
    build_event_trigger_support_text,
    build_policy_reference_auto,
    build_trigger_sections,
)
from ...services.time_utils import format_beijing, utc_now

router = APIRouter()


def _serialize_security_event(item: SecurityEvent, task: AttackTask | None = None) -> dict:
    guard_trace = build_task_guard_trace(task)
    return {
        "id": item.id,
        "task_id": item.task_id,
        "event_type": item.event_type,
        "event_level": item.event_level,
        "source": item.source,
        "target": item.target,
        "status": normalize_event_status(item.status, EVENT_STATUS_SUSPICIOUS),
        "created_at": format_beijing(item.created_at) or "",
        "detail": item.detail,
        "hit_rules": item.hit_rules,
        "hit_rule_details": [build_policy_reference_auto(value) for value in item.hit_rules],
        "raw_input": item.raw_input,
        "result": item.result,
        "operation_logs": item.operation_logs,
        "guard_trace": guard_trace,
        "trigger_summary": build_event_trigger_summary(hit_rules=item.hit_rules, guard_trace=guard_trace),
        "trigger_support_text": build_event_trigger_support_text(hit_rules=item.hit_rules, guard_trace=guard_trace),
        "trigger_sections": build_trigger_sections(hit_rules=item.hit_rules, guard_trace=guard_trace),
    }


def _serialize_attack_task(item: AttackTask | None) -> dict | None:
    if item is None:
        return None

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
        "scheduled_at": format_beijing(item.scheduled_at),
        "started_at": format_beijing(item.started_at),
        "finished_at": format_beijing(item.finished_at),
        "last_heartbeat_at": format_beijing(item.last_heartbeat_at),
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
        "guard_trace": build_task_guard_trace(item),
    }


def _serialize_report(item: Report | None) -> dict | None:
    if item is None:
        return None

    return {
        "id": item.id,
        "report_name": item.report_name,
        "report_type": item.report_type,
        "task_id": item.task_id,
        "file_path": item.file_path,
        "summary_text": item.summary_text,
        "created_by": item.created_by,
        "created_at": format_beijing(item.created_at) or "",
        "download_url": f"/api/reports/{item.id}/download",
    }


def _build_event_task_map(db: Session, items: list[SecurityEvent]) -> dict[int, AttackTask]:
    task_ids = sorted({item.task_id for item in items if item.task_id})
    if not task_ids:
        return {}
    return {task.id: task for task in db.query(AttackTask).filter(AttackTask.id.in_(task_ids)).all()}


def _get_security_event_or_404(db: Session, event_id: int) -> SecurityEvent:
    item = db.get(SecurityEvent, event_id)
    if item is None:
        raise HTTPException(status_code=404, detail="security event not found")
    return item


def _append_operation_log(item: SecurityEvent, operator: str, action: str) -> None:
    operation_logs = item.operation_logs
    operation_logs.append(
        {
            "operator": operator,
            "action": action,
            "time": format_beijing(utc_now()) or "",
        }
    )
    item.set_operation_logs(operation_logs)


def _filter_security_events(
    items: list[dict],
    event_type: Optional[str] = None,
    event_level: Optional[str] = None,
    status: Optional[str] = None,
    keyword: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> list[dict]:
    if event_type:
        items = [item for item in items if item["event_type"] == event_type]
    if event_level:
        items = [item for item in items if item["event_level"] == event_level]
    if status:
        normalized_status = normalize_event_status(status, EVENT_STATUS_SUSPICIOUS)
        items = [item for item in items if item["status"] == normalized_status]
    if keyword:
        items = [
            item
            for item in items
            if contains_keyword(item, keyword, ["event_type", "source", "target", "detail", "result"])
        ]
    if start_time:
        items = [item for item in items if item["created_at"] >= start_time]
    if end_time:
        items = [item for item in items if item["created_at"] <= end_time]

    return items


def _get_report_for_task(db: Session, task: AttackTask | None) -> Report | None:
    if task is None:
        return None

    if task.latest_report_id:
        item = db.get(Report, task.latest_report_id)
        if item is not None:
            return item

    return (
        db.query(Report)
        .filter(Report.task_id == task.id)
        .order_by(Report.created_at.desc(), Report.id.desc())
        .first()
    )


@router.get("")
def list_security_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    event_type: Optional[str] = None,
    event_level: Optional[str] = None,
    status: Optional[str] = None,
    keyword: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).all()
    task_map = _build_event_task_map(db, events)
    items = [_serialize_security_event(item, task_map.get(item.task_id or 0)) for item in events]
    items = _filter_security_events(
        items,
        event_type=event_type,
        event_level=event_level,
        status=status,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
    )
    return success(paginate(items, page=page, page_size=page_size))


@router.post("/batch-handle")
def batch_handle_events(
    payload: EventBatchHandle,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    updated_items = []
    for event_id in payload.ids:
        item = _get_security_event_or_404(db, event_id)
        normalized_status = normalize_event_status(payload.status, EVENT_STATUS_SUSPICIOUS)
        item.status = normalized_status
        _append_operation_log(item, current_user.username, normalized_status)
        task = db.get(AttackTask, item.task_id) if item.task_id else None
        updated_items.append(_serialize_security_event(item, task))

    append_audit_log(db, current_user, "security-events", "batch-handle", f"updated {len(updated_items)} events")
    db.commit()
    return success({"items": updated_items, "total": len(updated_items)}, message="batch handled")


@router.get("/{event_id}")
def get_security_event(
    event_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_security_event_or_404(db, event_id)
    task = db.get(AttackTask, item.task_id) if item.task_id else None
    return success(_serialize_security_event(item, task))


@router.get("/{event_id}/report-view")
def get_security_event_report_view(
    event_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_security_event_or_404(db, event_id)
    task = db.get(AttackTask, item.task_id) if item.task_id else None
    report = _get_report_for_task(db, task)
    analytics = build_security_event_report_view(db, event=item, task=task, report=report)

    return success(
        {
            "event": _serialize_security_event(item, task),
            "task": _serialize_attack_task(task),
            "report": _serialize_report(report),
            **analytics,
        }
    )


@router.put("/{event_id}/status")
def update_security_event_status(
    event_id: int,
    payload: EventStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_security_event_or_404(db, event_id)
    normalized_status = normalize_event_status(payload.status, EVENT_STATUS_SUSPICIOUS)
    item.status = normalized_status
    _append_operation_log(item, current_user.username, normalized_status)
    append_audit_log(db, current_user, "security-events", "update-status", f"updated event {event_id}")
    db.commit()
    db.refresh(item)
    task = db.get(AttackTask, item.task_id) if item.task_id else None
    return success(_serialize_security_event(item, task), message="status updated")
