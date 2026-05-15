from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from ..db.session import SessionLocal
from ..models import ManagedRuntime, RuntimeDispatchCommand
from .time_utils import format_beijing, utc_now

OPENCLAW_RUNTIME_TYPE = "openclaw_control_bridge"
RUNTIME_ONLINE_WINDOW = timedelta(minutes=10)
COMMAND_STATUS_PENDING = "pending"
COMMAND_STATUS_CLAIMED = "claimed"
COMMAND_STATUS_COMPLETED = "completed"
COMMAND_STATUS_FAILED = "failed"
COMMAND_STATUS_CANCELLED = "cancelled"
COMMAND_FINAL_STATUSES = {
    COMMAND_STATUS_COMPLETED,
    COMMAND_STATUS_FAILED,
    COMMAND_STATUS_CANCELLED,
}
RUNTIME_COMMAND_TYPE_OPENCLAW_WS_ATTACK = "openclaw_ws_attack"
RUNTIME_COMMAND_TYPE_REMOTE_SKILL_SCAN = "remote_skill_scan"


@dataclass
class RuntimeBindingResolution:
    has_binding: bool
    active_runtime: ManagedRuntime | None


def serialize_runtime_dispatch_command(item: RuntimeDispatchCommand) -> dict[str, Any]:
    return {
        "id": item.id,
        "runtime_id": item.runtime_id,
        "ai_endpoint_id": item.ai_endpoint_id,
        "source_task_id": item.source_task_id,
        "request_key": item.request_key,
        "command_type": item.command_type,
        "status": item.status,
        "payload": item.payload,
        "response": item.response,
        "error": item.error_text,
        "claimed_at": format_beijing(item.claimed_at) if item.claimed_at else "",
        "completed_at": format_beijing(item.completed_at) if item.completed_at else "",
        "expires_at": format_beijing(item.expires_at) if item.expires_at else "",
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
    }


def resolve_openclaw_runtime_binding(db: Session, ai_endpoint_id: int | None) -> RuntimeBindingResolution:
    if ai_endpoint_id is None:
        return RuntimeBindingResolution(has_binding=False, active_runtime=None)

    base_query = db.query(ManagedRuntime).filter(
        ManagedRuntime.ai_endpoint_id == ai_endpoint_id,
        ManagedRuntime.runtime_type == OPENCLAW_RUNTIME_TYPE,
    )
    has_binding = base_query.first() is not None
    if not has_binding:
        return RuntimeBindingResolution(has_binding=False, active_runtime=None)

    online_since = utc_now() - RUNTIME_ONLINE_WINDOW
    active_runtime = (
        base_query.filter(
            ManagedRuntime.status == "active",
            ManagedRuntime.last_seen_at.isnot(None),
            ManagedRuntime.last_seen_at >= online_since,
        )
        .order_by(ManagedRuntime.last_seen_at.desc(), ManagedRuntime.id.desc())
        .first()
    )
    return RuntimeBindingResolution(has_binding=True, active_runtime=active_runtime)


def enqueue_runtime_command(
    *,
    runtime_id: int,
    ai_endpoint_id: int | None,
    source_task_id: int | None,
    command_type: str,
    payload: dict[str, Any],
    expires_in_seconds: int = 300,
) -> int:
    db = SessionLocal()
    try:
        now = utc_now()
        item = RuntimeDispatchCommand(
            runtime_id=runtime_id,
            ai_endpoint_id=ai_endpoint_id,
            source_task_id=source_task_id,
            request_key=f"cmd_{uuid4().hex[:24]}",
            command_type=command_type,
            status=COMMAND_STATUS_PENDING,
            claimed_at=None,
            completed_at=None,
            expires_at=now + timedelta(seconds=max(30, int(expires_in_seconds))),
        )
        item.set_payload(dict(payload or {}))
        item.set_response({})
        db.add(item)
        db.commit()
        db.refresh(item)
        return int(item.id)
    finally:
        db.close()


def get_runtime_command(command_id: int) -> dict[str, Any] | None:
    db = SessionLocal()
    try:
        item = db.get(RuntimeDispatchCommand, command_id)
        if item is None:
            return None
        return serialize_runtime_dispatch_command(item)
    finally:
        db.close()


def cancel_runtime_command(command_id: int, *, reason: str) -> dict[str, Any] | None:
    db = SessionLocal()
    try:
        item = db.get(RuntimeDispatchCommand, command_id)
        if item is None:
            return None
        if item.status in COMMAND_FINAL_STATUSES:
            return serialize_runtime_dispatch_command(item)
        item.status = COMMAND_STATUS_CANCELLED
        item.error_text = str(reason or "").strip()
        item.completed_at = utc_now()
        item.set_response({"status": COMMAND_STATUS_CANCELLED, "summary": item.error_text})
        db.commit()
        db.refresh(item)
        return serialize_runtime_dispatch_command(item)
    finally:
        db.close()


def claim_next_runtime_command(db: Session, runtime_id: int) -> RuntimeDispatchCommand | None:
    now = utc_now()

    expired_items = (
        db.query(RuntimeDispatchCommand)
        .filter(RuntimeDispatchCommand.runtime_id == runtime_id)
        .filter(RuntimeDispatchCommand.status.in_((COMMAND_STATUS_PENDING, COMMAND_STATUS_CLAIMED)))
        .filter(RuntimeDispatchCommand.expires_at.isnot(None))
        .filter(RuntimeDispatchCommand.expires_at < now)
        .all()
    )
    for expired in expired_items:
        expired.status = COMMAND_STATUS_FAILED
        expired.error_text = expired.error_text or "runtime command expired before completion"
        expired.completed_at = now
        expired.set_response(
            {
                "status": COMMAND_STATUS_FAILED,
                "summary": expired.error_text,
            }
        )

    candidate_ids = [
        item.id
        for item in (
            db.query(RuntimeDispatchCommand.id)
            .filter(RuntimeDispatchCommand.runtime_id == runtime_id)
            .filter(RuntimeDispatchCommand.status == COMMAND_STATUS_PENDING)
            .order_by(RuntimeDispatchCommand.created_at.asc(), RuntimeDispatchCommand.id.asc())
            .limit(20)
            .all()
        )
    ]
    for command_id in candidate_ids:
        updated = (
            db.query(RuntimeDispatchCommand)
            .filter(RuntimeDispatchCommand.id == command_id)
            .filter(RuntimeDispatchCommand.runtime_id == runtime_id)
            .filter(RuntimeDispatchCommand.status == COMMAND_STATUS_PENDING)
            .update(
                {
                    RuntimeDispatchCommand.status: COMMAND_STATUS_CLAIMED,
                    RuntimeDispatchCommand.claimed_at: now,
                },
                synchronize_session=False,
            )
        )
        if not updated:
            continue
        db.flush()
        return db.get(RuntimeDispatchCommand, command_id)
    return None


def complete_runtime_command(
    db: Session,
    *,
    item: RuntimeDispatchCommand,
    status: str,
    summary: str,
    response_text: str | None,
    response_json: dict[str, Any] | list[Any] | None,
    error: str | None,
    metadata: dict[str, Any] | None,
) -> RuntimeDispatchCommand:
    normalized_status = str(status or "").strip().lower()
    if normalized_status not in COMMAND_FINAL_STATUSES:
        normalized_status = COMMAND_STATUS_COMPLETED

    item.status = normalized_status
    item.error_text = str(error or "").strip()
    item.completed_at = utc_now()
    item.set_response(
        {
            "status": normalized_status,
            "summary": str(summary or "").strip(),
            "response_text": str(response_text or ""),
            "response_json": response_json,
            "error": item.error_text,
            "metadata": dict(metadata or {}),
        }
    )
    db.flush()
    return item
