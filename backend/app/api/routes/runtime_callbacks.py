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
from ...services.mcp_security import (
    action_requires_mcp_ticket,
    issue_mcp_execution_ticket,
    resolve_task_ai_endpoint_id,
    serialize_mcp_execution_ticket,
    validate_mcp_execution_ticket,
)
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
    item = db.get(AttackTask, task_id)
    if item is None:
        raise HTTPException(status_code=404, detail="attack task not found")
    return item


def _merge_runtime_state(task: AttackTask, payload: dict) -> None:
    params = dict(task.params)
    runtime_state = dict(params.get("runtime") or {})
    runtime_state.update(payload)
    params["runtime"] = runtime_state
    task.set_params(params)


def _build_runtime_completion_action(task: AttackTask, payload: RuntimeTaskComplete) -> dict[str, object]:
    metadata = dict(payload.metadata or {})
    params = dict(task.params)
    return {
        "action_type": str(metadata.get("action_type") or "").strip(),
        "runtime_name": str(payload.runtime_name or task.runtime_name or "").strip(),
        "runtime_task_ref": str(payload.runtime_task_ref or task.runtime_task_ref or "").strip(),
        "call_id": str(payload.call_id or metadata.get("call_id") or metadata.get("ws_call_id") or "").strip(),
        "tool_call_id": str(
            payload.tool_call_id
            or metadata.get("tool_call_id")
            or metadata.get("openclaw_tool_call_id")
            or params.get("tool_call_id")
            or ""
        ).strip(),
        "operation_type": str(
            payload.operation_type
            or metadata.get("operation_type")
            or metadata.get("openclaw_operation_type")
            or params.get("operation_type")
            or ""
        ).strip().lower(),
        "event_name": str(
            payload.event_name
            or metadata.get("event_name")
            or metadata.get("openclaw_event_name")
            or params.get("event_name")
            or ""
        ).strip(),
        "mcp_ticket_key": str(payload.mcp_ticket_key or metadata.get("mcp_ticket_key") or "").strip(),
        "request_args_hash": str(
            payload.request_args_hash
            or metadata.get("request_args_hash")
            or params.get("request_args_hash")
            or ""
        ).strip(),
        "session_id": str(metadata.get("session_id") or params.get("session_id") or "").strip(),
        "approval_id": str(metadata.get("approval_id") or params.get("approval_id") or "").strip(),
        "mcp_server": str(metadata.get("mcp_server") or params.get("mcp_server") or "").strip(),
        "capability_name": str(metadata.get("capability_name") or params.get("capability_name") or "").strip(),
        "source_plugin": str(metadata.get("source_plugin") or params.get("source_plugin") or "").strip(),
        "target_plugin": str(metadata.get("target_plugin") or params.get("target_plugin") or "").strip(),
        "handoff_token": str(metadata.get("handoff_token") or params.get("handoff_token") or "").strip(),
        "requested_scopes": list(metadata.get("requested_scopes") or params.get("requested_scopes") or []),
        "metadata": metadata,
        "consume_mcp_ticket": bool(payload.consume_mcp_ticket or metadata.get("consume_mcp_ticket")),
    }


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
    issued_ticket = None
    if decision.decision != "deny" and action_requires_mcp_ticket(action):
        issued_ticket = issue_mcp_execution_ticket(
            db,
            task=item,
            runtime=None,
            action=action,
        )
        if issued_ticket is not None:
            serialized_decision["mcp_execution_ticket"] = serialize_mcp_execution_ticket(issued_ticket)
    _merge_runtime_state(
        item,
        {
            "authorization_at": format_beijing(now),
            "authorization_result": serialized_decision,
            "mcp_execution_ticket": serialize_mcp_execution_ticket(issued_ticket) if issued_ticket is not None else None,
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
        event = db.get(SecurityEvent, item.latest_event_id) if item.latest_event_id else None
        report = db.get(Report, item.latest_report_id) if item.latest_report_id else None
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
    completion_action = _build_runtime_completion_action(item, payload)
    mcp_ticket_validation = None
    if completion_action["mcp_ticket_key"] or completion_action["consume_mcp_ticket"]:
        mcp_ticket_validation = validate_mcp_execution_ticket(
            db,
            ticket_key=str(completion_action["mcp_ticket_key"] or ""),
            task_id=item.id,
            ai_endpoint_id=resolve_task_ai_endpoint_id(item),
            action=completion_action,
            consume=bool(completion_action["consume_mcp_ticket"]),
        )
    _merge_runtime_state(
        item,
        {
            "status": payload.status,
            "metadata": payload.metadata,
            "completed_at": format_beijing(now),
            "mcp_ticket_audit": {
                "allowed": mcp_ticket_validation.allowed,
                "code": mcp_ticket_validation.code,
                "reason": mcp_ticket_validation.reason,
                "ticket_key": str(completion_action["mcp_ticket_key"] or ""),
                "consume": bool(completion_action["consume_mcp_ticket"]),
                "completed_at": format_beijing(now),
            }
            if mcp_ticket_validation is not None
            else None,
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
    task_status = "failed" if payload.status == "failed" else "done"
    final_summary = payload.summary

    if mcp_ticket_validation is not None and not mcp_ticket_validation.allowed:
        task_status = "failed"
        event_status = "intercepted"
        event_level = "high"
        final_summary = mcp_ticket_validation.reason
        event_detail = f"{event_detail}; {mcp_ticket_validation.reason}" if event_detail else mcp_ticket_validation.reason
        result = result or mcp_ticket_validation.reason
        hit_rules = list(dict.fromkeys([*hit_rules, "mcp-session-bind"]))
        operation_logs = [
            *operation_logs,
            {
                "operator": item.runtime_name or "external-runtime",
                "action": "mcp_ticket_validation_failed",
                "time": format_beijing(now),
                "detail": mcp_ticket_validation.reason,
            },
        ]

    task, event, report = record_task_outcome(
        db,
        item,
        summary=final_summary,
        raw_response=raw_response,
        task_status=task_status,
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
