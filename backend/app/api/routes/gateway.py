from __future__ import annotations

import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, replace
from typing import Any, Iterable, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from sqlalchemy.orm import Session

from ...core.config import settings
from ...core.response import failure, success
from ...db.session import get_db
from ...models import AiEndpoint, AttackTask, DefenseConfig, ManagedRuntime, Report, RuntimeDispatchCommand, RuntimeEnrollmentToken, SecurityEvent, User
from ...schemas.gateway import (
    GatewayAgentRunRequest,
    GatewayChatCompletionsRequest,
    GatewayRuntimeCommandCompleteRequest,
    GatewayResponsesRequest,
    GatewayRuntimeAuthorizeRequest,
    GatewayRuntimeCompleteRequest,
    GatewayRuntimeHeartbeatRequest,
    GatewayTargetSelector,
)
from ...schemas.runtime_registry import RuntimeRegisterRequest, RuntimeRegisterStatusRequest
from ...schemas.task import AttackTaskCreate
from ...services.ai_endpoints import (
    attach_ai_endpoint_selection,
    build_ai_endpoint_snapshot,
    build_env_ai_endpoint_snapshot,
    get_default_ai_endpoint,
    normalize_endpoint_group,
    normalize_endpoint_key,
    provider_endpoint_from_ai_endpoint,
    provider_endpoint_from_env,
)
from ...services.event_status import EVENT_STATUS_ALLOWED, EVENT_STATUS_INTERCEPTED, EVENT_STATUS_SUSPICIOUS
from ...services.model_provider import (
    ProviderConfigurationError,
    ProviderEndpoint,
    ProviderExecutionError,
    ProviderResult,
    ProviderStreamSession,
    invoke_chat_completion_stream,
    invoke_chat_completion,
    provider_supports_streaming,
)
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
    authorize_task_preflight,
    serialize_authorization_decision,
)
from ...services.security import decode_access_token, hash_password
from ...services.task_runner import record_task_outcome
from ...services.time_utils import format_beijing, utc_now
from ...services.runtime_registry import (
    build_runtime_auth_headers,
    create_registration_identity,
    find_runtime_by_runtime_key,
    issue_runtime_credentials,
    resolve_enrollment_token,
    runtime_status_summary,
    serialize_managed_runtime,
    verify_runtime_poll_secret,
    verify_runtime_secret,
)
from ...services.runtime_dispatch import claim_next_runtime_command, complete_runtime_command, serialize_runtime_dispatch_command

router = APIRouter()
logger = logging.getLogger("app.gateway")
bearer_scheme = HTTPBearer(auto_error=False)

AUTHORIZATION_VALUE_RE = re.compile(r"(\bAuthorization\b\s*[:=]\s*(?:Bearer|Basic)\s+)([^\s\"',]+)", re.IGNORECASE)
QUERY_SECRET_RE = re.compile(
    r"([?&](?:api[_-]?key|access_token|refresh_token|token|sig(?:nature)?|auth|password)=)([^&#\s]+)",
    re.IGNORECASE,
)
JSON_SECRET_VALUE_RE = re.compile(
    r"(\"?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|smtp_password|qq_email_auth_code|password|secret|handoff_token|x-api-key)\"?\s*:\s*\")([^\"]+)(\")",
    re.IGNORECASE,
)
TEXT_SECRET_VALUE_RE = re.compile(
    r"(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|smtp_password|qq_email_auth_code|password|secret|handoff_token|x-api-key)\b\s*[:=]\s*)([^\s\"',}]+)",
    re.IGNORECASE,
)
COOKIE_RE = re.compile(r"(\b(?:cookie|set-cookie)\b\s*[:=]\s*)([^\r\n]+)", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b")
ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
WINDOWS_PATH_RE = re.compile(r"\b(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+")
UNIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9:])((?:\/[^\/\s\"'`]+){2,})")


@dataclass
class GatewayPrincipal:
    user: Optional[User]
    runtime: Optional[ManagedRuntime]
    client_id: str
    auth_mode: str


@dataclass
class GatewayExecutionOutcome:
    state: str
    status_code: int
    request_id: str
    task: AttackTask
    event: Optional[SecurityEvent]
    report: Optional[Report]
    authorization: dict[str, Any]
    provider_result: Optional[ProviderResult]
    provider_payload: Optional[dict[str, Any]]
    response_text: str
    redaction: dict[str, Any]
    summary: str
    detail: str
    event_status: str
    event_level: str


@dataclass
class GatewayPreparedExecution:
    request_id: str
    trace_id: str
    source_ip: str
    source_type: str
    source_label: str
    target_name: str
    task: AttackTask
    authorization: dict[str, Any]
    raw_input: str
    provider: ProviderEndpoint
    redaction_mode: str


def _format_datetime(value: Any) -> Optional[str]:
    return format_beijing(value)


def _serialize_task(item: AttackTask) -> dict[str, Any]:
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


def _serialize_event(item: Optional[SecurityEvent]) -> Optional[dict[str, Any]]:
    if item is None:
        return None
    return {
        "id": item.id,
        "task_id": item.task_id,
        "event_type": item.event_type,
        "event_level": item.event_level,
        "source": item.source,
        "target": item.target,
        "status": item.status,
        "detail": item.detail,
        "hit_rules": item.hit_rules,
        "created_at": _format_datetime(item.created_at),
    }


def _serialize_report(item: Optional[Report]) -> Optional[dict[str, Any]]:
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
        "created_at": _format_datetime(item.created_at),
    }


def _serialize_runtime_command(item: RuntimeDispatchCommand | None) -> dict[str, Any] | None:
    if item is None:
        return None
    return serialize_runtime_dispatch_command(item)


def _build_runtime_completion_action(task: AttackTask, payload: GatewayRuntimeCompleteRequest) -> dict[str, Any]:
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


def _mask_middle(value: str, visible_start: int = 4, visible_end: int = 2) -> str:
    text = value.strip()
    if not text:
        return ""
    if len(text) <= visible_start + visible_end + 1:
        return "***"
    return f"{text[:visible_start]}***{text[-visible_end:]}"


def _mask_email(value: str) -> str:
    local_part, _, domain = value.partition("@")
    local = local_part.strip()
    if not local:
        return f"***@{domain or '***'}"
    visible = local[:1] if len(local) <= 2 else local[:2]
    return f"{visible}***@{domain or '***'}"


def _mask_windows_path(value: str) -> str:
    normalized = value.replace("/", "\\")
    segments = [item for item in re.split(r"\\+", normalized) if item]
    tail = segments[-1] if segments else "***"
    if re.match(r"^[A-Za-z]:\\", normalized):
        return f"{normalized[:2]}\\...\\{tail}"
    return f"\\\\...\\{tail}"


def _mask_unix_path(value: str) -> str:
    segments = [item for item in value.split("/") if item]
    tail = segments[-1] if segments else "***"
    return f"/.../{tail}"


def _should_mask_unix_path(value: str) -> bool:
    return re.match(r"^/(?:api|@vite|src|assets|node_modules)\b", value, re.IGNORECASE) is None


def _token_matches(expected: str, actual: Optional[str]) -> bool:
    return bool(expected and actual) and secrets.compare_digest(expected, actual)


def _matches_service_token(value: Optional[str]) -> bool:
    return _token_matches(settings.gateway_api_token, value)


def _gateway_headers(
    *,
    request_id: str,
    authorization: Optional[dict[str, Any]] = None,
    task: Optional[AttackTask] = None,
    event: Optional[SecurityEvent] = None,
    report: Optional[Report] = None,
    output_action: Optional[str] = None,
) -> dict[str, str]:
    headers = {"X-BlueTeam-Request-ID": request_id}
    if authorization:
        headers["X-BlueTeam-Decision"] = str(authorization.get("decision") or "")
    if task is not None:
        headers["X-BlueTeam-Task-ID"] = str(task.id)
    if event is not None:
        headers["X-BlueTeam-Event-ID"] = str(event.id)
    if report is not None:
        headers["X-BlueTeam-Report-ID"] = str(report.id)
    if output_action:
        headers["X-BlueTeam-Output-Action"] = output_action
    return headers


def _openai_error_response(
    status_code: int,
    message: str,
    *,
    request_id: str,
    code: str,
    headers: Optional[dict[str, str]] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        headers=headers or {"X-BlueTeam-Request-ID": request_id},
        content={
            "error": {
                "message": message,
                "type": "invalid_request_error" if status_code < 500 else "server_error",
                "code": code,
                "request_id": request_id,
            }
        },
    )


def _service_error_response(status_code: int, message: str, data: Any = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=failure(status_code, message, data))


def _get_task_or_404(db: Session, task_id: int) -> AttackTask:
    item = db.get(AttackTask, task_id)
    if item is None:
        raise HTTPException(status_code=404, detail="attack task not found")
    return item


def _resolve_task_creator_id(db: Session, principal: GatewayPrincipal) -> int:
    if principal.user is not None:
        return principal.user.id
    if principal.runtime is not None:
        if principal.runtime.approved_by:
            return principal.runtime.approved_by
        if principal.runtime.enrollment_token_id:
            token = db.get(RuntimeEnrollmentToken, principal.runtime.enrollment_token_id)
            if token is not None and token.issued_by:
                return token.issued_by
    fallback_user = db.query(User).order_by(User.id.asc()).first()
    return int(fallback_user.id) if fallback_user is not None else 1


def _resolve_gateway_principal(
    x_gateway_token: Optional[str],
    x_runtime_token: Optional[str],
    x_runtime_key: Optional[str],
    x_runtime_secret: Optional[str],
    x_client_id: Optional[str],
    credentials: Optional[HTTPAuthorizationCredentials],
    db: Session,
) -> GatewayPrincipal:
    for token in (
        credentials.credentials if credentials is not None else None,
        x_gateway_token,
        x_runtime_token,
    ):
        if _matches_service_token(token):
            return GatewayPrincipal(
                user=None,
                runtime=None,
                client_id=(x_client_id or "gateway-service").strip() or "gateway-service",
                auth_mode="service_token",
            )

    runtime_header_present = bool(str(x_runtime_key or "").strip() or str(x_runtime_secret or "").strip())
    runtime = find_runtime_by_runtime_key(db, x_runtime_key)
    if runtime is not None and runtime.status == "active" and verify_runtime_secret(runtime, x_runtime_secret):
        return GatewayPrincipal(
            user=None,
            runtime=runtime,
            client_id=(x_client_id or runtime.runtime_key or runtime.registration_id).strip()
            or runtime.registration_id,
            auth_mode="runtime_secret",
        )
    if runtime_header_present and credentials is None:
        raise HTTPException(status_code=401, detail="runtime credentials are invalid")

    if credentials is None:
        raise HTTPException(status_code=401, detail="missing gateway credentials")

    payload = decode_access_token(credentials.credentials)
    user_id = int(payload.get("uid", 0))
    user = db.get(User, user_id)
    if user is None or user.status != "active":
        raise HTTPException(status_code=401, detail="gateway user is inactive or missing")

    return GatewayPrincipal(
        user=user,
        runtime=None,
        client_id=(x_client_id or user.username).strip() or user.username,
        auth_mode="jwt",
    )


def gateway_principal_dependency(
    x_gateway_token: Optional[str] = Header(default=None, alias="X-Gateway-Token"),
    x_runtime_token: Optional[str] = Header(default=None, alias="X-Runtime-Token"),
    x_runtime_key: Optional[str] = Header(default=None, alias="X-Runtime-Key"),
    x_runtime_secret: Optional[str] = Header(default=None, alias="X-Runtime-Secret"),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> GatewayPrincipal:
    return _resolve_gateway_principal(
        x_gateway_token,
        x_runtime_token,
        x_runtime_key,
        x_runtime_secret,
        x_client_id,
        credentials,
        db,
    )


def _bearer_token_from_authorization_header(value: str | None) -> str | None:
    header = str(value or "").strip()
    if not header.lower().startswith("bearer "):
        return None
    return header[7:].strip() or None


def _resolve_gateway_principal_from_websocket(websocket: WebSocket, db: Session) -> GatewayPrincipal:
    return _resolve_gateway_principal(
        websocket.headers.get("x-gateway-token") or websocket.query_params.get("gateway_token"),
        websocket.headers.get("x-runtime-token") or websocket.query_params.get("runtime_token"),
        websocket.headers.get("x-runtime-key") or websocket.query_params.get("runtime_key"),
        websocket.headers.get("x-runtime-secret") or websocket.query_params.get("runtime_secret"),
        websocket.headers.get("x-client-id") or websocket.query_params.get("client_id"),
        HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=_bearer_token_from_authorization_header(
                websocket.headers.get("authorization") or websocket.query_params.get("authorization")
            )
            or str(websocket.query_params.get("access_token") or "").strip(),
        )
        if (
            _bearer_token_from_authorization_header(
                websocket.headers.get("authorization") or websocket.query_params.get("authorization")
            )
            or str(websocket.query_params.get("access_token") or "").strip()
        )
        else None,
        db,
    )


async def _ws_send_error(
    websocket: WebSocket,
    *,
    request_id: str,
    status_code: int,
    code: str,
    message: str,
) -> None:
    await websocket.send_json(
        {
            "event": "error",
            "data": {
                "request_id": request_id,
                "status_code": status_code,
                "code": code,
                "message": message,
            },
        }
    )


def _dedupe_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


def _content_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "input_text", "output_text", "content"):
            child = value.get(key)
            if isinstance(child, str) and child.strip():
                return child
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        parts = [_content_to_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    return str(value)


def _normalize_messages(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for item in messages:
        role = str(item.get("role") or "user").strip().lower()
        if role == "developer":
            role = "system"
        if role not in {"system", "assistant", "user"}:
            role = "user"
        normalized.append({"role": role, "content": _content_to_text(item.get("content"))})
    return normalized


def _messages_to_input_text(messages: list[dict[str, str]]) -> str:
    return "\n\n".join(
        str(item.get("content") or "").strip()
        for item in messages
        if str(item.get("content") or "").strip()
    )


def _normalize_chat_request_messages(payload: GatewayChatCompletionsRequest) -> list[dict[str, str]]:
    return _normalize_messages([item.model_dump() for item in payload.messages])


def _normalize_responses_input(payload: GatewayResponsesRequest) -> list[dict[str, str]]:
    messages: list[dict[str, Any]] = []
    if payload.instructions:
        messages.append({"role": "system", "content": payload.instructions})

    input_value = payload.input
    if isinstance(input_value, str):
        messages.append({"role": "user", "content": input_value})
    elif isinstance(input_value, dict):
        if input_value.get("role") or input_value.get("content") is not None:
            messages.append(input_value)
        else:
            messages.append({"role": "user", "content": json.dumps(input_value, ensure_ascii=False)})
    elif isinstance(input_value, list):
        for item in input_value:
            if isinstance(item, str):
                messages.append({"role": "user", "content": item})
            elif isinstance(item, dict):
                if item.get("role") or item.get("content") is not None:
                    messages.append(item)
                else:
                    messages.append({"role": "user", "content": json.dumps(item, ensure_ascii=False)})
            else:
                messages.append({"role": "user", "content": str(item)})

    normalized = _normalize_messages(messages)
    return normalized or [{"role": "user", "content": ""}]


def _normalize_agent_run_messages(payload: GatewayAgentRunRequest) -> list[dict[str, str]]:
    messages: list[dict[str, Any]] = []
    if payload.instructions:
        messages.append({"role": "system", "content": payload.instructions})
    if payload.messages:
        messages.extend(item.model_dump() for item in payload.messages)
    elif payload.input_text:
        messages.append({"role": "user", "content": payload.input_text})
    return _normalize_messages(messages or [{"role": "user", "content": payload.input_text or ""}])


def _resolve_managed_endpoint(
    db: Session,
    *,
    endpoint_id: Optional[int] = None,
    endpoint_key: Optional[str] = None,
    endpoint_group: Optional[str] = None,
) -> Optional[AiEndpoint]:
    query = db.query(AiEndpoint).filter(AiEndpoint.enabled.is_(True))

    if endpoint_id is not None:
        item = query.filter(AiEndpoint.id == endpoint_id).first()
        if item is None:
            raise ValueError(f"AI endpoint #{endpoint_id} not found or disabled")
        return item

    if endpoint_key:
        normalized_key = normalize_endpoint_key(endpoint_key)
        item = query.filter(AiEndpoint.endpoint_key == normalized_key).first()
        if item is None:
            item = query.filter(AiEndpoint.display_name == endpoint_key.strip()).first()
        if item is None:
            raise ValueError(f"AI endpoint {endpoint_key} not found or disabled")
        return item

    if endpoint_group:
        normalized_group = normalize_endpoint_group(endpoint_group)
        item = (
            query.filter(AiEndpoint.endpoint_group == normalized_group)
            .order_by(AiEndpoint.is_default.desc(), AiEndpoint.id.asc())
            .first()
        )
        if item is None:
            raise ValueError(f"AI endpoint group {normalized_group} does not have an enabled target")
        return item

    return None


def _should_override_model(model_hint: Optional[str], snapshot: dict[str, Any]) -> bool:
    normalized = str(model_hint or "").strip()
    if not normalized:
        return False
    for key in ("endpoint_key", "display_name", "model_name"):
        if normalized == str(snapshot.get(key) or "").strip():
            return False
    return True


def _resolve_provider_and_snapshot(
    db: Session,
    *,
    selector: Optional[GatewayTargetSelector],
    header_target_endpoint: Optional[str],
    header_route_group: Optional[str],
    preferred_endpoint_id: Optional[int],
    model_hint: Optional[str],
) -> tuple[ProviderEndpoint, dict[str, Any]]:
    selector = selector or GatewayTargetSelector()
    endpoint: Optional[AiEndpoint] = None

    try:
        endpoint = _resolve_managed_endpoint(
            db,
            endpoint_id=selector.endpoint_id,
            endpoint_key=selector.endpoint_key or header_target_endpoint,
            endpoint_group=selector.endpoint_group or header_route_group,
        )
    except ValueError:
        if selector.endpoint_id is not None or selector.endpoint_key or selector.endpoint_group or header_target_endpoint or header_route_group:
            raise

    if endpoint is None and model_hint:
        try:
            endpoint = _resolve_managed_endpoint(db, endpoint_key=model_hint)
        except ValueError:
            endpoint = None

    if endpoint is None and preferred_endpoint_id is not None:
        endpoint = _resolve_managed_endpoint(db, endpoint_id=preferred_endpoint_id)

    if endpoint is None:
        endpoint = get_default_ai_endpoint(db)

    if endpoint is not None:
        provider = provider_endpoint_from_ai_endpoint(endpoint)
        snapshot = build_ai_endpoint_snapshot(endpoint)
    else:
        provider = provider_endpoint_from_env()
        if provider is None:
            raise ValueError("No AI endpoint is configured. Create a managed endpoint or configure AI_PROVIDER env vars.")
        snapshot = build_env_ai_endpoint_snapshot()

    if _should_override_model(model_hint, snapshot):
        provider = replace(provider, model=str(model_hint).strip())
        snapshot = {**snapshot, "model_name": str(model_hint).strip()}

    return provider, snapshot


def _provider_from_gateway_payload(
    base_endpoint: ProviderEndpoint,
    *,
    model_hint: Optional[str],
    temperature: Optional[float],
    max_tokens: Optional[int],
    extra_body: dict[str, Any],
) -> ProviderEndpoint:
    config = dict(base_endpoint.config or {})
    if temperature is not None:
        config["temperature"] = temperature
    if max_tokens is not None:
        config["max_tokens"] = max_tokens
    existing_extra_body = config.get("extra_body")
    merged_extra_body = dict(existing_extra_body) if isinstance(existing_extra_body, dict) else {}
    merged_extra_body.update(extra_body)
    if merged_extra_body:
        config["extra_body"] = merged_extra_body
    provider = replace(base_endpoint, config=config)
    if model_hint and model_hint.strip():
        provider = replace(provider, model=model_hint.strip())
    return provider


def _build_task_params(
    *,
    request_id: str,
    source_type: str,
    messages: list[dict[str, str]],
    request_payload: dict[str, Any],
    action: dict[str, Any],
    endpoint_snapshot: dict[str, Any],
    principal: GatewayPrincipal,
    trace_id: str,
    source_ip: str,
) -> dict[str, Any]:
    request_text = _messages_to_input_text(messages)
    return {
        "source_type": source_type,
        "source_ref": request_id,
        "execution_mode": "gateway",
        "ai_endpoint": endpoint_snapshot,
        "request_id": request_id,
        "title": source_type,
        "content": request_text,
        "message": request_text,
        "messages": messages,
        "request": request_payload,
        "paths": list(action.get("paths") or []),
        "skill_names": list(action.get("skill_names") or []),
        "plugin_names": list(action.get("plugin_names") or []),
        "source_plugin": str(action.get("source_plugin") or ""),
        "target_plugin": str(action.get("target_plugin") or ""),
        "mcp_server": str(action.get("mcp_server") or ""),
        "capability_name": str(action.get("capability_name") or ""),
        "session_id": str(action.get("session_id") or ""),
        "approval_id": str(action.get("approval_id") or ""),
        "handoff_token": str(action.get("handoff_token") or ""),
        "requested_scopes": list(action.get("requested_scopes") or []),
        "metadata": dict(action.get("metadata") or {}),
        "gateway": {
            "client_id": principal.client_id,
            "auth_mode": principal.auth_mode,
            "trace_id": trace_id,
            "source_ip": source_ip,
            "runtime_id": principal.runtime.id if principal.runtime is not None else None,
            "runtime_key": principal.runtime.runtime_key if principal.runtime is not None else "",
        },
    }


def _extract_provider_payload(provider_result: Optional[ProviderResult]) -> Optional[dict[str, Any]]:
    if provider_result is None:
        return None
    try:
        payload = json.loads(provider_result.raw_response)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _output_redaction_mode(db: Session) -> str:
    item = db.query(DefenseConfig).filter(DefenseConfig.defense_type == "output_redaction_gate").first()
    if item is None or not item.enabled:
        return "off"
    normalized = str(item.mode or "observe").strip().lower()
    return normalized if normalized in {"off", "observe", "enforce"} else "observe"


def _apply_output_redaction(text: str, *, mode: str) -> tuple[str, dict[str, Any]]:
    if not text or mode == "off":
        return text, {"mode": mode, "redacted": False, "intercepted": False, "findings": []}

    findings: dict[str, int] = {}
    redacted = text

    def mark(category: str) -> None:
        findings[category] = findings.get(category, 0) + 1

    def replace_with(category: str, builder):
        def callback(match):
            mark(category)
            return builder(match)

        return callback

    redacted = AUTHORIZATION_VALUE_RE.sub(
        replace_with("authorization", lambda match: f"{match.group(1)}{_mask_middle(match.group(2), 6, 4)}"),
        redacted,
    )
    redacted = QUERY_SECRET_RE.sub(
        replace_with("query_secret", lambda match: f"{match.group(1)}{_mask_middle(match.group(2), 4, 2)}"),
        redacted,
    )
    redacted = JSON_SECRET_VALUE_RE.sub(
        replace_with("secret_field", lambda match: f"{match.group(1)}{_mask_middle(match.group(2), 4, 2)}{match.group(3)}"),
        redacted,
    )
    redacted = TEXT_SECRET_VALUE_RE.sub(
        replace_with("secret_field", lambda match: f"{match.group(1)}{_mask_middle(match.group(2), 4, 2)}"),
        redacted,
    )
    redacted = COOKIE_RE.sub(
        replace_with("cookie", lambda match: f"{match.group(1)}{_mask_middle(match.group(2), 8, 4)}"),
        redacted,
    )
    redacted = JWT_RE.sub(replace_with("jwt", lambda match: _mask_middle(match.group(0), 10, 6)), redacted)
    redacted = OPENAI_KEY_RE.sub(replace_with("openai_key", lambda match: _mask_middle(match.group(0), 8, 4)), redacted)
    redacted = ANTHROPIC_KEY_RE.sub(replace_with("anthropic_key", lambda match: _mask_middle(match.group(0), 8, 4)), redacted)
    redacted = EMAIL_RE.sub(replace_with("email", lambda match: _mask_email(match.group(0))), redacted)
    redacted = WINDOWS_PATH_RE.sub(replace_with("windows_path", lambda match: _mask_windows_path(match.group(0))), redacted)

    def unix_callback(match):
        path = match.group(1)
        if not _should_mask_unix_path(path):
            return path
        mark("unix_path")
        return _mask_unix_path(path)

    redacted = UNIX_PATH_RE.sub(unix_callback, redacted)
    finding_items = [{"category": key, "count": value} for key, value in sorted(findings.items())]

    if not finding_items:
        return text, {"mode": mode, "redacted": False, "intercepted": False, "findings": []}

    if mode == "enforce":
        return (
            "The gateway intercepted the model output because sensitive data was detected.",
            {"mode": mode, "redacted": True, "intercepted": True, "findings": finding_items},
        )

    return redacted, {"mode": mode, "redacted": redacted != text, "intercepted": False, "findings": finding_items}


def _request_payload_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False)


def _redaction_hit_rules(redaction: dict[str, Any]) -> list[str]:
    return ["output-sanitize"] if redaction.get("findings") else []


def _determine_event_severity(
    authorization: dict[str, Any],
    redaction: dict[str, Any],
) -> tuple[str, str]:
    decision = str(authorization.get("decision") or "").strip().lower()
    if redaction.get("intercepted") or decision == "deny":
        return EVENT_STATUS_INTERCEPTED, "high"
    if redaction.get("redacted") or decision == "review":
        return EVENT_STATUS_SUSPICIOUS, "medium"
    return EVENT_STATUS_ALLOWED, "low"


def _build_result_summary(
    *,
    source_label: str,
    authorization: dict[str, Any],
    redaction: dict[str, Any],
    endpoint_name: str,
) -> tuple[str, str]:
    decision = str(authorization.get("decision") or "").strip().lower()
    if redaction.get("intercepted"):
        return (
            f"{source_label} output was intercepted by the gateway.",
            f"Upstream endpoint {endpoint_name} returned content that hit the output redaction gate in enforce mode.",
        )
    if decision == "review":
        return (
            f"{source_label} was forwarded but marked suspicious.",
            str(authorization.get("detail") or f"Preflight decision for {endpoint_name} was review."),
        )
    if redaction.get("redacted"):
        return (
            f"{source_label} returned with redacted output.",
            f"Upstream endpoint {endpoint_name} returned content that required masking before release.",
        )
    if decision == "deny":
        return (
            f"{source_label} was denied before upstream execution.",
            str(authorization.get("detail") or "Preflight policy rejected the request."),
        )
    return (
        f"{source_label} completed successfully through the gateway.",
        f"Request was forwarded to {endpoint_name} and returned without additional blocking.",
    )


def _build_gateway_raw_response(
    *,
    request_id: str,
    source_type: str,
    authorization: dict[str, Any],
    redaction: dict[str, Any],
    provider_result: Optional[ProviderResult] = None,
    provider_payload: Optional[dict[str, Any]] = None,
    error: Optional[str] = None,
) -> str:
    payload: dict[str, Any] = {
        "engine": "gateway_proxy",
        "request_id": request_id,
        "source_type": source_type,
        "authorization": authorization,
        "redaction": redaction,
        "ai_review_mode": "gateway_preflight_only",
        "ai_review_invoked": False,
        "review_decision": "preflight_only",
    }
    if provider_result is not None:
        payload["provider"] = {
            "provider": provider_result.provider,
            "model": provider_result.model,
            "endpoint_id": provider_result.endpoint_id,
            "endpoint_key": provider_result.endpoint_key,
            "endpoint_name": provider_result.endpoint_name,
            "output_text": provider_result.output_text,
            "usage": provider_result.usage,
            "raw_response": provider_payload if provider_payload is not None else provider_result.raw_response,
        }
    if error:
        payload["error"] = error
    return json.dumps(payload, ensure_ascii=False)


def _build_operation_logs(
    *,
    blocked: bool,
    provider_called: bool,
    redaction: dict[str, Any],
) -> list[dict[str, Any]]:
    timestamp = format_beijing(utc_now()) or ""
    items = [
        {"operator": "gateway", "action": "request_received", "time": timestamp},
        {"operator": "policy_enforcer", "action": "preflight_evaluated", "time": timestamp},
    ]
    if blocked:
        items.append({"operator": "gateway", "action": "request_blocked", "time": timestamp})
        return items
    if provider_called:
        items.append({"operator": "provider", "action": "upstream_completed", "time": timestamp})
    if redaction.get("intercepted"):
        items.append({"operator": "output_redaction_gate", "action": "output_intercepted", "time": timestamp})
    elif redaction.get("redacted"):
        items.append({"operator": "output_redaction_gate", "action": "output_redacted", "time": timestamp})
    else:
        items.append({"operator": "gateway", "action": "output_passed", "time": timestamp})
    return items


def _build_chat_completion_response(outcome: GatewayExecutionOutcome) -> dict[str, Any]:
    payload = outcome.provider_payload or {}
    if isinstance(payload.get("choices"), list) and payload.get("choices"):
        response = json.loads(json.dumps(payload, ensure_ascii=False))
        message = response["choices"][0].get("message") or {}
        if outcome.response_text or "content" in message:
            message["content"] = outcome.response_text
            response["choices"][0]["message"] = message
        if outcome.redaction.get("intercepted"):
            response["choices"][0]["finish_reason"] = "content_filter"
        response["model"] = outcome.provider_result.model if outcome.provider_result is not None else response.get("model")
        if outcome.provider_result is not None and not response.get("usage"):
            response["usage"] = outcome.provider_result.usage
        return response

    return {
        "id": f"chatcmpl_{outcome.request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": outcome.provider_result.model if outcome.provider_result is not None else "",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": outcome.response_text},
                "finish_reason": "content_filter" if outcome.redaction.get("intercepted") else "stop",
            }
        ],
        "usage": outcome.provider_result.usage if outcome.provider_result is not None else {},
    }


def _build_responses_response(outcome: GatewayExecutionOutcome) -> dict[str, Any]:
    return {
        "id": f"resp_{outcome.request_id}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": outcome.provider_result.model if outcome.provider_result is not None else "",
        "output": [
            {
                "id": f"msg_{outcome.request_id}",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": outcome.response_text}],
            }
        ],
        "usage": outcome.provider_result.usage if outcome.provider_result is not None else {},
    }


def _build_agent_run_response_data(outcome: GatewayExecutionOutcome) -> dict[str, Any]:
    return {
        "request_id": outcome.request_id,
        "authorization": outcome.authorization,
        "task": _serialize_task(outcome.task),
        "event": _serialize_event(outcome.event),
        "report": _serialize_report(outcome.report),
        "upstream_response": _build_chat_completion_response(outcome) if outcome.state == "completed" else None,
        "redaction": outcome.redaction,
        "summary": outcome.summary,
        "detail": outcome.detail,
    }


def _stream_text_chunks(text: str, *, chunk_size: int = 96) -> list[str]:
    if not text:
        return []
    normalized_chunk_size = max(chunk_size, 1)
    return [text[index : index + normalized_chunk_size] for index in range(0, len(text), normalized_chunk_size)]


def _sse_event_bytes(data: Any, *, event: str | None = None) -> bytes:
    lines: list[str] = []
    if event:
        lines.append(f"event: {event}")

    if isinstance(data, (dict, list)):
        payload = json.dumps(data, ensure_ascii=False)
    else:
        payload = str(data)

    payload_lines = payload.splitlines() or [""]
    for item in payload_lines:
        lines.append(f"data: {item}")
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _chat_completion_stream_body(outcome: GatewayExecutionOutcome) -> Iterable[bytes]:
    created_at = int(time.time())
    response_id = f"chatcmpl_{outcome.request_id}"
    model_name = outcome.provider_result.model if outcome.provider_result is not None else ""
    chunks = _stream_text_chunks(outcome.response_text)

    if chunks:
        first_chunk = chunks[0]
        yield _sse_event_bytes(
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created_at,
                "model": model_name,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": first_chunk}, "finish_reason": None}],
            }
        )
        for chunk in chunks[1:]:
            yield _sse_event_bytes(
                {
                    "id": response_id,
                    "object": "chat.completion.chunk",
                    "created": created_at,
                    "model": model_name,
                    "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": None}],
                }
            )
    else:
        yield _sse_event_bytes(
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created_at,
                "model": model_name,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
        )

    yield _sse_event_bytes(
        {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created_at,
            "model": model_name,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "content_filter" if outcome.redaction.get("intercepted") else "stop",
                }
            ],
        }
    )
    yield _sse_event_bytes("[DONE]")


def _responses_stream_body(outcome: GatewayExecutionOutcome) -> Iterable[bytes]:
    response_payload = _build_responses_response(outcome)
    response_id = str(response_payload.get("id") or f"resp_{outcome.request_id}")
    item_id = f"msg_{outcome.request_id}"

    yield _sse_event_bytes(
        {
            "type": "response.created",
            "response": {
                "id": response_id,
                "object": "response",
                "created_at": response_payload.get("created_at"),
                "status": "in_progress",
                "model": response_payload.get("model"),
            },
        },
        event="response.created",
    )

    for chunk in _stream_text_chunks(outcome.response_text):
        yield _sse_event_bytes(
            {
                "type": "response.output_text.delta",
                "response_id": response_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": chunk,
            },
            event="response.output_text.delta",
        )

    yield _sse_event_bytes(
        {
            "type": "response.output_text.done",
            "response_id": response_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "text": outcome.response_text,
        },
        event="response.output_text.done",
    )
    yield _sse_event_bytes({"type": "response.completed", "response": response_payload}, event="response.completed")
    yield _sse_event_bytes("[DONE]", event="done")


def _agent_run_stream_body(outcome: GatewayExecutionOutcome) -> Iterable[bytes]:
    completed_payload = success(_build_agent_run_response_data(outcome), message="agent run completed")
    yield _sse_event_bytes(
        {
            "type": "agent.run.started",
            "request_id": outcome.request_id,
            "task_id": outcome.task.id,
            "status": "in_progress",
        },
        event="agent.run.started",
    )

    for chunk in _stream_text_chunks(outcome.response_text):
        yield _sse_event_bytes(
            {
                "type": "agent.run.delta",
                "request_id": outcome.request_id,
                "task_id": outcome.task.id,
                "delta": chunk,
            },
            event="agent.run.delta",
        )

    yield _sse_event_bytes(completed_payload, event="agent.run.completed")
    yield _sse_event_bytes("[DONE]", event="done")


def _streaming_gateway_response(
    body: Iterable[bytes],
    *,
    request_id: str,
    authorization: Optional[dict[str, Any]] = None,
    task: Optional[AttackTask] = None,
    event: Optional[SecurityEvent] = None,
    report: Optional[Report] = None,
    output_action: Optional[str] = None,
) -> StreamingResponse:
    headers = _gateway_headers(
        request_id=request_id,
        authorization=authorization,
        task=task,
        event=event,
        report=report,
        output_action=output_action,
    )
    headers["Cache-Control"] = "no-cache"
    headers["X-Accel-Buffering"] = "no"
    return StreamingResponse(body, media_type="text/event-stream", headers=headers)


def _live_chat_completion_stream_body(
    db: Session,
    prepared: GatewayPreparedExecution,
    stream_session: ProviderStreamSession,
) -> Iterable[bytes]:
    created_at = int(time.time())
    response_id = f"chatcmpl_{prepared.request_id}"
    emitted_any = False

    try:
        for delta in stream_session.iter_deltas():
            is_first = not emitted_any
            emitted_any = True
            yield _sse_event_bytes(
                {
                    "id": response_id,
                    "object": "chat.completion.chunk",
                    "created": created_at,
                    "model": stream_session.model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": delta} if is_first else {"content": delta},
                            "finish_reason": None,
                        }
                    ],
                }
            )
    except ProviderExecutionError as exc:
        _finalize_gateway_error(db, prepared, status_code=502, error_message=str(exc))
        yield _sse_event_bytes(
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created_at,
                "model": stream_session.model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "error"}],
                "error": {"message": str(exc)},
            }
        )
        yield _sse_event_bytes("[DONE]")
        return

    provider_result = stream_session.build_result()
    redaction = {"mode": "off", "redacted": False, "intercepted": False, "findings": []}
    _finalize_gateway_completed(
        db,
        prepared,
        provider_result=provider_result,
        provider_payload=None,
        response_text=provider_result.output_text,
        redaction=redaction,
    )
    if not emitted_any:
        yield _sse_event_bytes(
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created_at,
                "model": provider_result.model,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
        )
    yield _sse_event_bytes(
        {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created_at,
            "model": provider_result.model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
    )
    yield _sse_event_bytes("[DONE]")


def _live_responses_stream_body(
    db: Session,
    prepared: GatewayPreparedExecution,
    stream_session: ProviderStreamSession,
) -> Iterable[bytes]:
    response_id = f"resp_{prepared.request_id}"
    item_id = f"msg_{prepared.request_id}"
    created_payload = {
        "type": "response.created",
        "response": {
            "id": response_id,
            "object": "response",
            "created_at": int(time.time()),
            "status": "in_progress",
            "model": stream_session.model,
        },
    }
    yield _sse_event_bytes(created_payload, event="response.created")

    try:
        for delta in stream_session.iter_deltas():
            yield _sse_event_bytes(
                {
                    "type": "response.output_text.delta",
                    "response_id": response_id,
                    "item_id": item_id,
                    "output_index": 0,
                    "content_index": 0,
                    "delta": delta,
                },
                event="response.output_text.delta",
            )
    except ProviderExecutionError as exc:
        _finalize_gateway_error(db, prepared, status_code=502, error_message=str(exc))
        yield _sse_event_bytes(
            {
                "type": "response.error",
                "response_id": response_id,
                "error": {"message": str(exc)},
            },
            event="response.error",
        )
        yield _sse_event_bytes("[DONE]", event="done")
        return

    provider_result = stream_session.build_result()
    redaction = {"mode": "off", "redacted": False, "intercepted": False, "findings": []}
    outcome = _finalize_gateway_completed(
        db,
        prepared,
        provider_result=provider_result,
        provider_payload=None,
        response_text=provider_result.output_text,
        redaction=redaction,
    )
    yield _sse_event_bytes(
        {
            "type": "response.output_text.done",
            "response_id": response_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "text": provider_result.output_text,
        },
        event="response.output_text.done",
    )
    yield _sse_event_bytes({"type": "response.completed", "response": _build_responses_response(outcome)}, event="response.completed")
    yield _sse_event_bytes("[DONE]", event="done")


def _live_agent_run_stream_body(
    db: Session,
    prepared: GatewayPreparedExecution,
    stream_session: ProviderStreamSession,
) -> Iterable[bytes]:
    yield _sse_event_bytes(
        {
            "type": "agent.run.started",
            "request_id": prepared.request_id,
            "task_id": prepared.task.id,
            "status": "in_progress",
        },
        event="agent.run.started",
    )

    try:
        for delta in stream_session.iter_deltas():
            yield _sse_event_bytes(
                {
                    "type": "agent.run.delta",
                    "request_id": prepared.request_id,
                    "task_id": prepared.task.id,
                    "delta": delta,
                },
                event="agent.run.delta",
            )
    except ProviderExecutionError as exc:
        _finalize_gateway_error(db, prepared, status_code=502, error_message=str(exc))
        yield _sse_event_bytes(
            {
                "type": "agent.run.error",
                "request_id": prepared.request_id,
                "task_id": prepared.task.id,
                "error": {"message": str(exc)},
            },
            event="agent.run.error",
        )
        yield _sse_event_bytes("[DONE]", event="done")
        return

    provider_result = stream_session.build_result()
    redaction = {"mode": "off", "redacted": False, "intercepted": False, "findings": []}
    outcome = _finalize_gateway_completed(
        db,
        prepared,
        provider_result=provider_result,
        provider_payload=None,
        response_text=provider_result.output_text,
        redaction=redaction,
    )
    yield _sse_event_bytes(success(_build_agent_run_response_data(outcome), message="agent run completed"), event="agent.run.completed")
    yield _sse_event_bytes("[DONE]", event="done")


def _output_action(outcome: GatewayExecutionOutcome) -> str:
    if outcome.state == "blocked":
        return "block"
    if outcome.state == "provider_error":
        return "error"
    if outcome.redaction.get("intercepted"):
        return "intercept"
    if outcome.redaction.get("redacted"):
        return "redact"
    return "pass"


def _prepare_gateway_execution(
    db: Session,
    *,
    principal: GatewayPrincipal,
    request_id: str,
    trace_id: str,
    source_ip: str,
    source_type: str,
    attack_type: str,
    source_label: str,
    request_payload: dict[str, Any],
    selector: Optional[GatewayTargetSelector],
    header_target_endpoint: Optional[str],
    header_route_group: Optional[str],
    model_hint: Optional[str],
    messages: list[dict[str, str]],
    action: dict[str, Any],
    temperature: Optional[float],
    max_tokens: Optional[int],
    extra_body: dict[str, Any],
) -> GatewayPreparedExecution | GatewayExecutionOutcome:
    if principal.runtime is not None:
        principal.runtime.last_seen_at = utc_now()

    provider_endpoint, endpoint_snapshot = _resolve_provider_and_snapshot(
        db,
        selector=selector,
        header_target_endpoint=header_target_endpoint,
        header_route_group=header_route_group,
        preferred_endpoint_id=principal.runtime.ai_endpoint_id if principal.runtime is not None else None,
        model_hint=model_hint,
    )
    target_name = str(
        endpoint_snapshot.get("display_name") or endpoint_snapshot.get("endpoint_key") or provider_endpoint.endpoint_name
    )

    task = AttackTask(
        task_name=f"{source_type}-{request_id[:8]}",
        attack_type=attack_type,
        target_agent=target_name,
        status="running",
        source_type=source_type,
        source_ref=request_id,
        execution_mode="gateway",
        runtime_name=principal.runtime.display_name if principal.runtime is not None else "gateway",
        runtime_task_ref=request_id,
        created_by=principal.user.id if principal.user is not None else 1,
    )
    task.set_params(
        _build_task_params(
            request_id=request_id,
            source_type=source_type,
            messages=messages,
            request_payload=request_payload,
            action=action,
            endpoint_snapshot=endpoint_snapshot,
            principal=principal,
            trace_id=trace_id,
            source_ip=source_ip,
        )
    )
    db.add(task)
    db.flush()

    authorization = authorize_task_preflight(db, task, action)
    append_task_authorization_snapshot(task, action=action, decision=authorization)
    serialized_authorization = serialize_authorization_decision(authorization)
    redaction_mode = _output_redaction_mode(db)
    raw_input = _request_payload_json(
        {
            "request": request_payload,
            "messages": messages,
            "gateway": {
                "request_id": request_id,
                "trace_id": trace_id,
                "client_id": principal.client_id,
                "auth_mode": principal.auth_mode,
                "source_ip": source_ip,
                "upstream_endpoint": endpoint_snapshot,
            },
        }
    )

    if str(serialized_authorization.get("decision") or "").strip().lower() == "deny":
        redaction = {"mode": redaction_mode, "redacted": False, "intercepted": False, "findings": []}
        summary, detail = _build_result_summary(
            source_label=source_label,
            authorization=serialized_authorization,
            redaction={"intercepted": True},
            endpoint_name=target_name,
        )
        event_status, event_level = _determine_event_severity(serialized_authorization, {"intercepted": True})
        task, event, report = record_task_outcome(
            db,
            task,
            summary=summary,
            raw_response=_build_gateway_raw_response(
                request_id=request_id,
                source_type=source_type,
                authorization=serialized_authorization,
                redaction=redaction,
            ),
            task_status="done",
            event_type="gateway_preflight",
            event_level=event_level,
            event_status=event_status,
            event_source=f"gateway/{source_type}",
            event_detail=detail,
            hit_rules=_dedupe_strings([*list(serialized_authorization.get("matched_rules") or []), "gateway-preflight-blocked"]),
            raw_input=raw_input,
            result=summary,
            operation_logs=_build_operation_logs(blocked=True, provider_called=False, redaction=redaction),
            report_type=source_type,
            created_by=task.created_by or 1,
            create_report=True,
        )
        db.commit()
        db.refresh(task)
        if event is not None:
            db.refresh(event)
        if report is not None:
            db.refresh(report)
        return GatewayExecutionOutcome(
            state="blocked",
            status_code=403,
            request_id=request_id,
            task=task,
            event=event,
            report=report,
            authorization=serialized_authorization,
            provider_result=None,
            provider_payload=None,
            response_text="The gateway blocked the request before upstream execution.",
            redaction=redaction,
            summary=summary,
            detail=detail,
            event_status=event_status,
            event_level=event_level,
        )

    provider = _provider_from_gateway_payload(
        provider_endpoint,
        model_hint=model_hint,
        temperature=temperature,
        max_tokens=max_tokens,
        extra_body=extra_body,
    )
    return GatewayPreparedExecution(
        request_id=request_id,
        trace_id=trace_id,
        source_ip=source_ip,
        source_type=source_type,
        source_label=source_label,
        target_name=target_name,
        task=task,
        authorization=serialized_authorization,
        raw_input=raw_input,
        provider=provider,
        redaction_mode=redaction_mode,
    )


def _finalize_gateway_completed(
    db: Session,
    prepared: GatewayPreparedExecution,
    *,
    provider_result: ProviderResult,
    provider_payload: dict[str, Any] | None,
    response_text: str,
    redaction: dict[str, Any],
) -> GatewayExecutionOutcome:
    event_status, event_level = _determine_event_severity(prepared.authorization, redaction)
    summary, detail = _build_result_summary(
        source_label=prepared.source_label,
        authorization=prepared.authorization,
        redaction=redaction,
        endpoint_name=prepared.target_name,
    )
    task, event, report = record_task_outcome(
        db,
        prepared.task,
        summary=summary,
        raw_response=_build_gateway_raw_response(
            request_id=prepared.request_id,
            source_type=prepared.source_type,
            authorization=prepared.authorization,
            redaction=redaction,
            provider_result=provider_result,
            provider_payload=provider_payload,
        ),
        task_status="done",
        event_type="gateway_response_redaction" if redaction.get("findings") else "gateway_request",
        event_level=event_level,
        event_status=event_status,
        event_source=f"gateway/{prepared.source_type}",
        event_detail=detail,
        hit_rules=_dedupe_strings([*list(prepared.authorization.get("matched_rules") or []), *_redaction_hit_rules(redaction)]),
        raw_input=prepared.raw_input,
        result=response_text,
        operation_logs=_build_operation_logs(blocked=False, provider_called=True, redaction=redaction),
        report_type=prepared.source_type,
        created_by=prepared.task.created_by or 1,
        create_report=True,
    )
    db.commit()
    db.refresh(task)
    if event is not None:
        db.refresh(event)
    if report is not None:
        db.refresh(report)
    return GatewayExecutionOutcome(
        state="completed",
        status_code=200,
        request_id=prepared.request_id,
        task=task,
        event=event,
        report=report,
        authorization=prepared.authorization,
        provider_result=provider_result,
        provider_payload=provider_payload,
        response_text=response_text,
        redaction=redaction,
        summary=summary,
        detail=detail,
        event_status=event_status,
        event_level=event_level,
    )


def _finalize_gateway_error(
    db: Session,
    prepared: GatewayPreparedExecution,
    *,
    status_code: int,
    error_message: str,
) -> GatewayExecutionOutcome:
    redaction = {"mode": prepared.redaction_mode, "redacted": False, "intercepted": False, "findings": []}
    summary = f"{prepared.source_label} upstream call failed."
    detail = error_message
    task, event, report = record_task_outcome(
        db,
        prepared.task,
        summary=summary,
        raw_response=_build_gateway_raw_response(
            request_id=prepared.request_id,
            source_type=prepared.source_type,
            authorization=prepared.authorization,
            redaction=redaction,
            error=error_message,
        ),
        task_status="failed",
        event_type="gateway_provider_error",
        event_level="medium",
        event_status=EVENT_STATUS_SUSPICIOUS,
        event_source=f"gateway/{prepared.source_type}",
        event_detail=detail,
        hit_rules=_dedupe_strings([*list(prepared.authorization.get("matched_rules") or []), "provider-error"]),
        raw_input=prepared.raw_input,
        result=error_message,
        operation_logs=_build_operation_logs(blocked=False, provider_called=False, redaction=redaction),
        report_type=f"{prepared.source_type}_error",
        created_by=prepared.task.created_by or 1,
        create_report=True,
    )
    db.commit()
    db.refresh(task)
    if event is not None:
        db.refresh(event)
    if report is not None:
        db.refresh(report)
    return GatewayExecutionOutcome(
        state="provider_error",
        status_code=status_code,
        request_id=prepared.request_id,
        task=task,
        event=event,
        report=report,
        authorization=prepared.authorization,
        provider_result=None,
        provider_payload=None,
        response_text="Upstream provider execution failed.",
        redaction=redaction,
        summary=summary,
        detail=detail,
        event_status=EVENT_STATUS_SUSPICIOUS,
        event_level="medium",
    )


def _should_use_live_streaming(provider: ProviderEndpoint, redaction_mode: str) -> bool:
    return redaction_mode == "off" and provider_supports_streaming(provider)


def _execute_prepared_gateway_request(
    db: Session,
    prepared: GatewayPreparedExecution,
    *,
    messages: list[dict[str, str]],
) -> GatewayExecutionOutcome:
    try:
        provider_result = invoke_chat_completion(messages, endpoint=prepared.provider)
        provider_payload = _extract_provider_payload(provider_result)
        response_text, redaction = _apply_output_redaction(provider_result.output_text, mode=prepared.redaction_mode)
        return _finalize_gateway_completed(
            db,
            prepared,
            provider_result=provider_result,
            provider_payload=provider_payload,
            response_text=response_text,
            redaction=redaction,
        )
    except ProviderConfigurationError as exc:
        status_code = 400
        error_message = str(exc)
    except ProviderExecutionError as exc:
        status_code = 502
        error_message = str(exc)
    return _finalize_gateway_error(db, prepared, status_code=status_code, error_message=error_message)


def _execute_gateway_request(
    db: Session,
    *,
    principal: GatewayPrincipal,
    request_id: str,
    trace_id: str,
    source_ip: str,
    source_type: str,
    attack_type: str,
    source_label: str,
    request_payload: dict[str, Any],
    selector: Optional[GatewayTargetSelector],
    header_target_endpoint: Optional[str],
    header_route_group: Optional[str],
    model_hint: Optional[str],
    messages: list[dict[str, str]],
    action: dict[str, Any],
    temperature: Optional[float],
    max_tokens: Optional[int],
    extra_body: dict[str, Any],
) -> GatewayExecutionOutcome:
    prepared = _prepare_gateway_execution(
        db,
        principal=principal,
        request_id=request_id,
        trace_id=trace_id,
        source_ip=source_ip,
        source_type=source_type,
        attack_type=attack_type,
        source_label=source_label,
        request_payload=request_payload,
        selector=selector,
        header_target_endpoint=header_target_endpoint,
        header_route_group=header_route_group,
        model_hint=model_hint,
        messages=messages,
        action=action,
        temperature=temperature,
        max_tokens=max_tokens,
        extra_body=extra_body,
    )
    if isinstance(prepared, GatewayExecutionOutcome):
        return prepared
    return _execute_prepared_gateway_request(db, prepared, messages=messages)


def _runtime_success_payload(
    task: AttackTask,
    event: Optional[SecurityEvent] = None,
    report: Optional[Report] = None,
) -> dict[str, Any]:
    return {
        "task": _serialize_task(task),
        "event": _serialize_event(event),
        "report": _serialize_report(report),
    }


@router.post("/chat/completions")
async def gateway_chat_completions(
    request: Request,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
    x_route_group: Optional[str] = Header(default=None, alias="X-Route-Group"),
    x_target_endpoint: Optional[str] = Header(default=None, alias="X-Target-Endpoint"),
    x_session_id: Optional[str] = Header(default=None, alias="X-Session-ID"),
    x_approval_id: Optional[str] = Header(default=None, alias="X-Approval-ID"),
    x_trace_id: Optional[str] = Header(default=None, alias="X-Trace-ID"),
):
    request_id = request.headers.get("x-request-id") or uuid4().hex[:12]
    trace_id = x_trace_id or request_id
    source_ip = request.client.host if request.client else "-"

    try:
        raw_body = await request.json()
    except Exception:
        return _openai_error_response(400, "Request body must be valid JSON.", request_id=request_id, code="invalid_json")

    try:
        payload = GatewayChatCompletionsRequest.model_validate(raw_body)
    except ValidationError as exc:
        return _openai_error_response(400, f"Invalid chat completion request: {exc.errors()}", request_id=request_id, code="invalid_request")

    messages = _normalize_chat_request_messages(payload)
    request_text = _messages_to_input_text(messages)
    session_id = payload.session_id or x_session_id
    approval_id = payload.approval_id or x_approval_id
    request_payload = payload.model_dump(mode="json")
    action = {
        "action_type": "chat_completion",
        "runtime_name": "gateway",
        "runtime_task_ref": request_id,
        "input_text": request_text,
        "paths": list(payload.paths),
        "skill_names": list(payload.skill_names),
        "plugin_names": list(payload.plugin_names),
        "source_plugin": payload.source_plugin,
        "target_plugin": payload.target_plugin,
        "mcp_server": payload.mcp_server,
        "capability_name": payload.capability_name,
        "session_id": session_id,
        "approval_id": approval_id,
        "handoff_token": payload.handoff_token,
        "requested_scopes": list(payload.requested_scopes),
        "metadata": {
            **dict(payload.metadata or {}),
            "client_id": principal.client_id,
            "trace_id": trace_id,
            "message": request_text,
        },
    }
    extra_body = {
        key: value
        for key, value in request_payload.items()
        if key
        not in {
            "model",
            "messages",
            "temperature",
            "max_tokens",
            "stream",
            "metadata",
            "target_selector",
            "requested_scopes",
            "paths",
            "skill_names",
            "plugin_names",
            "source_plugin",
            "target_plugin",
            "mcp_server",
            "capability_name",
            "session_id",
            "approval_id",
            "handoff_token",
        }
    }

    try:
        prepared_or_outcome = _prepare_gateway_execution(
            db,
            principal=principal,
            request_id=request_id,
            trace_id=trace_id,
            source_ip=source_ip,
            source_type="gateway_chat_completion",
            attack_type="chat_completion",
            source_label="Chat completions request",
            request_payload=request_payload,
            selector=payload.target_selector,
            header_target_endpoint=x_target_endpoint,
            header_route_group=x_route_group,
            model_hint=payload.model,
            messages=messages,
            action=action,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            extra_body=extra_body,
        )
    except ValueError as exc:
        return _openai_error_response(400, str(exc), request_id=request_id, code="route_resolution_failed")

    if isinstance(prepared_or_outcome, GatewayExecutionOutcome):
        outcome = prepared_or_outcome
    elif payload.stream and _should_use_live_streaming(prepared_or_outcome.provider, prepared_or_outcome.redaction_mode):
        stream_session = invoke_chat_completion_stream(messages, endpoint=prepared_or_outcome.provider)
        return _streaming_gateway_response(
            _live_chat_completion_stream_body(db, prepared_or_outcome, stream_session),
            request_id=prepared_or_outcome.request_id,
            authorization=prepared_or_outcome.authorization,
            task=prepared_or_outcome.task,
            output_action="pass",
        )
    else:
        outcome = _execute_prepared_gateway_request(db, prepared_or_outcome, messages=messages)

    headers = _gateway_headers(
        request_id=outcome.request_id,
        authorization=outcome.authorization,
        task=outcome.task,
        event=outcome.event,
        report=outcome.report,
        output_action=_output_action(outcome),
    )
    if outcome.state == "blocked":
        return _openai_error_response(403, outcome.summary, request_id=request_id, code="policy_denied", headers=headers)
    if outcome.state == "provider_error":
        return _openai_error_response(outcome.status_code, outcome.detail, request_id=request_id, code="provider_error", headers=headers)
    if payload.stream:
        return _streaming_gateway_response(
            _chat_completion_stream_body(outcome),
            request_id=outcome.request_id,
            authorization=outcome.authorization,
            task=outcome.task,
            event=outcome.event,
            report=outcome.report,
            output_action=_output_action(outcome),
        )
    return JSONResponse(status_code=200, headers=headers, content=_build_chat_completion_response(outcome))


@router.post("/responses")
async def gateway_responses(
    request: Request,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
    x_route_group: Optional[str] = Header(default=None, alias="X-Route-Group"),
    x_target_endpoint: Optional[str] = Header(default=None, alias="X-Target-Endpoint"),
    x_session_id: Optional[str] = Header(default=None, alias="X-Session-ID"),
    x_approval_id: Optional[str] = Header(default=None, alias="X-Approval-ID"),
    x_trace_id: Optional[str] = Header(default=None, alias="X-Trace-ID"),
):
    request_id = request.headers.get("x-request-id") or uuid4().hex[:12]
    trace_id = x_trace_id or request_id
    source_ip = request.client.host if request.client else "-"

    try:
        raw_body = await request.json()
    except Exception:
        return _openai_error_response(400, "Request body must be valid JSON.", request_id=request_id, code="invalid_json")

    try:
        payload = GatewayResponsesRequest.model_validate(raw_body)
    except ValidationError as exc:
        return _openai_error_response(400, f"Invalid responses request: {exc.errors()}", request_id=request_id, code="invalid_request")

    messages = _normalize_responses_input(payload)
    request_text = _messages_to_input_text(messages)
    session_id = payload.session_id or x_session_id
    approval_id = payload.approval_id or x_approval_id
    request_payload = payload.model_dump(mode="json")
    action = {
        "action_type": "responses",
        "runtime_name": "gateway",
        "runtime_task_ref": request_id,
        "input_text": request_text,
        "paths": list(payload.paths),
        "skill_names": list(payload.skill_names),
        "plugin_names": list(payload.plugin_names),
        "source_plugin": payload.source_plugin,
        "target_plugin": payload.target_plugin,
        "mcp_server": payload.mcp_server,
        "capability_name": payload.capability_name,
        "session_id": session_id,
        "approval_id": approval_id,
        "handoff_token": payload.handoff_token,
        "requested_scopes": list(payload.requested_scopes),
        "metadata": {
            **dict(payload.metadata or {}),
            "client_id": principal.client_id,
            "trace_id": trace_id,
            "message": request_text,
        },
    }
    extra_body = {
        key: value
        for key, value in request_payload.items()
        if key
        not in {
            "model",
            "input",
            "instructions",
            "temperature",
            "max_output_tokens",
            "stream",
            "metadata",
            "target_selector",
            "requested_scopes",
            "paths",
            "skill_names",
            "plugin_names",
            "source_plugin",
            "target_plugin",
            "mcp_server",
            "capability_name",
            "session_id",
            "approval_id",
            "handoff_token",
        }
    }

    try:
        prepared_or_outcome = _prepare_gateway_execution(
            db,
            principal=principal,
            request_id=request_id,
            trace_id=trace_id,
            source_ip=source_ip,
            source_type="gateway_responses",
            attack_type="responses",
            source_label="Responses request",
            request_payload=request_payload,
            selector=payload.target_selector,
            header_target_endpoint=x_target_endpoint,
            header_route_group=x_route_group,
            model_hint=payload.model,
            messages=messages,
            action=action,
            temperature=payload.temperature,
            max_tokens=payload.max_output_tokens,
            extra_body=extra_body,
        )
    except ValueError as exc:
        return _openai_error_response(400, str(exc), request_id=request_id, code="route_resolution_failed")

    if isinstance(prepared_or_outcome, GatewayExecutionOutcome):
        outcome = prepared_or_outcome
    elif payload.stream and _should_use_live_streaming(prepared_or_outcome.provider, prepared_or_outcome.redaction_mode):
        stream_session = invoke_chat_completion_stream(messages, endpoint=prepared_or_outcome.provider)
        return _streaming_gateway_response(
            _live_responses_stream_body(db, prepared_or_outcome, stream_session),
            request_id=prepared_or_outcome.request_id,
            authorization=prepared_or_outcome.authorization,
            task=prepared_or_outcome.task,
            output_action="pass",
        )
    else:
        outcome = _execute_prepared_gateway_request(db, prepared_or_outcome, messages=messages)

    headers = _gateway_headers(
        request_id=outcome.request_id,
        authorization=outcome.authorization,
        task=outcome.task,
        event=outcome.event,
        report=outcome.report,
        output_action=_output_action(outcome),
    )
    if outcome.state == "blocked":
        return _openai_error_response(403, outcome.summary, request_id=request_id, code="policy_denied", headers=headers)
    if outcome.state == "provider_error":
        return _openai_error_response(outcome.status_code, outcome.detail, request_id=request_id, code="provider_error", headers=headers)
    if payload.stream:
        return _streaming_gateway_response(
            _responses_stream_body(outcome),
            request_id=outcome.request_id,
            authorization=outcome.authorization,
            task=outcome.task,
            event=outcome.event,
            report=outcome.report,
            output_action=_output_action(outcome),
        )
    return JSONResponse(status_code=200, headers=headers, content=_build_responses_response(outcome))


@router.post("/agents/run")
async def gateway_agents_run(
    request: Request,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
    x_route_group: Optional[str] = Header(default=None, alias="X-Route-Group"),
    x_target_endpoint: Optional[str] = Header(default=None, alias="X-Target-Endpoint"),
    x_session_id: Optional[str] = Header(default=None, alias="X-Session-ID"),
    x_approval_id: Optional[str] = Header(default=None, alias="X-Approval-ID"),
    x_trace_id: Optional[str] = Header(default=None, alias="X-Trace-ID"),
):
    request_id = request.headers.get("x-request-id") or uuid4().hex[:12]
    trace_id = x_trace_id or request_id
    source_ip = request.client.host if request.client else "-"

    try:
        raw_body = await request.json()
    except Exception:
        return _service_error_response(400, "Request body must be valid JSON.")

    try:
        payload = GatewayAgentRunRequest.model_validate(raw_body)
    except ValidationError as exc:
        return _service_error_response(400, f"Invalid agent run request: {exc.errors()}")

    messages = _normalize_agent_run_messages(payload)
    request_text = _messages_to_input_text(messages)
    session_id = payload.session_id or x_session_id
    approval_id = payload.approval_id or x_approval_id
    request_payload = payload.model_dump(mode="json")
    action = {
        "action_type": "agent_run",
        "runtime_name": payload.runtime_name or "gateway-agent",
        "runtime_task_ref": request_id,
        "input_text": request_text,
        "paths": list(payload.paths),
        "skill_names": list(payload.skill_names),
        "plugin_names": list(payload.plugin_names),
        "source_plugin": payload.source_plugin,
        "target_plugin": payload.target_plugin,
        "mcp_server": payload.mcp_server,
        "capability_name": payload.capability_name,
        "session_id": session_id,
        "approval_id": approval_id,
        "handoff_token": payload.handoff_token,
        "requested_scopes": list(payload.requested_scopes),
        "metadata": {
            **dict(payload.metadata or {}),
            "client_id": principal.client_id,
            "trace_id": trace_id,
            "message": request_text,
        },
    }
    extra_body = {
        key: value
        for key, value in request_payload.items()
        if key
        not in {
            "model",
            "runtime_name",
            "input_text",
            "instructions",
            "messages",
            "temperature",
            "max_tokens",
            "stream",
            "metadata",
            "target_selector",
            "requested_scopes",
            "paths",
            "skill_names",
            "plugin_names",
            "source_plugin",
            "target_plugin",
            "mcp_server",
            "capability_name",
            "session_id",
            "approval_id",
            "handoff_token",
        }
    }

    try:
        prepared_or_outcome = _prepare_gateway_execution(
            db,
            principal=principal,
            request_id=request_id,
            trace_id=trace_id,
            source_ip=source_ip,
            source_type="gateway_agent_run",
            attack_type="agent_run",
            source_label="Agent run request",
            request_payload=request_payload,
            selector=payload.target_selector,
            header_target_endpoint=x_target_endpoint,
            header_route_group=x_route_group,
            model_hint=payload.model,
            messages=messages,
            action=action,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            extra_body=extra_body,
        )
    except ValueError as exc:
        return _service_error_response(400, str(exc))

    if isinstance(prepared_or_outcome, GatewayExecutionOutcome):
        outcome = prepared_or_outcome
    elif payload.stream and _should_use_live_streaming(prepared_or_outcome.provider, prepared_or_outcome.redaction_mode):
        stream_session = invoke_chat_completion_stream(messages, endpoint=prepared_or_outcome.provider)
        return _streaming_gateway_response(
            _live_agent_run_stream_body(db, prepared_or_outcome, stream_session),
            request_id=prepared_or_outcome.request_id,
            authorization=prepared_or_outcome.authorization,
            task=prepared_or_outcome.task,
            output_action="pass",
        )
    else:
        outcome = _execute_prepared_gateway_request(db, prepared_or_outcome, messages=messages)

    data = _build_agent_run_response_data(outcome)
    if outcome.state == "blocked":
        return _service_error_response(403, outcome.summary, data)
    if outcome.state == "provider_error":
        return _service_error_response(outcome.status_code, outcome.detail, data)
    if payload.stream:
        return _streaming_gateway_response(
            _agent_run_stream_body(outcome),
            request_id=outcome.request_id,
            authorization=outcome.authorization,
            task=outcome.task,
            event=outcome.event,
            report=outcome.report,
            output_action=_output_action(outcome),
        )
    return JSONResponse(
        status_code=200,
        headers=_gateway_headers(
            request_id=outcome.request_id,
            authorization=outcome.authorization,
            task=outcome.task,
            event=outcome.event,
            report=outcome.report,
            output_action=_output_action(outcome),
        ),
        content=success(data, message="agent run completed"),
    )


@router.websocket("/ws/chat/completions")
async def gateway_chat_completions_ws(websocket: WebSocket):
    db = next(get_db())
    request_id = websocket.headers.get("x-request-id") or websocket.query_params.get("request_id") or uuid4().hex[:12]
    try:
        principal = _resolve_gateway_principal_from_websocket(websocket, db)
    except HTTPException as exc:
        await websocket.close(code=4401, reason=str(exc.detail))
        db.close()
        return

    await websocket.accept()
    trace_id = websocket.headers.get("x-trace-id") or websocket.query_params.get("trace_id") or request_id
    source_ip = websocket.client.host if websocket.client else "-"

    try:
        raw_body = await websocket.receive_json()
        payload = GatewayChatCompletionsRequest.model_validate(raw_body)
    except Exception as exc:
        await _ws_send_error(websocket, request_id=request_id, status_code=400, code="invalid_request", message=str(exc))
        await websocket.close(code=4400)
        db.close()
        return

    messages = _normalize_chat_request_messages(payload)
    request_payload = payload.model_dump(mode="json")
    action = {
        "action_type": "chat_completion",
        "runtime_name": "gateway",
        "runtime_task_ref": request_id,
        "input_text": _messages_to_input_text(messages),
        "paths": list(payload.paths),
        "skill_names": list(payload.skill_names),
        "plugin_names": list(payload.plugin_names),
        "source_plugin": payload.source_plugin,
        "target_plugin": payload.target_plugin,
        "mcp_server": payload.mcp_server,
        "capability_name": payload.capability_name,
        "session_id": payload.session_id,
        "approval_id": payload.approval_id,
        "handoff_token": payload.handoff_token,
        "requested_scopes": list(payload.requested_scopes),
        "metadata": {
            **dict(payload.metadata or {}),
            "client_id": principal.client_id,
            "trace_id": trace_id,
            "message": _messages_to_input_text(messages),
        },
    }
    extra_body = {
        key: value
        for key, value in request_payload.items()
        if key
        not in {
            "model",
            "messages",
            "temperature",
            "max_tokens",
            "stream",
            "metadata",
            "target_selector",
            "requested_scopes",
            "paths",
            "skill_names",
            "plugin_names",
            "source_plugin",
            "target_plugin",
            "mcp_server",
            "capability_name",
            "session_id",
            "approval_id",
            "handoff_token",
        }
    }

    try:
        prepared_or_outcome = _prepare_gateway_execution(
            db,
            principal=principal,
            request_id=request_id,
            trace_id=trace_id,
            source_ip=source_ip,
            source_type="gateway_chat_completion",
            attack_type="chat_completion",
            source_label="Chat completions request",
            request_payload=request_payload,
            selector=payload.target_selector,
            header_target_endpoint=websocket.headers.get("x-target-endpoint") or websocket.query_params.get("target_endpoint"),
            header_route_group=websocket.headers.get("x-route-group") or websocket.query_params.get("route_group"),
            model_hint=payload.model,
            messages=messages,
            action=action,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            extra_body=extra_body,
        )
    except ValueError as exc:
        await _ws_send_error(websocket, request_id=request_id, status_code=400, code="route_resolution_failed", message=str(exc))
        await websocket.close(code=4400)
        db.close()
        return

    if isinstance(prepared_or_outcome, GatewayExecutionOutcome):
        outcome = prepared_or_outcome
        await _ws_send_error(
            websocket,
            request_id=request_id,
            status_code=outcome.status_code,
            code="policy_denied" if outcome.state == "blocked" else "provider_error",
            message=outcome.detail if outcome.state == "provider_error" else outcome.summary,
        )
        await websocket.close()
        db.close()
        return

    if _should_use_live_streaming(prepared_or_outcome.provider, prepared_or_outcome.redaction_mode):
        created_at = int(time.time())
        response_id = f"chatcmpl_{request_id}"
        stream_session = invoke_chat_completion_stream(messages, endpoint=prepared_or_outcome.provider)
        emitted_any = False
        try:
            for delta in stream_session.iter_deltas():
                is_first = not emitted_any
                emitted_any = True
                await websocket.send_json(
                    {
                        "event": "chat.completion.chunk",
                        "data": {
                            "id": response_id,
                            "object": "chat.completion.chunk",
                            "created": created_at,
                            "model": stream_session.model,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"role": "assistant", "content": delta} if is_first else {"content": delta},
                                    "finish_reason": None,
                                }
                            ],
                        },
                    }
                )
        except ProviderExecutionError as exc:
            _finalize_gateway_error(db, prepared_or_outcome, status_code=502, error_message=str(exc))
            await _ws_send_error(websocket, request_id=request_id, status_code=502, code="provider_error", message=str(exc))
            await websocket.close()
            db.close()
            return

        provider_result = stream_session.build_result()
        outcome = _finalize_gateway_completed(
            db,
            prepared_or_outcome,
            provider_result=provider_result,
            provider_payload=None,
            response_text=provider_result.output_text,
            redaction={"mode": "off", "redacted": False, "intercepted": False, "findings": []},
        )
        await websocket.send_json({"event": "chat.completion.completed", "data": _build_chat_completion_response(outcome)})
        await websocket.send_json({"event": "done", "data": "[DONE]"})
        await websocket.close()
        db.close()
        return

    outcome = _execute_prepared_gateway_request(db, prepared_or_outcome, messages=messages)
    if outcome.state != "completed":
        await _ws_send_error(
            websocket,
            request_id=request_id,
            status_code=outcome.status_code,
            code="policy_denied" if outcome.state == "blocked" else "provider_error",
            message=outcome.detail if outcome.state == "provider_error" else outcome.summary,
        )
        await websocket.close()
        db.close()
        return

    created_at = int(time.time())
    response_id = f"chatcmpl_{request_id}"
    chunks = _stream_text_chunks(outcome.response_text)
    if chunks:
        await websocket.send_json(
            {
                "event": "chat.completion.chunk",
                "data": {
                    "id": response_id,
                    "object": "chat.completion.chunk",
                    "created": created_at,
                    "model": outcome.provider_result.model if outcome.provider_result is not None else "",
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": chunks[0]}, "finish_reason": None}],
                },
            }
        )
        for chunk in chunks[1:]:
            await websocket.send_json(
                {
                    "event": "chat.completion.chunk",
                    "data": {
                        "id": response_id,
                        "object": "chat.completion.chunk",
                        "created": created_at,
                        "model": outcome.provider_result.model if outcome.provider_result is not None else "",
                        "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": None}],
                    },
                }
            )
    await websocket.send_json({"event": "chat.completion.completed", "data": _build_chat_completion_response(outcome)})
    await websocket.send_json({"event": "done", "data": "[DONE]"})
    await websocket.close()
    db.close()


@router.websocket("/ws/responses")
async def gateway_responses_ws(websocket: WebSocket):
    db = next(get_db())
    request_id = websocket.headers.get("x-request-id") or websocket.query_params.get("request_id") or uuid4().hex[:12]
    try:
        principal = _resolve_gateway_principal_from_websocket(websocket, db)
    except HTTPException as exc:
        await websocket.close(code=4401, reason=str(exc.detail))
        db.close()
        return

    await websocket.accept()
    trace_id = websocket.headers.get("x-trace-id") or websocket.query_params.get("trace_id") or request_id
    source_ip = websocket.client.host if websocket.client else "-"

    try:
        raw_body = await websocket.receive_json()
        payload = GatewayResponsesRequest.model_validate(raw_body)
    except Exception as exc:
        await _ws_send_error(websocket, request_id=request_id, status_code=400, code="invalid_request", message=str(exc))
        await websocket.close(code=4400)
        db.close()
        return

    messages = _normalize_responses_input(payload)
    request_payload = payload.model_dump(mode="json")
    request_text = _messages_to_input_text(messages)
    action = {
        "action_type": "responses",
        "runtime_name": "gateway",
        "runtime_task_ref": request_id,
        "input_text": request_text,
        "paths": list(payload.paths),
        "skill_names": list(payload.skill_names),
        "plugin_names": list(payload.plugin_names),
        "source_plugin": payload.source_plugin,
        "target_plugin": payload.target_plugin,
        "mcp_server": payload.mcp_server,
        "capability_name": payload.capability_name,
        "session_id": payload.session_id,
        "approval_id": payload.approval_id,
        "handoff_token": payload.handoff_token,
        "requested_scopes": list(payload.requested_scopes),
        "metadata": {
            **dict(payload.metadata or {}),
            "client_id": principal.client_id,
            "trace_id": trace_id,
            "message": request_text,
        },
    }
    extra_body = {
        key: value
        for key, value in request_payload.items()
        if key
        not in {
            "model",
            "input",
            "instructions",
            "temperature",
            "max_output_tokens",
            "stream",
            "metadata",
            "target_selector",
            "requested_scopes",
            "paths",
            "skill_names",
            "plugin_names",
            "source_plugin",
            "target_plugin",
            "mcp_server",
            "capability_name",
            "session_id",
            "approval_id",
            "handoff_token",
        }
    }

    try:
        prepared_or_outcome = _prepare_gateway_execution(
            db,
            principal=principal,
            request_id=request_id,
            trace_id=trace_id,
            source_ip=source_ip,
            source_type="gateway_responses",
            attack_type="responses",
            source_label="Responses request",
            request_payload=request_payload,
            selector=payload.target_selector,
            header_target_endpoint=websocket.headers.get("x-target-endpoint") or websocket.query_params.get("target_endpoint"),
            header_route_group=websocket.headers.get("x-route-group") or websocket.query_params.get("route_group"),
            model_hint=payload.model,
            messages=messages,
            action=action,
            temperature=payload.temperature,
            max_tokens=payload.max_output_tokens,
            extra_body=extra_body,
        )
    except ValueError as exc:
        await _ws_send_error(websocket, request_id=request_id, status_code=400, code="route_resolution_failed", message=str(exc))
        await websocket.close(code=4400)
        db.close()
        return

    if isinstance(prepared_or_outcome, GatewayExecutionOutcome):
        outcome = prepared_or_outcome
        await _ws_send_error(
            websocket,
            request_id=request_id,
            status_code=outcome.status_code,
            code="policy_denied" if outcome.state == "blocked" else "provider_error",
            message=outcome.detail if outcome.state == "provider_error" else outcome.summary,
        )
        await websocket.close()
        db.close()
        return

    outcome = _execute_prepared_gateway_request(db, prepared_or_outcome, messages=messages)
    if outcome.state != "completed":
        await _ws_send_error(
            websocket,
            request_id=request_id,
            status_code=outcome.status_code,
            code="policy_denied" if outcome.state == "blocked" else "provider_error",
            message=outcome.detail if outcome.state == "provider_error" else outcome.summary,
        )
        await websocket.close()
        db.close()
        return

    response_id = f"resp_{request_id}"
    item_id = f"msg_{request_id}"
    await websocket.send_json(
        {
            "event": "response.created",
            "data": {
                "type": "response.created",
                "response": {
                    "id": response_id,
                    "object": "response",
                    "created_at": int(time.time()),
                    "status": "in_progress",
                    "model": outcome.provider_result.model if outcome.provider_result is not None else "",
                },
            },
        }
    )
    for chunk in _stream_text_chunks(outcome.response_text):
        await websocket.send_json(
            {
                "event": "response.output_text.delta",
                "data": {
                    "type": "response.output_text.delta",
                    "response_id": response_id,
                    "item_id": item_id,
                    "output_index": 0,
                    "content_index": 0,
                    "delta": chunk,
                },
            }
        )
    await websocket.send_json({"event": "response.completed", "data": _build_responses_response(outcome)})
    await websocket.send_json({"event": "done", "data": "[DONE]"})
    await websocket.close()
    db.close()


@router.websocket("/ws/agents/run")
async def gateway_agents_run_ws(websocket: WebSocket):
    db = next(get_db())
    request_id = websocket.headers.get("x-request-id") or websocket.query_params.get("request_id") or uuid4().hex[:12]
    try:
        principal = _resolve_gateway_principal_from_websocket(websocket, db)
    except HTTPException as exc:
        await websocket.close(code=4401, reason=str(exc.detail))
        db.close()
        return

    await websocket.accept()
    trace_id = websocket.headers.get("x-trace-id") or websocket.query_params.get("trace_id") or request_id
    source_ip = websocket.client.host if websocket.client else "-"

    try:
        raw_body = await websocket.receive_json()
        payload = GatewayAgentRunRequest.model_validate(raw_body)
    except Exception as exc:
        await _ws_send_error(websocket, request_id=request_id, status_code=400, code="invalid_request", message=str(exc))
        await websocket.close(code=4400)
        db.close()
        return

    messages = _normalize_agent_run_messages(payload)
    request_text = _messages_to_input_text(messages)
    request_payload = payload.model_dump(mode="json")
    action = {
        "action_type": "agent_run",
        "runtime_name": payload.runtime_name or "gateway-agent",
        "runtime_task_ref": request_id,
        "input_text": request_text,
        "paths": list(payload.paths),
        "skill_names": list(payload.skill_names),
        "plugin_names": list(payload.plugin_names),
        "source_plugin": payload.source_plugin,
        "target_plugin": payload.target_plugin,
        "mcp_server": payload.mcp_server,
        "capability_name": payload.capability_name,
        "session_id": payload.session_id,
        "approval_id": payload.approval_id,
        "handoff_token": payload.handoff_token,
        "requested_scopes": list(payload.requested_scopes),
        "metadata": {
            **dict(payload.metadata or {}),
            "client_id": principal.client_id,
            "trace_id": trace_id,
            "message": request_text,
        },
    }
    extra_body = {
        key: value
        for key, value in request_payload.items()
        if key
        not in {
            "model",
            "runtime_name",
            "input_text",
            "instructions",
            "messages",
            "temperature",
            "max_tokens",
            "stream",
            "metadata",
            "target_selector",
            "requested_scopes",
            "paths",
            "skill_names",
            "plugin_names",
            "source_plugin",
            "target_plugin",
            "mcp_server",
            "capability_name",
            "session_id",
            "approval_id",
            "handoff_token",
        }
    }

    try:
        prepared_or_outcome = _prepare_gateway_execution(
            db,
            principal=principal,
            request_id=request_id,
            trace_id=trace_id,
            source_ip=source_ip,
            source_type="gateway_agent_run",
            attack_type="agent_run",
            source_label="Agent run request",
            request_payload=request_payload,
            selector=payload.target_selector,
            header_target_endpoint=websocket.headers.get("x-target-endpoint") or websocket.query_params.get("target_endpoint"),
            header_route_group=websocket.headers.get("x-route-group") or websocket.query_params.get("route_group"),
            model_hint=payload.model,
            messages=messages,
            action=action,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            extra_body=extra_body,
        )
    except ValueError as exc:
        await _ws_send_error(websocket, request_id=request_id, status_code=400, code="route_resolution_failed", message=str(exc))
        await websocket.close(code=4400)
        db.close()
        return

    if isinstance(prepared_or_outcome, GatewayExecutionOutcome):
        outcome = prepared_or_outcome
        await _ws_send_error(
            websocket,
            request_id=request_id,
            status_code=outcome.status_code,
            code="policy_denied" if outcome.state == "blocked" else "provider_error",
            message=outcome.detail if outcome.state == "provider_error" else outcome.summary,
        )
        await websocket.close()
        db.close()
        return

    outcome = _execute_prepared_gateway_request(db, prepared_or_outcome, messages=messages)
    if outcome.state != "completed":
        await _ws_send_error(
            websocket,
            request_id=request_id,
            status_code=outcome.status_code,
            code="policy_denied" if outcome.state == "blocked" else "provider_error",
            message=outcome.detail if outcome.state == "provider_error" else outcome.summary,
        )
        await websocket.close()
        db.close()
        return

    await websocket.send_json(
        {
            "event": "agent.run.started",
            "data": {
                "type": "agent.run.started",
                "request_id": request_id,
                "task_id": outcome.task.id,
                "status": "in_progress",
            },
        }
    )
    for chunk in _stream_text_chunks(outcome.response_text):
        await websocket.send_json(
            {
                "event": "agent.run.delta",
                "data": {
                    "type": "agent.run.delta",
                    "request_id": request_id,
                    "task_id": outcome.task.id,
                    "delta": chunk,
                },
            }
        )
    await websocket.send_json({"event": "agent.run.completed", "data": success(_build_agent_run_response_data(outcome), message="agent run completed")})
    await websocket.send_json({"event": "done", "data": "[DONE]"})
    await websocket.close()
    db.close()


@router.post("/runtime/register")
def gateway_runtime_register(
    payload: RuntimeRegisterRequest,
    db: Session = Depends(get_db),
):
    try:
        token = resolve_enrollment_token(db, payload.enrollment_token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    registration_id, poll_secret = create_registration_identity()
    display_name = (
        payload.display_name.strip()
        or payload.hostname.strip()
        or f"{payload.runtime_type.strip() or token.runtime_type}-{registration_id[-6:]}"
    )
    bound_endpoint_id = token.ai_endpoint_id if token.ai_endpoint_id is not None else payload.ai_endpoint_id
    if bound_endpoint_id is not None:
        endpoint = db.get(AiEndpoint, bound_endpoint_id)
        if endpoint is None:
            raise HTTPException(status_code=404, detail="ai endpoint not found")

    item = ManagedRuntime(
        registration_id=registration_id,
        display_name=display_name,
        runtime_type=payload.runtime_type.strip() or token.runtime_type,
        poll_secret_hash=hash_password(poll_secret),
        enrollment_token_id=token.id,
        ai_endpoint_id=bound_endpoint_id,
        status="pending",
        hostname=payload.hostname.strip(),
        fingerprint=payload.fingerprint.strip(),
        client_version=payload.client_version.strip(),
    )
    item.set_ip_addresses(_dedupe_strings(payload.ip_addresses))
    item.set_requested_scopes(_dedupe_strings(payload.requested_scopes))
    item.set_capabilities(_dedupe_strings(payload.capabilities))
    item.set_meta(dict(payload.metadata or {}))

    token.used_count += 1
    db.add(item)
    db.commit()
    db.refresh(item)

    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "registration": {
                "registration_id": registration_id,
                "poll_secret": poll_secret,
                "status": item.status,
                "status_summary": runtime_status_summary(item),
                "poll_after_seconds": 5,
            },
        },
        message="runtime registration submitted",
    )


@router.post("/runtime/register/status")
def gateway_runtime_register_status(
    payload: RuntimeRegisterStatusRequest,
    db: Session = Depends(get_db),
):
    item = db.query(ManagedRuntime).filter(ManagedRuntime.registration_id == payload.registration_id.strip()).first()
    if item is None:
        raise HTTPException(status_code=404, detail="runtime registration not found")
    if not verify_runtime_poll_secret(item, payload.poll_secret.strip()):
        raise HTTPException(status_code=401, detail="runtime registration credentials are invalid")

    response_data: dict[str, Any] = {
        "runtime": serialize_managed_runtime(db, item),
        "status": item.status,
        "status_summary": runtime_status_summary(item),
    }
    if item.status == "approved":
        credentials = issue_runtime_credentials(item)
        db.commit()
        db.refresh(item)
        response_data = {
            **response_data,
            "runtime": serialize_managed_runtime(db, item),
            "status": item.status,
            "status_summary": runtime_status_summary(item),
            "runtime_credentials": {
                "runtime_key": credentials.runtime_key,
                "runtime_secret": credentials.runtime_secret,
                "auth_headers": build_runtime_auth_headers(credentials.runtime_key, credentials.runtime_secret),
            },
        }
    elif item.status == "active":
        response_data["runtime_credentials"] = None

    return success(response_data, message="runtime registration status")


@router.get("/runtime/session")
def gateway_runtime_session(
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    now = utc_now()
    if principal.runtime is not None:
        principal.runtime.last_seen_at = now
        db.commit()
        db.refresh(principal.runtime)
        return success(
            {
                "auth_mode": principal.auth_mode,
                "client_id": principal.client_id,
                "runtime": serialize_managed_runtime(db, principal.runtime),
            },
            message="runtime session active",
        )

    return success(
        {
            "auth_mode": principal.auth_mode,
            "client_id": principal.client_id,
            "user": {
                "id": principal.user.id if principal.user is not None else 0,
                "username": principal.user.username if principal.user is not None else "",
                "role": principal.user.role if principal.user is not None else "",
            },
        },
        message="gateway session active",
    )


@router.get("/runtime/commands/next")
def gateway_runtime_next_command(
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    if principal.runtime is None:
        raise HTTPException(status_code=403, detail="runtime authentication is required")

    now = utc_now()
    principal.runtime.last_seen_at = now
    item = claim_next_runtime_command(db, principal.runtime.id)
    db.commit()
    if item is not None:
        db.refresh(item)
    db.refresh(principal.runtime)
    return success(
        {
            "runtime": serialize_managed_runtime(db, principal.runtime),
            "command": _serialize_runtime_command(item),
        },
        message="runtime command ready" if item is not None else "no runtime command",
    )


@router.post("/runtime/commands/{command_id}/complete")
def gateway_runtime_complete_command(
    command_id: int,
    payload: GatewayRuntimeCommandCompleteRequest,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    if principal.runtime is None:
        raise HTTPException(status_code=403, detail="runtime authentication is required")

    item = db.get(RuntimeDispatchCommand, command_id)
    if item is None:
        raise HTTPException(status_code=404, detail="runtime command not found")
    if item.runtime_id != principal.runtime.id:
        raise HTTPException(status_code=403, detail="runtime command does not belong to this runtime")

    now = utc_now()
    principal.runtime.last_seen_at = now
    if item.status not in {"completed", "failed", "cancelled"}:
        complete_runtime_command(
            db,
            item=item,
            status=payload.status,
            summary=payload.summary,
            response_text=payload.response_text,
            response_json=payload.response_json,
            error=payload.error,
            metadata=payload.metadata,
        )
        db.commit()
        db.refresh(item)
    else:
        db.commit()
    db.refresh(principal.runtime)
    return success({"command": _serialize_runtime_command(item)}, message="runtime command completed")


@router.post("/runtime/tasks")
def gateway_runtime_create_task(
    payload: AttackTaskCreate,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    task_name = payload.task_name.strip()
    attack_type = payload.attack_type.strip()
    target_agent = payload.target_agent.strip()
    if not task_name or not attack_type or not target_agent:
        raise HTTPException(status_code=400, detail="task_name, attack_type and target_agent are required")

    requested_endpoint_id = payload.ai_endpoint_id
    if requested_endpoint_id is None and principal.runtime is not None and principal.runtime.ai_endpoint_id is not None:
        requested_endpoint_id = principal.runtime.ai_endpoint_id

    params_json = dict(payload.params_json or {})
    params_json["execution_mode"] = "runtime_callback"
    params_json.setdefault("source_type", "runtime_gateway")
    params_json.setdefault("source_ref", principal.client_id)
    params_json.setdefault("runtime_registration_id", principal.runtime.registration_id if principal.runtime is not None else "")
    params_json.setdefault("runtime_client_id", principal.client_id)

    try:
        params_json, _endpoint = attach_ai_endpoint_selection(db, params_json, ai_endpoint_id=requested_endpoint_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    item = AttackTask(
        task_name=task_name,
        attack_type=attack_type,
        target_agent=target_agent,
        status="ready",
        source_type=str(params_json.get("source_type") or "runtime_gateway"),
        source_ref=str(params_json.get("source_ref") or principal.client_id),
        execution_mode="runtime_callback",
        runtime_name=principal.runtime.display_name if principal.runtime is not None else "",
        created_by=_resolve_task_creator_id(db, principal),
    )
    item.set_params(params_json)
    db.add(item)
    db.commit()
    db.refresh(item)
    logger.info(
        "runtime task created | task_id=%s attack_type=%s client_id=%s runtime=%s",
        item.id,
        item.attack_type,
        principal.client_id,
        principal.runtime.registration_id if principal.runtime is not None else "-",
    )
    return success(_serialize_task(item), message="runtime task created")


@router.post("/runtime/authorize")
def gateway_runtime_authorize(
    payload: GatewayRuntimeAuthorizeRequest,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    item = _get_task_or_404(db, payload.task_id)
    if item.status in {"done", "failed"} and item.latest_report_id:
        return success(_runtime_success_payload(item), message="task already completed")

    now = utc_now()
    if principal.runtime is not None:
        principal.runtime.last_seen_at = now
    if payload.runtime_name:
        item.runtime_name = payload.runtime_name
    if payload.runtime_task_ref:
        item.runtime_task_ref = payload.runtime_task_ref
    item.execution_mode = "runtime_callback"
    item.last_heartbeat_at = now

    action = payload.model_dump()
    action.pop("task_id", None)
    decision = authorize_runtime_action(db, item, action)
    append_task_authorization_snapshot(item, action=action, decision=decision)
    serialized_decision = serialize_authorization_decision(decision)
    issued_ticket = None
    if decision.decision != "deny" and action_requires_mcp_ticket(action):
        issued_ticket = issue_mcp_execution_ticket(
            db,
            task=item,
            runtime=principal.runtime,
            action=action,
        )
        if issued_ticket is not None:
            serialized_decision["mcp_execution_ticket"] = serialize_mcp_execution_ticket(issued_ticket)

    params = dict(item.params)
    runtime_state = dict(params.get("runtime") or {})
    runtime_state["authorization_at"] = format_beijing(now)
    runtime_state["authorization_result"] = serialized_decision
    if issued_ticket is not None:
        runtime_state["mcp_execution_ticket"] = serialize_mcp_execution_ticket(issued_ticket)
    params["runtime"] = runtime_state
    item.set_params(params)

    db.commit()
    db.refresh(item)
    return success({"task": _serialize_task(item), "authorization": serialized_decision}, message="runtime authorization evaluated")


@router.post("/runtime/heartbeat")
def gateway_runtime_heartbeat(
    payload: GatewayRuntimeHeartbeatRequest,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    item = _get_task_or_404(db, payload.task_id)
    if item.status in {"done", "failed"} and item.latest_report_id:
        return success(_runtime_success_payload(item), message="task already completed")

    now = utc_now()
    if principal.runtime is not None:
        principal.runtime.last_seen_at = now
    item.status = "running"
    item.execution_mode = "runtime_callback"
    item.runtime_name = payload.runtime_name
    item.runtime_task_ref = payload.runtime_task_ref or item.runtime_task_ref
    item.started_at = item.started_at or now
    item.last_heartbeat_at = now
    item.scheduled_at = None

    params = dict(item.params)
    runtime_state = dict(params.get("runtime") or {})
    runtime_state.update(
        {
            "status": payload.status,
            "message": payload.message,
            "progress": payload.progress,
            "metadata": payload.metadata,
            "heartbeat_at": format_beijing(now),
        }
    )
    params["runtime"] = runtime_state
    item.set_params(params)

    db.commit()
    db.refresh(item)
    return success(_serialize_task(item), message="heartbeat received")


@router.post("/runtime/complete")
def gateway_runtime_complete(
    payload: GatewayRuntimeCompleteRequest,
    db: Session = Depends(get_db),
    principal: GatewayPrincipal = Depends(gateway_principal_dependency),
):
    item = _get_task_or_404(db, payload.task_id)
    if item.status in {"done", "failed"} and item.latest_report_id:
        event = db.get(SecurityEvent, item.latest_event_id) if item.latest_event_id else None
        report = db.get(Report, item.latest_report_id) if item.latest_report_id else None
        return success(_runtime_success_payload(item, event, report), message="task already completed")

    now = utc_now()
    if principal.runtime is not None:
        principal.runtime.last_seen_at = now
    item.execution_mode = "runtime_callback"
    item.runtime_name = payload.runtime_name or item.runtime_name or "external-runtime"
    item.runtime_task_ref = payload.runtime_task_ref or item.runtime_task_ref
    item.started_at = item.started_at or now
    item.last_heartbeat_at = now
    item.scheduled_at = None

    params = dict(item.params)
    runtime_state = dict(params.get("runtime") or {})
    completion_action = _build_runtime_completion_action(item, payload)
    mcp_ticket_validation = None
    if completion_action["mcp_ticket_key"] or completion_action["consume_mcp_ticket"]:
        mcp_ticket_validation = validate_mcp_execution_ticket(
            db,
            ticket_key=completion_action["mcp_ticket_key"],
            task_id=item.id,
            runtime_id=principal.runtime.id if principal.runtime is not None else None,
            ai_endpoint_id=resolve_task_ai_endpoint_id(item),
            action=completion_action,
            consume=completion_action["consume_mcp_ticket"],
        )
        runtime_state["mcp_ticket_audit"] = {
            "allowed": mcp_ticket_validation.allowed,
            "code": mcp_ticket_validation.code,
            "reason": mcp_ticket_validation.reason,
            "ticket_key": completion_action["mcp_ticket_key"],
            "consume": completion_action["consume_mcp_ticket"],
            "completed_at": format_beijing(now),
        }
    runtime_state.update(
        {
            "status": payload.status,
            "metadata": payload.metadata,
            "completed_at": format_beijing(now),
        }
    )
    params["runtime"] = runtime_state
    item.set_params(params)

    raw_response = payload.raw_response_text
    if not raw_response and payload.raw_response_json is not None:
        raw_response = json.dumps(payload.raw_response_json, ensure_ascii=False)
    if not raw_response:
        raw_response = json.dumps({"runtime_metadata": payload.metadata}, ensure_ascii=False)

    event_payload = payload.event
    event_type = event_payload.event_type if event_payload is not None else (item.attack_type or "runtime_execution")
    event_level = event_payload.event_level if event_payload is not None else ("high" if payload.status == "failed" else "medium")
    event_status = event_payload.event_status if event_payload is not None else (
        EVENT_STATUS_SUSPICIOUS if payload.status == "failed" else EVENT_STATUS_ALLOWED
    )
    event_source = event_payload.source if event_payload is not None and event_payload.source else f"gateway/runtime/{item.runtime_name or 'external-runtime'}"
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
        event_status = EVENT_STATUS_INTERCEPTED
        event_level = "high"
        final_summary = mcp_ticket_validation.reason
        event_detail = f"{event_detail}; {mcp_ticket_validation.reason}" if event_detail else mcp_ticket_validation.reason
        result = result or mcp_ticket_validation.reason
        hit_rules = _dedupe_strings([*hit_rules, "mcp-session-bind"])
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

    return success(_runtime_success_payload(task, event, report), message="runtime result ingested")
