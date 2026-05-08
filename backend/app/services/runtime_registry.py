from __future__ import annotations

import secrets
from datetime import timedelta
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..models import AiEndpoint, AttackTask, ManagedRuntime, RuntimeEnrollmentToken, User
from .ai_endpoints import build_ai_endpoint_snapshot
from .security import hash_password, verify_password
from .time_utils import format_beijing, utc_now

ENROLLMENT_TOKEN_PREFIX = "btenr"
RUNTIME_KEY_PREFIX = "rtm"
RUNTIME_SECRET_PREFIX = "rts"
REGISTRATION_PREFIX = "reg"
POLL_SECRET_PREFIX = "clm"


@dataclass
class EnrollmentSecretBundle:
    token_key: str
    secret: str
    token_value: str
    secret_hint: str


@dataclass
class RuntimeCredentialBundle:
    runtime_key: str
    runtime_secret: str
    runtime_secret_hint: str


def _generate_public_id(prefix: str, length: int = 12) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return f"{prefix}_{''.join(secrets.choice(alphabet) for _ in range(length))}"


def _generate_secret(prefix: str, length: int = 32) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    return f"{prefix}_{''.join(secrets.choice(alphabet) for _ in range(length))}"


def _mask_secret(secret: str, *, visible_start: int = 6, visible_end: int = 4) -> str:
    value = secret.strip()
    if not value:
        return ""
    if len(value) <= visible_start + visible_end + 1:
        return "***"
    return f"{value[:visible_start]}***{value[-visible_end:]}"


def _build_enrollment_token_value(token_key: str, secret: str) -> str:
    return f"{ENROLLMENT_TOKEN_PREFIX}.{token_key}.{secret}"


def parse_enrollment_token(value: str) -> tuple[str, str]:
    normalized = str(value or "").strip()
    prefix, separator, remainder = normalized.partition(".")
    if prefix != ENROLLMENT_TOKEN_PREFIX or not separator:
        raise ValueError("无效的注册令牌格式")
    token_key, separator, secret = remainder.partition(".")
    if not token_key or not separator or not secret:
        raise ValueError("无效的注册令牌格式")
    return token_key.strip(), secret.strip()


def create_enrollment_secret() -> EnrollmentSecretBundle:
    token_key = _generate_public_id("enr")
    secret = _generate_secret("sek", 28)
    return EnrollmentSecretBundle(
        token_key=token_key,
        secret=secret,
        token_value=_build_enrollment_token_value(token_key, secret),
        secret_hint=_mask_secret(secret),
    )


def create_registration_identity() -> tuple[str, str]:
    return _generate_public_id(REGISTRATION_PREFIX), _generate_secret(POLL_SECRET_PREFIX, 26)


def create_runtime_credentials() -> RuntimeCredentialBundle:
    runtime_key = _generate_public_id(RUNTIME_KEY_PREFIX)
    runtime_secret = _generate_secret(RUNTIME_SECRET_PREFIX, 36)
    return RuntimeCredentialBundle(
        runtime_key=runtime_key,
        runtime_secret=runtime_secret,
        runtime_secret_hint=_mask_secret(runtime_secret),
    )


def _runtime_endpoint_snapshot(db: Session, endpoint_id: int | None) -> dict[str, Any] | None:
    if endpoint_id is None:
        return None
    item = db.query(AiEndpoint).get(endpoint_id)
    if item is None:
        return None
    return build_ai_endpoint_snapshot(item)


def serialize_runtime_enrollment_token(db: Session, item: RuntimeEnrollmentToken) -> dict[str, Any]:
    now = utc_now()
    expired = item.expires_at is not None and item.expires_at <= now
    effective_status = "expired" if expired and item.status == "active" else item.status
    return {
        "id": item.id,
        "token_key": item.token_key,
        "token_label": item.token_label,
        "token_hint": f"{item.token_key}.{item.secret_hint}",
        "runtime_type": item.runtime_type,
        "status": effective_status,
        "usage_limit": item.usage_limit,
        "used_count": item.used_count,
        "remaining_uses": max(item.usage_limit - item.used_count, 0),
        "expires_at": format_beijing(item.expires_at) if item.expires_at else "",
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
        "ai_endpoint": _runtime_endpoint_snapshot(db, item.ai_endpoint_id),
        "binding_state": "bound" if item.ai_endpoint_id is not None else "unbound",
    }


def serialize_managed_runtime(db: Session, item: ManagedRuntime) -> dict[str, Any]:
    now = utc_now()
    is_online = bool(item.last_seen_at and item.last_seen_at >= now - timedelta(minutes=10))
    return {
        "id": item.id,
        "registration_id": item.registration_id,
        "display_name": item.display_name,
        "runtime_type": item.runtime_type,
        "runtime_key": item.runtime_key or "",
        "runtime_secret_hint": item.runtime_secret_hint,
        "status": item.status,
        "hostname": item.hostname,
        "fingerprint": item.fingerprint,
        "client_version": item.client_version,
        "ip_addresses": item.ip_addresses,
        "requested_scopes": item.requested_scopes,
        "capabilities": item.capabilities,
        "metadata": item.meta,
        "ai_endpoint": _runtime_endpoint_snapshot(db, item.ai_endpoint_id),
        "approved_at": format_beijing(item.approved_at) if item.approved_at else "",
        "rejected_at": format_beijing(item.rejected_at) if item.rejected_at else "",
        "revoked_at": format_beijing(item.revoked_at) if item.revoked_at else "",
        "last_seen_at": format_beijing(item.last_seen_at) if item.last_seen_at else "",
        "credential_delivered_at": format_beijing(item.credential_delivered_at) if item.credential_delivered_at else "",
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
        "rejection_reason": item.rejection_reason,
        "binding_state": "bound" if item.ai_endpoint_id is not None else "unbound",
        "status_summary": runtime_status_summary(item),
        "is_online": is_online,
    }


def issue_runtime_credentials(runtime: ManagedRuntime) -> RuntimeCredentialBundle:
    credentials = create_runtime_credentials()
    runtime.runtime_key = credentials.runtime_key
    runtime.runtime_secret_hash = hash_password(credentials.runtime_secret)
    runtime.runtime_secret_hint = credentials.runtime_secret_hint
    runtime.credential_delivered_at = utc_now()
    runtime.status = "active"
    return credentials


def verify_runtime_secret(runtime: ManagedRuntime, secret: str | None) -> bool:
    if not runtime.runtime_secret_hash or not secret:
        return False
    return verify_password(secret, runtime.runtime_secret_hash)


def resolve_enrollment_token(db: Session, enrollment_token: str) -> RuntimeEnrollmentToken:
    token_key, secret = parse_enrollment_token(enrollment_token)
    item = db.query(RuntimeEnrollmentToken).filter(RuntimeEnrollmentToken.token_key == token_key).first()
    if item is None:
        raise ValueError("注册令牌不存在")
    if item.status != "active":
        raise ValueError("注册令牌已停用")
    if item.expires_at is not None and item.expires_at <= utc_now():
        item.status = "expired"
        db.commit()
        raise ValueError("注册令牌已过期")
    if item.used_count >= item.usage_limit:
        raise ValueError("注册令牌已达到使用上限")
    if not verify_password(secret, item.secret_hash):
        raise ValueError("注册令牌无效")
    return item


def verify_runtime_poll_secret(runtime: ManagedRuntime, secret: str) -> bool:
    return verify_password(secret, runtime.poll_secret_hash)


def find_runtime_by_runtime_key(db: Session, runtime_key: str | None) -> ManagedRuntime | None:
    key = str(runtime_key or "").strip()
    if not key:
        return None
    return db.query(ManagedRuntime).filter(ManagedRuntime.runtime_key == key).first()


def runtime_registry_endpoint_usage(db: Session) -> dict[int, dict[str, Any]]:
    usage: dict[int, dict[str, Any]] = {}

    def ensure(endpoint_id: int) -> dict[str, Any]:
        return usage.setdefault(
            endpoint_id,
            {
                "token_count": 0,
                "runtime_count": 0,
                "runtime_pending_count": 0,
                "runtime_active_count": 0,
                "runtime_online_count": 0,
                "active_task_count": 0,
                "task_count": 0,
                "last_runtime_seen_at": "",
            },
        )

    for token in db.query(RuntimeEnrollmentToken).all():
        if token.ai_endpoint_id is None:
            continue
        ensure(token.ai_endpoint_id)["token_count"] += 1

    for runtime in db.query(ManagedRuntime).all():
        if runtime.ai_endpoint_id is None:
            continue
        bucket = ensure(runtime.ai_endpoint_id)
        bucket["runtime_count"] += 1
        if runtime.status in {"pending", "approved"}:
            bucket["runtime_pending_count"] += 1
        if runtime.status == "active":
            bucket["runtime_active_count"] += 1
        if runtime.last_seen_at is not None:
            rendered = format_beijing(runtime.last_seen_at) or ""
            if not bucket["last_runtime_seen_at"] or rendered > bucket["last_runtime_seen_at"]:
                bucket["last_runtime_seen_at"] = rendered
            if runtime.last_seen_at >= utc_now() - timedelta(minutes=10):
                bucket["runtime_online_count"] += 1

    for task in db.query(AttackTask).all():
        raw_value = task.params.get("ai_endpoint_id")
        endpoint_id: int | None = None
        if isinstance(raw_value, int):
            endpoint_id = raw_value
        elif isinstance(raw_value, str) and raw_value.strip().isdigit():
            endpoint_id = int(raw_value.strip())
        if endpoint_id is None:
            continue
        bucket = ensure(endpoint_id)
        bucket["task_count"] += 1
        if task.status in {"ready", "queued", "scheduled", "running"}:
            bucket["active_task_count"] += 1

    return usage


def runtime_registry_payload(db: Session) -> dict[str, Any]:
    token_items = (
        db.query(RuntimeEnrollmentToken)
        .order_by(RuntimeEnrollmentToken.created_at.desc(), RuntimeEnrollmentToken.id.desc())
        .all()
    )
    runtime_items = (
        db.query(ManagedRuntime)
        .order_by(ManagedRuntime.created_at.desc(), ManagedRuntime.id.desc())
        .all()
    )
    serialized_tokens = [serialize_runtime_enrollment_token(db, item) for item in token_items]
    serialized_runtimes = [serialize_managed_runtime(db, item) for item in runtime_items]
    unbound_tokens = [item for item in serialized_tokens if item["ai_endpoint"] is None]
    unbound_runtimes = [item for item in serialized_runtimes if item["ai_endpoint"] is None]
    online_runtimes = sum(1 for item in serialized_runtimes if item["is_online"])

    summary = {
        "tokens_total": len(token_items),
        "tokens_active": sum(1 for item in token_items if item.status == "active"),
        "runtimes_total": len(runtime_items),
        "runtimes_pending": sum(1 for item in runtime_items if item.status == "pending"),
        "runtimes_approved": sum(1 for item in runtime_items if item.status == "approved"),
        "runtimes_active": sum(1 for item in runtime_items if item.status == "active"),
        "tokens_unbound": len(unbound_tokens),
        "runtimes_unbound": len(unbound_runtimes),
        "runtimes_online": online_runtimes,
    }
    return {
        "summary": summary,
        "tokens": serialized_tokens,
        "runtimes": serialized_runtimes,
        "unbound_tokens": unbound_tokens,
        "unbound_runtimes": unbound_runtimes,
    }


def build_runtime_onboarding_steps(*, server_base: str, enrollment_token: str) -> list[str]:
    base = server_base.rstrip("/")
    return [
        "1. 在客户端脚本里填写平台注册地址。",
        f"2. 使用一次性注册令牌: {enrollment_token}",
        f"3. 客户端向 {base}/gateway/v1/runtime/register 发起注册申请。",
        "4. 管理员在控制台审批后，客户端轮询注册状态并自动领取长期 Runtime 凭据。",
        "5. 后续所有模型请求与运行时回调都改用 Runtime 凭据访问平台网关。",
    ]


def build_runtime_auth_headers(runtime_key: str, runtime_secret: str) -> list[dict[str, str]]:
    return [
        {"name": "X-Runtime-Key", "value": runtime_key},
        {"name": "X-Runtime-Secret", "value": runtime_secret},
    ]


def runtime_status_summary(item: ManagedRuntime) -> str:
    if item.status == "pending":
        return "等待审批"
    if item.status == "approved":
        return "已批准，等待客户端领取凭据"
    if item.status == "active":
        return "已发放长期凭据"
    if item.status == "rejected":
        return "已拒绝"
    if item.status == "revoked":
        return "已吊销"
    return item.status


def runtime_actor_name(user: User | None) -> str:
    if user is None:
        return "-"
    return user.real_name or user.username
