from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AiEndpoint, ManagedRuntime, RuntimeEnrollmentToken, User
from ...schemas.runtime_registry import (
    RuntimeApprovalRequest,
    RuntimeBootstrapActivationRequest,
    RuntimeActivationCodeExchangeRequest,
    RuntimeActivationCodeIssueRequest,
    RuntimeActivationRequestCreate,
    RuntimeBindingRequest,
    RuntimeEnrollmentTokenCreate,
    RuntimeEnrollmentTokenBindingRequest,
    RuntimeRejectionRequest,
)
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.runtime_registry import (
    build_runtime_activation_steps,
    build_runtime_bootstrap_steps,
    build_runtime_onboarding_steps,
    create_activation_code,
    create_bootstrap_activation_code,
    create_enrollment_secret,
    create_registration_identity,
    issue_runtime_credentials,
    resolve_bootstrap_activation_token,
    runtime_registry_payload,
    runtime_status_summary,
    serialize_managed_runtime,
    serialize_runtime_enrollment_token,
    verify_runtime_activation_code,
)
from ...services.security import hash_password
from ...services.time_utils import utc_now

router = APIRouter()
public_router = APIRouter()


def _get_runtime_or_404(db: Session, runtime_id: int) -> ManagedRuntime:
    item = db.get(ManagedRuntime, runtime_id)
    if item is None:
        raise HTTPException(status_code=404, detail="runtime not found")
    return item


def _get_endpoint_or_404(db: Session, endpoint_id: int) -> AiEndpoint:
    item = db.get(AiEndpoint, endpoint_id)
    if item is None:
        raise HTTPException(status_code=404, detail="ai endpoint not found")
    return item


def _get_token_or_404(db: Session, token_id: int) -> RuntimeEnrollmentToken:
    item = db.get(RuntimeEnrollmentToken, token_id)
    if item is None:
        raise HTTPException(status_code=404, detail="runtime enrollment token not found")
    return item


def _clear_activation_state(item: ManagedRuntime) -> None:
    item.activation_code_hash = None
    item.activation_code_hint = ""
    item.activation_issued_at = None
    item.activation_expires_at = None


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


@router.get("")
def list_runtime_registry(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success(runtime_registry_payload(db))


@router.post("/activation-requests")
def create_runtime_activation_request(
    payload: RuntimeActivationRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)

    registration_id, poll_secret = create_registration_identity()
    runtime_type = payload.runtime_type.strip() or "agent"
    display_name = (
        (payload.display_name or "").strip()
        or payload.hostname.strip()
        or f"{runtime_type}-{registration_id[-6:]}"
    )
    item = ManagedRuntime(
        registration_id=registration_id,
        display_name=display_name,
        runtime_type=runtime_type,
        poll_secret_hash=hash_password(poll_secret),
        ai_endpoint_id=payload.ai_endpoint_id,
        status="activation_requested",
        hostname=payload.hostname.strip(),
        fingerprint=payload.fingerprint.strip(),
        client_version=payload.client_version.strip(),
    )
    item.set_ip_addresses(_dedupe_strings(payload.ip_addresses))
    item.set_requested_scopes(_dedupe_strings(payload.requested_scopes))
    item.set_capabilities(_dedupe_strings(payload.capabilities))
    item.set_meta(dict(payload.metadata or {}))
    db.add(item)
    db.flush()
    append_audit_log(
        db,
        current_user,
        "runtime-registry",
        "create-activation-request",
        f"created runtime activation request {item.registration_id}",
    )
    db.commit()
    db.refresh(item)

    public_origin = str(request.base_url).rstrip("/")
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "registration": {
                "registration_id": registration_id,
                "status": item.status,
                "status_summary": runtime_status_summary(item),
            },
            "onboarding_steps": build_runtime_activation_steps(
                server_base=public_origin,
                registration_id=registration_id,
            ),
        },
        message="runtime activation request created",
    )


@router.post("/tokens")
def create_runtime_enrollment_token(
    payload: RuntimeEnrollmentTokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    label = payload.token_label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="token_label is required")
    if payload.usage_limit <= 0:
        raise HTTPException(status_code=400, detail="usage_limit must be greater than 0")
    delivery_mode = payload.delivery_mode.strip().lower() or "approval"
    if delivery_mode not in {"approval", "activation_code"}:
        raise HTTPException(status_code=400, detail="delivery_mode must be approval or activation_code")
    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)
    if delivery_mode == "activation_code" and payload.ai_endpoint_id is None:
        raise HTTPException(status_code=400, detail="activation_code mode requires ai_endpoint_id")

    bundle = create_enrollment_secret()
    bootstrap_activation = create_bootstrap_activation_code() if delivery_mode == "activation_code" else None
    item = RuntimeEnrollmentToken(
        token_key=bundle.token_key,
        token_label=label,
        secret_hash=hash_password(bundle.secret),
        secret_hint=bundle.secret_hint,
        delivery_mode=delivery_mode,
        bootstrap_code_hash=hash_password(bootstrap_activation.activation_code) if bootstrap_activation else None,
        bootstrap_code_hint=bootstrap_activation.activation_code_hint if bootstrap_activation else "",
        runtime_type=payload.runtime_type.strip() or "agent",
        ai_endpoint_id=payload.ai_endpoint_id,
        usage_limit=payload.usage_limit,
        issued_by=current_user.id,
        expires_at=payload.expires_at,
        status="active",
    )
    db.add(item)
    db.flush()
    append_audit_log(db, current_user, "runtime-registry", "create-token", f"created runtime enrollment token {item.token_key}")
    db.commit()
    db.refresh(item)

    public_origin = str(request.base_url).rstrip("/")
    return success(
        {
            "token": serialize_runtime_enrollment_token(db, item),
            "enrollment_token": bundle.token_value,
            "activation_code": bootstrap_activation.activation_code if bootstrap_activation else "",
            "onboarding_steps": (
                build_runtime_bootstrap_steps(
                    server_base=public_origin,
                    activation_code=bootstrap_activation.activation_code,
                )
                if bootstrap_activation
                else build_runtime_onboarding_steps(
                    server_base=public_origin,
                    enrollment_token=bundle.token_value,
                )
            ),
        },
        message="runtime enrollment token created",
    )


@router.post("/tokens/{token_id}/bind")
def bind_runtime_enrollment_token(
    token_id: int,
    payload: RuntimeEnrollmentTokenBindingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_token_or_404(db, token_id)
    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)
    item.ai_endpoint_id = payload.ai_endpoint_id
    append_audit_log(
        db,
        current_user,
        "runtime-registry",
        "bind-token",
        f"bound runtime enrollment token {item.token_key} to endpoint {payload.ai_endpoint_id or 'unbound'}",
    )
    db.commit()
    db.refresh(item)
    return success(
        {
            "token": serialize_runtime_enrollment_token(db, item),
        },
        message="runtime enrollment token updated",
    )


@router.post("/runtimes/{runtime_id}/activation-code")
def issue_runtime_activation_code(
    runtime_id: int,
    payload: RuntimeActivationCodeIssueRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_runtime_or_404(db, runtime_id)
    if item.status not in {"activation_requested", "activation_issued"}:
        raise HTTPException(status_code=400, detail=f"runtime cannot issue activation code in status {item.status}")

    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)
        item.ai_endpoint_id = payload.ai_endpoint_id
    if payload.display_name is not None and payload.display_name.strip():
        item.display_name = payload.display_name.strip()

    expires_in_minutes = max(1, min(int(payload.expires_in_minutes or 10), 60 * 24))
    activation = create_activation_code()
    item.activation_code_hash = hash_password(activation.activation_code)
    item.activation_code_hint = activation.activation_code_hint
    item.activation_issued_at = utc_now()
    item.activation_expires_at = item.activation_issued_at + timedelta(minutes=expires_in_minutes)
    item.approved_by = current_user.id
    item.approved_at = item.activation_issued_at
    item.rejected_at = None
    item.rejection_reason = ""
    item.status = "activation_issued"
    append_audit_log(
        db,
        current_user,
        "runtime-registry",
        "issue-activation-code",
        f"issued activation code for runtime {item.registration_id}",
    )
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status_summary": runtime_status_summary(item),
            "activation_code": activation.activation_code,
            "activation_expires_at": item.activation_expires_at.isoformat() if item.activation_expires_at else "",
        },
        message="runtime activation code issued",
    )


@public_router.post("/activate")
def activate_runtime(
    payload: RuntimeActivationCodeExchangeRequest,
    db: Session = Depends(get_db),
):
    registration_id = payload.registration_id.strip()
    item = db.query(ManagedRuntime).filter(ManagedRuntime.registration_id == registration_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="runtime activation request not found")
    if item.status != "activation_issued":
        raise HTTPException(status_code=400, detail=f"runtime cannot be activated in status {item.status}")
    if item.activation_expires_at is not None and item.activation_expires_at <= utc_now():
        _clear_activation_state(item)
        item.status = "activation_requested"
        db.commit()
        raise HTTPException(status_code=400, detail="activation code has expired")
    if not verify_runtime_activation_code(item, payload.activation_code):
        raise HTTPException(status_code=401, detail="activation code is invalid")

    credentials = issue_runtime_credentials(item)
    _clear_activation_state(item)
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status": item.status,
            "status_summary": runtime_status_summary(item),
            "runtime_credentials": {
                "runtime_key": credentials.runtime_key,
                "runtime_secret": credentials.runtime_secret,
            },
        },
        message="runtime activated",
    )


@public_router.post("/client-activate")
def activate_runtime_with_bootstrap_code(
    payload: RuntimeBootstrapActivationRequest,
    db: Session = Depends(get_db),
):
    try:
        token = resolve_bootstrap_activation_token(db, payload.activation_code)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    if token.ai_endpoint_id is None:
        raise HTTPException(status_code=400, detail="activation code is not bound to an ai endpoint")

    endpoint = db.get(AiEndpoint, token.ai_endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="ai endpoint not found")

    registration_id, poll_secret = create_registration_identity()
    display_name = (
        (payload.display_name or "").strip()
        or payload.hostname.strip()
        or f"{(payload.runtime_type or token.runtime_type).strip() or token.runtime_type}-{registration_id[-6:]}"
    )
    item = ManagedRuntime(
        registration_id=registration_id,
        display_name=display_name,
        runtime_type=payload.runtime_type.strip() or token.runtime_type,
        poll_secret_hash=hash_password(poll_secret),
        enrollment_token_id=token.id,
        ai_endpoint_id=token.ai_endpoint_id,
        status="approved",
        hostname=payload.hostname.strip(),
        fingerprint=payload.fingerprint.strip(),
        client_version=payload.client_version.strip(),
        approved_by=token.issued_by,
        approved_at=utc_now(),
    )
    item.set_ip_addresses(_dedupe_strings(payload.ip_addresses))
    item.set_requested_scopes(_dedupe_strings(payload.requested_scopes))
    item.set_capabilities(_dedupe_strings(payload.capabilities))
    item.set_meta(dict(payload.metadata or {}))

    token.used_count += 1
    credentials = issue_runtime_credentials(item)
    db.add(item)
    db.commit()
    db.refresh(item)

    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status": item.status,
            "status_summary": runtime_status_summary(item),
            "runtime_credentials": {
                "runtime_key": credentials.runtime_key,
                "runtime_secret": credentials.runtime_secret,
            },
        },
        message="runtime activated from bootstrap code",
    )


@router.post("/runtimes/{runtime_id}/approve")
def approve_runtime(
    runtime_id: int,
    payload: RuntimeApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_runtime_or_404(db, runtime_id)
    if item.status not in {"pending", "approved"}:
        raise HTTPException(status_code=400, detail=f"runtime cannot be approved in status {item.status}")
    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)
        item.ai_endpoint_id = payload.ai_endpoint_id
    if payload.display_name is not None and payload.display_name.strip():
        item.display_name = payload.display_name.strip()
    item.status = "approved"
    item.approved_by = current_user.id
    item.approved_at = utc_now()
    item.rejected_at = None
    item.rejection_reason = ""
    append_audit_log(db, current_user, "runtime-registry", "approve-runtime", f"approved runtime {item.registration_id}")
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status_summary": runtime_status_summary(item),
        },
        message="runtime approved",
    )


@router.post("/runtimes/{runtime_id}/bind")
def bind_runtime(
    runtime_id: int,
    payload: RuntimeBindingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_runtime_or_404(db, runtime_id)
    if item.status == "revoked":
        raise HTTPException(status_code=400, detail="revoked runtime cannot be rebound")
    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)
    item.ai_endpoint_id = payload.ai_endpoint_id
    if payload.display_name is not None and payload.display_name.strip():
        item.display_name = payload.display_name.strip()
    append_audit_log(
        db,
        current_user,
        "runtime-registry",
        "bind-runtime",
        f"bound runtime {item.registration_id} to endpoint {payload.ai_endpoint_id or 'unbound'}",
    )
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status_summary": runtime_status_summary(item),
        },
        message="runtime binding updated",
    )


@router.post("/runtimes/{runtime_id}/reject")
def reject_runtime(
    runtime_id: int,
    payload: RuntimeRejectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_runtime_or_404(db, runtime_id)
    if item.status not in {"pending", "approved", "activation_requested", "activation_issued"}:
        raise HTTPException(status_code=400, detail=f"runtime cannot be rejected in status {item.status}")
    item.status = "rejected"
    _clear_activation_state(item)
    item.rejected_at = utc_now()
    item.rejection_reason = payload.reason.strip()
    append_audit_log(db, current_user, "runtime-registry", "reject-runtime", f"rejected runtime {item.registration_id}")
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status_summary": runtime_status_summary(item),
        },
        message="runtime rejected",
    )


@router.post("/runtimes/{runtime_id}/revoke")
def revoke_runtime(
    runtime_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_runtime_or_404(db, runtime_id)
    if item.status == "revoked":
        return success(
            {
                "runtime": serialize_managed_runtime(db, item),
                "status_summary": runtime_status_summary(item),
            },
            message="runtime already revoked",
        )
    item.status = "revoked"
    item.revoked_at = utc_now()
    item.runtime_secret_hash = None
    item.runtime_secret_hint = ""
    _clear_activation_state(item)
    append_audit_log(db, current_user, "runtime-registry", "revoke-runtime", f"revoked runtime {item.registration_id}")
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "status_summary": runtime_status_summary(item),
        },
        message="runtime revoked",
    )


@router.post("/runtimes/{runtime_id}/rotate")
def rotate_runtime_secret(
    runtime_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_runtime_or_404(db, runtime_id)
    if item.status != "active":
        raise HTTPException(status_code=400, detail="only active runtime can rotate credentials")
    credentials = issue_runtime_credentials(item)
    append_audit_log(db, current_user, "runtime-registry", "rotate-runtime-secret", f"rotated runtime credentials {item.registration_id}")
    db.commit()
    db.refresh(item)
    return success(
        {
            "runtime": serialize_managed_runtime(db, item),
            "runtime_key": credentials.runtime_key,
            "runtime_secret": credentials.runtime_secret,
        },
        message="runtime credentials rotated",
    )
