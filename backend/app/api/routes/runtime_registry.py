from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AiEndpoint, ManagedRuntime, RuntimeEnrollmentToken, User
from ...schemas.runtime_registry import (
    RuntimeApprovalRequest,
    RuntimeBindingRequest,
    RuntimeEnrollmentTokenCreate,
    RuntimeEnrollmentTokenBindingRequest,
    RuntimeRejectionRequest,
)
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.runtime_registry import (
    build_runtime_onboarding_steps,
    create_enrollment_secret,
    issue_runtime_credentials,
    runtime_registry_payload,
    runtime_status_summary,
    serialize_managed_runtime,
    serialize_runtime_enrollment_token,
)
from ...services.security import hash_password
from ...services.time_utils import utc_now

router = APIRouter()


def _get_runtime_or_404(db: Session, runtime_id: int) -> ManagedRuntime:
    item = db.query(ManagedRuntime).get(runtime_id)
    if item is None:
        raise HTTPException(status_code=404, detail="runtime not found")
    return item


def _get_endpoint_or_404(db: Session, endpoint_id: int) -> AiEndpoint:
    item = db.query(AiEndpoint).get(endpoint_id)
    if item is None:
        raise HTTPException(status_code=404, detail="ai endpoint not found")
    return item


def _get_token_or_404(db: Session, token_id: int) -> RuntimeEnrollmentToken:
    item = db.query(RuntimeEnrollmentToken).get(token_id)
    if item is None:
        raise HTTPException(status_code=404, detail="runtime enrollment token not found")
    return item


@router.get("")
def list_runtime_registry(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success(runtime_registry_payload(db))


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
    if payload.ai_endpoint_id is not None:
        _get_endpoint_or_404(db, payload.ai_endpoint_id)

    bundle = create_enrollment_secret()
    item = RuntimeEnrollmentToken(
        token_key=bundle.token_key,
        token_label=label,
        secret_hash=hash_password(bundle.secret),
        secret_hint=bundle.secret_hint,
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
            "onboarding_steps": build_runtime_onboarding_steps(
                server_base=public_origin,
                enrollment_token=bundle.token_value,
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
    if item.status not in {"pending", "approved"}:
        raise HTTPException(status_code=400, detail=f"runtime cannot be rejected in status {item.status}")
    item.status = "rejected"
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
