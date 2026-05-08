from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import User
from ...schemas.user import UserCreate, UserPasswordReset, UserRolesUpdate, UserStatusUpdate, UserUpdate
from ...services.audit import append_audit_log
from ...services.authorization import get_current_user
from ...services.repository import contains_keyword, paginate
from ...services.security import hash_password
from ...services.time_utils import format_beijing

router = APIRouter()

_ALLOWED_USER_STATUSES = {"active", "disabled"}
_ALLOWED_USER_ROLES = {"admin", "analyst"}
_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _serialize_user(item: User) -> dict:
    return {
        "id": item.id,
        "username": item.username,
        "real_name": item.real_name,
        "email": item.email,
        "status": item.status,
        "roles": item.roles,
        "created_at": format_beijing(item.created_at) or "",
    }


def _get_user_or_404(db: Session, user_id: int) -> User:
    item = db.query(User).get(user_id)
    if item is None:
        raise HTTPException(status_code=404, detail="user not found")
    return item


def _normalize_username(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="username is required")
    if len(normalized) < 3 or len(normalized) > 64:
        raise HTTPException(status_code=400, detail="username length must be between 3 and 64 characters")
    return normalized


def _normalize_real_name(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="real_name is required")
    return normalized[:128]


def _normalize_email(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="email is required")
    if not _EMAIL_REGEX.match(normalized):
        raise HTTPException(status_code=400, detail="email format is invalid")
    return normalized[:255]


def _normalize_status(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in _ALLOWED_USER_STATUSES:
        raise HTTPException(status_code=400, detail="status must be active or disabled")
    return normalized


def _normalize_roles(roles: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in roles:
        role = str(value or "").strip().lower()
        if not role:
            continue
        if role not in _ALLOWED_USER_ROLES:
            raise HTTPException(status_code=400, detail=f"unsupported role: {role}")
        if role not in normalized:
            normalized.append(role)
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one role is required")
    return normalized


def _validate_password(value: str) -> str:
    normalized = str(value or "")
    if len(normalized) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")
    return normalized


def _ensure_unique_username(db: Session, username: str, *, exclude_id: int | None = None) -> None:
    query = db.query(User).filter(User.username == username)
    if exclude_id is not None:
        query = query.filter(User.id != exclude_id)
    if query.first() is not None:
        raise HTTPException(status_code=400, detail=f"username already exists: {username}")


def _active_admin_count(db: Session, *, exclude_user_id: int | None = None) -> int:
    count = 0
    for item in db.query(User).all():
        if exclude_user_id is not None and item.id == exclude_user_id:
            continue
        if item.status == "active" and "admin" in item.roles:
            count += 1
    return count


def _ensure_admin_guardrails(
    db: Session,
    *,
    target_user: User,
    next_status: Optional[str] = None,
    next_roles: Optional[list[str]] = None,
    current_user: Optional[User] = None,
    deleting: bool = False,
) -> None:
    resulting_status = next_status if next_status is not None else target_user.status
    resulting_roles = list(next_roles if next_roles is not None else target_user.roles)
    resulting_is_active_admin = resulting_status == "active" and "admin" in resulting_roles

    if current_user is not None and target_user.id == current_user.id:
        if deleting:
            raise HTTPException(status_code=400, detail="current user cannot delete itself")
        if resulting_status != "active":
            raise HTTPException(status_code=400, detail="current user cannot disable itself")
        if "admin" not in resulting_roles:
            raise HTTPException(status_code=400, detail="current user cannot remove its own admin role")

    if deleting or not resulting_is_active_admin:
        if "admin" in target_user.roles and target_user.status == "active" and _active_admin_count(db, exclude_user_id=target_user.id) == 0:
            raise HTTPException(status_code=400, detail="at least one active admin user must remain")


@router.get("")
def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    keyword: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    items = [_serialize_user(item) for item in db.query(User).order_by(User.id).all()]
    if keyword:
        items = [item for item in items if contains_keyword(item, keyword, ["username", "real_name", "email"])]
    if status:
        normalized_status = _normalize_status(status)
        items = [item for item in items if item["status"] == normalized_status]
    return success(paginate(items, page=page, page_size=page_size))


@router.get("/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    return success(_serialize_user(_get_user_or_404(db, user_id)))


@router.post("")
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    username = _normalize_username(payload.username)
    _ensure_unique_username(db, username)

    item = User(
        username=username,
        real_name=_normalize_real_name(payload.real_name),
        email=_normalize_email(payload.email),
        status=_normalize_status(payload.status),
        password_hash=hash_password(_validate_password(payload.password)),
    )
    item.set_roles(_normalize_roles(payload.roles or ["analyst"]))
    db.add(item)
    db.flush()
    append_audit_log(db, current_user, "users", "create", f"created user {item.username}")
    db.commit()
    db.refresh(item)
    return success(_serialize_user(item), message="user created")


@router.put("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = _get_user_or_404(db, user_id)
    next_status = _normalize_status(payload.status) if payload.status is not None else None
    next_roles = _normalize_roles(payload.roles) if payload.roles is not None else None
    _ensure_admin_guardrails(
        db,
        target_user=item,
        next_status=next_status,
        next_roles=next_roles,
        current_user=current_user,
    )

    if payload.real_name is not None:
        item.real_name = _normalize_real_name(payload.real_name)
    if payload.email is not None:
        item.email = _normalize_email(payload.email)
    if next_status is not None:
        item.status = next_status
    if next_roles is not None:
        item.set_roles(next_roles)

    append_audit_log(db, current_user, "users", "update", f"updated user {item.username}")
    db.commit()
    db.refresh(item)
    return success(_serialize_user(item), message="user updated")


@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    payload: UserPasswordReset,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = _get_user_or_404(db, user_id)
    item.password_hash = hash_password(_validate_password(payload.new_password))
    append_audit_log(db, current_user, "users", "reset-password", f"reset password for {item.username}")
    db.commit()
    db.refresh(item)
    return success(_serialize_user(item), message="password reset")


@router.post("/{user_id}/status")
def update_user_status(
    user_id: int,
    payload: UserStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = _get_user_or_404(db, user_id)
    next_status = _normalize_status(payload.status)
    _ensure_admin_guardrails(
        db,
        target_user=item,
        next_status=next_status,
        current_user=current_user,
    )
    item.status = next_status
    append_audit_log(db, current_user, "users", "set-status", f"set user {item.username} status to {next_status}")
    db.commit()
    db.refresh(item)
    return success(_serialize_user(item), message="user status updated")


@router.post("/{user_id}/roles")
def update_user_roles(
    user_id: int,
    payload: UserRolesUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = _get_user_or_404(db, user_id)
    next_roles = _normalize_roles(payload.roles)
    _ensure_admin_guardrails(
        db,
        target_user=item,
        next_roles=next_roles,
        current_user=current_user,
    )
    item.set_roles(next_roles)
    append_audit_log(db, current_user, "users", "set-roles", f"updated roles for {item.username}")
    db.commit()
    db.refresh(item)
    return success(_serialize_user(item), message="user roles updated")


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = _get_user_or_404(db, user_id)
    _ensure_admin_guardrails(db, target_user=item, current_user=current_user, deleting=True)
    username = item.username
    db.delete(item)
    append_audit_log(db, current_user, "users", "delete", f"deleted user {username}")
    db.commit()
    return success({"id": user_id}, message="user deleted")
