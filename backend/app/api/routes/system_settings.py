from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.logging import set_runtime_log_level
from ...core.response import success
from ...db.session import get_db
from ...models import AuditLog, SystemSetting, User
from ...schemas.system import SystemSettingUpdate
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.system_actions import (
    SYSTEM_ACTION_DEFINITIONS,
    list_system_actions as list_available_system_actions,
    run_system_action as execute_system_action,
)
from ...services.system_settings_registry import (
    default_system_settings,
    field_meta_for_setting,
    normalize_setting_value,
    sort_visible_settings,
    visible_setting_keys,
)
from ...services.time_utils import format_beijing
from ...services.repository import contains_keyword, paginate

router = APIRouter()


def _field_meta_for_setting(db: Session, item: SystemSetting) -> dict:
    return field_meta_for_setting(item.setting_key)


def _serialize_setting(db: Session, item: SystemSetting) -> dict:
    return {
        "setting_key": item.setting_key,
        "setting_value": item.setting_value,
        "description": item.description,
        "field_meta": _field_meta_for_setting(db, item),
    }


def _serialize_audit_log(item: AuditLog) -> dict:
    return {
        "id": item.id,
        "user_id": item.user_id,
        "module": item.module,
        "action": item.action,
        "detail": item.detail,
        "created_at": format_beijing(item.created_at) or "",
    }


def _ensure_visible_settings(db: Session) -> None:
    visible_keys = set(visible_setting_keys())
    existing_items = {item.setting_key: item for item in db.query(SystemSetting).all()}
    changed = False
    for item in default_system_settings():
        if item["setting_key"] not in visible_keys:
            continue
        setting = existing_items.get(item["setting_key"])
        if setting is None:
            db.add(SystemSetting(**item))
            changed = True
            continue
        if not setting.description:
            setting.description = item["description"]
            changed = True
    if changed:
        db.commit()


@router.get("")
def list_system_settings(
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    _ensure_visible_settings(db)
    setting_items = sort_visible_settings(
        db.query(SystemSetting)
        .filter(SystemSetting.setting_key.in_(visible_setting_keys()))
        .all()
    )
    items = [_serialize_setting(db, item) for item in setting_items]
    if keyword:
        items = [item for item in items if contains_keyword(item, keyword, ["setting_key", "setting_value", "description"])]
    return success({"items": items, "total": len(items)})


@router.get("/actions")
def list_system_actions(_: User = Depends(require_roles("admin"))):
    items = list_available_system_actions()
    return success({"items": items, "total": len(items)})


@router.get("/audit-logs")
def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    module: Optional[str] = None,
    action: Optional[str] = None,
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    data = [_serialize_audit_log(item) for item in db.query(AuditLog).order_by(AuditLog.created_at.desc()).all()]

    if module:
        data = [item for item in data if item["module"] == module]
    if action:
        data = [item for item in data if item["action"] == action]
    if keyword:
        data = [item for item in data if contains_keyword(item, keyword, ["module", "action", "detail"])]

    return success(paginate(data, page=page, page_size=page_size))


@router.post("/actions/{action_key}")
def run_system_action(
    action_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    if action_key not in SYSTEM_ACTION_DEFINITIONS:
        raise HTTPException(status_code=404, detail="系统动作不存在")

    try:
        result = execute_system_action(action_key, db, current_user)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return success(result, message="action completed")


@router.put("/{setting_key}")
def update_system_setting(
    setting_key: str,
    payload: SystemSettingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = db.get(SystemSetting, setting_key)
    if item is None:
        raise HTTPException(status_code=404, detail="系统设置不存在")

    try:
        normalized_value = normalize_setting_value(setting_key, payload.setting_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    item.setting_value = normalized_value

    if setting_key == "log_level":
        set_runtime_log_level(item.setting_value)

    audit_log = append_audit_log(db, current_user, "system-settings", "update", f"更新系统设置 {setting_key}")
    db.commit()
    db.refresh(item)
    db.refresh(audit_log)

    return success(
        {
            "setting": _serialize_setting(db, item),
            "audit_log": _serialize_audit_log(audit_log),
        },
        message="updated",
    )
