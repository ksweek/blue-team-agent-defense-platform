from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ...core.logging import set_runtime_log_level
from ...core.response import success
from ...db.session import get_db
from ...models import AuditLog, SystemSetting, User
from ...schemas.system import (
    BackupRestoreRequest,
    DefenseConfigImportRequest,
    RollbackRequest,
    SystemSettingUpdate,
)
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.system_actions import (
    SYSTEM_ACTION_DEFINITIONS,
    list_system_actions as list_available_system_actions,
    run_system_action as execute_system_action,
)
from ...services.system_snapshots import (
    list_managed_artifacts,
    resolve_managed_artifact_path,
    restore_platform_backup,
    rollback_from_snapshot,
    import_defense_snapshot,
)
from ...services.system_settings_registry import (
    field_meta_for_setting,
    normalize_setting_value,
    sort_visible_settings,
    visible_setting_keys,
)
from ...services.time_utils import format_beijing
from ...services.repository import contains_keyword, paginate

router = APIRouter()

ARTIFACT_MEDIA_TYPES = {
    ".json": "application/json",
    ".zip": "application/zip",
}


def _serialize_setting(item: SystemSetting) -> dict:
    return {
        "setting_key": item.setting_key,
        "setting_value": item.setting_value,
        "description": item.description,
        "field_meta": field_meta_for_setting(item.setting_key),
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


def _serialize_managed_artifact(item: dict) -> dict:
    artifact_path = str(item.get("artifact_path") or "")
    return {
        **item,
        "download_url": f"/api/system-settings/artifacts/download?artifact_path={quote(artifact_path, safe='')}",
    }


@router.get("")
def list_system_settings(
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    setting_items = sort_visible_settings(
        db.query(SystemSetting)
        .filter(SystemSetting.setting_key.in_(visible_setting_keys()))
        .all()
    )
    items = [_serialize_setting(item) for item in setting_items]
    if keyword:
        items = [item for item in items if contains_keyword(item, keyword, ["setting_key", "setting_value", "description"])]
    return success({"items": items, "total": len(items)})


@router.get("/actions")
def list_system_actions(_: User = Depends(require_roles("admin"))):
    items = list_available_system_actions()
    return success({"items": items, "total": len(items)})


@router.get("/artifacts/backups")
def list_backup_artifacts(_: User = Depends(require_roles("admin"))):
    items = [_serialize_managed_artifact(item) for item in list_managed_artifacts("backups")]
    return success({"items": items, "total": len(items)})


@router.get("/artifacts/exports")
def list_export_artifacts(_: User = Depends(require_roles("admin"))):
    items = [_serialize_managed_artifact(item) for item in list_managed_artifacts("exports")]
    return success({"items": items, "total": len(items)})


@router.get("/artifacts/rollbacks")
def list_rollback_artifacts(_: User = Depends(require_roles("admin"))):
    items = [_serialize_managed_artifact(item) for item in list_managed_artifacts("rollbacks")]
    return success({"items": items, "total": len(items)})


@router.get("/artifacts/download")
def download_managed_artifact(
    artifact_path: str,
    _: User = Depends(require_roles("admin")),
):
    try:
        path = resolve_managed_artifact_path(artifact_path, kinds=["backups", "exports", "rollbacks"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    suffix = path.suffix.lower()
    media_type = ARTIFACT_MEDIA_TYPES.get(suffix, "application/octet-stream")
    return FileResponse(
        path=Path(path),
        media_type=media_type,
        filename=path.name,
    )


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


@router.post("/restore-backup")
def restore_backup(
    payload: BackupRestoreRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    try:
        result = restore_platform_backup(db, payload.artifact_path)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    actor = db.query(User).get(current_user.id) or db.query(User).order_by(User.id.asc()).first()
    if actor is not None:
        append_audit_log(
            db,
            actor,
            "system-settings",
            "restore-backup",
            f"restored platform backup {result['artifact_path']}",
        )
    db.commit()
    return success(result, message="backup restored")


@router.post("/import-defense-config")
def import_defense_config(
    payload: DefenseConfigImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    try:
        result = import_defense_snapshot(
            db,
            payload.artifact_path,
            apply_system_settings=payload.apply_system_settings,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    append_audit_log(
        db,
        current_user,
        "system-settings",
        "import-defense-config",
        f"imported defense config from {result['artifact_path']}",
    )
    db.commit()
    return success(result, message="defense config imported")


@router.post("/rollback")
def rollback_system_changes(
    payload: RollbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    try:
        result = rollback_from_snapshot(db, payload.artifact_path)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    actor = db.query(User).get(current_user.id) or db.query(User).order_by(User.id.asc()).first()
    if actor is not None:
        append_audit_log(
            db,
            actor,
            "system-settings",
            "rollback",
            f"rolled back from {result['artifact_path']}",
        )
    db.commit()
    return success(result, message="rollback completed")


@router.put("/{setting_key}")
def update_system_setting(
    setting_key: str,
    payload: SystemSettingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = db.query(SystemSetting).get(setting_key)
    if item is None:
        raise HTTPException(status_code=404, detail="系统设置不存在")

    try:
        item.setting_value = normalize_setting_value(setting_key, payload.setting_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if setting_key == "log_level":
        set_runtime_log_level(item.setting_value)

    audit_log = append_audit_log(db, current_user, "system-settings", "update", f"更新系统设置 {setting_key}")
    db.commit()
    db.refresh(item)
    db.refresh(audit_log)

    return success(
        {
            "setting": _serialize_setting(item),
            "audit_log": _serialize_audit_log(audit_log),
        },
        message="updated",
    )
