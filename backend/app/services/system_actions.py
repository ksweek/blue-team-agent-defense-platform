from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from ..models import AuditLog, SystemSetting, User
from .audit import append_audit_log
from .email_notifications import send_test_email
from .system_snapshots import create_platform_backup_archive, relative_backend_path, write_defense_export_file
from .time_utils import beijing_now, format_beijing

SYSTEM_ACTION_DEFINITIONS = {
    "export-defense-config": {
        "label": "导出防御配置",
        "detail": "导出当前防线策略、全局策略和系统设置快照，敏感口令字段默认脱敏。",
        "button_text": "导出",
        "tone": "info",
        "audit_action": "export-defense-config",
    },
    "platform-backup": {
        "label": "执行平台备份",
        "detail": "生成可恢复的平台备份 ZIP，默认不附带原始数据库文件，敏感凭据字段按脱敏快照导出。",
        "button_text": "备份",
        "tone": "warn",
        "audit_action": "platform-backup",
    },
    "refresh-permission-cache": {
        "label": "刷新权限缓存",
        "detail": "刷新权限映射版本并记录最近刷新时间。",
        "button_text": "刷新",
        "tone": "safe",
        "audit_action": "refresh-permission-cache",
    },
    "send-test-email": {
        "label": "发送测试邮件",
        "detail": "按当前邮件配置发送一封测试邮件。",
        "button_text": "发送",
        "tone": "info",
        "audit_action": "send-test-email",
    },
}


def list_system_actions() -> list[dict]:
    return [_serialize_system_action(key, meta) for key, meta in SYSTEM_ACTION_DEFINITIONS.items()]


def run_system_action(action_key: str, db: Session, current_user: User) -> dict:
    action_meta = SYSTEM_ACTION_DEFINITIONS.get(action_key)
    if action_meta is None:
        raise KeyError(action_key)

    if action_key == "export-defense-config":
        detail, output, audit_detail = _export_defense_config(db)
    elif action_key == "platform-backup":
        detail, output, audit_detail = _create_platform_backup(db)
    elif action_key == "refresh-permission-cache":
        detail, output, audit_detail = _refresh_permission_cache(db)
    else:
        detail, output, audit_detail = _send_test_email_action(db)

    audit_log = append_audit_log(
        db,
        current_user,
        "system-settings",
        action_meta["audit_action"],
        audit_detail,
    )
    db.commit()
    db.refresh(audit_log)

    return {
        "action_key": action_key,
        "action_label": action_meta["label"],
        "tone": action_meta["tone"],
        "status": "completed",
        "detail": detail,
        "output": output,
        "created_at": format_beijing(audit_log.created_at) or "",
        "audit_log": _serialize_audit_log(audit_log),
    }


def _serialize_system_action(action_key: str, meta: dict) -> dict:
    return {
        "action_key": action_key,
        "action_label": meta["label"],
        "detail": meta["detail"],
        "button_text": meta["button_text"],
        "tone": meta["tone"],
        "method": "POST",
        "status": "available",
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


def _export_defense_config(db: Session) -> tuple[str, str, str]:
    file_path = write_defense_export_file(db)
    output = _relative_output(file_path)
    detail = f"已导出当前防御配置快照到 {output}，敏感口令字段已按脱敏策略处理。"
    audit_detail = f"导出防御配置快照 {output}"
    return detail, output, audit_detail


def _create_platform_backup(db: Session) -> tuple[str, str, str]:
    file_path = create_platform_backup_archive(db)
    output = _relative_output(file_path)
    detail = f"已生成平台备份文件 {output}，备份快照默认不包含原始数据库文件且会脱敏凭据字段。"
    audit_detail = f"执行平台备份 {output}"
    return detail, output, audit_detail


def _refresh_permission_cache(db: Session) -> tuple[str, str, str]:
    refreshed_at = beijing_now()
    setting = db.query(SystemSetting).get("permission_cache_refreshed_at")
    value = refreshed_at.isoformat()
    if setting is None:
        setting = SystemSetting(
            setting_key="permission_cache_refreshed_at",
            setting_value=value,
            description="权限缓存刷新时间",
        )
        db.add(setting)
    else:
        setting.setting_value = value
        setting.description = "权限缓存刷新时间"
    output = refreshed_at.strftime("%Y-%m-%d %H:%M:%S")
    detail = "已刷新权限缓存并记录最近刷新时间。"
    audit_detail = f"刷新权限缓存，北京时间 {output}"
    return detail, output, audit_detail


def _send_test_email_action(db: Session) -> tuple[str, str, str]:
    result = send_test_email(db)
    detail = f"测试邮件已发送到 {result['recipients']}。"
    output = f"{result['subject']} / {result['sent_at']}"
    audit_detail = f"发送测试邮件到 {result['recipients']}"
    return detail, output, audit_detail


def _relative_output(path: Path) -> str:
    return relative_backend_path(path)
