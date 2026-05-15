from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy.orm import Session

from ..core.config import BACKEND_DIR
from ..models import (
    AiEndpoint,
    Asset,
    AssetWhitelist,
    AttackTask,
    AuditLog,
    DefenseConfig,
    DefensePolicy,
    Report,
    SecurityEvent,
    Skill,
    SystemSetting,
    TaskRuntimeLog,
    User,
)
from .ai_endpoints import build_ai_endpoint_config_view, build_endpoint_config_payload, sync_default_ai_endpoint
from .security import hash_password
from .system_settings_registry import field_meta_for_setting, visible_setting_keys
from .time_utils import beijing_now, format_beijing

SYSTEM_ACTION_ROOT = BACKEND_DIR / "data" / "system_actions"
BACKUP_DIR = SYSTEM_ACTION_ROOT / "backups"
EXPORT_DIR = SYSTEM_ACTION_ROOT / "exports"
ROLLBACK_DIR = SYSTEM_ACTION_ROOT / "rollbacks"
MANAGED_ARTIFACT_DIRS = [BACKUP_DIR, EXPORT_DIR, ROLLBACK_DIR]
SCHEMA_VERSION = 1
SECRET_REDACTED_VALUE = "__REDACTED__"
SECRET_MODE_INCLUDED = "included"
SECRET_MODE_REDACTED = "redacted"


def ensure_system_action_dirs() -> None:
    for path in MANAGED_ARTIFACT_DIRS:
        path.mkdir(parents=True, exist_ok=True)


def relative_backend_path(path: Path) -> str:
    return str(path.resolve().relative_to(BACKEND_DIR.resolve())).replace("\\", "/")


def list_managed_artifacts(kind: str) -> list[dict]:
    ensure_system_action_dirs()
    directory = _artifact_dir(kind)
    suffix = ".zip" if kind == "backups" else ".json"
    items: list[dict] = []
    for path in sorted(directory.glob(f"*{suffix}"), key=lambda item: item.stat().st_mtime, reverse=True):
        stat = path.stat()
        items.append(
            {
                "kind": kind,
                "name": path.name,
                "artifact_path": relative_backend_path(path),
                "size_bytes": stat.st_size,
                "updated_at": format_beijing(datetime.fromtimestamp(stat.st_mtime)) or "",
            }
        )
    return items


def resolve_managed_artifact_path(artifact_path: str, *, kinds: list[str]) -> Path:
    ensure_system_action_dirs()
    raw_value = str(artifact_path or "").strip()
    if not raw_value:
        raise ValueError("artifact_path is required")

    candidate = Path(raw_value)
    if not candidate.is_absolute():
        candidate = (BACKEND_DIR / candidate).resolve()
    else:
        candidate = candidate.resolve()

    allowed_dirs = [_artifact_dir(kind).resolve() for kind in kinds]
    if not any(candidate.is_relative_to(directory) for directory in allowed_dirs):
        raise ValueError("artifact_path must point to a managed system_actions artifact")
    if not candidate.exists():
        raise ValueError(f"artifact not found: {candidate}")
    return candidate


def build_defense_export_payload(db: Session, *, include_secrets: bool = False) -> dict:
    created_at = beijing_now()
    defense_items = db.query(DefenseConfig).order_by(DefenseConfig.id.asc()).all()
    policy = db.query(DefensePolicy).order_by(DefensePolicy.id.asc()).first()
    settings_items = (
        db.query(SystemSetting)
        .filter(SystemSetting.setting_key.in_(visible_setting_keys()))
        .order_by(SystemSetting.setting_key.asc())
        .all()
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "defense",
        "exported_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "timezone": "Asia/Shanghai",
        "secret_mode": SECRET_MODE_INCLUDED if include_secrets else SECRET_MODE_REDACTED,
        "defense_configs": [_serialize_defense_config(item) for item in defense_items],
        "defense_policy": _serialize_defense_policy(policy),
        "system_settings": [_serialize_system_setting(item, include_secrets=include_secrets) for item in settings_items],
    }


def write_defense_export_file(db: Session) -> Path:
    ensure_system_action_dirs()
    created_at = beijing_now()
    file_path = EXPORT_DIR / f"defense-config-export-{created_at:%Y%m%d-%H%M%S}.json"
    payload = build_defense_export_payload(db, include_secrets=False)
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return file_path


def create_platform_backup_archive(db: Session) -> Path:
    ensure_system_action_dirs()
    created_at = beijing_now()
    file_path = BACKUP_DIR / f"platform-backup-{created_at:%Y%m%d-%H%M%S}.zip"
    payload = build_platform_snapshot(db, include_secrets=False)

    with ZipFile(file_path, mode="w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "scope": "platform",
                    "created_at": payload["exported_at"],
                    "timezone": "Asia/Shanghai",
                    "secret_mode": payload["secret_mode"],
                    "database_file_included": False,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
        archive.writestr(
            "snapshot/platform_state.json",
            json.dumps(payload, ensure_ascii=False, indent=2),
        )
    return file_path


def create_rollback_snapshot(db: Session, *, scope: str, reason: str) -> Path:
    ensure_system_action_dirs()
    created_at = beijing_now()
    file_path = ROLLBACK_DIR / f"{scope}-rollback-{created_at:%Y%m%d-%H%M%S}.json"
    if scope == "platform":
        payload = build_platform_snapshot(db, include_secrets=True)
    elif scope == "defense":
        payload = build_defense_export_payload(db, include_secrets=True)
    else:
        raise ValueError(f"unsupported rollback scope: {scope}")
    payload["rollback_reason"] = reason
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return file_path


def build_platform_snapshot(db: Session, *, include_secrets: bool = False) -> dict:
    created_at = beijing_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "platform",
        "exported_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "timezone": "Asia/Shanghai",
        "secret_mode": SECRET_MODE_INCLUDED if include_secrets else SECRET_MODE_REDACTED,
        "users": [_serialize_user(item, include_secrets=include_secrets) for item in db.query(User).order_by(User.id.asc()).all()],
        "defense_configs": [_serialize_defense_config(item) for item in db.query(DefenseConfig).order_by(DefenseConfig.id.asc()).all()],
        "defense_policy": _serialize_defense_policy(db.query(DefensePolicy).order_by(DefensePolicy.id.asc()).first()),
        "system_settings": [
            _serialize_system_setting(item, include_secrets=include_secrets)
            for item in db.query(SystemSetting).order_by(SystemSetting.setting_key.asc()).all()
        ],
        "audit_logs": [_serialize_audit_log(item) for item in db.query(AuditLog).order_by(AuditLog.id.asc()).all()],
        "security_events": [_serialize_security_event(item) for item in db.query(SecurityEvent).order_by(SecurityEvent.id.asc()).all()],
        "assets": [_serialize_asset(item) for item in db.query(Asset).order_by(Asset.id.asc()).all()],
        "asset_whitelists": [_serialize_asset_whitelist(item) for item in db.query(AssetWhitelist).order_by(AssetWhitelist.id.asc()).all()],
        "skills": [_serialize_skill(item) for item in db.query(Skill).order_by(Skill.id.asc()).all()],
        "ai_endpoints": [
            _serialize_ai_endpoint(item, include_secrets=include_secrets)
            for item in db.query(AiEndpoint).order_by(AiEndpoint.id.asc()).all()
        ],
        "attack_tasks": [_serialize_attack_task(item) for item in db.query(AttackTask).order_by(AttackTask.id.asc()).all()],
        "reports": [_serialize_report(item) for item in db.query(Report).order_by(Report.id.asc()).all()],
        "task_runtime_logs": [_serialize_task_runtime_log(item) for item in db.query(TaskRuntimeLog).order_by(TaskRuntimeLog.id.asc()).all()],
    }


def import_defense_snapshot(db: Session, artifact_path: str, *, apply_system_settings: bool = True) -> dict:
    path = resolve_managed_artifact_path(artifact_path, kinds=["exports", "rollbacks"])
    payload = json.loads(path.read_text(encoding="utf-8"))
    secret_mode = _secret_mode(payload)
    rollback_path = create_rollback_snapshot(db, scope="defense", reason=f"before import {relative_backend_path(path)}")
    _apply_defense_payload(db, payload, apply_system_settings=apply_system_settings)
    result = {
        "artifact_path": relative_backend_path(path),
        "rollback_path": relative_backend_path(rollback_path),
        "scope": "defense",
        "secret_mode": secret_mode,
        "counts": {
            "defense_configs": len(payload.get("defense_configs") or []),
            "system_settings": len(payload.get("system_settings") or []) if apply_system_settings else 0,
        },
    }
    if secret_mode == SECRET_MODE_REDACTED and apply_system_settings:
        result["warnings"] = ["该工件中的敏感设置已脱敏，导入时将保留当前系统中的现有密钥值。"]
    return result


def restore_platform_backup(db: Session, artifact_path: str) -> dict:
    path = resolve_managed_artifact_path(artifact_path, kinds=["backups"])
    with ZipFile(path) as archive:
        payload = json.loads(archive.read("snapshot/platform_state.json").decode("utf-8"))
    secret_mode = _secret_mode(payload)
    rollback_path = create_rollback_snapshot(db, scope="platform", reason=f"before restore {relative_backend_path(path)}")
    _apply_platform_payload(db, payload)
    result = {
        "artifact_path": relative_backend_path(path),
        "rollback_path": relative_backend_path(rollback_path),
        "scope": "platform",
        "secret_mode": secret_mode,
        "counts": {
            "users": len(payload.get("users") or []),
            "attack_tasks": len(payload.get("attack_tasks") or []),
            "security_events": len(payload.get("security_events") or []),
            "reports": len(payload.get("reports") or []),
        },
    }
    if secret_mode == SECRET_MODE_REDACTED:
        result["warnings"] = ["该备份中的密码哈希和连接密钥已脱敏，恢复后会优先保留当前实例中的现有密钥值。"]
    return result


def rollback_from_snapshot(db: Session, artifact_path: str | None = None) -> dict:
    ensure_system_action_dirs()
    if artifact_path:
        path = resolve_managed_artifact_path(artifact_path, kinds=["rollbacks"])
    else:
        candidates = sorted(ROLLBACK_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        if not candidates:
            raise ValueError("no rollback artifact is available")
        path = candidates[0]
    payload = json.loads(path.read_text(encoding="utf-8"))
    scope = str(payload.get("scope") or "").strip().lower()
    if scope == "platform":
        _apply_platform_payload(db, payload)
    elif scope == "defense":
        _apply_defense_payload(db, payload, apply_system_settings=True)
    else:
        raise ValueError(f"unsupported rollback scope: {scope}")
    return {
        "artifact_path": relative_backend_path(path),
        "scope": scope,
        "secret_mode": _secret_mode(payload),
    }


def _artifact_dir(kind: str) -> Path:
    if kind == "backups":
        return BACKUP_DIR
    if kind == "exports":
        return EXPORT_DIR
    if kind == "rollbacks":
        return ROLLBACK_DIR
    raise ValueError(f"unsupported artifact kind: {kind}")


def _is_redacted_secret(value: object) -> bool:
    return str(value or "") == SECRET_REDACTED_VALUE


def _secret_mode(payload: dict) -> str:
    return str(payload.get("secret_mode") or SECRET_MODE_INCLUDED).strip().lower() or SECRET_MODE_INCLUDED


def _is_secret_setting(setting_key: str) -> bool:
    return field_meta_for_setting(setting_key).get("control") == "password"


def _restore_setting_value(setting_key: str, raw_value: object, current_values: dict[str, str]) -> str:
    if _is_secret_setting(setting_key) and _is_redacted_secret(raw_value):
        return current_values.get(setting_key, "")
    return str(raw_value or "")


def _bootstrap_password_hash_for_user(username: str) -> str:
    if username == "admin" and settings.bootstrap_admin_password:
        return hash_password(settings.bootstrap_admin_password)
    if username == "analyst" and settings.bootstrap_analyst_password:
        return hash_password(settings.bootstrap_analyst_password)
    return ""


def _restore_user_password_hash(item: dict, current_hashes: dict[str, str]) -> str:
    raw_value = item.get("password_hash")
    username = str(item.get("username") or "")
    if _is_redacted_secret(raw_value):
        return current_hashes.get(username) or _bootstrap_password_hash_for_user(username)
    return str(raw_value or "")


def _restore_endpoint_api_key(item: dict, current_keys: dict[tuple[int, str], str]) -> str:
    raw_value = item.get("api_key")
    endpoint_id = int(item.get("id") or 0)
    endpoint_key = str(item.get("endpoint_key") or "")
    if _is_redacted_secret(raw_value):
        return current_keys.get((endpoint_id, endpoint_key), "")
    return str(raw_value or "")


def _restore_endpoint_config(
    item: dict,
    current_configs: dict[tuple[int, str], dict],
    *,
    preserve_hidden: bool,
) -> dict:
    raw_value = item.get("config_json")
    config_json = dict(raw_value) if isinstance(raw_value, dict) else {}
    if not preserve_hidden:
        return config_json

    endpoint_id = int(item.get("id") or 0)
    endpoint_key = str(item.get("endpoint_key") or "")
    current_config = current_configs.get((endpoint_id, endpoint_key), {})
    return build_endpoint_config_payload(current_config, public_config=config_json)


def _apply_defense_payload(db: Session, payload: dict, *, apply_system_settings: bool) -> None:
    existing_configs = {item.id: item for item in db.query(DefenseConfig).all()}
    seen_config_ids: set[int] = set()
    for item in payload.get("defense_configs") or []:
        config_id = int(item["id"])
        config = existing_configs.get(config_id)
        if config is None:
            config = DefenseConfig(id=config_id)
            db.add(config)
        config.defense_name = str(item.get("defense_name") or "")
        config.defense_type = str(item.get("defense_type") or "")
        config.threat_level = str(item.get("threat_level") or "medium")
        config.mode = str(item.get("mode") or "observe")
        config.enabled = bool(item.get("enabled", True))
        config.description = str(item.get("description") or "")
        config.set_config(dict(item.get("config_json") or {}))
        seen_config_ids.add(config_id)
    for config_id, config in existing_configs.items():
        if config_id not in seen_config_ids:
            db.delete(config)

    defense_policy_payload = payload.get("defense_policy") or {}
    policy = db.get(DefensePolicy, 1)
    if policy is None:
        policy = DefensePolicy(id=1)
        db.add(policy)
    policy.set_guard_rules(list(defense_policy_payload.get("guard_rules") or []))
    policy.set_scan_rules(list(defense_policy_payload.get("scan_rules") or []))
    policy.set_advanced_rule(dict(defense_policy_payload.get("advanced_rule") or {}))
    policy.set_ai_review_policy(dict(defense_policy_payload.get("ai_review_policy") or {}))
    policy.set_protected_paths([str(item).strip() for item in defense_policy_payload.get("protected_paths") or [] if str(item).strip()])
    policy.set_protected_skills([str(item).strip() for item in defense_policy_payload.get("protected_skills") or [] if str(item).strip()])
    policy.set_protected_plugins([str(item).strip() for item in defense_policy_payload.get("protected_plugins") or [] if str(item).strip()])
    updated_at = _parse_optional_datetime(defense_policy_payload.get("updated_at"))
    if updated_at is not None:
        policy.updated_at = updated_at

    if apply_system_settings:
        current_setting_values = {item.setting_key: item.setting_value for item in db.query(SystemSetting).all()}
        existing_settings = {item.setting_key: item for item in db.query(SystemSetting).all()}
        for item in payload.get("system_settings") or []:
            setting_key = str(item.get("setting_key") or "").strip()
            if not setting_key:
                continue
            setting = existing_settings.get(setting_key)
            if setting is None:
                setting = SystemSetting(setting_key=setting_key, setting_value="", description="")
                db.add(setting)
            setting.setting_value = _restore_setting_value(setting_key, item.get("setting_value"), current_setting_values)
            setting.description = str(item.get("description") or "")
            updated_at = _parse_optional_datetime(item.get("updated_at"))
            if updated_at is not None:
                setting.updated_at = updated_at

    db.flush()


def _apply_platform_payload(db: Session, payload: dict) -> None:
    secret_mode = _secret_mode(payload)
    current_user_hashes = {item.username: item.password_hash for item in db.query(User).all() if item.password_hash}
    current_setting_values = {item.setting_key: item.setting_value for item in db.query(SystemSetting).all()}
    current_endpoint_keys = {
        (item.id, item.endpoint_key): item.api_key for item in db.query(AiEndpoint).all() if item.api_key
    }
    current_endpoint_configs = {
        (item.id, item.endpoint_key): item.config for item in db.query(AiEndpoint).all() if item.config
    }
    _clear_platform_tables(db)
    for item in payload.get("users") or []:
        user = User(
            id=int(item["id"]),
            username=str(item.get("username") or ""),
            real_name=str(item.get("real_name") or ""),
            email=str(item.get("email") or ""),
            status=str(item.get("status") or "active"),
            password_hash=_restore_user_password_hash(item, current_user_hashes),
            created_at=_parse_datetime(item.get("created_at")),
        )
        user.set_roles(list(item.get("roles") or []))
        db.add(user)

    for item in payload.get("defense_configs") or []:
        config = DefenseConfig(
            id=int(item["id"]),
            defense_name=str(item.get("defense_name") or ""),
            defense_type=str(item.get("defense_type") or ""),
            threat_level=str(item.get("threat_level") or "medium"),
            mode=str(item.get("mode") or "observe"),
            enabled=bool(item.get("enabled", True)),
            description=str(item.get("description") or ""),
            updated_at=_parse_datetime(item.get("updated_at")),
        )
        config.set_config(dict(item.get("config_json") or {}))
        db.add(config)

    defense_policy_payload = payload.get("defense_policy") or {}
    policy = DefensePolicy(
        id=1,
        updated_by=defense_policy_payload.get("updated_by"),
        updated_at=_parse_datetime(defense_policy_payload.get("updated_at")),
    )
    policy.set_guard_rules(list(defense_policy_payload.get("guard_rules") or []))
    policy.set_scan_rules(list(defense_policy_payload.get("scan_rules") or []))
    policy.set_advanced_rule(dict(defense_policy_payload.get("advanced_rule") or {}))
    policy.set_ai_review_policy(dict(defense_policy_payload.get("ai_review_policy") or {}))
    policy.set_protected_paths(list(defense_policy_payload.get("protected_paths") or []))
    policy.set_protected_skills(list(defense_policy_payload.get("protected_skills") or []))
    policy.set_protected_plugins(list(defense_policy_payload.get("protected_plugins") or []))
    db.add(policy)

    for item in payload.get("system_settings") or []:
        db.add(
            SystemSetting(
                setting_key=str(item.get("setting_key") or ""),
                setting_value=_restore_setting_value(
                    str(item.get("setting_key") or ""),
                    item.get("setting_value"),
                    current_setting_values,
                ),
                description=str(item.get("description") or ""),
                updated_at=_parse_datetime(item.get("updated_at")),
            )
        )

    for item in payload.get("audit_logs") or []:
        db.add(
            AuditLog(
                id=int(item["id"]),
                user_id=int(item.get("user_id") or 0),
                module=str(item.get("module") or ""),
                action=str(item.get("action") or ""),
                detail=str(item.get("detail") or ""),
                created_at=_parse_datetime(item.get("created_at")),
            )
        )

    for item in payload.get("security_events") or []:
        event = SecurityEvent(
            id=int(item["id"]),
            task_id=item.get("task_id"),
            event_type=str(item.get("event_type") or ""),
            event_level=str(item.get("event_level") or "medium"),
            source=str(item.get("source") or ""),
            target=str(item.get("target") or ""),
            status=str(item.get("status") or "suspicious"),
            detail=str(item.get("detail") or ""),
            raw_input=str(item.get("raw_input") or ""),
            result=str(item.get("result") or ""),
            created_at=_parse_datetime(item.get("created_at")),
        )
        event.set_hit_rules(list(item.get("hit_rules") or []))
        event.set_operation_logs(list(item.get("operation_logs") or []))
        db.add(event)

    for item in payload.get("assets") or []:
        db.add(
            Asset(
                id=int(item["id"]),
                asset_name=str(item.get("asset_name") or ""),
                asset_type=str(item.get("asset_type") or ""),
                asset_path=str(item.get("asset_path") or ""),
                risk_level=str(item.get("risk_level") or "medium"),
                status=str(item.get("status") or ""),
                updated_at=_parse_datetime(item.get("updated_at")),
            )
        )

    for item in payload.get("asset_whitelists") or []:
        db.add(
            AssetWhitelist(
                id=int(item["id"]),
                asset_id=int(item.get("asset_id") or 0),
                whitelist_type=str(item.get("whitelist_type") or ""),
                rule_value=str(item.get("rule_value") or ""),
                description=str(item.get("description") or ""),
                created_at=_parse_datetime(item.get("created_at")),
            )
        )

    for item in payload.get("skills") or []:
        db.add(
            Skill(
                id=int(item["id"]),
                skill_name=str(item.get("skill_name") or ""),
                skill_type=str(item.get("skill_type") or ""),
                provider=str(item.get("provider") or ""),
                source_path=str(item.get("source_path") or ""),
                trust_status=str(item.get("trust_status") or ""),
                created_at=_parse_datetime(item.get("created_at")),
                updated_at=_parse_datetime(item.get("updated_at")),
            )
        )

    for item in payload.get("ai_endpoints") or []:
        endpoint = AiEndpoint(
            id=int(item["id"]),
            endpoint_key=str(item.get("endpoint_key") or ""),
            display_name=str(item.get("display_name") or ""),
            endpoint_group=str(item.get("endpoint_group") or "default"),
            provider_type=str(item.get("provider_type") or ""),
            base_url=str(item.get("base_url") or ""),
            api_key=_restore_endpoint_api_key(item, current_endpoint_keys),
            model_name=str(item.get("model_name") or ""),
            enabled=bool(item.get("enabled", True)),
            is_default=bool(item.get("is_default", False)),
            protection_enabled=bool(item.get("protection_enabled", True)),
            protection_mode=str(item.get("protection_mode") or "enforce"),
            description=str(item.get("description") or ""),
            created_at=_parse_datetime(item.get("created_at")),
            updated_at=_parse_datetime(item.get("updated_at")),
        )
        endpoint.set_config(
            _restore_endpoint_config(
                item,
                current_endpoint_configs,
                preserve_hidden=secret_mode == SECRET_MODE_REDACTED,
            )
        )
        db.add(endpoint)

    for item in payload.get("attack_tasks") or []:
        task = AttackTask(
            id=int(item["id"]),
            task_name=str(item.get("task_name") or ""),
            attack_type=str(item.get("attack_type") or ""),
            target_agent=str(item.get("target_agent") or ""),
            status=str(item.get("status") or "queued"),
            source_type=item.get("source_type"),
            source_ref=item.get("source_ref"),
            execution_mode=item.get("execution_mode"),
            runtime_name=item.get("runtime_name"),
            runtime_task_ref=item.get("runtime_task_ref"),
            raw_response=str(item.get("raw_response") or ""),
            result_summary=str(item.get("result_summary") or ""),
            latest_event_id=item.get("latest_event_id"),
            latest_report_id=item.get("latest_report_id"),
            created_by=item.get("created_by"),
            scheduled_at=_parse_optional_datetime(item.get("scheduled_at")),
            started_at=_parse_optional_datetime(item.get("started_at")),
            finished_at=_parse_optional_datetime(item.get("finished_at")),
            last_heartbeat_at=_parse_optional_datetime(item.get("last_heartbeat_at")),
            created_at=_parse_datetime(item.get("created_at")),
            updated_at=_parse_datetime(item.get("updated_at")),
        )
        task.set_params(dict(item.get("params_json") or {}))
        db.add(task)

    for item in payload.get("reports") or []:
        db.add(
            Report(
                id=int(item["id"]),
                task_id=int(item.get("task_id") or 0),
                report_name=str(item.get("report_name") or ""),
                report_type=str(item.get("report_type") or ""),
                file_path=str(item.get("file_path") or ""),
                summary_text=str(item.get("summary_text") or ""),
                created_by=int(item.get("created_by") or 1),
                created_at=_parse_datetime(item.get("created_at")),
            )
        )

    for item in payload.get("task_runtime_logs") or []:
        log_item = TaskRuntimeLog(
            id=int(item["id"]),
            task_id=int(item.get("task_id") or 0),
            log_offset=int(item.get("log_offset") or 0),
            level=str(item.get("level") or "info"),
            stage=str(item.get("stage") or ""),
            message=str(item.get("message") or ""),
            created_at=_parse_datetime(item.get("created_at")),
        )
        log_item.set_meta(dict(item.get("metadata") or {}))
        db.add(log_item)

    db.flush()
    sync_default_ai_endpoint(db)


def _clear_platform_tables(db: Session) -> None:
    for model in [
        TaskRuntimeLog,
        Report,
        SecurityEvent,
        AttackTask,
        AssetWhitelist,
        Asset,
        Skill,
        AiEndpoint,
        AuditLog,
        SystemSetting,
        DefensePolicy,
        DefenseConfig,
        User,
    ]:
        db.query(model).delete(synchronize_session=False)
    db.flush()
    # Bulk deletes with synchronize_session=False leave stale identities in the session.
    # Clear them before re-inserting objects with the same primary keys during restore.
    db.expunge_all()


def _serialize_user(item: User, *, include_secrets: bool) -> dict:
    return {
        "id": item.id,
        "username": item.username,
        "real_name": item.real_name,
        "email": item.email,
        "status": item.status,
        "password_hash": item.password_hash if include_secrets or not item.password_hash else SECRET_REDACTED_VALUE,
        "roles": item.roles,
        "created_at": item.created_at.isoformat(),
    }


def _serialize_defense_config(item: DefenseConfig) -> dict:
    return {
        "id": item.id,
        "defense_name": item.defense_name,
        "defense_type": item.defense_type,
        "threat_level": item.threat_level,
        "mode": item.mode,
        "enabled": item.enabled,
        "description": item.description,
        "config_json": item.config,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_defense_policy(item: DefensePolicy | None) -> dict:
    if item is None:
        return {
            "guard_rules": [],
            "scan_rules": [],
            "advanced_rule": {},
            "ai_review_policy": {},
            "protected_paths": [],
            "protected_skills": [],
            "protected_plugins": [],
            "updated_by": None,
            "updated_at": None,
        }
    return {
        "guard_rules": item.guard_rules,
        "scan_rules": item.scan_rules,
        "advanced_rule": item.advanced_rule,
        "ai_review_policy": item.ai_review_policy,
        "protected_paths": item.protected_paths,
        "protected_skills": item.protected_skills,
        "protected_plugins": item.protected_plugins,
        "updated_by": item.updated_by,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_system_setting(item: SystemSetting, *, include_secrets: bool) -> dict:
    setting_value = item.setting_value
    if _is_secret_setting(item.setting_key) and setting_value and not include_secrets:
        setting_value = SECRET_REDACTED_VALUE
    return {
        "setting_key": item.setting_key,
        "setting_value": setting_value,
        "description": item.description,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_audit_log(item: AuditLog) -> dict:
    return {
        "id": item.id,
        "user_id": item.user_id,
        "module": item.module,
        "action": item.action,
        "detail": item.detail,
        "created_at": item.created_at.isoformat(),
    }


def _serialize_security_event(item: SecurityEvent) -> dict:
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
        "raw_input": item.raw_input,
        "result": item.result,
        "operation_logs": item.operation_logs,
        "created_at": item.created_at.isoformat(),
    }


def _serialize_asset(item: Asset) -> dict:
    return {
        "id": item.id,
        "asset_name": item.asset_name,
        "asset_type": item.asset_type,
        "asset_path": item.asset_path,
        "risk_level": item.risk_level,
        "status": item.status,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_asset_whitelist(item: AssetWhitelist) -> dict:
    return {
        "id": item.id,
        "asset_id": item.asset_id,
        "whitelist_type": item.whitelist_type,
        "rule_value": item.rule_value,
        "description": item.description,
        "created_at": item.created_at.isoformat(),
    }


def _serialize_skill(item: Skill) -> dict:
    return {
        "id": item.id,
        "skill_name": item.skill_name,
        "skill_type": item.skill_type,
        "provider": item.provider,
        "source_path": item.source_path,
        "trust_status": item.trust_status,
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_ai_endpoint(item: AiEndpoint, *, include_secrets: bool) -> dict:
    config_json = item.config
    if not include_secrets:
        config_json = build_ai_endpoint_config_view(item.config)["config_public_json"]

    return {
        "id": item.id,
        "endpoint_key": item.endpoint_key,
        "display_name": item.display_name,
        "endpoint_group": item.endpoint_group,
        "provider_type": item.provider_type,
        "base_url": item.base_url,
        "api_key": item.api_key if include_secrets or not item.api_key else SECRET_REDACTED_VALUE,
        "model_name": item.model_name,
        "enabled": item.enabled,
        "is_default": item.is_default,
        "protection_enabled": item.protection_enabled,
        "protection_mode": item.protection_mode,
        "description": item.description,
        "config_json": config_json,
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_attack_task(item: AttackTask) -> dict:
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
        "raw_response": item.raw_response,
        "result_summary": item.result_summary,
        "latest_event_id": item.latest_event_id,
        "latest_report_id": item.latest_report_id,
        "created_by": item.created_by,
        "scheduled_at": item.scheduled_at.isoformat() if item.scheduled_at else None,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "finished_at": item.finished_at.isoformat() if item.finished_at else None,
        "last_heartbeat_at": item.last_heartbeat_at.isoformat() if item.last_heartbeat_at else None,
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_report(item: Report) -> dict:
    return {
        "id": item.id,
        "task_id": item.task_id,
        "report_name": item.report_name,
        "report_type": item.report_type,
        "file_path": item.file_path,
        "summary_text": item.summary_text,
        "created_by": item.created_by,
        "created_at": item.created_at.isoformat(),
    }


def _serialize_task_runtime_log(item: TaskRuntimeLog) -> dict:
    return {
        "id": item.id,
        "task_id": item.task_id,
        "log_offset": item.log_offset,
        "level": item.level,
        "stage": item.stage,
        "message": item.message,
        "metadata": item.meta,
        "created_at": item.created_at.isoformat(),
    }


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    return datetime.fromisoformat(str(value))


def _parse_optional_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value))
