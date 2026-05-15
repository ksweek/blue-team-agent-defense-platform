from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateColumn

from ..db.base import Base
from ..db.session import SessionLocal, engine, ping_database
from ..core.config import (
    DEFAULT_BOOTSTRAP_ADMIN_PASSWORD,
    DEFAULT_BOOTSTRAP_ANALYST_PASSWORD,
    DEFAULT_JWT_SECRET,
    DEFAULT_SERVICE_TOKEN,
    settings,
)
from ..models import (
    Asset,
    AssetWhitelist,
    AiEndpoint,
    AttackTask,
    AuditLog,
    DefenseConfig,
    DefensePolicy,
    ManagedRuntime,
    Report,
    RuntimeEnrollmentToken,
    SecurityEvent,
    Skill,
    SystemSetting,
    User,
)
from .event_status import EVENT_STATUS_SUSPICIOUS, normalize_event_status
from .ai_endpoints import sync_default_ai_endpoint
from .seed import (
    asset_whitelists,
    assets,
    audit_logs,
    default_advanced_rule,
    default_ai_review_policy,
    default_guard_rules,
    default_protected_paths,
    default_protected_plugins,
    default_protected_skills,
    default_scan_rules,
    defense_configs,
    reports,
    security_events,
    skills,
    tasks,
    users,
)
from .security import hash_password
from .system_settings_registry import default_system_settings


RUNTIME_BOOTSTRAP_MODES = {"auto", "validate"}
INIT_COMMAND_MODES = {"setup", "schema", "validate"}


def validate_runtime_configuration(*, role: str) -> None:
    if not settings.is_production:
        return

    issues: list[str] = []
    if settings.database_backend == "sqlite":
        issues.append("DATABASE_URL must point to PostgreSQL when APP_ENV=production")
    if settings.jwt_secret == DEFAULT_JWT_SECRET:
        issues.append("JWT_SECRET is still using the development default")
    if settings.gateway_api_token == DEFAULT_SERVICE_TOKEN:
        issues.append("GATEWAY_API_TOKEN is still using the development default")
    if settings.bootstrap_mode != "validate":
        issues.append("BOOTSTRAP_MODE must be validate for runtime processes in production")
    if settings.bootstrap_admin_password == DEFAULT_BOOTSTRAP_ADMIN_PASSWORD:
        issues.append("BOOTSTRAP_ADMIN_PASSWORD is still using the local demo default")
    if settings.bootstrap_analyst_password == DEFAULT_BOOTSTRAP_ANALYST_PASSWORD:
        issues.append("BOOTSTRAP_ANALYST_PASSWORD is still using the local demo default")

    if issues:
        bullet_lines = "\n".join(f"- {item}" for item in issues)
        raise RuntimeError(
            f"unsafe production configuration for {role} startup:\n{bullet_lines}\n"
            "Run `python backend/scripts/init_db.py --mode schema` before starting production services."
        )


def init_database(mode: str | None = None) -> None:
    resolved_mode = _resolve_init_mode(mode)
    if mode is not None:
        validate_init_command_configuration(mode=resolved_mode)
    if resolved_mode == "validate":
        ping_database()
        return

    Base.metadata.create_all(bind=engine)
    _ensure_model_columns()

    db = SessionLocal()
    try:
        _seed_platform_defaults(db)
        if resolved_mode in {"auto", "setup"} and settings.seed_sample_data:
            _seed_sample_data(db)
        _normalize_existing_levels(db)
        db.commit()
    finally:
        db.close()


def _resolve_init_mode(mode: str | None) -> str:
    candidate = (mode or settings.bootstrap_mode or "auto").strip().lower()
    if candidate in RUNTIME_BOOTSTRAP_MODES | INIT_COMMAND_MODES:
        return candidate
    allowed = ", ".join(sorted(RUNTIME_BOOTSTRAP_MODES | INIT_COMMAND_MODES))
    raise RuntimeError(f"unsupported bootstrap mode `{candidate}`; expected one of: {allowed}")


def validate_init_command_configuration(*, mode: str) -> None:
    if not settings.is_production:
        return

    issues: list[str] = []
    if settings.database_backend == "sqlite":
        issues.append("DATABASE_URL must point to PostgreSQL when APP_ENV=production")
    if settings.bootstrap_admin_password == DEFAULT_BOOTSTRAP_ADMIN_PASSWORD:
        issues.append("BOOTSTRAP_ADMIN_PASSWORD is still using the local demo default")
    if settings.bootstrap_analyst_password == DEFAULT_BOOTSTRAP_ANALYST_PASSWORD:
        issues.append("BOOTSTRAP_ANALYST_PASSWORD is still using the local demo default")
    if mode == "setup" and settings.seed_sample_data:
        issues.append("SEED_SAMPLE_DATA must be false when running production bootstrap")

    if issues:
        bullet_lines = "\n".join(f"- {item}" for item in issues)
        raise RuntimeError(f"unsafe production bootstrap configuration:\n{bullet_lines}")


def _seed_platform_defaults(db) -> None:
    _seed_users(db)
    _seed_defense_configs(db)
    _seed_defense_policy(db)
    _seed_system_settings(db)


def _seed_sample_data(db) -> None:
    _seed_audit_logs(db)
    _seed_security_events(db)
    _seed_assets(db)
    _seed_asset_whitelists(db)
    _seed_skills(db)
    _seed_ai_endpoints(db)
    _seed_tasks(db)
    _seed_reports(db)


def _ensure_model_columns() -> None:
    _ensure_table_columns(
        DefensePolicy.__table__,
        [
            "ai_review_policy_json",
        ],
    )
    _ensure_table_columns(
        AttackTask.__table__,
        [
            "source_type",
            "source_ref",
            "execution_mode",
            "runtime_name",
            "runtime_task_ref",
            "scheduled_at",
            "started_at",
            "finished_at",
            "last_heartbeat_at",
        ],
    )
    _ensure_table_columns(
        AiEndpoint.__table__,
        [
            "endpoint_group",
            "governance_json",
        ],
    )
    _ensure_table_columns(
        RuntimeEnrollmentToken.__table__,
        [
            "delivery_mode",
            "bootstrap_code_hash",
            "bootstrap_code_hint",
        ],
    )
    _ensure_table_columns(
        ManagedRuntime.__table__,
        [
            "activation_code_hash",
            "activation_code_hint",
            "activation_issued_at",
            "activation_expires_at",
        ],
    )
    _ensure_table_columns(
        Skill.__table__,
        [
            "source_path",
        ],
    )


def _ensure_table_columns(table, column_names: list[str]) -> None:
    inspector = inspect(engine)
    existing = {column["name"] for column in inspector.get_columns(table.name)}
    pending_columns = [name for name in column_names if name not in existing]
    if not pending_columns:
        return

    with engine.begin() as connection:
        for column_name in pending_columns:
            column = table.columns[column_name]
            ddl = str(CreateColumn(column).compile(dialect=engine.dialect))
            default_sql = _column_default_sql(column)
            if default_sql and " DEFAULT " not in ddl.upper():
                ddl = f"{ddl} DEFAULT {default_sql}"
            connection.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {ddl}"))


def _column_default_sql(column) -> str | None:
    default = getattr(column, "default", None)
    if default is None or not getattr(default, "is_scalar", False):
        return None
    return _literal_sql(default.arg)


def _literal_sql(value: Any) -> str | None:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return None


def _normalize_level(value: str | None) -> str:
    if not value:
        return "medium"

    lowered = value.lower()
    if lowered == "high" or "\u9ad8" in value:
        return "high"
    if lowered == "low" or "\u4f4e" in value:
        return "low"
    return "medium"


def _seed_users(db) -> None:
    if db.query(User.id).first() is not None:
        return

    password_map = {
        "admin": settings.bootstrap_admin_password,
        "analyst": settings.bootstrap_analyst_password,
    }
    for item in users:
        user = User(
            id=item["id"],
            username=item["username"],
            real_name=item["real_name"],
            email=item["email"],
            status=item["status"],
            password_hash=hash_password(password_map.get(item["username"], "changeme123")),
        )
        user.set_roles(item["roles"])
        db.add(user)


def _seed_defense_configs(db) -> None:
    existing_items = db.query(DefenseConfig).order_by(DefenseConfig.id.asc()).all()
    existing_by_type = {item.defense_type: item for item in existing_items}
    existing_by_id = {item.id: item for item in existing_items}

    for item in defense_configs:
        config = existing_by_type.get(item["defense_type"]) or existing_by_id.get(item["id"])
        if config is None:
            config = DefenseConfig(
                id=item["id"],
                defense_name=item["defense_name"],
                defense_type=item["defense_type"],
                threat_level=item["threat_level"],
                mode=item["mode"],
                enabled=item["enabled"],
                description=item["description"],
            )
            config.set_config(item.get("config_json", {}))
            db.add(config)
            continue

        config.defense_name = item["defense_name"]
        config.defense_type = item["defense_type"]
        config.threat_level = item["threat_level"]
        config.description = item["description"]
        config.set_config(_merge_config(item.get("config_json", {}), config.config))


def _seed_defense_policy(db) -> None:
    policy = db.get(DefensePolicy, 1)
    if policy is None:
        policy = DefensePolicy(id=1)
        db.add(policy)
        existing_guard_rules: list[dict] = []
        existing_scan_rules: list[dict] = []
        existing_advanced_rule: dict = {}
        existing_ai_review_policy: dict = {}
        existing_protected_paths: list[str] = []
        existing_protected_skills: list[str] = []
        existing_protected_plugins: list[str] = []
    else:
        existing_guard_rules = policy.guard_rules
        existing_scan_rules = policy.scan_rules
        existing_advanced_rule = policy.advanced_rule
        existing_ai_review_policy = policy.ai_review_policy
        existing_protected_paths = policy.protected_paths
        existing_protected_skills = policy.protected_skills
        existing_protected_plugins = policy.protected_plugins

    policy.set_guard_rules(_merge_policy_rules(default_guard_rules, existing_guard_rules))
    policy.set_scan_rules(_merge_policy_rules(default_scan_rules, existing_scan_rules))
    policy.set_advanced_rule(_merge_advanced_rule(default_advanced_rule, existing_advanced_rule))
    policy.set_ai_review_policy(_merge_ai_review_policy(default_ai_review_policy, existing_ai_review_policy))
    policy.set_protected_paths(_merge_string_list(default_protected_paths, existing_protected_paths))
    policy.set_protected_skills(_merge_string_list(default_protected_skills, existing_protected_skills))
    policy.set_protected_plugins(_merge_string_list(default_protected_plugins, existing_protected_plugins))


def _seed_system_settings(db) -> None:
    existing_items = {item.setting_key: item for item in db.query(SystemSetting).all()}

    for item in default_system_settings():
        setting = existing_items.get(item["setting_key"])
        if setting is None:
            db.add(SystemSetting(**item))
            continue

        if not setting.description:
            setting.description = item["description"]


def _seed_audit_logs(db) -> None:
    if db.query(AuditLog.id).first() is not None:
        return

    for item in audit_logs:
        db.add(
            AuditLog(
                id=item["id"],
                user_id=item["user_id"],
                module=item["module"],
                action=item["action"],
                detail=item["detail"],
                created_at=datetime.strptime(item["created_at"], "%Y-%m-%d %H:%M:%S"),
            )
        )


def _seed_security_events(db) -> None:
    if db.query(SecurityEvent.id).first() is not None:
        return

    for item in security_events:
        event = SecurityEvent(
            id=item["id"],
            event_type=item["event_type"],
            event_level=_normalize_level(item["event_level"]),
            source=item["source"],
            target=item["target"],
            status=item["status"],
            detail=item["detail"],
            raw_input=item.get("raw_input", ""),
            result=item.get("result", ""),
            created_at=datetime.strptime(item["created_at"], "%Y-%m-%d %H:%M:%S"),
        )
        event.set_hit_rules(item.get("hit_rules", []))
        event.set_operation_logs(item.get("operation_logs", []))
        db.add(event)


def _seed_assets(db) -> None:
    if db.query(Asset.id).first() is not None:
        return

    for item in assets:
        db.add(Asset(**{**item, "risk_level": _normalize_level(item["risk_level"])}))


def _seed_asset_whitelists(db) -> None:
    if db.query(AssetWhitelist.id).first() is not None:
        return

    for item in asset_whitelists:
        db.add(AssetWhitelist(**item))


def _seed_skills(db) -> None:
    existing_items = {item.id: item for item in db.query(Skill).order_by(Skill.id.asc()).all()}
    for item in skills:
        skill = existing_items.get(item["id"])
        if skill is None:
            db.add(
                Skill(
                    id=item["id"],
                    skill_name=item["skill_name"],
                    skill_type=item["skill_type"],
                    provider=item["provider"],
                    source_path=item.get("source_path", ""),
                    trust_status=item["trust_status"],
                    created_at=datetime.strptime(item["created_at"], "%Y-%m-%d"),
                )
            )
            continue

        skill.skill_name = item["skill_name"]
        skill.skill_type = item["skill_type"]
        skill.provider = item["provider"]
        if not skill.source_path:
            skill.source_path = item.get("source_path", "")
        if not skill.trust_status:
            skill.trust_status = item["trust_status"]


def _seed_tasks(db) -> None:
    if db.query(AttackTask.id).first() is not None:
        return

    for item in tasks:
        task = AttackTask(
            id=item["id"],
            task_name=item["task_name"],
            attack_type=item["attack_type"],
            target_agent=item["target_agent"],
            status=item["status"],
            created_by=1,
        )
        task.set_params(item.get("params_json", {}))
        db.add(task)


def _seed_ai_endpoints(db) -> None:
    items = db.query(AiEndpoint).order_by(AiEndpoint.id.asc()).all()
    if items:
        sync_default_ai_endpoint(db)
        return

    if settings.ai_provider == "disabled" or not settings.ai_base_url or not settings.ai_model:
        return

    endpoint = AiEndpoint(
        endpoint_key="env-default",
        display_name="Environment Default",
        endpoint_group="environment",
        provider_type=settings.ai_provider,
        base_url=settings.ai_base_url,
        api_key=settings.ai_api_key,
        model_name=settings.ai_model,
        enabled=True,
        is_default=True,
        protection_enabled=True,
        protection_mode="enforce",
        description="Seeded from legacy AI_PROVIDER environment variables.",
    )
    endpoint.set_config({})
    db.add(endpoint)
    db.flush()
    sync_default_ai_endpoint(db, endpoint)


def _seed_reports(db) -> None:
    if db.query(Report.id).first() is not None:
        return

    for item in reports:
        db.add(
            Report(
                id=item["id"],
                task_id=item["task_id"],
                report_name=item["report_name"],
                report_type=item["report_type"],
                file_path=item["file_path"],
                summary_text=item.get("summary_text", ""),
                created_by=item["created_by"],
                created_at=datetime.strptime(item["created_at"], "%Y-%m-%d %H:%M:%S"),
            )
        )


def _normalize_existing_levels(db) -> None:
    for item in db.query(SecurityEvent).all():
        normalized_level = _normalize_level(item.event_level)
        if item.event_level != normalized_level:
            item.event_level = normalized_level
        normalized_status = normalize_event_status(item.status, EVENT_STATUS_SUSPICIOUS)
        if item.status != normalized_status:
            item.status = normalized_status

    for item in db.query(Asset).all():
        normalized_level = _normalize_level(item.risk_level)
        if item.risk_level != normalized_level:
            item.risk_level = normalized_level


def _merge_config(defaults: dict, current: dict) -> dict:
    return {**defaults, **(current or {})}


def _merge_policy_rules(defaults: list[dict], current: list[dict]) -> list[dict]:
    current_by_key = {
        str(item.get("key")): item
        for item in current
        if isinstance(item, dict) and item.get("key")
    }
    merged: list[dict] = []
    seen_keys: set[str] = set()

    for item in defaults:
        key = str(item["key"])
        existing = current_by_key.get(key, {})
        merged.append(
            {
                "key": key,
                "title": item["title"],
                "description": item["description"],
                "enabled": bool(existing.get("enabled", item["enabled"])),
                "mode": str(existing.get("mode", item["mode"])),
            }
        )
        seen_keys.add(key)

    for item in current:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if not key or key in seen_keys:
            continue
        merged.append(
            {
                "key": key,
                "title": str(item.get("title") or key),
                "description": str(item.get("description") or ""),
                "enabled": bool(item.get("enabled", True)),
                "mode": str(item.get("mode") or "observe"),
            }
        )

    return merged


def _merge_advanced_rule(defaults: dict, current: dict) -> dict:
    return {
        "key": str(current.get("key") or defaults["key"]),
        "title": defaults["title"],
        "description": defaults["description"],
        "enabled": bool(current.get("enabled", defaults["enabled"])),
        "mode": str(current.get("mode", defaults["mode"])),
    }


def _merge_ai_review_policy(defaults: dict, current: dict) -> dict:
    return {
        "key": str(current.get("key") or defaults["key"]),
        "title": defaults["title"],
        "description": defaults["description"],
        "mode": str(current.get("mode", defaults["mode"])),
    }


def _merge_string_list(defaults: list[str], current: list[str]) -> list[str]:
    merged: list[str] = []
    for value in [*defaults, *current]:
        normalized = str(value or "").strip()
        if normalized and normalized not in merged:
            merged.append(normalized)
    return merged
