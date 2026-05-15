from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from .db.base import Base


def _serialize_json(value: Any, fallback: Any) -> str:
    return json.dumps(value if value is not None else fallback, ensure_ascii=False)


def _parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True)
    real_name = Column(String(128), nullable=False)
    email = Column(String(255), nullable=False)
    status = Column(String(32), default="active", nullable=False)
    password_hash = Column(String(255), nullable=False)
    roles_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    @property
    def roles(self) -> list[str]:
        return list(_parse_json(self.roles_json, []))

    def set_roles(self, roles: list[str]) -> None:
        self.roles_json = _serialize_json(roles, [])


class DefenseConfig(Base):
    __tablename__ = "defense_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    defense_name = Column(String(128), nullable=False)
    defense_type = Column(String(128), index=True, nullable=False)
    threat_level = Column(String(32), nullable=False)
    mode = Column(String(32), default="observe", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    description = Column(Text, nullable=False)
    config_json = Column(Text, default="{}", nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def config(self) -> dict[str, Any]:
        return dict(_parse_json(self.config_json, {}))

    def set_config(self, payload: dict[str, Any]) -> None:
        self.config_json = _serialize_json(payload, {})


class DefensePolicy(Base):
    __tablename__ = "defense_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    guard_rules_json = Column(Text, default="[]", nullable=False)
    scan_rules_json = Column(Text, default="[]", nullable=False)
    advanced_rule_json = Column(Text, default="{}", nullable=False)
    ai_review_policy_json = Column(Text, default="{}", nullable=False)
    protected_paths_json = Column(Text, default="[]", nullable=False)
    protected_skills_json = Column(Text, default="[]", nullable=False)
    protected_plugins_json = Column(Text, default="[]", nullable=False)
    updated_by = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def guard_rules(self) -> list[dict[str, Any]]:
        return list(_parse_json(self.guard_rules_json, []))

    def set_guard_rules(self, items: list[dict[str, Any]]) -> None:
        self.guard_rules_json = _serialize_json(items, [])

    @property
    def scan_rules(self) -> list[dict[str, Any]]:
        return list(_parse_json(self.scan_rules_json, []))

    def set_scan_rules(self, items: list[dict[str, Any]]) -> None:
        self.scan_rules_json = _serialize_json(items, [])

    @property
    def advanced_rule(self) -> dict[str, Any]:
        return dict(_parse_json(self.advanced_rule_json, {}))

    def set_advanced_rule(self, item: dict[str, Any]) -> None:
        self.advanced_rule_json = _serialize_json(item, {})

    @property
    def ai_review_policy(self) -> dict[str, Any]:
        return dict(_parse_json(self.ai_review_policy_json, {}))

    def set_ai_review_policy(self, item: dict[str, Any]) -> None:
        self.ai_review_policy_json = _serialize_json(item, {})

    @property
    def protected_paths(self) -> list[str]:
        return list(_parse_json(self.protected_paths_json, []))

    def set_protected_paths(self, items: list[str]) -> None:
        self.protected_paths_json = _serialize_json(items, [])

    @property
    def protected_skills(self) -> list[str]:
        return list(_parse_json(self.protected_skills_json, []))

    def set_protected_skills(self, items: list[str]) -> None:
        self.protected_skills_json = _serialize_json(items, [])

    @property
    def protected_plugins(self) -> list[str]:
        return list(_parse_json(self.protected_plugins_json, []))

    def set_protected_plugins(self, items: list[str]) -> None:
        self.protected_plugins_json = _serialize_json(items, [])


class SystemSetting(Base):
    __tablename__ = "system_settings"

    setting_key = Column(String(64), primary_key=True)
    setting_value = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True, nullable=False)
    module = Column(String(64), index=True, nullable=False)
    action = Column(String(64), index=True, nullable=False)
    detail = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, index=True, nullable=True)
    event_type = Column(String(64), index=True, nullable=False)
    event_level = Column(String(32), index=True, nullable=False)
    source = Column(String(128), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(32), index=True, nullable=False)
    detail = Column(Text, nullable=False)
    hit_rules_json = Column(Text, default="[]", nullable=False)
    raw_input = Column(Text, default="", nullable=False)
    result = Column(Text, default="", nullable=False)
    operation_logs_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    @property
    def hit_rules(self) -> list[str]:
        return list(_parse_json(self.hit_rules_json, []))

    def set_hit_rules(self, items: list[str]) -> None:
        self.hit_rules_json = _serialize_json(items, [])

    @property
    def operation_logs(self) -> list[dict[str, Any]]:
        return list(_parse_json(self.operation_logs_json, []))

    def set_operation_logs(self, items: list[dict[str, Any]]) -> None:
        self.operation_logs_json = _serialize_json(items, [])


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_name = Column(String(128), nullable=False)
    asset_type = Column(String(64), index=True, nullable=False)
    asset_path = Column(String(255), nullable=False)
    risk_level = Column(String(32), index=True, nullable=False)
    status = Column(String(32), index=True, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AssetWhitelist(Base):
    __tablename__ = "asset_whitelists"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, index=True, nullable=False)
    whitelist_type = Column(String(32), index=True, nullable=False)
    rule_value = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Skill(Base):
    __tablename__ = "skills"

    id = Column(Integer, primary_key=True, autoincrement=True)
    skill_name = Column(String(128), nullable=False)
    skill_type = Column(String(64), index=True, nullable=False)
    provider = Column(String(64), index=True, nullable=False)
    source_path = Column(String(255), default="", nullable=False)
    trust_status = Column(String(32), index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AiEndpoint(Base):
    __tablename__ = "ai_endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_key = Column(String(64), unique=True, index=True, nullable=False)
    display_name = Column(String(128), nullable=False)
    endpoint_group = Column(String(64), default="default", nullable=False)
    provider_type = Column(String(64), index=True, nullable=False, default="openai_compatible")
    base_url = Column(String(255), nullable=False)
    api_key = Column(String(255), default="", nullable=False)
    model_name = Column(String(128), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)
    protection_enabled = Column(Boolean, default=True, nullable=False)
    protection_mode = Column(String(32), default="enforce", nullable=False)
    description = Column(Text, default="", nullable=False)
    config_json = Column(Text, default="{}", nullable=False)
    governance_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def config(self) -> dict[str, Any]:
        return dict(_parse_json(self.config_json, {}))

    def set_config(self, payload: dict[str, Any]) -> None:
        self.config_json = _serialize_json(payload, {})

    @property
    def governance(self) -> dict[str, Any]:
        return dict(_parse_json(self.governance_json, {}))

    def set_governance(self, payload: dict[str, Any]) -> None:
        self.governance_json = _serialize_json(payload, {})


class RuntimeEnrollmentToken(Base):
    __tablename__ = "runtime_enrollment_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_key = Column(String(64), unique=True, index=True, nullable=False)
    token_label = Column(String(128), nullable=False)
    secret_hash = Column(String(255), nullable=False)
    secret_hint = Column(String(64), default="", nullable=False)
    delivery_mode = Column(String(32), default="approval", nullable=False)
    bootstrap_code_hash = Column(String(255), nullable=True)
    bootstrap_code_hint = Column(String(64), default="", nullable=False)
    runtime_type = Column(String(64), default="agent", nullable=False)
    ai_endpoint_id = Column(Integer, nullable=True)
    status = Column(String(32), index=True, default="active", nullable=False)
    usage_limit = Column(Integer, default=1, nullable=False)
    used_count = Column(Integer, default=0, nullable=False)
    issued_by = Column(Integer, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ManagedRuntime(Base):
    __tablename__ = "managed_runtimes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    registration_id = Column(String(64), unique=True, index=True, nullable=False)
    display_name = Column(String(128), nullable=False)
    runtime_type = Column(String(64), default="agent", nullable=False)
    runtime_key = Column(String(64), unique=True, index=True, nullable=True)
    runtime_secret_hash = Column(String(255), nullable=True)
    runtime_secret_hint = Column(String(64), default="", nullable=False)
    poll_secret_hash = Column(String(255), nullable=False)
    activation_code_hash = Column(String(255), nullable=True)
    activation_code_hint = Column(String(64), default="", nullable=False)
    enrollment_token_id = Column(Integer, nullable=True)
    ai_endpoint_id = Column(Integer, nullable=True)
    status = Column(String(32), index=True, default="pending", nullable=False)
    hostname = Column(String(128), default="", nullable=False)
    fingerprint = Column(String(255), default="", nullable=False)
    client_version = Column(String(64), default="", nullable=False)
    ip_addresses_json = Column(Text, default="[]", nullable=False)
    requested_scopes_json = Column(Text, default="[]", nullable=False)
    capabilities_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    approved_by = Column(Integer, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    activation_issued_at = Column(DateTime, nullable=True)
    activation_expires_at = Column(DateTime, nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, default="", nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
    credential_delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def ip_addresses(self) -> list[str]:
        return list(_parse_json(self.ip_addresses_json, []))

    def set_ip_addresses(self, items: list[str]) -> None:
        self.ip_addresses_json = _serialize_json(items, [])

    @property
    def requested_scopes(self) -> list[str]:
        return list(_parse_json(self.requested_scopes_json, []))

    def set_requested_scopes(self, items: list[str]) -> None:
        self.requested_scopes_json = _serialize_json(items, [])

    @property
    def capabilities(self) -> list[str]:
        return list(_parse_json(self.capabilities_json, []))

    def set_capabilities(self, items: list[str]) -> None:
        self.capabilities_json = _serialize_json(items, [])

    @property
    def meta(self) -> dict[str, Any]:
        return dict(_parse_json(self.metadata_json, {}))

    def set_meta(self, payload: dict[str, Any]) -> None:
        self.metadata_json = _serialize_json(payload, {})


class McpServerRegistry(Base):
    __tablename__ = "mcp_server_registry"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ai_endpoint_id = Column(Integer, index=True, nullable=True)
    server_name = Column(String(128), index=True, nullable=False)
    server_label = Column(String(128), default="", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    trust_mode = Column(String(32), default="trusted", nullable=False)
    require_ticket = Column(Boolean, default=True, nullable=False)
    require_approval = Column(Boolean, default=False, nullable=False)
    allowed_scopes_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def allowed_scopes(self) -> list[str]:
        return list(_parse_json(self.allowed_scopes_json, []))

    def set_allowed_scopes(self, items: list[str]) -> None:
        self.allowed_scopes_json = _serialize_json(items, [])

    @property
    def meta(self) -> dict[str, Any]:
        return dict(_parse_json(self.metadata_json, {}))

    def set_meta(self, payload: dict[str, Any]) -> None:
        self.metadata_json = _serialize_json(payload, {})


class McpCapabilityPolicy(Base):
    __tablename__ = "mcp_capability_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ai_endpoint_id = Column(Integer, index=True, nullable=True)
    server_name = Column(String(128), index=True, nullable=False)
    capability_name = Column(String(128), index=True, nullable=False)
    capability_label = Column(String(128), default="", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    risk_level = Column(String(32), default="medium", nullable=False)
    approval_mode = Column(String(32), default="inherit", nullable=False)
    allowed_scopes_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def allowed_scopes(self) -> list[str]:
        return list(_parse_json(self.allowed_scopes_json, []))

    def set_allowed_scopes(self, items: list[str]) -> None:
        self.allowed_scopes_json = _serialize_json(items, [])

    @property
    def meta(self) -> dict[str, Any]:
        return dict(_parse_json(self.metadata_json, {}))

    def set_meta(self, payload: dict[str, Any]) -> None:
        self.metadata_json = _serialize_json(payload, {})


class McpExecutionTicket(Base):
    __tablename__ = "mcp_execution_tickets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ticket_key = Column(String(64), unique=True, index=True, nullable=False)
    task_id = Column(Integer, index=True, nullable=False)
    runtime_id = Column(Integer, index=True, nullable=True)
    ai_endpoint_id = Column(Integer, index=True, nullable=True)
    status = Column(String(32), index=True, default="issued", nullable=False)
    action_type = Column(String(64), default="", nullable=False)
    session_id = Column(String(128), default="", nullable=False)
    mcp_server = Column(String(128), default="", nullable=False)
    capability_name = Column(String(128), default="", nullable=False)
    call_id = Column(String(128), default="", nullable=False)
    tool_call_id = Column(String(128), default="", nullable=False)
    source_plugin = Column(String(128), default="", nullable=False)
    target_plugin = Column(String(128), default="", nullable=False)
    handoff_token = Column(String(255), default="", nullable=False)
    approval_id = Column(String(128), default="", nullable=False)
    requested_scopes_json = Column(Text, default="[]", nullable=False)
    args_hash = Column(String(128), default="", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    consumed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def requested_scopes(self) -> list[str]:
        return list(_parse_json(self.requested_scopes_json, []))

    def set_requested_scopes(self, items: list[str]) -> None:
        self.requested_scopes_json = _serialize_json(items, [])

    @property
    def meta(self) -> dict[str, Any]:
        return dict(_parse_json(self.metadata_json, {}))

    def set_meta(self, payload: dict[str, Any]) -> None:
        self.metadata_json = _serialize_json(payload, {})


class RuntimeDispatchCommand(Base):
    __tablename__ = "runtime_dispatch_commands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    runtime_id = Column(Integer, index=True, nullable=False)
    ai_endpoint_id = Column(Integer, index=True, nullable=True)
    source_task_id = Column(Integer, index=True, nullable=True)
    request_key = Column(String(64), unique=True, index=True, nullable=False)
    command_type = Column(String(64), index=True, nullable=False)
    status = Column(String(32), index=True, nullable=False, default="pending")
    payload_json = Column(Text, default="{}", nullable=False)
    response_json = Column(Text, default="{}", nullable=False)
    error_text = Column(Text, default="", nullable=False)
    claimed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def payload(self) -> dict[str, Any]:
        return dict(_parse_json(self.payload_json, {}))

    def set_payload(self, payload: dict[str, Any]) -> None:
        self.payload_json = _serialize_json(payload, {})

    @property
    def response(self) -> dict[str, Any]:
        return dict(_parse_json(self.response_json, {}))

    def set_response(self, payload: dict[str, Any]) -> None:
        self.response_json = _serialize_json(payload, {})


class AttackTask(Base):
    __tablename__ = "attack_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_name = Column(String(128), nullable=False)
    attack_type = Column(String(64), index=True, nullable=False)
    target_agent = Column(String(128), nullable=False)
    status = Column(String(32), index=True, nullable=False, default="queued")
    source_type = Column(String(64), nullable=True)
    source_ref = Column(String(255), nullable=True)
    execution_mode = Column(String(32), nullable=True)
    runtime_name = Column(String(64), nullable=True)
    runtime_task_ref = Column(String(128), nullable=True)
    params_json = Column(Text, default="{}", nullable=False)
    raw_response = Column(Text, default="", nullable=False)
    result_summary = Column(Text, default="", nullable=False)
    latest_event_id = Column(Integer, nullable=True)
    latest_report_id = Column(Integer, nullable=True)
    created_by = Column(Integer, nullable=True)
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    last_heartbeat_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def params(self) -> dict[str, Any]:
        return dict(_parse_json(self.params_json, {}))

    def set_params(self, payload: dict[str, Any]) -> None:
        self.params_json = _serialize_json(payload, {})


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, index=True, nullable=False)
    report_name = Column(String(128), nullable=False)
    report_type = Column(String(64), index=True, nullable=False)
    file_path = Column(String(255), nullable=False)
    summary_text = Column(Text, default="", nullable=False)
    created_by = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class TaskRuntimeLog(Base):
    __tablename__ = "task_runtime_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, index=True, nullable=False)
    log_offset = Column(Integer, nullable=False)
    level = Column(String(32), nullable=False)
    stage = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    @property
    def meta(self) -> dict[str, Any]:
        return dict(_parse_json(self.metadata_json, {}))

    def set_meta(self, payload: dict[str, Any]) -> None:
        self.metadata_json = _serialize_json(payload, {})
