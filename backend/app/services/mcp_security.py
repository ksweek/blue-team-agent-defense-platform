from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from ..models import (
    AiEndpoint,
    AttackTask,
    ManagedRuntime,
    McpCapabilityPolicy,
    McpExecutionTicket,
    McpServerRegistry,
)
from .ai_endpoints import TARGET_TYPE_OPENCLAW_CONTROL, get_ai_endpoint_target_type
from .time_utils import format_beijing, utc_now

MCP_TICKET_STATUS_ISSUED = "issued"
MCP_TICKET_STATUS_CONSUMED = "consumed"
MCP_TICKET_STATUS_EXPIRED = "expired"
DEFAULT_OPENCLAW_MCP_TEMPLATE_KEY = "openclaw_default"

TOOL_OPERATION_TYPES = {"tool_call", "tool_result"}
MCP_TRUST_MODES = ("trusted", "restricted", "blocked")
MCP_APPROVAL_MODES = ("inherit", "required", "deny")
MCP_RISK_LEVELS = ("low", "medium", "high")
MCP_SCOPE_CATALOG = (
    {"value": "read", "label": "Read-only data", "risk_level": "low"},
    {"value": "list", "label": "List resources", "risk_level": "low"},
    {"value": "stat", "label": "Inspect metadata", "risk_level": "low"},
    {"value": "request", "label": "Send outbound request", "risk_level": "medium"},
    {"value": "navigate", "label": "Navigate browser session", "risk_level": "medium"},
    {"value": "workspace.read", "label": "Read workspace", "risk_level": "medium"},
    {"value": "workspace.scan", "label": "Scan workspace", "risk_level": "medium"},
    {"value": "write", "label": "Write or modify", "risk_level": "high"},
    {"value": "delete", "label": "Delete or overwrite", "risk_level": "high"},
    {"value": "exec", "label": "Execute command", "risk_level": "high"},
    {"value": "shell", "label": "Interactive shell", "risk_level": "high"},
    {"value": "network", "label": "Network side effects", "risk_level": "high"},
)
MCP_SERVER_CATALOG = (
    {
        "server_name": "filesystem",
        "server_label": "Filesystem",
        "suggested_scopes": ["read", "list", "stat", "write", "delete"],
        "notes": "Use for local file access style MCP servers.",
    },
    {
        "server_name": "browser",
        "server_label": "Browser",
        "suggested_scopes": ["request", "navigate"],
        "notes": "Use for browser automation, page fetching, or browsing helpers.",
    },
    {
        "server_name": "workspace",
        "server_label": "Workspace",
        "suggested_scopes": ["workspace.read", "workspace.scan", "write"],
        "notes": "Use for workspace-level scans, indexing, and project automation.",
    },
    {
        "server_name": "shell",
        "server_label": "Shell",
        "suggested_scopes": ["exec", "shell", "network"],
        "notes": "Use for shell or process execution MCP integrations.",
    },
    {
        "server_name": "github",
        "server_label": "GitHub",
        "suggested_scopes": ["read", "write", "network"],
        "notes": "Use for GitHub or remote SCM MCP integrations.",
    },
)
MCP_CAPABILITY_CATALOG = (
    {
        "server_name": "filesystem",
        "capability_name": "read_*",
        "capability_label": "Read files",
        "risk_level": "low",
        "approval_mode": "inherit",
        "suggested_scopes": ["read", "list", "stat"],
        "notes": "Pattern for read-only file capabilities.",
    },
    {
        "server_name": "filesystem",
        "capability_name": "write_*",
        "capability_label": "Write files",
        "risk_level": "high",
        "approval_mode": "required",
        "suggested_scopes": ["write"],
        "notes": "Pattern for file creation or modification.",
    },
    {
        "server_name": "filesystem",
        "capability_name": "delete_*",
        "capability_label": "Delete files",
        "risk_level": "high",
        "approval_mode": "required",
        "suggested_scopes": ["delete"],
        "notes": "Pattern for destructive file operations.",
    },
    {
        "server_name": "browser",
        "capability_name": "browser.request",
        "capability_label": "Browser request",
        "risk_level": "medium",
        "approval_mode": "inherit",
        "suggested_scopes": ["request"],
        "notes": "Out-of-browser HTTP fetches or headless browsing requests.",
    },
    {
        "server_name": "browser",
        "capability_name": "browser.navigate",
        "capability_label": "Browser navigate",
        "risk_level": "medium",
        "approval_mode": "inherit",
        "suggested_scopes": ["navigate"],
        "notes": "Navigation and browsing-state changes.",
    },
    {
        "server_name": "workspace",
        "capability_name": "workspace.scan",
        "capability_label": "Workspace scan",
        "risk_level": "medium",
        "approval_mode": "inherit",
        "suggested_scopes": ["workspace.read", "workspace.scan"],
        "notes": "Project tree scan, indexing, or repository introspection.",
    },
    {
        "server_name": "shell",
        "capability_name": "shell.exec",
        "capability_label": "Shell exec",
        "risk_level": "high",
        "approval_mode": "required",
        "suggested_scopes": ["exec", "shell", "network"],
        "notes": "Command execution with side effects.",
    },
)
PREDEFINED_MCP_POLICY_TEMPLATES: dict[str, dict[str, Any]] = {
    DEFAULT_OPENCLAW_MCP_TEMPLATE_KEY: {
        "label": "OpenClaw Default Hardened",
        "description": (
            "Built-in default for OpenClaw targets. Starts in strict allowlist mode, keeps local reads open, "
            "requires approval for browser fetches and workspace scans, and blocks shell/exec by default."
        ),
        "recommended": True,
        "servers": [
            {
                "server_name": "filesystem",
                "server_label": "Filesystem",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": False,
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "workspace",
                "server_label": "Workspace",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": False,
                "allowed_scopes": ["workspace.read", "workspace.scan"],
            },
            {
                "server_name": "browser",
                "server_label": "Browser",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "shell",
                "server_label": "Shell",
                "enabled": False,
                "trust_mode": "blocked",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": [],
            },
        ],
        "capabilities": [
            {
                "server_name": "filesystem",
                "capability_name": "read_*",
                "capability_label": "Read files",
                "enabled": True,
                "risk_level": "low",
                "approval_mode": "inherit",
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "list_*",
                "capability_label": "List files",
                "enabled": True,
                "risk_level": "low",
                "approval_mode": "inherit",
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "workspace",
                "capability_name": "workspace.scan",
                "capability_label": "Workspace scan",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["workspace.read", "workspace.scan"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.request",
                "capability_label": "Browser request",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.navigate",
                "capability_label": "Browser navigate",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["navigate"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "write_*",
                "capability_label": "Write files",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["write"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "delete_*",
                "capability_label": "Delete files",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["delete"],
            },
            {
                "server_name": "shell",
                "capability_name": "shell.exec",
                "capability_label": "Shell exec",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["exec", "shell", "network"],
            },
        ],
    },
    "openclaw_safe_readonly": {
        "label": "OpenClaw Safe Readonly",
        "description": "Read-focused baseline for OpenClaw targets. Keeps local reads open and forces approval for external fetches or broader workspace scans.",
        "recommended": True,
        "servers": [
            {
                "server_name": "filesystem",
                "server_label": "Filesystem",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": False,
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "browser",
                "server_label": "Browser",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "workspace",
                "server_label": "Workspace",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": ["workspace.read", "workspace.scan"],
            },
        ],
        "capabilities": [
            {
                "server_name": "filesystem",
                "capability_name": "read_*",
                "capability_label": "Read files",
                "enabled": True,
                "risk_level": "low",
                "approval_mode": "inherit",
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "list_*",
                "capability_label": "List files",
                "enabled": True,
                "risk_level": "low",
                "approval_mode": "inherit",
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.request",
                "capability_label": "Browser request",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.navigate",
                "capability_label": "Browser navigate",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["navigate"],
            },
            {
                "server_name": "workspace",
                "capability_name": "workspace.scan",
                "capability_label": "Workspace scan",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["workspace.read", "workspace.scan"],
            },
        ],
    },
    "openclaw_balanced": {
        "label": "OpenClaw Balanced",
        "description": "Balanced OpenClaw profile. Read flows stay open, browser/workspace expansion needs approval, and shell remains an explicit opt-in path.",
        "recommended": False,
        "servers": [
            {
                "server_name": "filesystem",
                "server_label": "Filesystem",
                "enabled": True,
                "trust_mode": "trusted",
                "require_ticket": True,
                "require_approval": False,
                "allowed_scopes": ["read", "list", "stat", "write"],
            },
            {
                "server_name": "browser",
                "server_label": "Browser",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "workspace",
                "server_label": "Workspace",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": ["workspace.read", "workspace.scan", "write"],
            },
            {
                "server_name": "shell",
                "server_label": "Shell",
                "enabled": False,
                "trust_mode": "blocked",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": [],
            },
        ],
        "capabilities": [
            {
                "server_name": "filesystem",
                "capability_name": "read_*",
                "capability_label": "Read files",
                "enabled": True,
                "risk_level": "low",
                "approval_mode": "inherit",
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "write_*",
                "capability_label": "Write files",
                "enabled": True,
                "risk_level": "high",
                "approval_mode": "required",
                "allowed_scopes": ["write"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.request",
                "capability_label": "Browser request",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.navigate",
                "capability_label": "Browser navigate",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["navigate"],
            },
            {
                "server_name": "workspace",
                "capability_name": "workspace.scan",
                "capability_label": "Workspace scan",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["workspace.read", "workspace.scan"],
            },
            {
                "server_name": "shell",
                "capability_name": "shell.exec",
                "capability_label": "Shell exec",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["exec", "shell", "network"],
            },
        ],
    },
    "openclaw_strict": {
        "label": "OpenClaw Strict",
        "description": "Strict OpenClaw policy. Only a small read set is allowed by default and anything risky must be explicitly approved.",
        "recommended": False,
        "servers": [
            {
                "server_name": "filesystem",
                "server_label": "Filesystem",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": False,
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "browser",
                "server_label": "Browser",
                "enabled": True,
                "trust_mode": "restricted",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "shell",
                "server_label": "Shell",
                "enabled": False,
                "trust_mode": "blocked",
                "require_ticket": True,
                "require_approval": True,
                "allowed_scopes": [],
            },
        ],
        "capabilities": [
            {
                "server_name": "filesystem",
                "capability_name": "read_*",
                "capability_label": "Read files",
                "enabled": True,
                "risk_level": "low",
                "approval_mode": "inherit",
                "allowed_scopes": ["read", "list", "stat"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "write_*",
                "capability_label": "Write files",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["write"],
            },
            {
                "server_name": "filesystem",
                "capability_name": "delete_*",
                "capability_label": "Delete files",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["delete"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.request",
                "capability_label": "Browser request",
                "enabled": True,
                "risk_level": "medium",
                "approval_mode": "required",
                "allowed_scopes": ["request"],
            },
            {
                "server_name": "browser",
                "capability_name": "browser.navigate",
                "capability_label": "Browser navigate",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["navigate"],
            },
            {
                "server_name": "shell",
                "capability_name": "shell.exec",
                "capability_label": "Shell exec",
                "enabled": False,
                "risk_level": "high",
                "approval_mode": "deny",
                "allowed_scopes": ["exec", "shell", "network"],
            },
        ],
    },
}


@dataclass
class McpTicketValidationResult:
    allowed: bool
    code: str
    reason: str
    ticket: McpExecutionTicket | None = None


@dataclass
class EffectiveMcpServerPolicy:
    server_name: str
    server_label: str
    enabled: bool
    trust_mode: str
    require_ticket: bool
    require_approval: bool
    allowed_scopes: list[str]
    meta: dict[str, Any]
    ai_endpoint_id: int | None = None
    id: int | None = None
    created_at: Any = None
    updated_at: Any = None


@dataclass
class EffectiveMcpCapabilityPolicy:
    server_name: str
    capability_name: str
    capability_label: str
    enabled: bool
    risk_level: str
    approval_mode: str
    allowed_scopes: list[str]
    meta: dict[str, Any]
    ai_endpoint_id: int | None = None
    id: int | None = None
    created_at: Any = None
    updated_at: Any = None


@dataclass
class EffectiveMcpPolicyState:
    endpoint: AiEndpoint | None
    target_type: str | None
    endpoint_servers: list[McpServerRegistry]
    endpoint_capabilities: list[McpCapabilityPolicy]
    global_servers: list[McpServerRegistry]
    global_capabilities: list[McpCapabilityPolicy]
    builtin_servers: list[EffectiveMcpServerPolicy]
    builtin_capabilities: list[EffectiveMcpCapabilityPolicy]
    builtin_template_key: str | None

    @property
    def uses_builtin_defaults(self) -> bool:
        return bool(self.builtin_servers or self.builtin_capabilities)

    @property
    def strict_allowlist(self) -> bool:
        return bool(
            self.endpoint_servers
            or self.endpoint_capabilities
            or self.global_servers
            or self.global_capabilities
            or self.uses_builtin_defaults
        )


def serialize_mcp_execution_ticket(item: McpExecutionTicket) -> dict[str, Any]:
    return {
        "id": item.id,
        "ticket_key": item.ticket_key,
        "status": item.status,
        "action_type": item.action_type,
        "session_id": item.session_id,
        "mcp_server": item.mcp_server,
        "capability_name": item.capability_name,
        "call_id": item.call_id,
        "tool_call_id": item.tool_call_id,
        "requested_scopes": item.requested_scopes,
        "issued_at": format_beijing(item.issued_at) or "",
        "expires_at": format_beijing(item.expires_at) if item.expires_at else "",
        "consumed_at": format_beijing(item.consumed_at) if item.consumed_at else "",
    }


def resolve_task_ai_endpoint_id(task: AttackTask) -> int | None:
    raw_value = task.params.get("ai_endpoint_id")
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str) and raw_value.strip().isdigit():
        return int(raw_value.strip())
    return None


def action_has_mcp_surface(action: dict[str, Any]) -> bool:
    operation_type = _normalize_token(action.get("operation_type"))
    if operation_type in TOOL_OPERATION_TYPES:
        return True
    if _normalize_token(action.get("action_type")) in {"openclaw_ws_tool_result"}:
        return True
    for key in ("mcp_server", "capability_name", "tool_call_id", "call_id", "mcp_ticket_key"):
        if str(action.get(key) or "").strip():
            return True
    metadata = dict(action.get("metadata") or {})
    if _normalize_token(metadata.get("openclaw_operation_type")) in TOOL_OPERATION_TYPES:
        return True
    if _normalize_token(metadata.get("openclaw_event_type")) == "tool_call":
        return True
    event_name = _normalize_token(action.get("event_name") or metadata.get("event_name") or metadata.get("openclaw_event_name"))
    return event_name == "session_tool"


def action_is_tool_result(action: dict[str, Any]) -> bool:
    operation_type = _normalize_token(action.get("operation_type"))
    if operation_type == "tool_result":
        return True
    if _normalize_token(action.get("action_type")) == "openclaw_ws_tool_result":
        return True
    metadata = dict(action.get("metadata") or {})
    if _normalize_token(metadata.get("openclaw_event_type")) == "tool_call":
        return True
    event_name = _normalize_token(action.get("event_name") or metadata.get("event_name") or metadata.get("openclaw_event_name"))
    return event_name == "session_tool"


def action_requires_mcp_ticket(action: dict[str, Any]) -> bool:
    if action_is_tool_result(action):
        return False
    operation_type = _normalize_token(action.get("operation_type"))
    if operation_type == "tool_call":
        return True
    metadata = dict(action.get("metadata") or {})
    return _normalize_token(metadata.get("openclaw_operation_type")) == "tool_call" and action_has_mcp_surface(action)


def _policy_row_sort_key(row: Any, *, ai_endpoint_id: int | None) -> tuple[int, int, int, int]:
    server_name = str(getattr(row, "server_name", "") or "").strip()
    capability_name = str(getattr(row, "capability_name", "") or "").strip()
    row_id = int(getattr(row, "id", 0) or 0)
    return (
        1 if getattr(row, "ai_endpoint_id", None) == ai_endpoint_id else 0,
        1 if _normalize_token(server_name) != "*" else 0,
        1 if not capability_name or _normalize_token(capability_name) != "*" else 0,
        row_id,
    )


def _build_effective_server_policy(
    item: dict[str, Any],
    *,
    ai_endpoint_id: int | None,
    template_key: str,
    managed_by: str,
    notes: str,
) -> EffectiveMcpServerPolicy:
    return EffectiveMcpServerPolicy(
        ai_endpoint_id=ai_endpoint_id,
        server_name=normalize_mcp_server_name(item.get("server_name")),
        server_label=str(item.get("server_label") or item.get("server_name") or "").strip(),
        enabled=bool(item.get("enabled", True)),
        trust_mode=normalize_mcp_trust_mode(item.get("trust_mode")),
        require_ticket=bool(item.get("require_ticket", True)),
        require_approval=bool(item.get("require_approval", False)),
        allowed_scopes=_normalize_scope_list(item.get("allowed_scopes")),
        meta={
            "template_key": template_key,
            "managed_by": managed_by,
            "notes": notes,
            **dict(item.get("meta") or {}),
        },
    )


def _build_effective_capability_policy(
    item: dict[str, Any],
    *,
    ai_endpoint_id: int | None,
    template_key: str,
    managed_by: str,
    notes: str,
) -> EffectiveMcpCapabilityPolicy:
    return EffectiveMcpCapabilityPolicy(
        ai_endpoint_id=ai_endpoint_id,
        server_name=normalize_mcp_server_name(item.get("server_name"), allow_wildcard=True),
        capability_name=normalize_mcp_capability_name(item.get("capability_name")),
        capability_label=str(item.get("capability_label") or item.get("capability_name") or "").strip(),
        enabled=bool(item.get("enabled", True)),
        risk_level=normalize_mcp_risk_level(item.get("risk_level")),
        approval_mode=normalize_mcp_approval_mode(item.get("approval_mode")),
        allowed_scopes=_normalize_scope_list(item.get("allowed_scopes")),
        meta={
            "template_key": template_key,
            "managed_by": managed_by,
            "notes": notes,
            **dict(item.get("meta") or {}),
        },
    )


def _build_builtin_template_rows(
    *,
    template_key: str,
    ai_endpoint_id: int | None,
) -> tuple[list[EffectiveMcpServerPolicy], list[EffectiveMcpCapabilityPolicy]]:
    template = get_predefined_mcp_policy_template(template_key)
    if template is None:
        return [], []
    notes = "Implicit built-in OpenClaw MCP baseline. Save or apply another template to override it explicitly."
    servers = [
        _build_effective_server_policy(
            item,
            ai_endpoint_id=ai_endpoint_id,
            template_key=template_key,
            managed_by="builtin_default",
            notes=notes,
        )
        for item in list(template.get("servers") or [])
    ]
    capabilities = [
        _build_effective_capability_policy(
            item,
            ai_endpoint_id=ai_endpoint_id,
            template_key=template_key,
            managed_by="builtin_default",
            notes=notes,
        )
        for item in list(template.get("capabilities") or [])
    ]
    return servers, capabilities


def resolve_effective_mcp_policy_state(
    db: Session,
    *,
    endpoint: AiEndpoint | None = None,
    ai_endpoint_id: int | None = None,
) -> EffectiveMcpPolicyState:
    resolved_endpoint = endpoint
    resolved_endpoint_id = ai_endpoint_id
    if resolved_endpoint is None and ai_endpoint_id is not None:
        resolved_endpoint = db.get(AiEndpoint, ai_endpoint_id)
    if resolved_endpoint is not None:
        resolved_endpoint_id = int(resolved_endpoint.id)

    endpoint_servers: list[McpServerRegistry] = []
    endpoint_capabilities: list[McpCapabilityPolicy] = []
    if resolved_endpoint_id is not None:
        endpoint_servers, endpoint_capabilities = list_endpoint_mcp_policies(db, endpoint_id=resolved_endpoint_id)
    global_servers, global_capabilities = list_global_mcp_policies(db)

    target_type = get_ai_endpoint_target_type(resolved_endpoint) if resolved_endpoint is not None else None
    builtin_template_key: str | None = None
    builtin_servers: list[EffectiveMcpServerPolicy] = []
    builtin_capabilities: list[EffectiveMcpCapabilityPolicy] = []
    if (
        target_type == TARGET_TYPE_OPENCLAW_CONTROL
        and not endpoint_servers
        and not endpoint_capabilities
        and not global_servers
        and not global_capabilities
    ):
        builtin_template_key = DEFAULT_OPENCLAW_MCP_TEMPLATE_KEY
        builtin_servers, builtin_capabilities = _build_builtin_template_rows(
            template_key=builtin_template_key,
            ai_endpoint_id=resolved_endpoint_id,
        )

    return EffectiveMcpPolicyState(
        endpoint=resolved_endpoint,
        target_type=target_type,
        endpoint_servers=endpoint_servers,
        endpoint_capabilities=endpoint_capabilities,
        global_servers=global_servers,
        global_capabilities=global_capabilities,
        builtin_servers=builtin_servers,
        builtin_capabilities=builtin_capabilities,
        builtin_template_key=builtin_template_key,
    )


def has_mcp_policy_config(
    db: Session,
    ai_endpoint_id: int | None,
    *,
    endpoint: AiEndpoint | None = None,
) -> bool:
    return resolve_effective_mcp_policy_state(
        db,
        endpoint=endpoint,
        ai_endpoint_id=ai_endpoint_id,
    ).strict_allowlist


def find_mcp_server_policy_in_state(
    state: EffectiveMcpPolicyState,
    *,
    ai_endpoint_id: int | None,
    server_name: str,
) -> McpServerRegistry | EffectiveMcpServerPolicy | None:
    normalized_server = str(server_name or "").strip()
    if not normalized_server:
        return None

    candidates = [
        row
        for row in [*state.global_servers, *state.endpoint_servers]
        if _matches_pattern(str(getattr(row, "server_name", "") or ""), normalized_server)
    ]
    if candidates:
        return max(candidates, key=lambda row: _policy_row_sort_key(row, ai_endpoint_id=ai_endpoint_id))

    if not state.uses_builtin_defaults:
        return None

    builtin_candidates = [
        row
        for row in state.builtin_servers
        if _matches_pattern(str(getattr(row, "server_name", "") or ""), normalized_server)
    ]
    if not builtin_candidates:
        return None
    return max(builtin_candidates, key=lambda row: _policy_row_sort_key(row, ai_endpoint_id=ai_endpoint_id))


def find_mcp_capability_policy_in_state(
    state: EffectiveMcpPolicyState,
    *,
    ai_endpoint_id: int | None,
    server_name: str,
    capability_name: str,
) -> McpCapabilityPolicy | EffectiveMcpCapabilityPolicy | None:
    normalized_server = str(server_name or "").strip() or "*"
    normalized_capability = str(capability_name or "").strip()
    if not normalized_capability:
        return None

    candidates = [
        row
        for row in [*state.global_capabilities, *state.endpoint_capabilities]
        if _matches_pattern(str(getattr(row, "server_name", "") or ""), normalized_server)
        and _matches_pattern(str(getattr(row, "capability_name", "") or ""), normalized_capability)
    ]
    if candidates:
        return max(candidates, key=lambda row: _policy_row_sort_key(row, ai_endpoint_id=ai_endpoint_id))

    if not state.uses_builtin_defaults:
        return None

    builtin_candidates = [
        row
        for row in state.builtin_capabilities
        if _matches_pattern(str(getattr(row, "server_name", "") or ""), normalized_server)
        and _matches_pattern(str(getattr(row, "capability_name", "") or ""), normalized_capability)
    ]
    if not builtin_candidates:
        return None
    return max(builtin_candidates, key=lambda row: _policy_row_sort_key(row, ai_endpoint_id=ai_endpoint_id))


def find_mcp_server_policy(
    db: Session,
    *,
    ai_endpoint_id: int | None,
    server_name: str,
) -> McpServerRegistry | EffectiveMcpServerPolicy | None:
    state = resolve_effective_mcp_policy_state(db, ai_endpoint_id=ai_endpoint_id)
    return find_mcp_server_policy_in_state(
        state,
        ai_endpoint_id=ai_endpoint_id,
        server_name=server_name,
    )


def find_mcp_capability_policy(
    db: Session,
    *,
    ai_endpoint_id: int | None,
    server_name: str,
    capability_name: str,
) -> McpCapabilityPolicy | EffectiveMcpCapabilityPolicy | None:
    state = resolve_effective_mcp_policy_state(db, ai_endpoint_id=ai_endpoint_id)
    return find_mcp_capability_policy_in_state(
        state,
        ai_endpoint_id=ai_endpoint_id,
        server_name=server_name,
        capability_name=capability_name,
    )


def issue_mcp_execution_ticket(
    db: Session,
    *,
    task: AttackTask,
    runtime: ManagedRuntime | None,
    action: dict[str, Any],
    expires_in_seconds: int = 600,
) -> McpExecutionTicket | None:
    if not action_requires_mcp_ticket(action):
        return None

    now = utc_now()
    item = McpExecutionTicket(
        ticket_key=f"mcpt_{uuid4().hex[:28]}",
        task_id=task.id,
        runtime_id=runtime.id if runtime is not None else None,
        ai_endpoint_id=resolve_task_ai_endpoint_id(task),
        status=MCP_TICKET_STATUS_ISSUED,
        action_type=str(action.get("action_type") or "").strip(),
        session_id=str(action.get("session_id") or "").strip(),
        mcp_server=str(action.get("mcp_server") or "").strip(),
        capability_name=str(action.get("capability_name") or "").strip(),
        call_id=str(action.get("call_id") or "").strip(),
        tool_call_id=str(action.get("tool_call_id") or "").strip(),
        source_plugin=str(action.get("source_plugin") or "").strip(),
        target_plugin=str(action.get("target_plugin") or "").strip(),
        handoff_token=str(action.get("handoff_token") or "").strip(),
        approval_id=str(action.get("approval_id") or "").strip(),
        args_hash=str(action.get("request_args_hash") or action.get("args_hash") or "").strip(),
        issued_at=now,
        expires_at=now + timedelta(seconds=max(60, int(expires_in_seconds))),
    )
    item.set_requested_scopes(_normalize_scope_list(action.get("requested_scopes")))
    item.set_meta(
        {
            "operation_type": _normalize_token(action.get("operation_type")),
            "event_name": str(action.get("event_name") or "").strip(),
            "runtime_name": str(action.get("runtime_name") or "").strip(),
        }
    )
    db.add(item)
    db.flush()
    return item


def validate_mcp_execution_ticket(
    db: Session,
    *,
    ticket_key: str,
    task_id: int | None = None,
    runtime_id: int | None = None,
    ai_endpoint_id: int | None = None,
    action: dict[str, Any] | None = None,
    consume: bool = False,
) -> McpTicketValidationResult:
    normalized_key = str(ticket_key or "").strip()
    if not normalized_key:
        return McpTicketValidationResult(False, "missing_ticket", "MCP execution ticket is missing.")

    item = (
        db.query(McpExecutionTicket)
        .filter(McpExecutionTicket.ticket_key == normalized_key)
        .order_by(McpExecutionTicket.id.desc())
        .first()
    )
    if item is None:
        return McpTicketValidationResult(False, "unknown_ticket", "MCP execution ticket was not recognized.")

    now = utc_now()
    if item.status == MCP_TICKET_STATUS_ISSUED and item.expires_at is not None and item.expires_at < now:
        item.status = MCP_TICKET_STATUS_EXPIRED
        db.flush()
        return McpTicketValidationResult(False, "expired_ticket", "MCP execution ticket has expired.", ticket=item)

    if item.status != MCP_TICKET_STATUS_ISSUED:
        return McpTicketValidationResult(False, "ticket_replay", "MCP execution ticket has already been consumed.", ticket=item)

    if task_id is not None and item.task_id != task_id:
        return McpTicketValidationResult(False, "task_mismatch", "MCP execution ticket does not belong to this task.", ticket=item)

    if runtime_id is not None and item.runtime_id not in {None, runtime_id}:
        return McpTicketValidationResult(False, "runtime_mismatch", "MCP execution ticket does not belong to this runtime.", ticket=item)

    if ai_endpoint_id is not None and item.ai_endpoint_id not in {None, ai_endpoint_id}:
        return McpTicketValidationResult(False, "endpoint_mismatch", "MCP execution ticket does not belong to this AI target.", ticket=item)

    candidate = dict(action or {})
    for field_name, mismatch_reason in (
        ("session_id", "MCP session binding does not match the issued ticket."),
        ("mcp_server", "MCP server binding does not match the issued ticket."),
        ("capability_name", "MCP capability binding does not match the issued ticket."),
        ("tool_call_id", "MCP tool_call binding does not match the issued ticket."),
        ("call_id", "MCP request binding does not match the issued ticket."),
        ("source_plugin", "MCP source plugin binding does not match the issued ticket."),
        ("target_plugin", "MCP target plugin binding does not match the issued ticket."),
    ):
        expected = str(candidate.get(field_name) or "").strip()
        actual = str(getattr(item, field_name) or "").strip()
        if expected and actual and expected != actual:
            return McpTicketValidationResult(False, f"{field_name}_mismatch", mismatch_reason, ticket=item)

    requested_scopes = {scope.lower() for scope in _normalize_scope_list(candidate.get("requested_scopes"))}
    allowed_scopes = {scope.lower() for scope in item.requested_scopes}
    if requested_scopes:
        if not allowed_scopes or not requested_scopes.issubset(allowed_scopes):
            return McpTicketValidationResult(
                False,
                "scope_mismatch",
                "MCP execution ticket scopes do not cover the current action.",
                ticket=item,
            )

    args_hash = str(candidate.get("request_args_hash") or candidate.get("args_hash") or "").strip()
    if args_hash and item.args_hash and args_hash != item.args_hash:
        return McpTicketValidationResult(
            False,
            "args_hash_mismatch",
            "MCP execution ticket does not match the original request arguments.",
            ticket=item,
        )

    if consume:
        item.status = MCP_TICKET_STATUS_CONSUMED
        item.consumed_at = now
        db.flush()

    return McpTicketValidationResult(True, "ok", "MCP execution ticket validated.", ticket=item)


def _normalize_scope_list(value: Any) -> list[str]:
    items: list[str] = []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            items.append(stripped)
    elif isinstance(value, (list, tuple, set)):
        for entry in value:
            if isinstance(entry, str):
                stripped = entry.strip()
                if stripped:
                    items.append(stripped)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(item)
    return deduped


def _matches_pattern(pattern: str, value: str) -> bool:
    normalized_pattern = str(pattern or "").strip() or "*"
    normalized_value = str(value or "").strip()
    if not normalized_value:
        return False
    return fnmatch.fnmatch(normalized_value.lower(), normalized_pattern.lower())


def _normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text.replace(".", "_")


def normalize_mcp_server_name(value: Any, *, allow_wildcard: bool = False) -> str:
    text = str(value or "").strip()
    if text:
        return text
    return "*" if allow_wildcard else ""


def normalize_mcp_capability_name(value: Any) -> str:
    return str(value or "").strip()


def normalize_mcp_trust_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in MCP_TRUST_MODES:
        return normalized
    return "trusted"


def normalize_mcp_approval_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in MCP_APPROVAL_MODES:
        return normalized
    return "inherit"


def normalize_mcp_risk_level(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in MCP_RISK_LEVELS:
        return normalized
    return "medium"


def serialize_mcp_server_policy(item: McpServerRegistry) -> dict[str, Any]:
    meta = item.meta
    return {
        "id": item.id,
        "server_name": item.server_name,
        "server_label": item.server_label,
        "enabled": bool(item.enabled),
        "trust_mode": normalize_mcp_trust_mode(item.trust_mode),
        "require_ticket": bool(item.require_ticket),
        "require_approval": bool(item.require_approval),
        "allowed_scopes": _normalize_scope_list(item.allowed_scopes),
        "template_key": str(meta.get("template_key") or "").strip() or None,
        "managed_by": str(meta.get("managed_by") or "").strip() or None,
        "notes": str(meta.get("notes") or "").strip() or None,
        "meta": meta,
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
    }


def serialize_mcp_capability_policy(item: McpCapabilityPolicy) -> dict[str, Any]:
    meta = item.meta
    return {
        "id": item.id,
        "server_name": item.server_name or "*",
        "capability_name": item.capability_name,
        "capability_label": item.capability_label,
        "enabled": bool(item.enabled),
        "risk_level": normalize_mcp_risk_level(item.risk_level),
        "approval_mode": normalize_mcp_approval_mode(item.approval_mode),
        "allowed_scopes": _normalize_scope_list(item.allowed_scopes),
        "template_key": str(meta.get("template_key") or "").strip() or None,
        "managed_by": str(meta.get("managed_by") or "").strip() or None,
        "notes": str(meta.get("notes") or "").strip() or None,
        "meta": meta,
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
    }


def list_predefined_mcp_policy_templates() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key, definition in PREDEFINED_MCP_POLICY_TEMPLATES.items():
        items.append(
            {
                "key": key,
                "label": str(definition.get("label") or key),
                "description": str(definition.get("description") or "").strip(),
                "recommended": bool(definition.get("recommended")),
                "server_count": len(definition.get("servers") or []),
                "capability_count": len(definition.get("capabilities") or []),
            }
        )
    return items


def get_predefined_mcp_policy_template(template_key: str) -> dict[str, Any] | None:
    normalized_key = str(template_key or "").strip()
    if not normalized_key:
        return None
    return PREDEFINED_MCP_POLICY_TEMPLATES.get(normalized_key)


def list_endpoint_mcp_policies(
    db: Session,
    *,
    endpoint_id: int,
) -> tuple[list[McpServerRegistry], list[McpCapabilityPolicy]]:
    servers = (
        db.query(McpServerRegistry)
        .filter(McpServerRegistry.ai_endpoint_id == endpoint_id)
        .order_by(McpServerRegistry.server_name.asc(), McpServerRegistry.id.asc())
        .all()
    )
    capabilities = (
        db.query(McpCapabilityPolicy)
        .filter(McpCapabilityPolicy.ai_endpoint_id == endpoint_id)
        .order_by(McpCapabilityPolicy.server_name.asc(), McpCapabilityPolicy.capability_name.asc(), McpCapabilityPolicy.id.asc())
        .all()
    )
    return servers, capabilities


def list_global_mcp_policies(db: Session) -> tuple[list[McpServerRegistry], list[McpCapabilityPolicy]]:
    servers = (
        db.query(McpServerRegistry)
        .filter(McpServerRegistry.ai_endpoint_id.is_(None))
        .order_by(McpServerRegistry.server_name.asc(), McpServerRegistry.id.asc())
        .all()
    )
    capabilities = (
        db.query(McpCapabilityPolicy)
        .filter(McpCapabilityPolicy.ai_endpoint_id.is_(None))
        .order_by(McpCapabilityPolicy.server_name.asc(), McpCapabilityPolicy.capability_name.asc(), McpCapabilityPolicy.id.asc())
        .all()
    )
    return servers, capabilities


def delete_endpoint_mcp_policy_rows(db: Session, endpoint_id: int) -> dict[str, int]:
    server_rows, capability_rows = list_endpoint_mcp_policies(db, endpoint_id=endpoint_id)
    for row in server_rows:
        db.delete(row)
    for row in capability_rows:
        db.delete(row)
    db.flush()
    return {
        "deleted_servers": len(server_rows),
        "deleted_capabilities": len(capability_rows),
    }


def replace_endpoint_mcp_policy(
    db: Session,
    *,
    endpoint_id: int,
    servers: list[dict[str, Any]] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    template_key: str | None = None,
) -> dict[str, Any]:
    deleted = delete_endpoint_mcp_policy_rows(db, endpoint_id)
    normalized_template_key = str(template_key or "").strip()
    template_meta = {
        "template_key": normalized_template_key,
        "managed_by": "template",
    } if normalized_template_key else {}

    server_map: dict[str, dict[str, Any]] = {}
    for raw_item in servers or []:
        item = dict(raw_item or {})
        server_name = normalize_mcp_server_name(item.get("server_name"))
        if not server_name:
            continue
        server_map[server_name.lower()] = {
            "server_name": server_name,
            "server_label": str(item.get("server_label") or "").strip() or server_name,
            "enabled": bool(item.get("enabled", True)),
            "trust_mode": normalize_mcp_trust_mode(item.get("trust_mode")),
            "require_ticket": bool(item.get("require_ticket", True)),
            "require_approval": bool(item.get("require_approval", False)),
            "allowed_scopes": _normalize_scope_list(item.get("allowed_scopes")),
            "meta": {
                **template_meta,
                **dict(item.get("meta") or {}),
            },
        }

    capability_map: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_item in capabilities or []:
        item = dict(raw_item or {})
        server_name = normalize_mcp_server_name(item.get("server_name"), allow_wildcard=True)
        capability_name = normalize_mcp_capability_name(item.get("capability_name"))
        if not capability_name:
            continue
        capability_map[(server_name.lower(), capability_name.lower())] = {
            "server_name": server_name,
            "capability_name": capability_name,
            "capability_label": str(item.get("capability_label") or "").strip() or capability_name,
            "enabled": bool(item.get("enabled", True)),
            "risk_level": normalize_mcp_risk_level(item.get("risk_level")),
            "approval_mode": normalize_mcp_approval_mode(item.get("approval_mode")),
            "allowed_scopes": _normalize_scope_list(item.get("allowed_scopes")),
            "meta": {
                **template_meta,
                **dict(item.get("meta") or {}),
            },
        }

    created_servers: list[McpServerRegistry] = []
    created_capabilities: list[McpCapabilityPolicy] = []
    for item in server_map.values():
        row = McpServerRegistry(
            ai_endpoint_id=endpoint_id,
            server_name=item["server_name"],
            server_label=item["server_label"],
            enabled=item["enabled"],
            trust_mode=item["trust_mode"],
            require_ticket=item["require_ticket"],
            require_approval=item["require_approval"],
        )
        row.set_allowed_scopes(item["allowed_scopes"])
        row.set_meta(item["meta"])
        db.add(row)
        created_servers.append(row)

    for item in capability_map.values():
        row = McpCapabilityPolicy(
            ai_endpoint_id=endpoint_id,
            server_name=item["server_name"],
            capability_name=item["capability_name"],
            capability_label=item["capability_label"],
            enabled=item["enabled"],
            risk_level=item["risk_level"],
            approval_mode=item["approval_mode"],
        )
        row.set_allowed_scopes(item["allowed_scopes"])
        row.set_meta(item["meta"])
        db.add(row)
        created_capabilities.append(row)

    db.flush()
    return {
        "deleted": deleted,
        "servers": [serialize_mcp_server_policy(item) for item in created_servers],
        "capabilities": [serialize_mcp_capability_policy(item) for item in created_capabilities],
    }


def apply_predefined_mcp_policy_template(
    db: Session,
    *,
    endpoint_id: int,
    template_key: str,
) -> dict[str, Any]:
    template = get_predefined_mcp_policy_template(template_key)
    if template is None:
        raise ValueError(f"unknown MCP policy template: {template_key}")
    return replace_endpoint_mcp_policy(
        db,
        endpoint_id=endpoint_id,
        servers=list(template.get("servers") or []),
        capabilities=list(template.get("capabilities") or []),
        template_key=template_key,
    )


def detect_endpoint_mcp_template_key(
    servers: list[McpServerRegistry],
    capabilities: list[McpCapabilityPolicy],
) -> str | None:
    rows = [*servers, *capabilities]
    if not rows:
        return None
    template_keys = {
        str(row.meta.get("template_key") or "").strip()
        for row in rows
        if str(row.meta.get("template_key") or "").strip()
    }
    if len(template_keys) != 1:
        return None
    return next(iter(template_keys))


def build_ai_endpoint_mcp_policy_profile(
    db: Session,
    *,
    endpoint: Any,
) -> dict[str, Any]:
    state = resolve_effective_mcp_policy_state(db, endpoint=endpoint, ai_endpoint_id=int(endpoint.id))
    template_key = detect_endpoint_mcp_template_key(state.endpoint_servers, state.endpoint_capabilities)
    matched_template_key = template_key or state.builtin_template_key
    visible_servers: list[Any] = state.endpoint_servers
    visible_capabilities: list[Any] = state.endpoint_capabilities
    compatibility_note = (
        "Once endpoint-level or global MCP rows exist, MCP/tool calls switch into strict allowlist mode."
        if not state.strict_allowlist
        else "Endpoint-level or global MCP policy rows are enforcing a strict allowlist."
    )
    if state.uses_builtin_defaults:
        visible_servers = state.builtin_servers
        visible_capabilities = state.builtin_capabilities
        compatibility_note = (
            "No endpoint/global MCP rows exist yet. OpenClaw targets still use the built-in hardened allowlist "
            f"template `{state.builtin_template_key}` until you save an explicit policy."
        )
    return {
        "endpoint": {
            "id": int(endpoint.id),
            "endpoint_key": str(endpoint.endpoint_key or "").strip(),
            "display_name": str(endpoint.display_name or endpoint.endpoint_key or "").strip(),
            "provider_type": str(endpoint.provider_type or "").strip(),
            "target_type": state.target_type or "",
            "protection_enabled": bool(endpoint.protection_enabled),
            "protection_mode": str(endpoint.protection_mode or "").strip(),
        },
        "policy_summary": {
            "endpoint_server_count": len(state.endpoint_servers),
            "endpoint_capability_count": len(state.endpoint_capabilities),
            "global_server_count": len(state.global_servers),
            "global_capability_count": len(state.global_capabilities),
            "effective_server_count": len(visible_servers),
            "effective_capability_count": len(visible_capabilities),
            "inherits_global_defaults": bool(state.global_servers or state.global_capabilities) and not bool(state.endpoint_servers or state.endpoint_capabilities),
            "uses_builtin_defaults": state.uses_builtin_defaults,
            "effective_mode": "strict_allowlist" if state.strict_allowlist else "compatibility_mode",
            "matched_template_key": matched_template_key,
            "builtin_template_key": state.builtin_template_key,
            "compatibility_note": compatibility_note,
        },
        "templates": list_predefined_mcp_policy_templates(),
        "servers": [serialize_mcp_server_policy(item) for item in visible_servers],
        "capabilities": [serialize_mcp_capability_policy(item) for item in visible_capabilities],
        "catalog": {
            "trust_modes": list(MCP_TRUST_MODES),
            "approval_modes": list(MCP_APPROVAL_MODES),
            "risk_levels": list(MCP_RISK_LEVELS),
            "scope_options": list(MCP_SCOPE_CATALOG),
            "server_suggestions": list(MCP_SERVER_CATALOG),
            "capability_suggestions": list(MCP_CAPABILITY_CATALOG),
        },
    }
