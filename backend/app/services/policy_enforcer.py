from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..models import Asset, AssetWhitelist, AttackTask, Skill
from .endpoint_governance import resolve_control_modes
from .mcp_security import (
    action_has_mcp_surface,
    action_is_tool_result,
    find_mcp_capability_policy_in_state,
    find_mcp_server_policy_in_state,
    resolve_effective_mcp_policy_state,
    validate_mcp_execution_ticket,
)
from .task_runner import (
    _assess_task_with_rules,
    _get_defense_policy_or_default,
    _serialize_rule_assessment,
    _task_profile,
)
from .time_utils import format_beijing, utc_now


DECISION_ALLOW = "allow"
DECISION_REVIEW = "review"
DECISION_DENY = "deny"

ACTION_TASK_EXECUTION = "task_execution"

HIGH_RISK_SCOPES = {
    "write",
    "shell",
    "network",
    "filesystem_write",
    "database_write",
    "secrets",
    "privileged",
}
RESTRICTED_APPROVAL_SCOPES = {
    "request",
    "navigate",
    "workspace.scan",
    "write",
    "delete",
    "exec",
    "shell",
    "network",
}
RESTRICTED_RISK_LEVELS = {"medium", "high"}

RULE_CONTROL_MAP: dict[str, tuple[str, ...]] = {
    "intent-scan": ("prompt_injection_firewall",),
    "secret-pattern-scan": ("prompt_injection_firewall", "output_redaction_gate"),
    "approval-persuasion-scan": ("prompt_injection_firewall", "approval_integrity_gate"),
    "approval-social-engineering-scan": ("prompt_injection_firewall", "approval_integrity_gate"),
    "external-content-scan": ("indirect_content_isolation",),
    "indirect-instruction-quarantine": ("indirect_content_isolation",),
    "retrieval-boundary-scan": ("indirect_content_isolation",),
    "tool-result-scan": ("indirect_content_isolation",),
    "tool-poisoning-scan": ("indirect_content_isolation", "tool_permission_broker"),
    "tool-approval-gate": ("tool_permission_broker", "approval_integrity_gate"),
    "workspace-scan": ("tool_permission_broker", "mcp_capability_binding", "cross_plugin_handoff_guard"),
    "mcp-tool-poisoning-scan": ("mcp_capability_binding", "cross_plugin_handoff_guard", "tool_permission_broker"),
    "mcp-session-bind": ("mcp_capability_binding",),
    "cross-plugin-proof": ("cross_plugin_handoff_guard",),
    "memory-write-guard": ("memory_taint_guard",),
    "memory-escalation-scan": ("memory_taint_guard",),
    "output-sanitize": ("output_redaction_gate",),
    "pii-exfiltration-scan": ("output_redaction_gate",),
    "prompt-leakage-scan": ("prompt_injection_firewall", "output_redaction_gate"),
    "canary-leak-scan": ("output_redaction_gate",),
    "encoding-evasion-scan": ("prompt_injection_firewall", "indirect_content_isolation"),
    "ansi-control-scan": ("prompt_injection_firewall", "indirect_content_isolation"),
}


@dataclass
class AuthorizationIssue:
    decision: str
    control: str
    rule: str
    summary: str
    detail: str
    target: str = ""


@dataclass
class AuthorizationDecision:
    decision: str
    summary: str
    detail: str
    matched_rules: list[str]
    matched_controls: list[str]
    issues: list[AuthorizationIssue]
    control_modes: dict[str, str]
    task_rule_assessment: dict[str, Any] | None
    context: dict[str, Any]


def serialize_authorization_issue(item: AuthorizationIssue) -> dict[str, Any]:
    return {
        "decision": item.decision,
        "control": item.control,
        "rule": item.rule,
        "summary": item.summary,
        "detail": item.detail,
        "target": item.target,
    }


def serialize_authorization_decision(item: AuthorizationDecision) -> dict[str, Any]:
    return {
        "decision": item.decision,
        "allowed": item.decision != DECISION_DENY,
        "requires_review": item.decision == DECISION_REVIEW,
        "summary": item.summary,
        "detail": item.detail,
        "matched_rules": list(item.matched_rules),
        "matched_controls": list(item.matched_controls),
        "issues": [serialize_authorization_issue(issue) for issue in item.issues],
        "control_modes": dict(item.control_modes),
        "task_rule_assessment": item.task_rule_assessment,
        "context": item.context,
    }


def append_task_authorization_snapshot(
    task: AttackTask,
    *,
    action: dict[str, Any],
    decision: AuthorizationDecision,
) -> None:
    params = dict(task.params)
    runtime_state = dict(params.get("runtime") or {})
    history = list(runtime_state.get("authorizations") or [])
    snapshot = {
        "authorized_at": format_beijing(utc_now()) or "",
        "action": action,
        "result": serialize_authorization_decision(decision),
    }
    history.append(snapshot)
    runtime_state["authorizations"] = history[-20:]
    runtime_state["last_authorization"] = snapshot
    params["runtime"] = runtime_state
    task.set_params(params)


def authorize_task_preflight(
    db: Session,
    task: AttackTask,
    action: dict[str, Any] | None = None,
) -> AuthorizationDecision:
    payload = _normalize_action_payload(task, action or {})
    return _authorize(db, task=task, payload=payload)


def authorize_runtime_action(
    db: Session,
    task: AttackTask,
    action: dict[str, Any],
) -> AuthorizationDecision:
    payload = _normalize_action_payload(task, action)
    return _authorize(db, task=task, payload=payload)


def _authorize(db: Session, *, task: AttackTask, payload: dict[str, Any]) -> AuthorizationDecision:
    raw_endpoint_id = task.params.get("ai_endpoint_id")
    ai_endpoint_id = raw_endpoint_id if isinstance(raw_endpoint_id, int) else None
    if ai_endpoint_id is None and isinstance(raw_endpoint_id, str) and raw_endpoint_id.strip().isdigit():
        ai_endpoint_id = int(raw_endpoint_id.strip())
    policy = _get_defense_policy_or_default(db, ai_endpoint_id=ai_endpoint_id)
    control_modes = _load_control_modes(db, ai_endpoint_id=ai_endpoint_id)
    issues: list[AuthorizationIssue] = []
    issue_keys: set[tuple[str, str, str, str]] = set()
    matched_rules: list[str] = []
    matched_controls: list[str] = []
    decision = DECISION_ALLOW

    def add_issue(
        control: str,
        rule: str,
        enforce_decision: str,
        summary: str,
        detail: str,
        *,
        target: str = "",
    ) -> None:
        nonlocal decision

        mode = control_modes.get(control, "off")
        if mode == "off":
            return

        effective_decision = enforce_decision if mode == "enforce" else DECISION_REVIEW
        issue_key = (effective_decision, control, rule, target or detail)
        if issue_key in issue_keys:
            return
        issue_keys.add(issue_key)

        issues.append(
            AuthorizationIssue(
                decision=effective_decision,
                control=control,
                rule=rule,
                summary=summary,
                detail=detail,
                target=target,
            )
        )
        if rule and rule not in matched_rules:
            matched_rules.append(rule)
        if control and control not in matched_controls:
            matched_controls.append(control)
        decision = _escalate_decision(decision, effective_decision)

    profile = _task_profile(task.attack_type)
    rule_assessment = _assess_task_with_rules(task, profile, policy)
    task_rule_assessment = _serialize_rule_assessment(rule_assessment)

    desired_decision = DECISION_DENY if rule_assessment.verdict == "blocked" else DECISION_REVIEW
    if rule_assessment.verdict in {"blocked", "suspicious"}:
        mapped_controls: set[str] = set()
        for rule_key in rule_assessment.hit_rules:
            normalized_rule = str(rule_key).strip().lower()
            for control in RULE_CONTROL_MAP.get(normalized_rule, ()):
                mapped_controls.add(control)
                add_issue(
                    control,
                    normalized_rule,
                    desired_decision,
                    f"Task preflight hit control {control}",
                    rule_assessment.detail or rule_assessment.summary,
                )
        if not mapped_controls:
            add_issue(
                "prompt_injection_firewall",
                "intent-scan",
                desired_decision,
                "Task preflight hit a high-risk instruction pattern",
                rule_assessment.detail or rule_assessment.summary,
            )

    _apply_path_checks(db, payload, policy.protected_paths if policy is not None else [], add_issue)
    _apply_skill_checks(db, payload, policy.protected_skills if policy is not None else [], add_issue)
    _apply_plugin_checks(db, payload, policy.protected_plugins if policy is not None else [], add_issue)
    _apply_mcp_checks(db, task=task, ai_endpoint_id=ai_endpoint_id, payload=payload, add_issue=add_issue)
    _apply_approval_checks(payload, add_issue)

    if decision == DECISION_ALLOW:
        summary = "Preflight authorization passed."
        detail = "The action did not hit any enabled preflight restriction."
    elif decision == DECISION_DENY:
        summary = f"Preflight authorization denied after hitting {len(issues)} control(s)."
        detail = "; ".join(issue.detail for issue in issues[:4])
    else:
        summary = f"Preflight authorization requires review after hitting {len(issues)} control(s)."
        detail = "; ".join(issue.detail for issue in issues[:4])

    return AuthorizationDecision(
        decision=decision,
        summary=summary,
        detail=detail,
        matched_rules=matched_rules,
        matched_controls=matched_controls,
        issues=issues,
        control_modes=control_modes,
        task_rule_assessment=task_rule_assessment,
        context=payload,
    )


def _normalize_action_payload(task: AttackTask, action: dict[str, Any]) -> dict[str, Any]:
    params = task.params
    metadata = dict(action.get("metadata") or {})

    payload = {
        "action_type": str(action.get("action_type") or ACTION_TASK_EXECUTION).strip().lower() or ACTION_TASK_EXECUTION,
        "runtime_name": str(action.get("runtime_name") or task.runtime_name or "").strip(),
        "runtime_task_ref": str(action.get("runtime_task_ref") or task.runtime_task_ref or "").strip(),
        "input_text": str(action.get("input_text") or "").strip(),
        "paths": _normalize_string_list(
            action.get("paths"),
            action.get("target_path"),
            params.get("paths"),
            params.get("target_path"),
            params.get("asset_path"),
            params.get("file_path"),
            params.get("path"),
        ),
        "skill_names": _normalize_string_list(
            action.get("skill_names"),
            action.get("skill_name"),
            params.get("skill_names"),
            params.get("skill_name"),
        ),
        "plugin_names": _normalize_string_list(
            action.get("plugin_names"),
            action.get("plugin_name"),
            params.get("plugin_names"),
            params.get("plugin_name"),
        ),
        "call_id": str(action.get("call_id") or metadata.get("ws_call_id") or params.get("call_id") or "").strip(),
        "source_plugin": str(action.get("source_plugin") or metadata.get("source_plugin") or params.get("source_plugin") or "").strip(),
        "target_plugin": str(action.get("target_plugin") or metadata.get("target_plugin") or params.get("target_plugin") or "").strip(),
        "mcp_server": str(action.get("mcp_server") or metadata.get("mcp_server") or params.get("mcp_server") or "").strip(),
        "capability_name": str(action.get("capability_name") or metadata.get("capability_name") or params.get("capability_name") or "").strip(),
        "session_id": str(action.get("session_id") or metadata.get("session_id") or params.get("session_id") or "").strip(),
        "approval_id": str(action.get("approval_id") or metadata.get("approval_id") or params.get("approval_id") or "").strip(),
        "handoff_token": str(action.get("handoff_token") or metadata.get("handoff_token") or params.get("handoff_token") or "").strip(),
        "tool_call_id": str(
            action.get("tool_call_id")
            or metadata.get("tool_call_id")
            or metadata.get("openclaw_tool_call_id")
            or params.get("tool_call_id")
            or ""
        ).strip(),
        "operation_type": str(
            action.get("operation_type")
            or metadata.get("operation_type")
            or metadata.get("openclaw_operation_type")
            or params.get("operation_type")
            or ""
        ).strip().lower(),
        "event_name": str(
            action.get("event_name")
            or metadata.get("event_name")
            or metadata.get("openclaw_event_name")
            or params.get("event_name")
            or ""
        ).strip(),
        "mcp_ticket_key": str(
            action.get("mcp_ticket_key")
            or metadata.get("mcp_ticket_key")
            or params.get("mcp_ticket_key")
            or ""
        ).strip(),
        "request_args_hash": str(
            action.get("request_args_hash")
            or metadata.get("request_args_hash")
            or params.get("request_args_hash")
            or ""
        ).strip(),
        "consume_mcp_ticket": bool(
            action.get("consume_mcp_ticket")
            or metadata.get("consume_mcp_ticket")
            or params.get("consume_mcp_ticket")
        ),
        "requested_scopes": _normalize_string_list(
            action.get("requested_scopes"),
            metadata.get("requested_scopes"),
            params.get("requested_scopes"),
        ),
        "metadata": metadata,
    }

    if not payload["input_text"]:
        payload["input_text"] = str(metadata.get("message") or metadata.get("prompt") or "")
    return payload


def _apply_path_checks(
    db: Session,
    payload: dict[str, Any],
    protected_paths: list[str],
    add_issue,
) -> None:
    target_paths = payload["paths"]
    if not target_paths:
        return

    assets = db.query(Asset).filter(Asset.asset_type == "path").order_by(Asset.id.asc()).all()
    whitelist_rows = db.query(AssetWhitelist).order_by(AssetWhitelist.id.asc()).all()
    whitelists_by_asset: dict[int, list[AssetWhitelist]] = {}
    for row in whitelist_rows:
        whitelists_by_asset.setdefault(row.asset_id, []).append(row)

    for target_path in target_paths:
        normalized_target = _normalize_path(target_path)
        if not normalized_target:
            continue

        matched_assets = [
            item
            for item in assets
            if item.status != "disabled" and _path_is_within(normalized_target, item.asset_path)
        ]
        matched_policy_paths = [item for item in protected_paths if _path_is_within(normalized_target, item)]

        if not matched_assets and not matched_policy_paths:
            continue

        if _is_path_whitelisted(
            normalized_target,
            matched_assets,
            whitelists_by_asset,
            payload["skill_names"],
            _candidate_plugin_names(payload),
        ):
            continue

        highest_risk_asset = next((item for item in matched_assets if item.status == "protected"), None)
        enforce_decision = DECISION_DENY if highest_risk_asset is not None or matched_policy_paths else DECISION_REVIEW
        detail_parts: list[str] = []
        if matched_assets:
            detail_parts.append("matched assets: " + ", ".join(item.asset_name for item in matched_assets))
        if matched_policy_paths:
            detail_parts.append(
                "matched policy paths: " + ", ".join(sorted({_normalize_path(item) for item in matched_policy_paths}))
            )

        add_issue(
            "tool_permission_broker",
            "tool-approval-gate",
            enforce_decision,
            "Path access requires preflight authorization",
            f"Path {normalized_target} did not match an allowlist entry; " + "; ".join(detail_parts),
            target=normalized_target,
        )


def _apply_skill_checks(
    db: Session,
    payload: dict[str, Any],
    protected_skills: list[str],
    add_issue,
) -> None:
    skill_names = payload["skill_names"]
    if not skill_names:
        return

    skills = db.query(Skill).order_by(Skill.id.asc()).all()
    skill_map = {item.skill_name.lower(): item for item in skills}

    for name in skill_names:
        skill = skill_map.get(name.lower())
        is_protected = _matches_any_pattern(name, protected_skills)

        if skill is not None and skill.trust_status == "trusted":
            continue

        if skill is not None and skill.trust_status == "pending":
            add_issue(
                "tool_permission_broker",
                "workspace-scan",
                DECISION_REVIEW,
                "Skill invocation requires review",
                f"Skill {name} is still pending trust approval.",
                target=name,
            )
            continue

        if is_protected:
            add_issue(
                "tool_permission_broker",
                "workspace-scan",
                DECISION_DENY,
                "Protected skill invocation was denied",
                f"Skill {name} is protected but was not resolved as trusted.",
                target=name,
            )
            continue

        add_issue(
            "tool_permission_broker",
            "workspace-scan",
            DECISION_REVIEW,
            "Unknown skill invocation requires review",
            f"Skill {name} was not found in the trusted skill registry.",
            target=name,
        )


def _apply_plugin_checks(
    db: Session,
    payload: dict[str, Any],
    protected_plugins: list[str],
    add_issue,
) -> None:
    plugin_names = _candidate_plugin_names(payload)
    if not plugin_names:
        return

    skills = db.query(Skill).order_by(Skill.id.asc()).all()
    plugin_map = {
        item.skill_name.lower(): item
        for item in skills
        if str(item.skill_type).strip().lower() == "plugin"
    }

    for name in plugin_names:
        plugin = plugin_map.get(name.lower())
        is_protected = _matches_any_pattern(name, protected_plugins)

        if plugin is not None and plugin.trust_status == "trusted":
            continue

        if plugin is not None and plugin.trust_status == "pending":
            add_issue(
                "cross_plugin_handoff_guard",
                "cross-plugin-proof",
                DECISION_REVIEW,
                "Plugin invocation requires review",
                f"Plugin {name} is still pending trust approval.",
                target=name,
            )
            continue

        if is_protected:
            add_issue(
                "cross_plugin_handoff_guard",
                "cross-plugin-proof",
                DECISION_DENY,
                "Protected plugin invocation was denied",
                f"Plugin {name} is protected but was not resolved as trusted.",
                target=name,
            )

    source_plugin = payload["source_plugin"]
    target_plugin = payload["target_plugin"]
    if source_plugin and target_plugin and source_plugin != target_plugin and not payload["handoff_token"]:
        add_issue(
            "cross_plugin_handoff_guard",
            "cross-plugin-proof",
            DECISION_DENY,
            "Cross-plugin handoff is missing proof",
            f"Handoff from {source_plugin} to {target_plugin} did not include handoff_token.",
            target=f"{source_plugin}->{target_plugin}",
        )


def _apply_mcp_checks(
    db: Session,
    *,
    task: AttackTask,
    ai_endpoint_id: int | None,
    payload: dict[str, Any],
    add_issue,
) -> None:
    if not action_has_mcp_surface(payload):
        return

    target = payload["capability_name"] or payload["mcp_server"] or payload["tool_call_id"] or payload["call_id"]
    requested_scopes = {item.lower() for item in payload["requested_scopes"]}
    state = resolve_effective_mcp_policy_state(db, ai_endpoint_id=ai_endpoint_id)
    explicit_registry = state.strict_allowlist
    server_policy = find_mcp_server_policy_in_state(
        state,
        ai_endpoint_id=ai_endpoint_id,
        server_name=payload["mcp_server"],
    )
    capability_policy = find_mcp_capability_policy_in_state(
        state,
        ai_endpoint_id=ai_endpoint_id,
        server_name=payload["mcp_server"],
        capability_name=payload["capability_name"],
    )

    if explicit_registry:
        if payload["mcp_server"] and server_policy is None:
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP server is not in the allowlist",
                f"MCP server {payload['mcp_server']} is not registered for this AI target.",
                target=target,
            )
        if payload["capability_name"] and capability_policy is None:
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP capability is not in the allowlist",
                f"MCP capability {payload['capability_name']} is not registered for this AI target.",
                target=target,
            )

    if server_policy is not None:
        trust_mode = str(server_policy.trust_mode or "").strip().lower()
        if not server_policy.enabled or trust_mode == "blocked":
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP server is blocked",
                f"MCP server {payload['mcp_server']} is disabled or blocked by policy.",
                target=target,
            )
        allowed_scopes = {item.lower() for item in server_policy.allowed_scopes}
        if requested_scopes and allowed_scopes and not requested_scopes.issubset(allowed_scopes):
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP server scope escalation was blocked",
                f"MCP server {payload['mcp_server']} only allows scopes {sorted(allowed_scopes)}.",
                target=target,
            )
        if server_policy.require_approval and not payload["approval_id"]:
            add_issue(
                "approval_integrity_gate",
                "tool-approval-gate",
                DECISION_DENY,
                "MCP server requires approval proof",
                f"MCP server {payload['mcp_server']} requires approval_id before execution.",
                target=target,
            )
        if trust_mode == "restricted" and not payload["approval_id"] and requested_scopes & RESTRICTED_APPROVAL_SCOPES:
            add_issue(
                "approval_integrity_gate",
                "tool-approval-gate",
                DECISION_DENY,
                "Restricted MCP server requires approval for sensitive scopes",
                f"MCP server {payload['mcp_server']} is restricted and sensitive scopes {sorted(requested_scopes & RESTRICTED_APPROVAL_SCOPES)} require approval_id.",
                target=target,
            )

    if capability_policy is not None:
        approval_mode = str(capability_policy.approval_mode or "").strip().lower()
        risk_level = str(capability_policy.risk_level or "").strip().lower()
        if not capability_policy.enabled or approval_mode == "deny":
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP capability is blocked",
                f"MCP capability {payload['capability_name']} is disabled or denied by policy.",
                target=target,
            )
        allowed_scopes = {item.lower() for item in capability_policy.allowed_scopes}
        if requested_scopes and allowed_scopes and not requested_scopes.issubset(allowed_scopes):
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP capability scope escalation was blocked",
                f"MCP capability {payload['capability_name']} only allows scopes {sorted(allowed_scopes)}.",
                target=target,
            )
        if approval_mode == "required" and not payload["approval_id"]:
            add_issue(
                "approval_integrity_gate",
                "tool-approval-gate",
                DECISION_DENY,
                "MCP capability requires approval proof",
                f"MCP capability {payload['capability_name']} requires approval_id before execution.",
                target=target,
            )
        if (
            approval_mode == "inherit"
            and server_policy is not None
            and str(server_policy.trust_mode or "").strip().lower() == "restricted"
            and not payload["approval_id"]
            and (
                bool(requested_scopes & RESTRICTED_APPROVAL_SCOPES)
                or (not requested_scopes and risk_level in RESTRICTED_RISK_LEVELS)
            )
        ):
            add_issue(
                "approval_integrity_gate",
                "tool-approval-gate",
                DECISION_DENY,
                "Restricted MCP capability requires approval",
                f"MCP capability {payload['capability_name']} inherits a restricted server policy and needs approval_id for medium/high-risk execution.",
                target=target,
            )

    if not payload["session_id"]:
        add_issue(
            "mcp_capability_binding",
            "mcp-session-bind",
            DECISION_DENY,
            "MCP capability call is missing binding data",
            "MCP tool calls and tool results must include session_id for request/result binding.",
            target=target,
        )

    if action_is_tool_result(payload):
        validation = validate_mcp_execution_ticket(
            db,
            ticket_key=payload["mcp_ticket_key"],
            task_id=task.id,
            ai_endpoint_id=ai_endpoint_id,
            action=payload,
            consume=False,
        )
        if not validation.allowed:
            add_issue(
                "mcp_capability_binding",
                "mcp-session-bind",
                DECISION_DENY,
                "MCP tool result binding failed",
                validation.reason,
                target=target or payload["mcp_ticket_key"],
            )


def _apply_approval_checks(payload: dict[str, Any], add_issue) -> None:
    requested_scopes = {item.lower() for item in payload["requested_scopes"]}
    if not (requested_scopes & HIGH_RISK_SCOPES):
        return

    if payload["approval_id"]:
        return

    add_issue(
        "approval_integrity_gate",
        "tool-approval-gate",
        DECISION_DENY,
        "High-risk action is missing approval proof",
        "The requested action asked for high-risk scopes but did not include approval_id.",
        target=",".join(sorted(requested_scopes & HIGH_RISK_SCOPES)),
    )


def _candidate_plugin_names(payload: dict[str, Any]) -> list[str]:
    return _dedupe_string_list(
        [
            *payload["plugin_names"],
            payload["source_plugin"],
            payload["target_plugin"],
        ]
    )


def _load_control_modes(
    db: Session,
    *,
    ai_endpoint_id: int | None = None,
) -> dict[str, str]:
    return resolve_control_modes(db, ai_endpoint_id=ai_endpoint_id)


def _normalize_string_list(*values: Any) -> list[str]:
    items: list[str] = []
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                items.append(stripped)
            continue
        if isinstance(value, (list, tuple, set)):
            for nested in value:
                if isinstance(nested, str):
                    stripped = nested.strip()
                    if stripped:
                        items.append(stripped)
    return _dedupe_string_list(items)


def _dedupe_string_list(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


def _matches_any_pattern(value: str, patterns: list[str]) -> bool:
    lowered = value.strip().lower()
    for item in patterns:
        pattern = str(item or "").strip().lower()
        if not pattern:
            continue
        if fnmatch.fnmatch(lowered, pattern):
            return True
    return False


def _normalize_path(value: str | None) -> str:
    normalized = str(value or "").strip().replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized.rstrip("/") or "/"


def _path_is_within(target_path: str, protected_path: str) -> bool:
    target = _normalize_path(target_path)
    protected = _normalize_path(protected_path)
    return target == protected or target.startswith(protected + "/")


def _is_path_whitelisted(
    target_path: str,
    matched_assets: list[Asset],
    whitelists_by_asset: dict[int, list[AssetWhitelist]],
    skill_names: list[str],
    plugin_names: list[str],
) -> bool:
    for asset in matched_assets:
        for row in whitelists_by_asset.get(asset.id, []):
            whitelist_type = str(row.whitelist_type or "").strip().lower()
            rule_value = str(row.rule_value or "").strip()
            if not rule_value:
                continue
            if whitelist_type == "path" and fnmatch.fnmatch(target_path.lower(), _normalize_path(rule_value).lower()):
                return True
            if whitelist_type == "skill" and any(fnmatch.fnmatch(item.lower(), rule_value.lower()) for item in skill_names):
                return True
            if whitelist_type == "plugin" and any(fnmatch.fnmatch(item.lower(), rule_value.lower()) for item in plugin_names):
                return True
    return False


def _escalate_decision(current: str, candidate: str) -> str:
    weights = {
        DECISION_ALLOW: 0,
        DECISION_REVIEW: 1,
        DECISION_DENY: 2,
    }
    return candidate if weights.get(candidate, 0) > weights.get(current, 0) else current
