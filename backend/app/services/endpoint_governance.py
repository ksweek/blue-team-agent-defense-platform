from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy.orm import Session

from ..models import AiEndpoint, DefensePolicy


@dataclass
class EffectiveDefensePolicy:
    guard_rules: list[dict[str, Any]]
    scan_rules: list[dict[str, Any]]
    advanced_rule: dict[str, Any]
    ai_review_policy: dict[str, Any]
    protected_paths: list[str]
    protected_skills: list[str]
    protected_plugins: list[str]


def _safe_governance(endpoint: AiEndpoint | None) -> dict[str, Any]:
    if endpoint is None:
        return {}
    value = endpoint.governance
    return value if isinstance(value, dict) else {}


def _write_governance(endpoint: AiEndpoint, payload: dict[str, Any]) -> None:
    endpoint.set_governance(payload)


def get_endpoint_governance(db: Session, ai_endpoint_id: int | None) -> dict[str, Any]:
    if ai_endpoint_id is None:
        return {}
    endpoint = db.get(AiEndpoint, ai_endpoint_id)
    return _safe_governance(endpoint)


def get_endpoint_skill_ids(endpoint: AiEndpoint | None) -> list[int]:
    raw_items = _safe_governance(endpoint).get("skill_ids")
    if not isinstance(raw_items, list):
        return []

    result: list[int] = []
    for item in raw_items:
        try:
            skill_id = int(item)
        except (TypeError, ValueError):
            continue
        if skill_id > 0 and skill_id not in result:
            result.append(skill_id)
    return result


def assign_skills_to_endpoint(endpoint: AiEndpoint, skill_ids: Iterable[int]) -> list[int]:
    governance = _safe_governance(endpoint)
    merged = get_endpoint_skill_ids(endpoint)
    for item in skill_ids:
        try:
            skill_id = int(item)
        except (TypeError, ValueError):
            continue
        if skill_id > 0 and skill_id not in merged:
            merged.append(skill_id)
    governance["skill_ids"] = merged
    _write_governance(endpoint, governance)
    return merged


def get_endpoint_defense_overrides(endpoint: AiEndpoint | None) -> dict[str, dict[str, Any]]:
    raw_value = _safe_governance(endpoint).get("defense_overrides")
    if not isinstance(raw_value, dict):
        return {}

    result: dict[str, dict[str, Any]] = {}
    for defense_type, payload in raw_value.items():
        if not isinstance(payload, dict):
            continue
        result[str(defense_type)] = dict(payload)
    return result


def set_endpoint_defense_override(
    endpoint: AiEndpoint,
    defense_type: str,
    *,
    enabled: bool,
    mode: str,
    config_json: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    governance = _safe_governance(endpoint)
    overrides = get_endpoint_defense_overrides(endpoint)
    overrides[str(defense_type)] = {
        "enabled": bool(enabled),
        "mode": str(mode),
        "config_json": dict(config_json or {}),
    }
    governance["defense_overrides"] = overrides
    _write_governance(endpoint, governance)
    return overrides


def get_endpoint_policy_override(endpoint: AiEndpoint | None) -> dict[str, Any]:
    value = _safe_governance(endpoint).get("defense_policy")
    return dict(value) if isinstance(value, dict) else {}


def set_endpoint_policy_override(endpoint: AiEndpoint, payload: dict[str, Any]) -> dict[str, Any]:
    governance = _safe_governance(endpoint)
    governance["defense_policy"] = dict(payload or {})
    _write_governance(endpoint, governance)
    return governance["defense_policy"]


def _merge_rule_list(base_items: list[dict[str, Any]], override_items: Any) -> list[dict[str, Any]]:
    if not isinstance(override_items, list):
        return deepcopy(base_items)

    override_map: dict[str, dict[str, Any]] = {}
    extra_items: list[dict[str, Any]] = []
    for item in override_items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if key:
            override_map[key] = deepcopy(item)
        else:
            extra_items.append(deepcopy(item))

    merged: list[dict[str, Any]] = []
    for item in base_items:
        key = str(item.get("key") or "").strip()
        merged.append(deepcopy(override_map.pop(key, item)))
    merged.extend(extra_items)
    merged.extend(deepcopy(item) for item in override_map.values())
    return merged


def resolve_effective_defense_policy(
    db: Session,
    *,
    ai_endpoint_id: int | None = None,
) -> EffectiveDefensePolicy | None:
    base = db.get(DefensePolicy, 1)
    if base is None:
        return None

    endpoint = db.get(AiEndpoint, ai_endpoint_id) if ai_endpoint_id is not None else None
    override = get_endpoint_policy_override(endpoint)

    advanced_rule = deepcopy(base.advanced_rule)
    if isinstance(override.get("advanced_rule"), dict):
        advanced_rule = deepcopy(override["advanced_rule"])

    ai_review_policy = deepcopy(base.ai_review_policy)
    if isinstance(override.get("ai_review_policy"), dict):
        ai_review_policy = deepcopy(override["ai_review_policy"])

    def _override_list(name: str, fallback: list[str]) -> list[str]:
        value = override.get(name)
        if not isinstance(value, list):
            return list(fallback)
        return [str(item) for item in value if str(item).strip()]

    return EffectiveDefensePolicy(
        guard_rules=_merge_rule_list(base.guard_rules, override.get("guard_rules")),
        scan_rules=_merge_rule_list(base.scan_rules, override.get("scan_rules")),
        advanced_rule=advanced_rule,
        ai_review_policy=ai_review_policy,
        protected_paths=_override_list("protected_paths", base.protected_paths),
        protected_skills=_override_list("protected_skills", base.protected_skills),
        protected_plugins=_override_list("protected_plugins", base.protected_plugins),
    )


def resolve_control_modes(
    db: Session,
    *,
    ai_endpoint_id: int | None = None,
) -> dict[str, str]:
    endpoint = db.get(AiEndpoint, ai_endpoint_id) if ai_endpoint_id is not None else None
    overrides = get_endpoint_defense_overrides(endpoint)
    result: dict[str, str] = {}

    from ..models import DefenseConfig

    items = db.query(DefenseConfig).order_by(DefenseConfig.id.asc()).all()
    for item in items:
        enabled = item.enabled
        mode = str(item.mode or "off").strip().lower()
        override = overrides.get(item.defense_type)
        if override is not None:
            enabled = bool(override.get("enabled", enabled))
            mode = str(override.get("mode") or mode).strip().lower()
        if not enabled:
            result[item.defense_type] = "off"
            continue
        if mode not in {"off", "observe", "enforce"}:
            mode = "observe"
        result[item.defense_type] = mode
    return result
