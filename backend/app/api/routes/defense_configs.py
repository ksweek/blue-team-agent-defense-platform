from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AiEndpoint, DefenseConfig, DefensePolicy, User
from ...schemas.defense import DefenseConfigBatchUpdate, DefenseConfigUpdate, DefensePolicyPayload
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.defense_coverage import build_defense_coverage_map
from ...services.endpoint_governance import (
    EffectiveDefensePolicy,
    get_endpoint_defense_overrides,
    resolve_effective_defense_policy,
    set_endpoint_defense_override,
    set_endpoint_policy_override,
)
from ...services.repository import contains_keyword, paginate
from ...services.security_taxonomy import enrich_defense_config, enrich_policy_rule

router = APIRouter()


DEFENSE_ENABLED_FIELD_META = {
    "control": "toggle",
    "placeholder": "",
    "helper_text": "开关切换后会立即提交到后端，不再存在额外保存步骤。",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "启用", "value": "true", "tone": "safe"},
        {"label": "停用", "value": "false", "tone": "info"},
    ],
}

DEFENSE_MODE_FIELD_META = {
    "control": "segmented",
    "placeholder": "",
    "helper_text": "模式切换后会立即生效，颜色语义同样由后端下发。",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "关闭", "value": "off", "tone": "info"},
        {"label": "观察", "value": "observe", "tone": "warn"},
        {"label": "执行", "value": "enforce", "tone": "safe"},
    ],
}

AI_REVIEW_MODE_FIELD_META = {
    "control": "segmented",
    "placeholder": "",
    "helper_text": "研判复核只对已开启保护的目标生效。辅助研判接口和密钥在系统设置中配置。",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "规则直断", "value": "rules_only", "tone": "info"},
        {"label": "疑似复核", "value": "suspicious_review", "tone": "warn"},
        {"label": "剩余全审", "value": "review_all_remaining", "tone": "safe"},
    ],
}

DEFENSE_RESOURCE_GROUPS = [
    {
        "kind": "path",
        "title": "受保护路径",
        "description": "需要重点保护的绝对路径、工作区目录或关键配置位置。",
        "field_meta": {
            "control": "token-input",
            "placeholder": "/srv/app/secrets",
            "helper_text": "输入后按 Enter 或逗号即可添加，删除标签会立即自动保存。",
            "button_text": "添加",
            "empty_text": "当前还没有纳管项，添加后会立即生效。",
            "options": [],
        },
    },
    {
        "kind": "skill",
        "title": "受保护技能",
        "description": "需要额外授权或审计的技能 ID、能力名或策略别名。",
        "field_meta": {
            "control": "token-input",
            "placeholder": "release-guard",
            "helper_text": "输入后按 Enter 或逗号即可添加，删除标签会立即自动保存。",
            "button_text": "添加",
            "empty_text": "当前还没有纳管项，添加后会立即生效。",
            "options": [],
        },
    },
    {
        "kind": "plugin",
        "title": "受保护插件",
        "description": "需要强约束的插件、MCP server capability 或扩展能力标识。",
        "field_meta": {
            "control": "token-input",
            "placeholder": "audit-guard",
            "helper_text": "输入后按 Enter 或逗号即可添加，删除标签会立即自动保存。",
            "button_text": "添加",
            "empty_text": "当前还没有纳管项，添加后会立即生效。",
            "options": [],
        },
    },
]


def _build_defense_field_meta() -> dict:
    return {
        "enabled": DEFENSE_ENABLED_FIELD_META,
        "mode": DEFENSE_MODE_FIELD_META,
    }


def _get_ai_endpoint_or_404(db: Session, ai_endpoint_id: int) -> AiEndpoint:
    item = db.get(AiEndpoint, ai_endpoint_id)
    if item is None:
        raise HTTPException(status_code=404, detail="AI endpoint not found")
    return item


def _effective_defense_payload(item: DefenseConfig, endpoint: AiEndpoint | None = None) -> dict:
    enabled = item.enabled
    mode = item.mode
    config_json = item.config
    override = get_endpoint_defense_overrides(endpoint).get(item.defense_type) if endpoint is not None else None
    if override is not None:
        enabled = bool(override.get("enabled", enabled))
        mode = str(override.get("mode") or mode)
        raw_config = override.get("config_json")
        if isinstance(raw_config, dict):
            config_json = dict(raw_config)

    return {
        "id": item.id,
        "defense_name": item.defense_name,
        "defense_type": item.defense_type,
        "threat_level": item.threat_level,
        "mode": mode,
        "enabled": enabled,
        "description": item.description,
        "config_json": config_json,
    }


def _serialize_defense_config(item: DefenseConfig, endpoint: AiEndpoint | None = None) -> dict:
    payload = _effective_defense_payload(item, endpoint)
    return enrich_defense_config(
        {
            **payload,
            "coverage_map": build_defense_coverage_map(payload["defense_type"], payload["config_json"]),
            "field_meta": _build_defense_field_meta(),
        }
    )


def _serialize_policy_rule(item: dict) -> dict:
    return enrich_policy_rule(
        {
        **item,
        "field_meta": _build_defense_field_meta(),
        }
    )


def _serialize_ai_review_policy(item: dict) -> dict:
    return enrich_policy_rule(
        {
        **item,
        "field_meta": AI_REVIEW_MODE_FIELD_META,
        }
    )


def _ai_review_policy_payload(payload: DefensePolicyPayload) -> dict:
    item = payload.ai_review_policy.model_dump()
    item["reviewer_ai_endpoint_id"] = None
    return item


def _serialize_policy(item: DefensePolicy | EffectiveDefensePolicy) -> dict:
    return {
        "guard_rules": [_serialize_policy_rule(rule) for rule in item.guard_rules],
        "scan_rules": [_serialize_policy_rule(rule) for rule in item.scan_rules],
        "advanced_rule": _serialize_policy_rule(item.advanced_rule),
        "ai_review_policy": _serialize_ai_review_policy(item.ai_review_policy),
        "protected_paths": item.protected_paths,
        "protected_skills": item.protected_skills,
        "protected_plugins": item.protected_plugins,
        "resource_groups": DEFENSE_RESOURCE_GROUPS,
        "global_field_meta": _build_defense_field_meta(),
    }


def _get_defense_config_or_404(db: Session, defense_id: int) -> DefenseConfig:
    item = db.get(DefenseConfig, defense_id)
    if item is None:
        raise HTTPException(status_code=404, detail="防御配置不存在")
    return item


def _get_defense_policy(
    db: Session,
    *,
    ai_endpoint_id: int | None = None,
) -> DefensePolicy | EffectiveDefensePolicy:
    if ai_endpoint_id is not None:
        _get_ai_endpoint_or_404(db, ai_endpoint_id)
        item = resolve_effective_defense_policy(db, ai_endpoint_id=ai_endpoint_id)
        if item is None:
            raise HTTPException(status_code=404, detail="防御策略不存在")
        return item

    item = db.get(DefensePolicy, 1)
    if item is None:
        raise HTTPException(status_code=404, detail="防御策略不存在")
    return item


def _filter_defense_configs(
    items: list[dict],
    mode: Optional[str] = None,
    enabled: Optional[bool] = None,
    defense_type: Optional[str] = None,
    keyword: Optional[str] = None,
) -> list[dict]:
    if mode:
        items = [item for item in items if item["mode"] == mode]
    if enabled is not None:
        items = [item for item in items if item["enabled"] is enabled]
    if defense_type:
        items = [item for item in items if item["defense_type"] == defense_type]
    if keyword:
        items = [
            item
            for item in items
            if contains_keyword(item, keyword, ["defense_name", "defense_type", "description", "threat_level"])
        ]

    return items


@router.get("")
def list_defense_configs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    mode: Optional[str] = None,
    enabled: Optional[bool] = None,
    defense_type: Optional[str] = None,
    keyword: Optional[str] = None,
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    endpoint = _get_ai_endpoint_or_404(db, ai_endpoint_id) if ai_endpoint_id is not None else None
    raw_items = [
        _serialize_defense_config(item, endpoint)
        for item in db.query(DefenseConfig).order_by(DefenseConfig.id).all()
    ]
    items = _filter_defense_configs(raw_items, mode=mode, enabled=enabled, defense_type=defense_type, keyword=keyword)
    return success(paginate(items, page=page, page_size=page_size))


@router.post("/batch-update")
def batch_update(
    payload: DefenseConfigBatchUpdate,
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    endpoint = _get_ai_endpoint_or_404(db, ai_endpoint_id) if ai_endpoint_id is not None else None
    updated_items = []
    for defense_id in payload.ids:
        item = _get_defense_config_or_404(db, defense_id)
        if endpoint is None:
            if payload.enabled is not None:
                item.enabled = payload.enabled
            if payload.mode is not None:
                item.mode = payload.mode
        else:
            effective = _effective_defense_payload(item, endpoint)
            set_endpoint_defense_override(
                endpoint,
                item.defense_type,
                enabled=payload.enabled if payload.enabled is not None else bool(effective["enabled"]),
                mode=payload.mode if payload.mode is not None else str(effective["mode"]),
                config_json=dict(effective["config_json"]),
            )
        updated_items.append(_serialize_defense_config(item, endpoint))

    append_audit_log(
        db,
        current_user,
        "defense-config",
        "batch-update",
        f"批量更新 {len(updated_items)} 条防御配置 scope={ai_endpoint_id or 'global'}",
    )
    db.commit()
    return success({"items": updated_items, "total": len(updated_items)}, message="batch updated")


@router.get("/profile")
def get_defense_policy_profile(
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    return success(_serialize_policy(_get_defense_policy(db, ai_endpoint_id=ai_endpoint_id)))


@router.put("/profile")
def update_defense_policy_profile(
    payload: DefensePolicyPayload,
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    ai_review_policy_payload = _ai_review_policy_payload(payload)
    if ai_endpoint_id is not None:
        endpoint = _get_ai_endpoint_or_404(db, ai_endpoint_id)
        set_endpoint_policy_override(
            endpoint,
            {
                "guard_rules": [rule.model_dump() for rule in payload.guard_rules],
                "scan_rules": [rule.model_dump() for rule in payload.scan_rules],
                "advanced_rule": payload.advanced_rule.model_dump(),
                "ai_review_policy": ai_review_policy_payload,
                "protected_paths": payload.protected_paths,
                "protected_skills": payload.protected_skills,
                "protected_plugins": payload.protected_plugins,
            },
        )
        append_audit_log(
            db,
            current_user,
            "defense-config",
            "update-profile",
            f"更新 AI endpoint #{ai_endpoint_id} 的扩展防御策略",
        )
        db.commit()
        return success(_serialize_policy(_get_defense_policy(db, ai_endpoint_id=ai_endpoint_id)), message="profile updated")

    item = _get_defense_policy(db)
    item.set_guard_rules([rule.model_dump() for rule in payload.guard_rules])
    item.set_scan_rules([rule.model_dump() for rule in payload.scan_rules])
    item.set_advanced_rule(payload.advanced_rule.model_dump())
    item.set_ai_review_policy(ai_review_policy_payload)
    item.set_protected_paths(payload.protected_paths)
    item.set_protected_skills(payload.protected_skills)
    item.set_protected_plugins(payload.protected_plugins)
    item.updated_by = current_user.id

    append_audit_log(db, current_user, "defense-config", "update-profile", "更新配置页扩展防御策略")
    db.commit()
    db.refresh(item)
    return success(_serialize_policy(item), message="profile updated")


@router.get("/{defense_id}")
def get_defense_config(
    defense_id: int,
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    endpoint = _get_ai_endpoint_or_404(db, ai_endpoint_id) if ai_endpoint_id is not None else None
    return success(_serialize_defense_config(_get_defense_config_or_404(db, defense_id), endpoint))


@router.put("/{defense_id}")
def update_defense_config(
    defense_id: int,
    payload: DefenseConfigUpdate,
    ai_endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_defense_config_or_404(db, defense_id)
    endpoint = _get_ai_endpoint_or_404(db, ai_endpoint_id) if ai_endpoint_id is not None else None
    if endpoint is None:
        item.enabled = payload.enabled
        item.mode = payload.mode
        item.set_config(payload.config_json)
    else:
        set_endpoint_defense_override(
            endpoint,
            item.defense_type,
            enabled=payload.enabled,
            mode=payload.mode,
            config_json=dict(payload.config_json),
        )

    append_audit_log(
        db,
        current_user,
        "defense-config",
        "update",
        f"更新防御配置 {item.defense_name} scope={ai_endpoint_id or 'global'}",
    )
    db.commit()
    db.refresh(item)
    return success(_serialize_defense_config(item, endpoint), message="updated")
