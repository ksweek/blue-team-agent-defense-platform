from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AiEndpoint, ManagedRuntime, RuntimeEnrollmentToken, User
from ...schemas.ai_endpoint import AiEndpointBatchUpdate, AiEndpointCreate, AiEndpointUpdate
from ...services.ai_endpoints import (
    PROVIDER_TEMPLATES,
    build_endpoint_config_payload,
    build_ai_endpoint_usage_summaries,
    count_active_tasks_for_endpoint,
    is_demo_ai_endpoint,
    normalize_endpoint_key,
    normalize_endpoint_group,
    normalize_protection_mode,
    normalize_provider_type,
    provider_endpoint_from_ai_endpoint,
    serialize_ai_endpoint,
    sync_default_ai_endpoint,
)
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.model_provider import ProviderConfigurationError, ProviderExecutionError, invoke_chat_completion

router = APIRouter()


def _list_payload(db: Session) -> dict:
    items = db.query(AiEndpoint).order_by(AiEndpoint.endpoint_group.asc(), AiEndpoint.is_default.desc(), AiEndpoint.id.asc()).all()
    usage_map = build_ai_endpoint_usage_summaries(db)
    serialized_items = [serialize_ai_endpoint(item, usage_summary=usage_map.get(item.id)) for item in items]
    default_item = next((item for item in items if item.is_default), None)
    group_count = len({normalize_endpoint_group(item.endpoint_group) for item in items})
    cleanup_candidates = sum(1 for item in serialized_items if item.get("is_cleanup_candidate"))
    summary = {
        "total": len(serialized_items),
        "enabled": sum(1 for item in items if item.enabled),
        "protected": sum(1 for item in items if item.protection_enabled and item.protection_mode != "off"),
        "default_id": default_item.id if default_item is not None else None,
        "default_display_name": default_item.display_name if default_item is not None else None,
        "default_group": normalize_endpoint_group(default_item.endpoint_group) if default_item is not None else None,
        "group_count": group_count,
        "cleanup_candidates": cleanup_candidates,
    }
    return {
        "items": serialized_items,
        "summary": summary,
    }


def _get_or_404(db: Session, endpoint_id: int) -> AiEndpoint:
    item = db.query(AiEndpoint).get(endpoint_id)
    if item is None:
        raise HTTPException(status_code=404, detail="ai endpoint not found")
    return item


def _release_endpoint_bindings(db: Session, endpoint_id: int) -> tuple[list[RuntimeEnrollmentToken], list[ManagedRuntime]]:
    bound_tokens = db.query(RuntimeEnrollmentToken).filter(RuntimeEnrollmentToken.ai_endpoint_id == endpoint_id).all()
    bound_runtimes = db.query(ManagedRuntime).filter(ManagedRuntime.ai_endpoint_id == endpoint_id).all()
    for token in bound_tokens:
        token.ai_endpoint_id = None
    for runtime in bound_runtimes:
        runtime.ai_endpoint_id = None
    return bound_tokens, bound_runtimes


def _delete_endpoint_record(db: Session, item: AiEndpoint) -> dict:
    active_count = count_active_tasks_for_endpoint(db, item.id)
    if active_count:
        raise HTTPException(
            status_code=400,
            detail=f"AI endpoint {item.endpoint_key} is still referenced by {active_count} active tasks.",
        )

    bound_tokens, bound_runtimes = _release_endpoint_bindings(db, item.id)
    endpoint_id = item.id
    endpoint_key = item.endpoint_key
    display_name = item.display_name
    db.delete(item)
    db.flush()
    return {
        "id": endpoint_id,
        "endpoint_key": endpoint_key,
        "display_name": display_name,
        "released_tokens": len(bound_tokens),
        "released_runtimes": len(bound_runtimes),
    }


def _apply_create_payload(item: AiEndpoint, payload: AiEndpointCreate) -> None:
    endpoint_key = normalize_endpoint_key(payload.endpoint_key)
    if not endpoint_key:
        raise HTTPException(status_code=400, detail="endpoint_key is required")
    item.endpoint_key = endpoint_key
    item.display_name = payload.display_name.strip() or endpoint_key
    item.endpoint_group = normalize_endpoint_group(payload.endpoint_group)
    item.provider_type = normalize_provider_type(payload.provider_type)
    item.base_url = payload.base_url.strip()
    item.api_key = payload.api_key.strip()
    item.model_name = payload.model_name.strip()
    item.enabled = payload.enabled
    item.is_default = payload.is_default
    item.protection_enabled = payload.protection_enabled
    item.protection_mode = normalize_protection_mode(payload.protection_mode)
    item.description = payload.description.strip()
    try:
        item.set_config(
            build_endpoint_config_payload(
                {},
                raw_config=dict(payload.config_json) if payload.config_json is not None else None,
                public_config=dict(payload.config_public_json),
                secret_updates=[secret.model_dump() for secret in payload.config_secret_updates],
                secret_remove_paths=list(payload.config_secret_remove_paths),
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _apply_update_payload(item: AiEndpoint, payload: AiEndpointUpdate) -> None:
    data = payload.model_dump(exclude_unset=True)
    if "endpoint_key" in data:
        endpoint_key = normalize_endpoint_key(str(data["endpoint_key"]))
        if not endpoint_key:
            raise HTTPException(status_code=400, detail="endpoint_key is required")
        item.endpoint_key = endpoint_key
    if "display_name" in data:
        item.display_name = str(data["display_name"]).strip() or item.endpoint_key
    if "endpoint_group" in data:
        item.endpoint_group = normalize_endpoint_group(data["endpoint_group"])
    if "provider_type" in data:
        item.provider_type = normalize_provider_type(str(data["provider_type"]))
    if "base_url" in data:
        item.base_url = str(data["base_url"]).strip()
    if "api_key" in data:
        api_key = str(data["api_key"] or "").strip()
        if api_key:
            item.api_key = api_key
    if "model_name" in data:
        item.model_name = str(data["model_name"]).strip()
    if "enabled" in data:
        item.enabled = bool(data["enabled"])
    if "is_default" in data:
        item.is_default = bool(data["is_default"])
    if "protection_enabled" in data:
        item.protection_enabled = bool(data["protection_enabled"])
    if "protection_mode" in data:
        item.protection_mode = normalize_protection_mode(str(data["protection_mode"]))
    if "description" in data:
        item.description = str(data["description"]).strip()
    if any(
        key in data
        for key in ("config_json", "config_public_json", "config_secret_updates", "config_secret_remove_paths")
    ):
        try:
            item.set_config(
                build_endpoint_config_payload(
                    item.config,
                    raw_config=dict(data["config_json"]) if isinstance(data.get("config_json"), dict) else None,
                    public_config=dict(data["config_public_json"]) if isinstance(data.get("config_public_json"), dict) else None,
                    secret_updates=[
                        secret.model_dump() if hasattr(secret, "model_dump") else dict(secret)
                        for secret in (data.get("config_secret_updates") or [])
                    ],
                    secret_remove_paths=[str(path) for path in (data.get("config_secret_remove_paths") or [])],
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


def _ensure_unique_key(db: Session, endpoint_key: str, *, exclude_id: int | None = None) -> None:
    query = db.query(AiEndpoint).filter(AiEndpoint.endpoint_key == endpoint_key)
    if exclude_id is not None:
        query = query.filter(AiEndpoint.id != exclude_id)
    if query.first() is not None:
        raise HTTPException(status_code=400, detail=f"endpoint_key already exists: {endpoint_key}")


@router.get("")
def list_ai_endpoints(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success(_list_payload(db))


@router.get("/provider-templates")
def list_provider_templates(
    _: User = Depends(require_roles("admin", "analyst")),
):
    items = [
        {
            "template_key": key,
            **value,
        }
        for key, value in PROVIDER_TEMPLATES.items()
    ]
    return success({"items": items, "total": len(items)})


@router.get("/{endpoint_id}")
def get_ai_endpoint(
    endpoint_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_or_404(db, endpoint_id)
    usage_map = build_ai_endpoint_usage_summaries(db)
    return success(serialize_ai_endpoint(item, usage_summary=usage_map.get(item.id)))


@router.post("/batch-update")
def batch_update_ai_endpoints(
    payload: AiEndpointBatchUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    endpoint_ids = [endpoint_id for endpoint_id in payload.ids if isinstance(endpoint_id, int)]
    if not endpoint_ids:
        raise HTTPException(status_code=400, detail="ids are required")

    items = db.query(AiEndpoint).filter(AiEndpoint.id.in_(endpoint_ids)).all()
    if len(items) != len(set(endpoint_ids)):
        raise HTTPException(status_code=404, detail="one or more ai endpoints were not found")

    protection_mode = None
    if payload.protection_mode is not None:
        protection_mode = normalize_protection_mode(payload.protection_mode)
    endpoint_group = None
    if payload.endpoint_group is not None:
        endpoint_group = normalize_endpoint_group(payload.endpoint_group)

    for item in items:
        if payload.enabled is not None:
            item.enabled = payload.enabled
        if payload.protection_enabled is not None:
            item.protection_enabled = payload.protection_enabled
        if protection_mode is not None:
            item.protection_mode = protection_mode
        if endpoint_group is not None:
            item.endpoint_group = endpoint_group

    sync_default_ai_endpoint(db)
    append_audit_log(
        db,
        current_user,
        "ai-endpoints",
        "batch-update",
        f"updated {len(items)} ai endpoints in batch",
    )
    db.commit()
    return success(_list_payload(db), message="ai endpoints batch updated")


@router.post("")
def create_ai_endpoint(
    payload: AiEndpointCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = AiEndpoint()
    _apply_create_payload(item, payload)
    _ensure_unique_key(db, item.endpoint_key)
    if db.query(AiEndpoint.id).first() is None:
        item.is_default = True

    db.add(item)
    db.flush()
    sync_default_ai_endpoint(db, item if item.is_default else None)
    append_audit_log(db, current_user, "ai-endpoints", "create", f"created ai endpoint {item.endpoint_key}")
    db.commit()
    db.refresh(item)
    usage_map = build_ai_endpoint_usage_summaries(db)
    return success(serialize_ai_endpoint(item, usage_summary=usage_map.get(item.id)), message="ai endpoint created")


@router.put("/{endpoint_id}")
def update_ai_endpoint(
    endpoint_id: int,
    payload: AiEndpointUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_or_404(db, endpoint_id)
    _apply_update_payload(item, payload)
    _ensure_unique_key(db, item.endpoint_key, exclude_id=item.id)
    sync_default_ai_endpoint(db, item if item.is_default else None)
    append_audit_log(db, current_user, "ai-endpoints", "update", f"updated ai endpoint {item.endpoint_key}")
    db.commit()
    db.refresh(item)
    usage_map = build_ai_endpoint_usage_summaries(db)
    return success(serialize_ai_endpoint(item, usage_summary=usage_map.get(item.id)), message="ai endpoint updated")


@router.delete("/{endpoint_id}")
def delete_ai_endpoint(
    endpoint_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_or_404(db, endpoint_id)
    result = _delete_endpoint_record(db, item)
    sync_default_ai_endpoint(db)
    append_audit_log(
        db,
        current_user,
        "ai-endpoints",
        "delete",
        f"deleted ai endpoint {result['endpoint_key']}; released {result['released_tokens']} tokens and {result['released_runtimes']} runtimes",
    )
    db.commit()
    return success(result, message="ai endpoint deleted")


@router.post("/cleanup-candidates")
def cleanup_ai_endpoint_candidates(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    items = db.query(AiEndpoint).order_by(AiEndpoint.id.asc()).all()
    usage_map = build_ai_endpoint_usage_summaries(db)

    deleted_items: list[dict] = []
    for item in items:
        usage = usage_map.get(item.id) or {}
        active_task_count = int(usage.get("active_task_count") or 0)
        runtime_active_count = int(usage.get("runtime_active_count") or 0)
        if not is_demo_ai_endpoint(item):
            continue
        if active_task_count or runtime_active_count:
            continue
        deleted_items.append(_delete_endpoint_record(db, item))

    if not deleted_items:
        return success(
            {
                "deleted_count": 0,
                "released_tokens": 0,
                "released_runtimes": 0,
                "items": [],
            },
            message="no cleanup candidates",
        )

    sync_default_ai_endpoint(db)
    released_tokens = sum(item["released_tokens"] for item in deleted_items)
    released_runtimes = sum(item["released_runtimes"] for item in deleted_items)
    append_audit_log(
        db,
        current_user,
        "ai-endpoints",
        "cleanup-candidates",
        f"cleaned up {len(deleted_items)} demo ai endpoints; released {released_tokens} tokens and {released_runtimes} runtimes",
    )
    db.commit()
    return success(
        {
            "deleted_count": len(deleted_items),
            "released_tokens": released_tokens,
            "released_runtimes": released_runtimes,
            "items": deleted_items,
        },
        message="cleanup candidates deleted",
    )


@router.post("/{endpoint_id}/test")
def test_ai_endpoint(
    endpoint_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    item = _get_or_404(db, endpoint_id)
    try:
        result = invoke_chat_completion(
            [{"role": "user", "content": "Reply with exactly OK."}],
            endpoint=provider_endpoint_from_ai_endpoint(item),
        )
    except (ProviderConfigurationError, ProviderExecutionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    append_audit_log(db, current_user, "ai-endpoints", "test", f"tested ai endpoint {item.endpoint_key}")
    db.commit()
    usage_map = build_ai_endpoint_usage_summaries(db)
    return success(
        {
            "endpoint": serialize_ai_endpoint(item, usage_summary=usage_map.get(item.id)),
            "provider": result.provider,
            "model": result.model,
            "output_text": result.output_text,
            "usage": result.usage,
        },
        message="ai endpoint test completed",
    )
