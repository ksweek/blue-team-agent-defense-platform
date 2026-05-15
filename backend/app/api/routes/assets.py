from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import Asset, AssetWhitelist, User
from ...schemas.asset import AssetCreate, AssetUpdate, AssetWhitelistCreate
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.repository import contains_keyword, paginate

router = APIRouter()


ASSET_STATUS_FIELD_META = {
    "control": "segmented",
    "placeholder": "",
    "helper_text": "Status updates are applied immediately.",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "Protected", "value": "protected", "tone": "safe"},
        {"label": "Monitoring", "value": "monitoring", "tone": "warn"},
        {"label": "Disabled", "value": "disabled", "tone": "info"},
    ],
}

ASSET_RISK_LEVEL_FIELD_META = {
    "control": "segmented",
    "placeholder": "",
    "helper_text": "Risk level controls governance priority.",
    "button_text": "",
    "empty_text": "",
    "options": [
        {"label": "High", "value": "high", "tone": "danger"},
        {"label": "Medium", "value": "medium", "tone": "warn"},
        {"label": "Low", "value": "low", "tone": "safe"},
    ],
}

ASSET_WHITELIST_FIELD_META = {
    "whitelist_type": {
        "control": "select",
        "placeholder": "",
        "helper_text": "Whitelist type metadata comes from backend.",
        "button_text": "",
        "empty_text": "",
        "options": [
            {"label": "Path", "value": "path", "tone": "info"},
            {"label": "Skill", "value": "skill", "tone": "safe"},
            {"label": "Plugin", "value": "plugin", "tone": "warn"},
        ],
    },
    "rule_value": {
        "control": "text",
        "placeholder": "/workspace/** or trusted-*",
        "helper_text": "Press Enter to add a rule immediately.",
        "button_text": "",
        "empty_text": "",
        "options": [],
    },
    "description": {
        "control": "text",
        "placeholder": "Optional rule description",
        "helper_text": "Fallback description is generated automatically.",
        "button_text": "Add rule",
        "empty_text": "No whitelist rules configured for the current asset.",
        "options": [],
    },
}


def _serialize_asset(item: Asset) -> dict:
    return {
        "id": item.id,
        "asset_name": item.asset_name,
        "asset_type": item.asset_type,
        "asset_path": item.asset_path,
        "risk_level": item.risk_level,
        "status": item.status,
        "field_meta": {
            "status": ASSET_STATUS_FIELD_META,
            "risk_level": ASSET_RISK_LEVEL_FIELD_META,
        },
    }


def _serialize_whitelist(item: AssetWhitelist) -> dict:
    return {
        "id": item.id,
        "asset_id": item.asset_id,
        "whitelist_type": item.whitelist_type,
        "rule_value": item.rule_value,
        "description": item.description,
    }


def _get_asset_or_404(db: Session, asset_id: int) -> Asset:
    item = db.get(Asset, asset_id)
    if item is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return item


def _get_whitelist_or_404(db: Session, whitelist_id: int) -> AssetWhitelist:
    item = db.get(AssetWhitelist, whitelist_id)
    if item is None:
        raise HTTPException(status_code=404, detail="asset whitelist not found")
    return item


@router.get("")
def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    asset_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    items = [_serialize_asset(item) for item in db.query(Asset).order_by(Asset.id).all()]

    if asset_type:
        items = [item for item in items if item["asset_type"] == asset_type]
    if risk_level:
        items = [item for item in items if item["risk_level"] == risk_level]
    if status:
        items = [item for item in items if item["status"] == status]
    if keyword:
        items = [item for item in items if contains_keyword(item, keyword, ["asset_name", "asset_path", "asset_type"])]

    return success(paginate(items, page=page, page_size=page_size))


@router.post("")
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = Asset(**payload.model_dump())
    db.add(item)
    append_audit_log(db, current_user, "assets", "create", f"created asset {payload.asset_name}")
    db.commit()
    db.refresh(item)
    return success(_serialize_asset(item), message="created")


@router.put("/{asset_id}")
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_asset_or_404(db, asset_id)
    item.asset_name = payload.asset_name
    item.asset_type = payload.asset_type
    item.asset_path = payload.asset_path
    item.risk_level = payload.risk_level
    item.status = payload.status
    append_audit_log(db, current_user, "assets", "update", f"updated asset {item.asset_name}")
    db.commit()
    db.refresh(item)
    return success(_serialize_asset(item), message="updated")


@router.get("/{asset_id}/whitelists")
def list_asset_whitelists(
    asset_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    whitelist_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    _get_asset_or_404(db, asset_id)
    data = db.query(AssetWhitelist).filter(AssetWhitelist.asset_id == asset_id).order_by(AssetWhitelist.id.desc()).all()
    items = [_serialize_whitelist(item) for item in data]
    if whitelist_type:
        items = [item for item in items if item["whitelist_type"] == whitelist_type]
    response = paginate(items, page=page, page_size=page_size)
    response["field_meta"] = ASSET_WHITELIST_FIELD_META
    return success(response)


@router.post("/{asset_id}/whitelists")
def create_asset_whitelist(
    asset_id: int,
    payload: AssetWhitelistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    asset = _get_asset_or_404(db, asset_id)
    item = AssetWhitelist(asset_id=asset_id, **payload.model_dump())
    db.add(item)
    append_audit_log(
        db,
        current_user,
        "assets",
        "create-whitelist",
        f"added {payload.whitelist_type} whitelist rule for {asset.asset_name}",
    )
    db.commit()
    db.refresh(item)
    return success(_serialize_whitelist(item), message="whitelist created")


@router.delete("/whitelists/{whitelist_id}")
def delete_asset_whitelist(
    whitelist_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_whitelist_or_404(db, whitelist_id)
    serialized = _serialize_whitelist(item)
    db.delete(item)
    append_audit_log(
        db,
        current_user,
        "assets",
        "delete-whitelist",
        f"removed whitelist rule {serialized['rule_value']}",
    )
    db.commit()
    return success(serialized, message="whitelist deleted")
