from pydantic import BaseModel

from .common import FieldMeta


class AssetFieldMeta(BaseModel):
    status: FieldMeta
    risk_level: FieldMeta


class AssetItem(BaseModel):
    id: int
    asset_name: str
    asset_type: str
    asset_path: str
    risk_level: str
    status: str
    field_meta: AssetFieldMeta


class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str
    asset_path: str
    risk_level: str
    status: str


class AssetUpdate(AssetCreate):
    pass


class AssetWhitelistFieldMeta(BaseModel):
    whitelist_type: FieldMeta
    rule_value: FieldMeta
    description: FieldMeta


class AssetWhitelistItem(BaseModel):
    id: int
    asset_id: int
    whitelist_type: str
    rule_value: str
    description: str


class AssetWhitelistCreate(BaseModel):
    whitelist_type: str
    rule_value: str
    description: str
