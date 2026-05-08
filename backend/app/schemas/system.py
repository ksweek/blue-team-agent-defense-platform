from pydantic import BaseModel
from typing import Optional


class SystemSettingFieldOption(BaseModel):
    label: str
    value: str


class SystemSettingFieldMeta(BaseModel):
    control: str
    placeholder: str
    helper_text: str
    options: list[SystemSettingFieldOption]


class SystemSettingItem(BaseModel):
    setting_key: str
    setting_value: str
    description: str
    field_meta: SystemSettingFieldMeta


class SystemSettingUpdate(BaseModel):
    setting_value: str


class AuditLogItem(BaseModel):
    id: int
    user_id: int
    module: str
    action: str
    detail: str
    created_at: str


class SystemActionDefinition(BaseModel):
    action_key: str
    action_label: str
    detail: str
    button_text: str
    tone: str
    method: str
    status: str


class SystemActionList(BaseModel):
    items: list[SystemActionDefinition]
    total: int


class SystemActionResult(BaseModel):
    action_key: str
    action_label: str
    tone: str
    status: str
    detail: str
    output: str
    created_at: str
    audit_log: AuditLogItem


class ManagedArtifactItem(BaseModel):
    kind: str
    name: str
    artifact_path: str
    size_bytes: int
    updated_at: str


class ManagedArtifactList(BaseModel):
    items: list[ManagedArtifactItem]
    total: int


class BackupRestoreRequest(BaseModel):
    artifact_path: str


class DefenseConfigImportRequest(BaseModel):
    artifact_path: str
    apply_system_settings: bool = True


class RollbackRequest(BaseModel):
    artifact_path: Optional[str] = None
