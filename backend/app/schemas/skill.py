from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .common import FieldMeta


class SkillFieldMeta(BaseModel):
    source_path: FieldMeta
    trust_status: FieldMeta


class SkillItem(BaseModel):
    id: int
    skill_name: str
    skill_type: str
    provider: str
    source_path: str
    source_path_state: str
    resolved_source_path: str
    trust_status: str
    created_at: str
    field_meta: SkillFieldMeta


class TrustStatusUpdate(BaseModel):
    trust_status: str


class SkillSourcePathUpdate(BaseModel):
    source_path: str = Field(default="", max_length=255)


class SkillCreateRequest(BaseModel):
    skill_name: str = Field(min_length=1, max_length=128)
    skill_type: str = Field(default="local", min_length=1, max_length=64)
    provider: str = Field(default="manual", min_length=1, max_length=64)
    source_path: str = Field(min_length=1, max_length=255)
    trust_status: str = Field(default="pending", min_length=1, max_length=32)


class SkillImportDirectoryRequest(BaseModel):
    directory_path: str = Field(min_length=1, max_length=255)
    skill_type: str = Field(default="local", min_length=1, max_length=64)
    provider: str = Field(default="imported", min_length=1, max_length=64)
    trust_status: str = Field(default="pending", min_length=1, max_length=32)
    recursive: bool = True


class SkillImportPreviewItem(BaseModel):
    skill_name: str
    source_path: str
    action: str
    action_label: str
    action_tone: str
    reason: str
    reason_label: str
    reason_tone: str
    existing_skill_id: Optional[int] = None


class SkillImportPreviewSummaryItem(BaseModel):
    key: str
    text: str
    value: int
    tone: str


class SkillResultPanelBadge(BaseModel):
    key: str
    text: str
    tone: str


class SkillResultPanelAction(BaseModel):
    action_key: str
    label: str
    tone: str
    disabled: bool = False


class SkillResultPanelItem(BaseModel):
    key: str
    title: str
    subtitle: str = ""
    badges: list[SkillResultPanelBadge] = Field(default_factory=list)


class SkillResultPanel(BaseModel):
    key: str
    panel_type: str = "result_panel"
    title: str
    summary_text: str
    detail_text: str = ""
    empty_text: str
    summary_items: list[SkillImportPreviewSummaryItem] = Field(default_factory=list)
    actions: list[SkillResultPanelAction] = Field(default_factory=list)
    items: list[SkillResultPanelItem] = Field(default_factory=list)


class SkillResultListItem(BaseModel):
    key: str
    task_id: Optional[int] = None
    status: str = ""
    title: str
    subtitle: str = ""
    summary_text: str = ""
    meta_text: str = ""
    badges: list[SkillResultPanelBadge] = Field(default_factory=list)
    meta_badges: list[SkillResultPanelBadge] = Field(default_factory=list)


class SkillResultList(BaseModel):
    key: str
    panel_type: str = "result_list"
    title: str
    empty_text: str
    total: int = 0
    page: int = 1
    page_size: int = 10
    items: list[SkillResultListItem] = Field(default_factory=list)


class SkillResultBlockSection(BaseModel):
    id: str = ""
    eyebrow: str
    title: str
    tag: str = ""
    tone: str = "info"


class SkillResultBlock(BaseModel):
    key: str
    block_type: str
    section: SkillResultBlockSection
    result_panel: Optional[SkillResultPanel] = None
    result_list: Optional[SkillResultList] = None


class SkillResultMeta(BaseModel):
    panels: list[SkillResultPanel] = Field(default_factory=list)
    lists: list[SkillResultList] = Field(default_factory=list)
    blocks: list[SkillResultBlock] = Field(default_factory=list)


class SkillImportPreviewResult(BaseModel):
    title: str
    base_directory: str
    detected: int
    created: int
    updated: int
    skipped: int
    confirm_button_text: str
    empty_text: str
    summary_text: str
    summary_items: list[SkillImportPreviewSummaryItem]
    items: list[SkillImportPreviewItem]
    result_panel: SkillResultPanel
    result_blocks: list[SkillResultBlock] = Field(default_factory=list)


class SkillScanRequest(BaseModel):
    skill_ids: list[int]
