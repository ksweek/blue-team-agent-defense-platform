from typing import Optional

from pydantic import BaseModel, Field

from .common import FieldMeta


class DefenseConfigFieldMeta(BaseModel):
    enabled: FieldMeta
    mode: FieldMeta


class DefenseConfigItem(BaseModel):
    id: int
    defense_name: str
    defense_type: str
    threat_level: str
    mode: str
    enabled: bool
    description: str
    config_json: dict = Field(default_factory=dict)
    field_meta: DefenseConfigFieldMeta


class DefenseConfigUpdate(BaseModel):
    enabled: bool
    mode: str
    config_json: dict


class DefenseConfigBatchUpdate(BaseModel):
    ids: list[int]
    enabled: Optional[bool] = None
    mode: Optional[str] = None


class DefensePolicyRule(BaseModel):
    key: str
    title: str
    description: str
    enabled: bool
    mode: str


class DefensePolicyRuleItem(DefensePolicyRule):
    field_meta: DefenseConfigFieldMeta


class DefenseResourceGroup(BaseModel):
    kind: str
    title: str
    description: str
    field_meta: FieldMeta


class AiReviewPolicy(BaseModel):
    key: str
    title: str
    description: str
    mode: str
    reviewer_ai_endpoint_id: Optional[int] = None


class AiReviewPolicyItem(AiReviewPolicy):
    field_meta: FieldMeta


class DefensePolicyPayload(BaseModel):
    guard_rules: list[DefensePolicyRule]
    scan_rules: list[DefensePolicyRule]
    advanced_rule: DefensePolicyRule
    ai_review_policy: AiReviewPolicy
    protected_paths: list[str]
    protected_skills: list[str]
    protected_plugins: list[str]
