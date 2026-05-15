from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class McpServerPolicyUpdateItem(BaseModel):
    server_name: str
    server_label: str = ""
    enabled: bool = True
    trust_mode: str = "trusted"
    require_ticket: bool = True
    require_approval: bool = False
    allowed_scopes: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class McpCapabilityPolicyUpdateItem(BaseModel):
    server_name: str = "*"
    capability_name: str
    capability_label: str = ""
    enabled: bool = True
    risk_level: str = "medium"
    approval_mode: str = "inherit"
    allowed_scopes: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class AiEndpointMcpPolicyUpdate(BaseModel):
    servers: list[McpServerPolicyUpdateItem] = Field(default_factory=list)
    capabilities: list[McpCapabilityPolicyUpdateItem] = Field(default_factory=list)


class AiEndpointMcpPolicyTemplateApply(BaseModel):
    template_key: str
