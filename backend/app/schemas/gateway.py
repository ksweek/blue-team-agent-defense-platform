from __future__ import annotations

from typing import Any, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from .task import RuntimeTaskAuthorizeRequest, RuntimeTaskComplete, RuntimeTaskHeartbeat


class GatewayTargetSelector(BaseModel):
    endpoint_id: Optional[int] = None
    endpoint_key: Optional[str] = None
    endpoint_group: Optional[str] = None


class GatewayChatMessage(BaseModel):
    role: str = "user"
    content: Any = ""


class GatewayChatCompletionsRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: Optional[str] = None
    messages: list[GatewayChatMessage] = Field(default_factory=list)
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = False
    tools: list[Any] = Field(default_factory=list)
    tool_choice: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    target_selector: Optional[GatewayTargetSelector] = None
    requested_scopes: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    skill_names: list[str] = Field(default_factory=list)
    plugin_names: list[str] = Field(default_factory=list)
    source_plugin: Optional[str] = None
    target_plugin: Optional[str] = None
    mcp_server: Optional[str] = None
    capability_name: Optional[str] = None
    session_id: Optional[str] = None
    approval_id: Optional[str] = None
    handoff_token: Optional[str] = None


class GatewayResponsesRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: Optional[str] = None
    input: Any = None
    instructions: Optional[str] = None
    temperature: Optional[float] = None
    max_output_tokens: Optional[int] = None
    stream: bool = False
    tools: list[Any] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    target_selector: Optional[GatewayTargetSelector] = None
    requested_scopes: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    skill_names: list[str] = Field(default_factory=list)
    plugin_names: list[str] = Field(default_factory=list)
    source_plugin: Optional[str] = None
    target_plugin: Optional[str] = None
    mcp_server: Optional[str] = None
    capability_name: Optional[str] = None
    session_id: Optional[str] = None
    approval_id: Optional[str] = None
    handoff_token: Optional[str] = None


class GatewayAgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: Optional[str] = None
    runtime_name: Optional[str] = None
    input_text: Optional[str] = None
    instructions: Optional[str] = None
    messages: list[GatewayChatMessage] = Field(default_factory=list)
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = False
    tools: list[Any] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    target_selector: Optional[GatewayTargetSelector] = None
    requested_scopes: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    skill_names: list[str] = Field(default_factory=list)
    plugin_names: list[str] = Field(default_factory=list)
    source_plugin: Optional[str] = None
    target_plugin: Optional[str] = None
    mcp_server: Optional[str] = None
    capability_name: Optional[str] = None
    session_id: Optional[str] = None
    approval_id: Optional[str] = None
    handoff_token: Optional[str] = None


class GatewayRuntimeAuthorizeRequest(RuntimeTaskAuthorizeRequest):
    task_id: int


class GatewayRuntimeHeartbeatRequest(RuntimeTaskHeartbeat):
    task_id: int


class GatewayRuntimeCompleteRequest(RuntimeTaskComplete):
    task_id: int


class GatewayRuntimeCommandCompleteRequest(BaseModel):
    status: str = "completed"
    summary: str = ""
    response_text: Optional[str] = None
    response_json: Optional[Union[dict[str, Any], list[Any]]] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
