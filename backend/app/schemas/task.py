from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Union

from pydantic import BaseModel, Field


class AttackTaskCreate(BaseModel):
    task_name: str
    attack_type: str
    target_agent: str
    ai_endpoint_id: Optional[int] = None
    params_json: dict[str, Any] = Field(default_factory=dict)


class AttackTaskFromSampleCreate(BaseModel):
    sample_id: str
    target_agent: str
    ai_endpoint_id: Optional[int] = None
    task_name: Optional[str] = None
    params_json: dict[str, Any] = Field(default_factory=dict)
    auto_run: bool = True
    schedule_at: Optional[datetime] = None


class AttackTaskBatchFromSamplesCreate(BaseModel):
    sample_ids: list[str]
    target_agent: str
    ai_endpoint_id: Optional[int] = None
    params_json: dict[str, Any] = Field(default_factory=dict)
    auto_run: bool = True
    schedule_at: Optional[datetime] = None


class AttackTaskDispatchRequest(BaseModel):
    task_ids: list[int]
    schedule_at: Optional[datetime] = None


class AttackTaskRetryRequest(BaseModel):
    schedule_at: Optional[datetime] = None


class ReportGenerateRequest(BaseModel):
    task_id: int
    report_type: str


class ReportBatchDownloadRequest(BaseModel):
    task_ids: list[int]
    include_manifest: bool = True
    formats: list[str] = Field(default_factory=lambda: ["json"])


class RuntimeEventPayload(BaseModel):
    event_type: str
    event_level: str = "medium"
    event_status: str = "suspicious"
    source: Optional[str] = None
    detail: str = ""
    hit_rules: list[str] = Field(default_factory=list)
    raw_input: str = ""
    result: str = ""
    operation_logs: list[dict[str, Any]] = Field(default_factory=list)


class RuntimeTaskHeartbeat(BaseModel):
    runtime_name: str
    runtime_task_ref: Optional[str] = None
    status: str = "running"
    message: Optional[str] = None
    progress: Optional[int] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeTaskAuthorizeRequest(BaseModel):
    runtime_name: Optional[str] = None
    runtime_task_ref: Optional[str] = None
    action_type: str = "task_execution"
    input_text: Optional[str] = None
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
    requested_scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeTaskComplete(BaseModel):
    runtime_name: Optional[str] = None
    runtime_task_ref: Optional[str] = None
    status: str = "done"
    summary: str
    raw_response_text: Optional[str] = None
    raw_response_json: Optional[Union[dict[str, Any], list[Any]]] = None
    report_type: str = "runtime_execution"
    metadata: dict[str, Any] = Field(default_factory=dict)
    event: Optional[RuntimeEventPayload] = None
