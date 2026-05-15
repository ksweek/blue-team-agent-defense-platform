from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class RuntimeEnrollmentTokenCreate(BaseModel):
    token_label: str
    runtime_type: str = "agent"
    ai_endpoint_id: Optional[int] = None
    usage_limit: int = 1
    expires_at: Optional[datetime] = None
    delivery_mode: str = "approval"


class RuntimeApprovalRequest(BaseModel):
    display_name: Optional[str] = None
    ai_endpoint_id: Optional[int] = None


class RuntimeActivationRequestCreate(BaseModel):
    display_name: Optional[str] = None
    runtime_type: str = "agent"
    hostname: str = ""
    fingerprint: str = ""
    client_version: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    requested_scopes: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    ai_endpoint_id: Optional[int] = None


class RuntimeActivationCodeIssueRequest(BaseModel):
    display_name: Optional[str] = None
    ai_endpoint_id: Optional[int] = None
    expires_in_minutes: int = 10


class RuntimeActivationCodeExchangeRequest(BaseModel):
    registration_id: str
    activation_code: str


class RuntimeBootstrapActivationRequest(BaseModel):
    activation_code: str
    display_name: Optional[str] = None
    runtime_type: str = "agent"
    hostname: str = ""
    fingerprint: str = ""
    client_version: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    requested_scopes: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeBindingRequest(BaseModel):
    display_name: Optional[str] = None
    ai_endpoint_id: Optional[int] = None


class RuntimeEnrollmentTokenBindingRequest(BaseModel):
    ai_endpoint_id: Optional[int] = None


class RuntimeRejectionRequest(BaseModel):
    reason: str = ""


class RuntimeRegisterRequest(BaseModel):
    enrollment_token: str
    display_name: Optional[str] = None
    runtime_type: str = "agent"
    hostname: str = ""
    fingerprint: str = ""
    client_version: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    requested_scopes: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    ai_endpoint_id: Optional[int] = None


class RuntimeRegisterStatusRequest(BaseModel):
    registration_id: str
    poll_secret: str
