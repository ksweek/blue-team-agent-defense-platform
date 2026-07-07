from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class RuntimeEnrollmentTokenCreate(BaseModel):
    token_label: str = Field(min_length=1, max_length=128)
    runtime_type: str = Field(default="agent", max_length=64)
    ai_endpoint_id: Optional[int] = None
    usage_limit: int = 1
    expires_at: Optional[datetime] = None
    delivery_mode: str = Field(default="approval", max_length=32)


class RuntimeApprovalRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=128)
    ai_endpoint_id: Optional[int] = None


class RuntimeActivationRequestCreate(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=128)
    runtime_type: str = Field(default="agent", max_length=64)
    hostname: str = Field(default="", max_length=255)
    fingerprint: str = Field(default="", max_length=256)
    client_version: str = Field(default="", max_length=64)
    ip_addresses: list[str] = Field(default_factory=list, max_length=32)
    requested_scopes: list[str] = Field(default_factory=list, max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)
    ai_endpoint_id: Optional[int] = None


class RuntimeActivationCodeIssueRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=128)
    ai_endpoint_id: Optional[int] = None
    expires_in_minutes: int = 10


class RuntimeActivationCodeExchangeRequest(BaseModel):
    registration_id: str = Field(min_length=1, max_length=128)
    activation_code: str = Field(min_length=1, max_length=256)


class RuntimeBootstrapActivationRequest(BaseModel):
    activation_code: str = Field(min_length=1, max_length=256)
    display_name: Optional[str] = Field(default=None, max_length=128)
    runtime_type: str = Field(default="agent", max_length=64)
    hostname: str = Field(default="", max_length=255)
    fingerprint: str = Field(default="", max_length=256)
    client_version: str = Field(default="", max_length=64)
    ip_addresses: list[str] = Field(default_factory=list, max_length=32)
    requested_scopes: list[str] = Field(default_factory=list, max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeBindingRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=128)
    ai_endpoint_id: Optional[int] = None


class RuntimeEnrollmentTokenBindingRequest(BaseModel):
    ai_endpoint_id: Optional[int] = None


class RuntimeRejectionRequest(BaseModel):
    reason: str = Field(default="", max_length=512)


class RuntimeRegisterRequest(BaseModel):
    enrollment_token: str = Field(min_length=1, max_length=256)
    display_name: Optional[str] = Field(default=None, max_length=128)
    runtime_type: str = Field(default="agent", max_length=64)
    hostname: str = Field(default="", max_length=255)
    fingerprint: str = Field(default="", max_length=256)
    client_version: str = Field(default="", max_length=64)
    ip_addresses: list[str] = Field(default_factory=list, max_length=32)
    requested_scopes: list[str] = Field(default_factory=list, max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)
    ai_endpoint_id: Optional[int] = None


class RuntimeRegisterStatusRequest(BaseModel):
    registration_id: str = Field(min_length=1, max_length=128)
    poll_secret: str = Field(min_length=1, max_length=256)
