from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class AiEndpointConfigSecretUpdate(BaseModel):
    path: str
    value: Any = ""


class AiEndpointCreate(BaseModel):
    endpoint_key: str
    display_name: str
    endpoint_group: str = "default"
    provider_type: str = "openai_compatible"
    base_url: str
    api_key: str = ""
    model_name: str
    enabled: bool = True
    is_default: bool = False
    protection_enabled: bool = True
    protection_mode: str = "enforce"
    description: str = ""
    config_json: Optional[dict[str, Any]] = None
    config_public_json: dict[str, Any] = Field(default_factory=dict)
    config_secret_updates: list[AiEndpointConfigSecretUpdate] = Field(default_factory=list)
    config_secret_remove_paths: list[str] = Field(default_factory=list)


class AiEndpointUpdate(BaseModel):
    endpoint_key: Optional[str] = None
    display_name: Optional[str] = None
    endpoint_group: Optional[str] = None
    provider_type: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    enabled: Optional[bool] = None
    is_default: Optional[bool] = None
    protection_enabled: Optional[bool] = None
    protection_mode: Optional[str] = None
    description: Optional[str] = None
    config_json: Optional[dict[str, Any]] = None
    config_public_json: Optional[dict[str, Any]] = None
    config_secret_updates: Optional[list[AiEndpointConfigSecretUpdate]] = None
    config_secret_remove_paths: Optional[list[str]] = None


class AiEndpointBatchUpdate(BaseModel):
    ids: list[int] = Field(default_factory=list)
    enabled: Optional[bool] = None
    protection_enabled: Optional[bool] = None
    protection_mode: Optional[str] = None
    endpoint_group: Optional[str] = None
