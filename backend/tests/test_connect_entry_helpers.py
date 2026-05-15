from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AGENT_GATEWAY_DIR = PROJECT_ROOT / "tools" / "agent_gateway"

if str(AGENT_GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_GATEWAY_DIR))

import connect_entry  # noqa: E402


def test_request_activation_clears_platform_password_and_syncs_ai_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    config_path = tmp_path / "runtime-config.json"
    config = {
        "platform": {
            "base_url": "http://127.0.0.1:8000",
            "username": "admin",
            "password": "admin123",
            "verify_tls": True,
        },
        "runtime": {
            "display_name": "Unit Test Runtime",
            "runtime_type": "agent_gateway",
            "hostname": "unit-host",
            "fingerprint": "unit-fingerprint",
            "client_version": "1.0.0",
            "ip_addresses": ["127.0.0.1"],
            "requested_scopes": ["audit"],
            "capabilities": ["connect"],
            "metadata": {"origin": "unit"},
            "ai_endpoint_id": 7,
        },
    }

    def fake_http_request(**_: object) -> dict[str, object]:
        return {
            "registration": {
                "registration_id": "reg-unit-001",
                "status": "activation_requested",
                "status_summary": "等待管理端签发激活码",
            },
            "runtime": {
                "id": 31,
                "display_name": "Unit Test Runtime",
                "status": "activation_requested",
                "ai_endpoint": {
                    "id": 7,
                    "endpoint_key": "unit-endpoint",
                    "display_name": "Unit Endpoint",
                },
            },
            "onboarding_steps": [{"step": "activate"}],
        }

    monkeypatch.setattr(connect_entry, "http_request", fake_http_request)

    result = connect_entry.request_activation(config_path, config, platform_token="token-unit")
    saved = json.loads(config_path.read_text(encoding="utf-8"))

    assert result["platform"]["password"] == ""
    assert saved["platform"]["password"] == ""
    assert saved["runtime"]["registration_id"] == "reg-unit-001"
    assert saved["runtime"]["managed_runtime_id"] == 31
    assert saved["runtime"]["ai_endpoint_id"] == 7
    assert saved["runtime"]["ai_endpoint_key"] == "unit-endpoint"
    assert saved["runtime"]["ai_endpoint_display_name"] == "Unit Endpoint"
    assert saved["runtime"]["activation_steps"] == [{"step": "activate"}]


def test_reset_runtime_for_reactivation_clears_credentials_but_keeps_binding() -> None:
    config = {
        "runtime": {
            "display_name": "Runtime A",
            "runtime_key": "key-old",
            "runtime_secret": "secret-old",
            "registration_id": "reg-old",
            "poll_secret": "poll-old",
            "activation_code_hint": "AB12",
            "activation_steps": [{"step": "old"}],
            "ai_endpoint_id": 11,
            "ai_endpoint_key": "deepseek-prod",
            "ai_endpoint_display_name": "DeepSeek Prod",
        }
    }

    reset = connect_entry.reset_runtime_for_reactivation(config)

    assert config["runtime"]["runtime_key"] == "key-old"
    assert reset["runtime"]["runtime_key"] == ""
    assert reset["runtime"]["runtime_secret"] == ""
    assert reset["runtime"]["managed_runtime_id"] is None
    assert reset["runtime"]["registration_id"] == ""
    assert reset["runtime"]["poll_secret"] == ""
    assert reset["runtime"]["activation_code_hint"] == ""
    assert reset["runtime"]["activation_steps"] == []
    assert reset["runtime"]["ai_endpoint_id"] == 11
    assert reset["runtime"]["ai_endpoint_key"] == "deepseek-prod"
    assert reset["runtime"]["ai_endpoint_display_name"] == "DeepSeek Prod"


def test_issue_activation_code_updates_runtime_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    config_path = tmp_path / "runtime-config.json"
    config = {
        "platform": {
            "base_url": "http://127.0.0.1:8000",
            "verify_tls": True,
        },
        "runtime": {
            "managed_runtime_id": 88,
            "display_name": "Gateway Runtime",
            "status": "activation_requested",
            "status_summary": "等待管理端签发激活码",
            "ai_endpoint_id": 5,
        },
    }

    def fake_http_request(**_: object) -> dict[str, object]:
        return {
            "status_summary": "激活码已签发",
            "activation_code": "ABCD1234",
            "runtime": {
                "id": 88,
                "display_name": "Gateway Runtime",
                "status": "activation_issued",
                "activation_code_hint": "AB****34",
                "ai_endpoint": {
                    "id": 5,
                    "endpoint_key": "gateway-prod",
                    "display_name": "Gateway Prod",
                },
            },
        }

    monkeypatch.setattr(connect_entry, "http_request", fake_http_request)

    updated, activation_code = connect_entry.issue_activation_code(
        config_path,
        config,
        platform_token="token-unit",
    )
    saved = json.loads(config_path.read_text(encoding="utf-8"))

    assert activation_code == "ABCD1234"
    assert updated["runtime"]["status"] == "activation_issued"
    assert saved["runtime"]["activation_code_hint"] == "AB****34"
    assert saved["runtime"]["ai_endpoint_key"] == "gateway-prod"
