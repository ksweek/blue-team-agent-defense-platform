from __future__ import annotations

import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tests._test_env import configure_test_environment

configure_test_environment()

import pytest
from fastapi.testclient import TestClient

from app.api.routes import gateway as gateway_route
from app.core.config import DEFAULT_JWT_SECRET, DEFAULT_SERVICE_TOKEN
from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app, create_app
from app.models import Report
from app.services.bootstrap import validate_runtime_configuration
from app.services.request_security import redact_url


def unwrap(response):
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["code"] == 0, payload
    return payload["data"]


def test_security_headers_are_applied(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200, response.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["X-Permitted-Cross-Domain-Policies"] == "none"
    assert response.headers["X-Request-ID"]


def test_trusted_host_middleware_blocks_untrusted_host(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "trusted_hosts", ["127.0.0.1", "testserver"])

    with TestClient(create_app(), raise_server_exceptions=False) as hardened_client:
        response = hardened_client.get("/health", headers={"host": "evil.example"})

    assert response.status_code == 400


def test_sensitive_query_values_are_redacted():
    redacted = redact_url("/gateway/v1/ws?token=secret-token&session_id=secret-session&safe=value")

    assert "secret-token" not in redacted
    assert "secret-session" not in redacted
    assert "token=%2A%2A%2A" in redacted or "token=***" in redacted
    assert "safe=value" in redacted


def test_validation_errors_redact_sensitive_inputs(client: TestClient):
    response = client.post("/api/auth/login", json={"username": "admin", "password": 123456})

    assert response.status_code == 422, response.text
    assert "123456" not in response.text


def test_production_config_rejects_wildcards_and_debug_details(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg://user:pass@db/app")
    monkeypatch.setattr(settings, "jwt_secret", f"{DEFAULT_JWT_SECRET}-changed")
    monkeypatch.setattr(settings, "gateway_api_token", f"{DEFAULT_SERVICE_TOKEN}-changed")
    monkeypatch.setattr(settings, "bootstrap_mode", "validate")
    monkeypatch.setattr(settings, "bootstrap_admin_password", "changed-admin-password")
    monkeypatch.setattr(settings, "bootstrap_analyst_password", "changed-analyst-password")
    monkeypatch.setattr(settings, "trusted_hosts", ["*"])
    monkeypatch.setattr(settings, "cors_origins", ["https://console.example"])
    monkeypatch.setattr(settings, "cors_origin_regex", "")
    monkeypatch.setattr(settings, "expose_internal_error_details", False)

    with pytest.raises(RuntimeError, match="TRUSTED_HOSTS"):
        validate_runtime_configuration(role="api")


def test_login_rate_limit_blocks_repeated_attempts(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "auth_login_rate_limit_attempts", 2)
    monkeypatch.setattr(settings, "auth_login_rate_limit_window_seconds", 60)

    username = f"rate-limit-{uuid.uuid4().hex[:8]}"
    payload = {"username": username, "password": "wrong-password"}

    first = client.post("/api/auth/login", json=payload)
    second = client.post("/api/auth/login", json=payload)
    third = client.post("/api/auth/login", json=payload)

    assert first.status_code == 401, first.text
    assert second.status_code == 401, second.text
    assert third.status_code == 429, third.text
    assert third.headers["Retry-After"]


def test_public_runtime_register_rate_limit_blocks_repeated_attempts(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "runtime_register_rate_limit_attempts", 2)
    monkeypatch.setattr(settings, "runtime_register_rate_limit_window_seconds", 60)

    payload = {
        "enrollment_token": f"invalid-enrollment-{uuid.uuid4().hex}",
        "display_name": "rate-limit-runtime",
        "runtime_type": "agent",
    }

    first = client.post("/gateway/v1/runtime/register", json=payload)
    second = client.post("/gateway/v1/runtime/register", json=payload)
    third = client.post("/gateway/v1/runtime/register", json=payload)

    assert first.status_code == 401, first.text
    assert second.status_code == 401, second.text
    assert third.status_code == 429, third.text
    assert third.headers["Retry-After"]


def test_http_request_body_limit_rejects_oversized_payload(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "http_request_max_bytes", 128)

    response = client.post(
        "/api/auth/login",
        json={
            "username": f"oversized-{uuid.uuid4().hex[:8]}",
            "password": "x" * 4096,
        },
    )

    assert response.status_code == 413, response.text
    payload = response.json()
    assert payload["message"] == "request body too large"


def test_internal_errors_are_redacted_in_client_response(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "expose_internal_error_details", False)

    def explode(*_args, **_kwargs):
        raise RuntimeError("leak-me-to-client")

    monkeypatch.setattr(gateway_route, "resolve_enrollment_token", explode)

    with TestClient(app, raise_server_exceptions=False) as hardened_client:
        response = hardened_client.post(
            "/gateway/v1/runtime/register",
            json={
                "enrollment_token": f"explode-{uuid.uuid4().hex}",
                "display_name": "explode-runtime",
                "runtime_type": "agent",
            },
        )

    assert response.status_code == 500, response.text
    payload = response.json()
    assert payload["message"] == "服务内部错误"
    assert "leak-me-to-client" not in response.text
    assert payload["data"]["request_id"]


def test_report_download_recovers_from_invalid_stored_path(client: TestClient, admin_headers: dict[str, str]):
    db = SessionLocal()
    report_id: int | None = None
    try:
        template_report = db.query(Report).order_by(Report.id.asc()).first()
        assert template_report is not None

        temp_report = Report(
            task_id=template_report.task_id,
            report_name=f"invalid-path-{uuid.uuid4().hex[:8]}",
            report_type=template_report.report_type,
            file_path="../../outside.json",
            summary_text="invalid path regression",
            created_by=template_report.created_by,
        )
        db.add(temp_report)
        db.commit()
        db.refresh(temp_report)
        report_id = int(temp_report.id)
    finally:
        db.close()

    try:
        detail_payload = unwrap(client.get(f"/api/reports/{report_id}", headers=admin_headers))
        assert detail_payload["artifact_path_valid"] is False
        assert detail_payload["artifact_exists"] is False

        download = client.get(f"/api/reports/{report_id}/download", headers=admin_headers)
        assert download.status_code == 200, download.text

        db = SessionLocal()
        try:
            repaired = db.get(Report, report_id)
            assert repaired is not None
            assert ".." not in repaired.file_path
            assert repaired.file_path.replace("\\", "/").startswith("data/reports/")
        finally:
            db.close()
    finally:
        if report_id is not None:
            db = SessionLocal()
            try:
                item = db.get(Report, report_id)
                if item is not None:
                    db.delete(item)
                    db.commit()
            finally:
                db.close()


if __name__ == "__main__":
    from backend.tests.run_backend_tests_cn import main as run_cn_tests

    raise SystemExit(run_cn_tests([str(Path(__file__).resolve())]))
