from __future__ import annotations

import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tests._test_env import configure_test_environment

configure_test_environment()

from fastapi.testclient import TestClient

from app.api.routes import auth as auth_routes
from app.services import email_notifications


def test_email_register_and_reset_password_flow(client: TestClient, monkeypatch):
    captured_codes: dict[tuple[str, str], str] = {}

    def fake_send_auth_code(db, *, recipient: str, code: str, purpose: str):
        captured_codes[(purpose, recipient)] = code
        return {"recipient": recipient, "subject": "test"}

    monkeypatch.setattr(auth_routes, "send_auth_verification_email", fake_send_auth_code)

    unique = uuid.uuid4().hex[:10]
    username = f"user_{unique}"
    email = f"{unique}@example.com"
    password = "register_123"
    next_password = "reset_12345"

    send_register_code = client.post(
        "/api/auth/send-code",
        json={"purpose": "register", "username": username, "email": email},
    )
    assert send_register_code.status_code == 200, send_register_code.text
    register_code = captured_codes[("register", email)]

    register = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
            "code": register_code,
            "real_name": "Email Flow User",
        },
    )
    assert register.status_code == 200, register.text
    assert register.json()["data"]["user"]["username"] == username

    send_reset_code = client.post(
        "/api/auth/send-code",
        json={"purpose": "reset_password", "email": email},
    )
    assert send_reset_code.status_code == 200, send_reset_code.text
    reset_code = captured_codes[("reset_password", email)]

    reset = client.post(
        "/api/auth/reset-password",
        json={"email": email, "code": reset_code, "new_password": next_password},
    )
    assert reset.status_code == 200, reset.text

    old_login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert old_login.status_code == 401

    new_login = client.post("/api/auth/login", json={"username": username, "password": next_password})
    assert new_login.status_code == 200, new_login.text


def test_auth_verification_email_does_not_require_digest_recipients(monkeypatch):
    sent: dict[str, object] = {}
    config = email_notifications.EmailNotificationConfig(
        enabled=False,
        recipients=[],
        template_key="standard_digest",
        min_level="high",
        digest_minutes=30,
        subject_prefix="[GuardianAgent]",
        sender="sender@qq.com",
        qq_email_account="sender@qq.com",
        qq_email_auth_code="auth-code",
    )

    monkeypatch.setattr(email_notifications, "load_email_notification_config", lambda db: config)
    monkeypatch.setattr(
        email_notifications,
        "_dispatch_email",
        lambda target_config, subject, body: sent.update(
            {"recipients": target_config.recipients, "subject": subject, "body": body}
        ),
    )

    result = email_notifications.send_auth_verification_email(
        object(),
        recipient="new-user@example.com",
        code="123456",
        purpose="register",
    )

    assert result["recipient"] == "new-user@example.com"
    assert sent["recipients"] == ["new-user@example.com"]
    assert "123456" in str(sent["body"])


if __name__ == "__main__":
    from backend.tests.run_backend_tests_cn import main as run_cn_tests

    raise SystemExit(run_cn_tests([str(Path(__file__).resolve())]))
