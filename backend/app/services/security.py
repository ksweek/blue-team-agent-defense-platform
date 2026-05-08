from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status

from ..core.config import settings


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${base64.urlsafe_b64encode(digest).decode('utf-8')}"


def verify_password(password: str, stored_password_hash: str) -> bool:
    try:
        salt, encoded_digest = stored_password_hash.split("$", 1)
    except ValueError:
        return False

    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    candidate = base64.urlsafe_b64encode(digest).decode("utf-8")
    return hmac.compare_digest(candidate, encoded_digest)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


def create_access_token(subject: str, user_id: int, roles: list[str]) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.jwt_expire_minutes)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "uid": user_id,
        "roles": roles,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    signing_input = ".".join(
        [
            _b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
            _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
        ]
    )
    signature = hmac.new(settings.jwt_secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    token = f"{signing_input}.{_b64url_encode(signature)}"
    return token, expires_at


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效的访问令牌") from exc

    signing_input = f"{header_segment}.{payload_segment}"
    expected_signature = hmac.new(
        settings.jwt_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    actual_signature = _b64url_decode(signature_segment)
    if not hmac.compare_digest(expected_signature, actual_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="访问令牌签名无效")

    payload = json.loads(_b64url_decode(payload_segment).decode("utf-8"))
    expires_at = int(payload.get("exp", 0))
    if expires_at <= int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="访问令牌已过期")

    return payload
