from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from time import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException, Request, status

from ..core.config import settings
from .cache import cache_service

SENSITIVE_FIELD_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "bootstrap_code",
    "code",
    "cookie",
    "credential",
    "enrollment_token",
    "gateway_token",
    "handoff_token",
    "jwt",
    "key",
    "password",
    "refresh_token",
    "secret",
    "session",
    "smtp",
    "token",
)
REDACTED_VALUE = "***"


def build_response_security_headers(*, scheme: str) -> dict[str, str]:
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "X-Permitted-Cross-Domain-Policies": "none",
    }
    if scheme.lower() == "https":
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return headers


def is_sensitive_name(name: object) -> bool:
    normalized = str(name or "").strip().lower().replace("-", "_")
    return any(fragment in normalized for fragment in SENSITIVE_FIELD_FRAGMENTS)


def redact_url(value: str) -> str:
    if not value:
        return value
    try:
        split = urlsplit(value)
        if not split.query:
            return value
        pairs = [
            (key, REDACTED_VALUE if is_sensitive_name(key) else item_value)
            for key, item_value in parse_qsl(split.query, keep_blank_values=True)
        ]
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs, doseq=True), split.fragment))
    except Exception:
        return value


def redact_mapping(value: Mapping[str, object] | None) -> dict[str, object]:
    redacted: dict[str, object] = {}
    for key, item_value in (value or {}).items():
        redacted[str(key)] = REDACTED_VALUE if is_sensitive_name(key) else item_value
    return redacted


def redact_validation_errors(errors: list[dict[str, object]]) -> list[dict[str, object]]:
    redacted_errors: list[dict[str, object]] = []
    for item in errors:
        redacted = dict(item)
        location = redacted.get("loc")
        if isinstance(location, (list, tuple)) and any(is_sensitive_name(part) for part in location):
            redacted["input"] = REDACTED_VALUE
        redacted_errors.append(redacted)
    return redacted_errors


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


def _hash_secret(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:16]


def _normalize_label(value: str) -> str:
    lowered = value.strip().lower()
    if not lowered:
        return "-"
    return hashlib.sha1(lowered.encode("utf-8")).hexdigest()[:16]


def build_rate_limit_subject(
    request: Request,
    *,
    label: str = "",
    secret_value: str = "",
) -> str:
    parts = [client_ip(request)]
    if label:
        parts.append(f"label:{_normalize_label(label)}")
    if secret_value:
        parts.append(f"secret:{_hash_secret(secret_value)}")
    return "|".join(parts)


def enforce_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    label: str = "",
    secret_value: str = "",
) -> None:
    if limit <= 0 or window_seconds <= 0:
        return

    now = time()
    subject = build_rate_limit_subject(request, label=label, secret_value=secret_value)
    key_parts = {"bucket": bucket, "subject": subject}
    state = cache_service.get_json("rate_limits", key_parts=key_parts, ttl_seconds=window_seconds) or {}

    count = int(state.get("count", 0) or 0)
    reset_at = float(state.get("reset_at", 0) or 0)
    if reset_at <= now:
        count = 0
        reset_at = now + window_seconds

    count += 1
    ttl_seconds = max(1, int(math.ceil(reset_at - now)))
    cache_service.set_json(
        "rate_limits",
        key_parts=key_parts,
        value={"count": count, "reset_at": reset_at},
        ttl_seconds=ttl_seconds,
    )

    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many requests",
            headers={"Retry-After": str(ttl_seconds)},
        )


async def buffer_request_body_with_limit(request: Request, *, max_bytes: int) -> bytes:
    if max_bytes <= 0:
        return b""

    content_length_value = request.headers.get("content-length", "").strip()
    if content_length_value:
        try:
            if int(content_length_value) > max_bytes:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="request body too large")
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid content-length header") from exc

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="request body too large")
        chunks.append(chunk)

    body = b"".join(chunks)
    restored = False

    async def receive() -> dict[str, object]:
        nonlocal restored
        if restored:
            return {"type": "http.request", "body": b"", "more_body": False}
        restored = True
        return {"type": "http.request", "body": body, "more_body": False}

    request._body = body  # type: ignore[attr-defined]
    request._receive = receive  # type: ignore[attr-defined]
    return body


def http_body_limit_bytes() -> int:
    return max(1024, int(settings.http_request_max_bytes))


def websocket_message_limit_bytes() -> int:
    return max(1024, int(settings.websocket_message_max_bytes))
