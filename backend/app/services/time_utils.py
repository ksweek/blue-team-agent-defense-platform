from __future__ import annotations

from datetime import datetime, timedelta, timezone

BEIJING_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")


def utc_now() -> datetime:
    return datetime.utcnow()


def beijing_now() -> datetime:
    return datetime.now(timezone.utc).astimezone(BEIJING_TZ)


def to_beijing(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(BEIJING_TZ)


def format_beijing(value: datetime | None, pattern: str = "%Y-%m-%d %H:%M:%S") -> str | None:
    if value is None:
        return None
    return to_beijing(value).strftime(pattern)


def parse_utc_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
