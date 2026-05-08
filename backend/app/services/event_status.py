from __future__ import annotations

EVENT_STATUS_INTERCEPTED = "intercepted"
EVENT_STATUS_SUSPICIOUS = "suspicious"
EVENT_STATUS_ALLOWED = "allowed"

LEGACY_EVENT_STATUS_MAP = {
    "blocked": EVENT_STATUS_INTERCEPTED,
    "pending": EVENT_STATUS_SUSPICIOUS,
    "closed": EVENT_STATUS_ALLOWED,
}


def normalize_event_status(status: str | None, fallback: str = EVENT_STATUS_SUSPICIOUS) -> str:
    lowered = (status or "").strip().lower()
    normalized = LEGACY_EVENT_STATUS_MAP.get(lowered, lowered)
    if normalized in {EVENT_STATUS_INTERCEPTED, EVENT_STATUS_SUSPICIOUS, EVENT_STATUS_ALLOWED}:
        return normalized

    fallback_normalized = LEGACY_EVENT_STATUS_MAP.get(str(fallback or "").strip().lower(), str(fallback or "").strip().lower())
    if fallback_normalized in {EVENT_STATUS_INTERCEPTED, EVENT_STATUS_SUSPICIOUS, EVENT_STATUS_ALLOWED}:
        return fallback_normalized
    return EVENT_STATUS_SUSPICIOUS
