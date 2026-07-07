from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ...core.response import success
from ...db.session import get_db
from ...models import AttackTask, DefenseConfig, SecurityEvent, User
from ...services.authorization import require_roles
from ...services.cache import cached_payload
from ...services.event_status import EVENT_STATUS_ALLOWED, EVENT_STATUS_INTERCEPTED, normalize_event_status
from ...services.time_utils import BEIJING_TZ, beijing_now, to_beijing

router = APIRouter()


def _normalize_level(level: str | None) -> str:
    if not level:
        return "medium"

    lowered = level.lower()
    if lowered == "high" or "\u9ad8" in level:
        return "high"
    if lowered == "low" or "\u4f4e" in level:
        return "low"
    return "medium"


def _parse_range_days(raw_range: str) -> int:
    digits = "".join(char for char in raw_range if char.isdigit())
    if not digits:
        return 7
    return max(1, min(int(digits), 30))


@router.get("/overview")
def overview(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    def load_payload() -> dict:
        return {
            "attack_count": db.query(AttackTask.id).count(),
            "blocked_count": (
                db.query(SecurityEvent.id)
                .filter(SecurityEvent.status.in_((EVENT_STATUS_INTERCEPTED, "blocked")))
                .count()
            ),
            "enabled_defense_count": db.query(DefenseConfig.id).filter(DefenseConfig.enabled.is_(True)).count(),
            "high_risk_event_count": (
                db.query(SecurityEvent.id)
                .filter(or_(SecurityEvent.event_level == "high", SecurityEvent.event_level.contains("高")))
                .count()
            ),
            "active_task_count": (
                db.query(AttackTask.id)
                .filter(AttackTask.status.in_(("ready", "queued", "scheduled", "running")))
                .count()
            ),
        }

    return success(
        cached_payload(
            "dashboard",
            key_parts={"route": "overview"},
            loader=load_payload,
            ttl_seconds=5,
        )
    )


@router.get("/trends")
def trends(
    time_range: str = Query("7d", alias="range"),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    days = _parse_range_days(time_range)
    today = beijing_now().date()
    labels = [today - timedelta(days=offset) for offset in reversed(list(range(days)))]
    start_at = (
        datetime.combine(labels[0], datetime.min.time(), tzinfo=BEIJING_TZ)
        .astimezone(timezone.utc)
        .replace(tzinfo=None)
    )

    attack_series: dict[str, int] = defaultdict(int)
    block_series: dict[str, int] = defaultdict(int)
    false_positive_series: dict[str, int] = defaultdict(int)

    def load_payload() -> dict:
        tasks = (
            db.query(AttackTask.created_at)
            .filter(AttackTask.created_at >= start_at)
            .order_by(AttackTask.created_at.asc(), AttackTask.id.asc())
            .all()
        )
        for created_at, in tasks:
            attack_series[to_beijing(created_at).strftime("%m-%d")] += 1

        events = (
            db.query(SecurityEvent.created_at, SecurityEvent.status)
            .filter(SecurityEvent.created_at >= start_at)
            .order_by(SecurityEvent.created_at.asc(), SecurityEvent.id.asc())
            .all()
        )
        for created_at, status in events:
            bucket = to_beijing(created_at).strftime("%m-%d")
            normalized_status = normalize_event_status(status, EVENT_STATUS_ALLOWED)
            if normalized_status == EVENT_STATUS_INTERCEPTED:
                block_series[bucket] += 1
            if normalized_status == EVENT_STATUS_ALLOWED:
                false_positive_series[bucket] += 1

        items = [
            {
                "day": day.strftime("%m-%d"),
                "attack": attack_series[day.strftime("%m-%d")],
                "block": block_series[day.strftime("%m-%d")],
                "false_positive": false_positive_series[day.strftime("%m-%d")],
            }
            for day in labels
        ]
        return {"range": time_range, "items": items}

    return success(
        cached_payload(
            "dashboard",
            key_parts={"route": "trends", "range": time_range},
            loader=load_payload,
            ttl_seconds=10,
        )
    )


@router.get("/sessions")
def sessions(
    limit: int = Query(6, ge=1, le=20),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    def load_payload() -> dict:
        tasks = (
            db.query(AttackTask)
            .order_by(AttackTask.created_at.desc(), AttackTask.id.desc())
            .limit(limit)
            .all()
        )
        task_ids = [item.id for item in tasks]
        latest_event_map: dict[int, SecurityEvent] = {}
        if task_ids:
            related_events = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.task_id.in_(task_ids))
                .order_by(SecurityEvent.task_id.asc(), SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
                .all()
            )
            for event in related_events:
                if event.task_id and event.task_id not in latest_event_map:
                    latest_event_map[event.task_id] = event

        items = []
        for item in tasks:
            event = latest_event_map.get(item.id)
            if event is not None:
                risk_level = _normalize_level(event.event_level)
            elif item.attack_type in {"jailbreak", "prompt_injection"}:
                risk_level = "high"
            else:
                risk_level = "medium"

            items.append(
                {
                    "session_id": f"task-{item.id}",
                    "session_name": item.task_name,
                    "status": item.status,
                    "risk_level": risk_level,
                }
            )

        active_total = (
            db.query(AttackTask.id)
            .filter(AttackTask.status.in_(("ready", "queued", "scheduled", "running")))
            .count()
        )
        return {"items": items, "total": active_total}

    return success(
        cached_payload(
            "dashboard",
            key_parts={"route": "sessions", "limit": limit},
            loader=load_payload,
            ttl_seconds=5,
        )
    )
