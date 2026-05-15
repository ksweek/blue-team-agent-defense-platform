from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AttackTask, DefenseConfig, SecurityEvent, User
from ...services.authorization import require_roles
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
    tasks = db.query(AttackTask).all()
    events = db.query(SecurityEvent).all()

    return success(
        {
            "attack_count": len(tasks),
            "blocked_count": sum(
                1 for item in events if normalize_event_status(item.status, EVENT_STATUS_ALLOWED) == EVENT_STATUS_INTERCEPTED
            ),
            "enabled_defense_count": db.query(DefenseConfig).filter(DefenseConfig.enabled.is_(True)).count(),
            "high_risk_event_count": sum(1 for item in events if _normalize_level(item.event_level) == "high"),
            "active_task_count": sum(1 for item in tasks if item.status in {"queued", "running"}),
        }
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

    tasks = (
        db.query(AttackTask)
        .filter(AttackTask.created_at >= start_at)
        .order_by(AttackTask.created_at.asc(), AttackTask.id.asc())
        .all()
    )
    for item in tasks:
        attack_series[to_beijing(item.created_at).strftime("%m-%d")] += 1

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.created_at >= start_at)
        .order_by(SecurityEvent.created_at.asc(), SecurityEvent.id.asc())
        .all()
    )
    for item in events:
        bucket = to_beijing(item.created_at).strftime("%m-%d")
        normalized_status = normalize_event_status(item.status, EVENT_STATUS_ALLOWED)
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
    return success({"range": time_range, "items": items})


@router.get("/sessions")
def sessions(
    limit: int = Query(6, ge=1, le=20),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    tasks = (
        db.query(AttackTask)
        .order_by(AttackTask.created_at.desc(), AttackTask.id.desc())
        .limit(limit)
        .all()
    )
    items = []
    for item in tasks:
        event = None
        if item.latest_event_id:
            event = db.get(SecurityEvent, item.latest_event_id)
        if event is None:
            event = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.task_id == item.id)
                .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
                .first()
            )

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

    active_total = db.query(AttackTask).filter(AttackTask.status.in_(("queued", "running"))).count()
    return success({"items": items, "total": active_total})
