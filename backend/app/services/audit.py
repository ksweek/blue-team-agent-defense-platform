from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import AuditLog, User


def append_audit_log(db: Session, user: User, module: str, action: str, detail: str) -> AuditLog:
    item = AuditLog(
        user_id=user.id,
        module=module,
        action=action,
        detail=detail,
    )
    db.add(item)
    db.flush()
    return item
