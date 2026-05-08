from __future__ import annotations

from collections.abc import Callable
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..db.session import get_db
from ..models import User
from .security import decode_access_token

ROLE_PAGE_MAP = {
    "admin": [
        "/",
        "/attack-lab",
        "/ai-endpoints",
        "/defense-config",
        "/security-events",
        "/asset-protection",
        "/skill-management",
        "/system-settings",
    ],
    "analyst": [
        "/",
        "/attack-lab",
        "/defense-config",
        "/security-events",
        "/asset-protection",
        "/skill-management",
    ],
}

bearer_scheme = HTTPBearer(auto_error=False)


def build_user_payload(user: User) -> dict:
    pages: list[str] = []
    for role in user.roles:
        for page in ROLE_PAGE_MAP.get(role, []):
            if page not in pages:
                pages.append(page)

    return {
        "id": user.id,
        "username": user.username,
        "real_name": user.real_name,
        "roles": user.roles,
        "pages": pages,
    }


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少访问令牌")

    payload = decode_access_token(credentials.credentials)
    user_id = int(payload.get("uid", 0))
    user = db.query(User).get(user_id)
    if user is None or user.status != "active":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在或已停用")
    return user


def require_roles(*allowed_roles: str) -> Callable[[User], User]:
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not set(current_user.roles).intersection(allowed_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="当前角色无权访问该资源")
        return current_user

    return dependency
