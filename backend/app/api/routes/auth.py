from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...core.response import success
from ...schemas.auth import LoginRequest, LoginResponse, LoginUser
from ...db.session import get_db
from ...models import User
from ...services.audit import append_audit_log
from ...services.authorization import build_user_payload, get_current_user
from ...services.security import create_access_token, verify_password

router = APIRouter()


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    if user.status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="当前用户已停用")

    token, expires_at = create_access_token(user.username, user.id, user.roles)
    append_audit_log(db, user, "auth", "login", f"用户 {user.username} 登录平台")
    db.commit()

    user_payload = build_user_payload(user)
    data = LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_at=expires_at.isoformat(),
        user=LoginUser(**user_payload),
    )
    return success(data.model_dump())


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return success(build_user_payload(current_user))
