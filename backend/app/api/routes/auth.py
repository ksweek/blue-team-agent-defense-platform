import hashlib
import hmac
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...core.config import settings
from ...core.response import success
from ...schemas.auth import AuthCodeRequest, LoginRequest, LoginResponse, LoginUser, PasswordResetRequest, RegisterRequest
from ...db.session import get_db
from ...models import User
from ...services.audit import append_audit_log
from ...services.authorization import build_user_payload, get_current_user
from ...services.cache import cache_service
from ...services.email_notifications import send_auth_verification_email
from ...services.request_security import enforce_rate_limit
from ...services.security import create_access_token, hash_password, verify_password

router = APIRouter()

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_AUTH_CODE_TTL_SECONDS = 600
_AUTH_CODE_PURPOSES = {"register", "reset_password"}


def _normalize_username(value: str) -> str:
    normalized = str(value or "").strip()
    if len(normalized) < 3 or len(normalized) > 64:
        raise HTTPException(status_code=400, detail="账号长度需要在 3 到 64 个字符之间")
    return normalized


def _normalize_email(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _EMAIL_REGEX.match(normalized):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    return normalized


def _validate_password(value: str) -> str:
    normalized = str(value or "")
    if len(normalized) < 8:
        raise HTTPException(status_code=400, detail="密码至少需要 8 个字符")
    return normalized


def _verification_key(purpose: str, email: str) -> dict[str, str]:
    return {"purpose": purpose, "email": email}


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _store_verification_code(purpose: str, email: str, code: str) -> None:
    cache_service.set_json(
        "auth-verification",
        key_parts=_verification_key(purpose, email),
        value={"code_hash": _hash_code(code)},
        ttl_seconds=_AUTH_CODE_TTL_SECONDS,
    )


def _consume_verification_code(purpose: str, email: str, code: str) -> None:
    cached = cache_service.get_json(
        "auth-verification",
        key_parts=_verification_key(purpose, email),
        ttl_seconds=_AUTH_CODE_TTL_SECONDS,
    )
    expected = str((cached or {}).get("code_hash") or "")
    if not expected or not hmac.compare_digest(expected, _hash_code(str(code or "").strip())):
        raise HTTPException(status_code=400, detail="验证码无效或已过期")
    cache_service.set_json(
        "auth-verification",
        key_parts=_verification_key(purpose, email),
        value={"used": True},
        ttl_seconds=1,
    )


def _issue_login_response(db: Session, user: User) -> dict:
    token, expires_at = create_access_token(user.username, user.id, user.roles)
    user_payload = build_user_payload(user)
    data = LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_at=expires_at.isoformat(),
        user=LoginUser(**user_payload),
    )
    return data.model_dump()


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(
        request,
        bucket="auth-login",
        limit=settings.auth_login_rate_limit_attempts,
        window_seconds=settings.auth_login_rate_limit_window_seconds,
        label=payload.username,
    )
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    if user.status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="当前用户已停用")

    append_audit_log(db, user, "auth", "login", f"用户 {user.username} 登录平台")
    db.commit()

    return success(_issue_login_response(db, user))


@router.post("/send-code")
def send_code(payload: AuthCodeRequest, request: Request, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    purpose = payload.purpose.strip()
    if purpose not in _AUTH_CODE_PURPOSES:
        raise HTTPException(status_code=400, detail="验证码用途不支持")

    enforce_rate_limit(
        request,
        bucket=f"auth-code-{purpose}",
        limit=5,
        window_seconds=600,
        label=email,
    )

    if purpose == "register":
        if payload.username:
            username = _normalize_username(payload.username)
            if db.query(User).filter(User.username == username).first() is not None:
                raise HTTPException(status_code=400, detail="账号已存在")
        if db.query(User).filter(User.email == email).first() is not None:
            raise HTTPException(status_code=400, detail="邮箱已注册")
    else:
        if db.query(User).filter(User.email == email).first() is None:
            return success({"sent": True}, message="如果邮箱存在，验证码将发送到该邮箱")

    code = f"{secrets.randbelow(1_000_000):06d}"
    _store_verification_code(purpose, email, code)
    try:
        send_auth_verification_email(db, recipient=email, code=code, purpose=purpose)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="验证码邮件发送失败，请检查邮箱发件配置") from exc

    return success({"sent": True}, message="验证码已发送")


@router.post("/register")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    username = _normalize_username(payload.username)
    password = _validate_password(payload.password)
    enforce_rate_limit(
        request,
        bucket="auth-register",
        limit=10,
        window_seconds=600,
        label=email,
    )

    if db.query(User).filter(User.username == username).first() is not None:
        raise HTTPException(status_code=400, detail="账号已存在")
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status_code=400, detail="邮箱已注册")
    _consume_verification_code("register", email, payload.code)

    user = User(
        username=username,
        real_name=(payload.real_name or username).strip()[:128],
        email=email,
        status="active",
        password_hash=hash_password(password),
    )
    user.set_roles(["analyst"])
    db.add(user)
    db.flush()
    append_audit_log(db, user, "auth", "register", f"用户 {user.username} 邮箱注册平台")
    db.commit()
    db.refresh(user)
    return success(_issue_login_response(db, user), message="注册成功")


@router.post("/reset-password")
def reset_password(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    password = _validate_password(payload.new_password)
    enforce_rate_limit(
        request,
        bucket="auth-reset-password",
        limit=10,
        window_seconds=600,
        label=email,
    )

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=400, detail="验证码无效或已过期")
    _consume_verification_code("reset_password", email, payload.code)

    user.password_hash = hash_password(password)
    append_audit_log(db, user, "auth", "reset-password", f"用户 {user.username} 通过邮箱验证码重置密码")
    db.commit()
    return success({"reset": True}, message="密码已重置")


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return success(build_user_payload(current_user))
