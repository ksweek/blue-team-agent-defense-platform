from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=4096)


class AuthCodeRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    purpose: str = Field(pattern="^(register|reset_password)$")
    username: Optional[str] = Field(default=None, max_length=64)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=4096)
    code: str = Field(min_length=4, max_length=12)
    real_name: Optional[str] = Field(default=None, max_length=128)


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    code: str = Field(min_length=4, max_length=12)
    new_password: str = Field(min_length=8, max_length=4096)


class LoginUser(BaseModel):
    id: int
    username: str
    real_name: str
    roles: list[str]
    pages: list[str]


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: str
    user: LoginUser
