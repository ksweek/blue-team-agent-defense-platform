from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class UserItem(BaseModel):
    id: int
    username: str
    real_name: str
    email: str
    status: str
    roles: list[str] = Field(default_factory=list)
    created_at: str = ""


class UserCreate(BaseModel):
    username: str
    real_name: str
    email: str
    password: str
    status: str = "active"
    roles: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    real_name: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    roles: Optional[list[str]] = None


class UserPasswordReset(BaseModel):
    new_password: str


class UserStatusUpdate(BaseModel):
    status: str


class UserRolesUpdate(BaseModel):
    roles: list[str] = Field(default_factory=list)
