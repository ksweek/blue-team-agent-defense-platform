from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


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
