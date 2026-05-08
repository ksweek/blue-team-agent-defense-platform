from typing import Generic, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    code: int
    message: str
    data: Optional[T] = None


class PaginatedData(BaseModel):
    items: list[dict]
    total: int


class FieldOption(BaseModel):
    label: str
    value: str
    tone: Optional[str] = None


class FieldMeta(BaseModel):
    control: str
    placeholder: str = ""
    helper_text: str = ""
    options: list[FieldOption] = Field(default_factory=list)
    button_text: str = ""
    empty_text: str = ""
