from pydantic import BaseModel


class SecurityEventItem(BaseModel):
    id: int
    event_type: str
    event_level: str
    source: str
    target: str
    status: str
    created_at: str


class SecurityEventDetail(SecurityEventItem):
    detail: str
    hit_rules: list[str]
    raw_input: str
    result: str
    operation_logs: list[dict]


class EventStatusUpdate(BaseModel):
    status: str


class EventBatchHandle(BaseModel):
    ids: list[int]
    status: str
