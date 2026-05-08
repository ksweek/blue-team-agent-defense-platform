from pydantic import BaseModel


class DashboardOverview(BaseModel):
    attack_count: int
    blocked_count: int
    enabled_defense_count: int
    high_risk_event_count: int
    active_task_count: int


class DashboardTrendItem(BaseModel):
    day: str
    attack: int
    block: int
    false_positive: int


class SessionItem(BaseModel):
    session_id: str
    session_name: str
    status: str
    risk_level: str
