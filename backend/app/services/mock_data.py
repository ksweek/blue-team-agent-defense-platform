from __future__ import annotations

from .seed import (
    assets,
    asset_whitelists,
    dashboard_overview,
    dashboard_sessions,
    dashboard_trends,
    defense_configs,
    reports,
    security_events,
    skills,
    system_settings,
    audit_logs,
    tasks,
    users,
)

MOCK_DATA = {
    "users": users,
    "dashboard_overview": dashboard_overview,
    "dashboard_trends": dashboard_trends,
    "dashboard_sessions": dashboard_sessions,
    "defense_configs": defense_configs,
    "security_events": security_events,
    "assets": assets,
    "asset_whitelists": asset_whitelists,
    "skills": skills,
    "tasks": tasks,
    "reports": reports,
    "system_settings": system_settings,
    "audit_logs": audit_logs,
}
