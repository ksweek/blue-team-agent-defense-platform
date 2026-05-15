from fastapi import APIRouter, Depends

from .routes import (
    ai_endpoints,
    assets,
    auth,
    dashboard,
    defense_configs,
    reports,
    runtime_registry,
    runtime_callbacks,
    samples,
    security_events,
    skills,
    system_settings,
    tasks,
    users,
)
from ..services.authorization import require_roles

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"], dependencies=[Depends(require_roles("admin"))])
api_router.include_router(
    ai_endpoints.router,
    prefix="/ai-endpoints",
    tags=["ai-endpoints"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    dashboard.router,
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    defense_configs.router,
    prefix="/defense-configs",
    tags=["defense-configs"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    security_events.router,
    prefix="/security-events",
    tags=["security-events"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    assets.router,
    prefix="/assets",
    tags=["assets"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    skills.router,
    prefix="/skills",
    tags=["skills"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    tasks.router,
    prefix="/attack-tasks",
    tags=["attack-tasks"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    runtime_registry.public_router,
    prefix="/runtime-registry",
    tags=["runtime-registry"],
)
api_router.include_router(
    runtime_registry.router,
    prefix="/runtime-registry",
    tags=["runtime-registry"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    samples.router,
    prefix="/samples",
    tags=["samples"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    reports.router,
    prefix="/reports",
    tags=["reports"],
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
api_router.include_router(
    runtime_callbacks.router,
    prefix="/runtime",
    tags=["runtime-callbacks"],
)
api_router.include_router(
    system_settings.router,
    prefix="/system-settings",
    tags=["system-settings"],
    dependencies=[Depends(require_roles("admin"))],
)
