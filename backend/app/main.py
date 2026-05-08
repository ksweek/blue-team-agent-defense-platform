from __future__ import annotations

import logging
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.router import api_router
from .api.routes import gateway
from .core.config import settings
from .core.logging import configure_logging, reset_request_id, set_request_id
from .core.response import error_code_from_status, failure
from .db.session import SessionLocal, ping_database
from .models import AiEndpoint
from .services.email_notifications import start_email_digest_worker, stop_email_digest_worker
from .services.bootstrap import init_database, validate_runtime_configuration
from .services.model_provider import provider_status
from .services.task_worker import start_task_worker, stop_task_worker, task_worker_snapshot

configure_logging()

app_logger = logging.getLogger("app.lifecycle")
request_logger = logging.getLogger("app.http")


def _request_target(request: Request) -> str:
    if request.url.query:
        return f"{request.url.path}?{request.url.query}"
    return request.url.path


def _request_log_method(status_code: int, path: str):
    if path == "/health" and status_code < 400:
        return request_logger.debug
    if status_code >= 500:
        return request_logger.error
    if status_code >= 400:
        return request_logger.warning
    return request_logger.info


def create_app() -> FastAPI:
    app_logger.info(
        "initializing application | version=%s env=%s bootstrap_mode=%s database=%s ai_provider=%s",
        settings.app_version,
        settings.app_env,
        settings.bootstrap_mode,
        settings.database_summary,
        settings.ai_provider,
    )
    validate_runtime_configuration(role="api")
    init_database()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Blue Team backend for function-calling agent defense workflows.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_origin_regex=settings.cors_origin_regex,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid4().hex[:8]
        token = set_request_id(request_id)
        started_at = perf_counter()
        client_host = request.client.host if request.client else "-"
        target = _request_target(request)

        try:
            response = await call_next(request)
            duration_ms = int((perf_counter() - started_at) * 1000)
            response.headers["X-Request-ID"] = request_id
            _request_log_method(response.status_code, request.url.path)(
                "%s %s -> %s %dms ip=%s",
                request.method,
                target,
                response.status_code,
                duration_ms,
                client_host,
            )
            return response
        finally:
            reset_request_id(token)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=failure(error_code_from_status(exc.status_code), str(exc.detail)),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        app_logger.warning(
            "request validation failed | method=%s path=%s errors=%s",
            request.method,
            request.url.path,
            exc.errors(),
        )
        return JSONResponse(
            status_code=422,
            content=failure(4002, "参数错误", exc.errors()),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        app_logger.exception(
            "unhandled exception | method=%s path=%s",
            request.method,
            request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content=failure(5001, f"服务内部错误: {exc}"),
        )

    @app.on_event("startup")
    async def startup_task_worker() -> None:
        if settings.task_worker_embedded:
            app_logger.info("starting embedded background worker")
            start_task_worker()
        else:
            app_logger.info("embedded background worker disabled by TASK_WORKER_EMBEDDED=false")
        start_email_digest_worker()
        snapshot = provider_status()
        db = SessionLocal()
        try:
            endpoint_count = db.query(AiEndpoint).filter(AiEndpoint.enabled.is_(True)).count()
        finally:
            db.close()
        app_logger.info(
            "startup complete | provider=%s model=%s configured=%s managed_endpoints=%s",
            snapshot["provider"],
            snapshot["model"] or "-",
            snapshot["configured"],
            endpoint_count,
        )

    @app.on_event("shutdown")
    async def shutdown_task_worker() -> None:
        if settings.task_worker_embedded:
            app_logger.info("stopping embedded background worker")
        stop_email_digest_worker()
        if settings.task_worker_embedded:
            stop_task_worker()
        app_logger.info("shutdown complete")

    @app.get("/health")
    def health() -> dict[str, str]:
        try:
            ping_database()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"database unavailable: {exc}") from exc

        worker_snapshot = task_worker_snapshot()
        provider_snapshot = provider_status()
        db = SessionLocal()
        try:
            endpoint_count = db.query(AiEndpoint).filter(AiEndpoint.enabled.is_(True)).count()
        finally:
            db.close()
        ai_configured = endpoint_count > 0 or provider_snapshot["configured"]
        return {
            "status": "ok",
            "service": "blue-team-backend",
            "database": settings.database_backend,
            "task_worker": worker_snapshot["status"],
            "ai_provider": "managed" if endpoint_count > 0 else str(provider_snapshot["provider"]),
            "ai_configured": "true" if ai_configured else "false",
            "ai_targets": str(endpoint_count),
        }

    app.include_router(api_router, prefix="/api")
    app.include_router(gateway.router, prefix="/gateway/v1", tags=["gateway"])
    return app


app = create_app()
