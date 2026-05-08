from __future__ import annotations

import contextvars
import logging
import os
import sys

from .config import settings

_REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_LOGGING_CONFIGURED = False


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = current_request_id()
        return True


class ProfessionalConsoleFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: "\x1b[38;5;244m",
        logging.INFO: "\x1b[38;5;45m",
        logging.WARNING: "\x1b[38;5;214m",
        logging.ERROR: "\x1b[38;5;203m",
        logging.CRITICAL: "\x1b[1;38;5;196m",
    }
    RESET = "\x1b[0m"

    def __init__(self, use_color: bool | None = None) -> None:
        super().__init__(datefmt="%Y-%m-%d %H:%M:%S")
        self.use_color = _should_use_color() if use_color is None else use_color

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, self.datefmt)
        level = f"{record.levelname:<7}"
        component = f"{_component_name(record.name):<18}"
        request_id = f"{getattr(record, 'request_id', '-'):<10}"
        message = record.getMessage()

        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        elif record.exc_text:
            message = f"{message}\n{record.exc_text}"

        if self.use_color:
            color = self.LEVEL_COLORS.get(record.levelno)
            if color:
                level = f"{color}{level}{self.RESET}"

        return f"[{timestamp}] {level} {component} {request_id} {message}"


def configure_logging(level: str | int | None = None) -> None:
    global _LOGGING_CONFIGURED

    if _LOGGING_CONFIGURED:
        return

    resolved_level = _resolve_level(level if level is not None else settings.log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(resolved_level)
    handler.addFilter(RequestContextFilter())
    handler.setFormatter(ProfessionalConsoleFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(resolved_level)
    root_logger.addHandler(handler)

    for logger_name in ("app", "uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.setLevel(resolved_level)
        logger.propagate = True

    if not settings.database_echo:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    logging.captureWarnings(True)
    _LOGGING_CONFIGURED = True


def set_request_id(value: str):
    return _REQUEST_ID.set(value or "-")


def reset_request_id(token) -> None:
    _REQUEST_ID.reset(token)


def current_request_id() -> str:
    return _REQUEST_ID.get()


def set_runtime_log_level(level: str | int) -> None:
    resolved_level = _resolve_level(level)
    root_logger = logging.getLogger()
    root_logger.setLevel(resolved_level)
    for handler in root_logger.handlers:
        handler.setLevel(resolved_level)

    for logger_name in ("app", "uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logging.getLogger(logger_name).setLevel(resolved_level)

    if not settings.database_echo:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def _resolve_level(level: str | int) -> int:
    if isinstance(level, int):
        return level

    normalized = str(level).strip().upper()
    return int(getattr(logging, normalized, logging.INFO))


def _should_use_color() -> bool:
    return bool(sys.stdout.isatty() and os.getenv("NO_COLOR") is None)


def _component_name(name: str) -> str:
    shortened = name[4:] if name.startswith("app.") else name
    if len(shortened) <= 18:
        return shortened
    return shortened[-18:]
