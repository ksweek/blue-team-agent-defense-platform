from typing import Any


def success(data: Any = None, message: str = "ok") -> dict[str, Any]:
    return {
        "code": 0,
        "message": message,
        "data": data,
    }


def failure(code: int, message: str, data: Any = None) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "data": data,
    }


def error_code_from_status(status_code: int) -> int:
    if status_code == 404:
        return 4003
    if status_code == 422:
        return 4002
    if status_code >= 500:
        return 5001
    return status_code
