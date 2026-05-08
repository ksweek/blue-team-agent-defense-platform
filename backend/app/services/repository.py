from __future__ import annotations

from typing import Any, Iterable, Optional

from fastapi import HTTPException


def get_by_id(items: list[dict[str, Any]], item_id: int, resource_name: str) -> dict[str, Any]:
    for item in items:
        if item.get("id") == item_id:
            return item
    raise HTTPException(status_code=404, detail=f"{resource_name}不存在")


def get_by_key(items: list[dict[str, Any]], key: str, value: Any, resource_name: str) -> dict[str, Any]:
    for item in items:
        if item.get(key) == value:
            return item
    raise HTTPException(status_code=404, detail=f"{resource_name}不存在")


def paginate(items: Iterable[dict[str, Any]], page: int = 1, page_size: int = 10) -> dict[str, Any]:
    normalized_items = list(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": normalized_items[start:end],
        "total": len(normalized_items),
        "page": page,
        "page_size": page_size,
    }


def next_id(items: list[dict[str, Any]]) -> int:
    return max((int(item.get("id", 0)) for item in items), default=0) + 1


def contains_keyword(item: dict[str, Any], keyword: Optional[str], fields: list[str]) -> bool:
    if not keyword:
        return True

    target = keyword.lower()
    return any(target in str(item.get(field, "")).lower() for field in fields)
