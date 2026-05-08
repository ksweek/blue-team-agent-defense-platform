from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ...core.response import success
from ...models import User
from ...services.authorization import require_roles
from ...services.repository import paginate
from ...services.sample_catalog import (
    catalog_summary,
    focused_pack_index,
    get_sample,
    query_samples,
    section_index,
    serialize_sample_list_item,
)

router = APIRouter()


@router.get("/summary")
def get_sample_catalog_summary(
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success(catalog_summary())


@router.get("/sections")
def list_sample_sections(
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success({"items": section_index()})


@router.get("/packs")
def list_sample_packs(
    _: User = Depends(require_roles("admin", "analyst")),
):
    return success({"items": focused_pack_index()})


@router.get("")
def list_samples(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    section: Optional[str] = None,
    pack: Optional[str] = None,
    attack_family: Optional[str] = None,
    risk_level: Optional[str] = None,
    test_mode: Optional[str] = None,
    source_repo: Optional[str] = None,
    keyword: Optional[str] = None,
    _: User = Depends(require_roles("admin", "analyst")),
):
    items = query_samples(
        section=section,
        pack=pack,
        attack_family=attack_family,
        risk_level=risk_level,
        test_mode=test_mode,
        source_repo=source_repo,
        keyword=keyword,
    )
    normalized_items = [serialize_sample_list_item(item) for item in items]
    return success(
        {
            **paginate(normalized_items, page=page, page_size=page_size),
            "filters": {
                "section": section,
                "pack": pack,
                "attack_family": attack_family,
                "risk_level": risk_level,
                "test_mode": test_mode,
                "source_repo": source_repo,
                "keyword": keyword,
            },
        }
    )


@router.get("/{sample_id}")
def get_sample_detail(
    sample_id: str,
    _: User = Depends(require_roles("admin", "analyst")),
):
    sample = get_sample(sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="sample not found")
    return success(sample)
