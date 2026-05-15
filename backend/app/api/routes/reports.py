from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ...core.response import success
from ...db.session import get_db
from ...models import AttackTask, Report, SecurityEvent, User
from ...schemas.task import ReportBatchDownloadRequest
from ...services.audit import append_audit_log
from ...services.authorization import require_roles
from ...services.report_bundle import build_task_report_bundle
from ...services.report_export import (
    DEFAULT_REPORT_EXPORT_FORMAT,
    REPORT_MEDIA_TYPES,
    SUPPORTED_REPORT_FORMATS,
    derive_report_variant_path,
    export_report_artifact,
    normalize_report_format,
    normalize_report_formats,
    resolve_report_path,
)
from ...services.repository import contains_keyword, paginate
from ...services.time_utils import format_beijing

router = APIRouter()


def _serialize_report(item: Report) -> dict:
    artifact_path = resolve_report_path(item.file_path)
    available_formats: list[str] = []
    for artifact_format in SUPPORTED_REPORT_FORMATS:
        variant_path = artifact_path if artifact_format == DEFAULT_REPORT_EXPORT_FORMAT else derive_report_variant_path(item.file_path, artifact_format)
        if variant_path.exists():
            available_formats.append(artifact_format)
    return {
        "id": item.id,
        "report_name": item.report_name,
        "report_type": item.report_type,
        "task_id": item.task_id,
        "file_path": item.file_path,
        "artifact_exists": artifact_path.exists(),
        "download_url": f"/api/reports/{item.id}/download",
        "download_urls": {
            artifact_format: f"/api/reports/{item.id}/download?format={artifact_format}"
            for artifact_format in SUPPORTED_REPORT_FORMATS
        },
        "supported_formats": list(SUPPORTED_REPORT_FORMATS),
        "available_formats": available_formats,
        "summary_text": item.summary_text,
        "created_by": item.created_by,
        "created_at": format_beijing(item.created_at) or "",
    }


def _get_task_or_404(db: Session, task_id: int) -> AttackTask:
    item = db.get(AttackTask, task_id)
    if item is None:
        raise HTTPException(status_code=404, detail="attack task not found")
    return item


def _get_report_or_404(db: Session, report_id: int) -> Report:
    item = db.get(Report, report_id)
    if item is None:
        raise HTTPException(status_code=404, detail="report not found")
    return item


def _get_latest_event_for_task(db: Session, task_id: int) -> SecurityEvent | None:
    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.task_id == task_id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .first()
    )


@router.post("/batch-download")
def batch_download_reports(
    payload: ReportBatchDownloadRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    task_ids = list(dict.fromkeys(payload.task_ids))
    if not task_ids:
        raise HTTPException(status_code=400, detail="task_ids is required")

    tasks = [_get_task_or_404(db, task_id) for task_id in task_ids]
    try:
        formats = normalize_report_formats(payload.formats)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        bundle_path, bundle_meta = build_task_report_bundle(
            db,
            tasks,
            formats=formats,
            include_manifest=payload.include_manifest,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    append_audit_log(
        db,
        current_user,
        "reports",
        "batch-download",
        f"downloaded bundle for {bundle_meta['included_count']} reports",
    )
    db.commit()

    return FileResponse(
        path=Path(bundle_path),
        media_type="application/zip",
        filename=bundle_path.name,
    )


@router.get("")
def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    report_type: Optional[str] = None,
    task_id: Optional[int] = None,
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    items = [_serialize_report(item) for item in db.query(Report).order_by(Report.created_at.desc(), Report.id.desc()).all()]

    if report_type:
        items = [item for item in items if item["report_type"] == report_type]
    if task_id is not None:
        items = [item for item in items if item["task_id"] == task_id]
    if keyword:
        items = [item for item in items if contains_keyword(item, keyword, ["report_name", "report_type", "file_path"])]

    return success(paginate(items, page=page, page_size=page_size))


@router.get("/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    item = _get_report_or_404(db, report_id)
    return success(_serialize_report(item))


@router.post("/{report_id}/export")
def export_report(
    report_id: int,
    artifact_format: str = Query(DEFAULT_REPORT_EXPORT_FORMAT, alias="format"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    try:
        normalized_format = normalize_report_format(artifact_format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    item = _get_report_or_404(db, report_id)
    task = _get_task_or_404(db, item.task_id)
    event = _get_latest_event_for_task(db, task.id)
    try:
        artifact_path = export_report_artifact(
            db,
            item,
            task=task,
            event=event,
            artifact_format=normalized_format,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    append_audit_log(db, current_user, "reports", "export", f"exported report {item.id} as {normalized_format}")
    db.commit()
    db.refresh(item)
    return success(
        {
            **_serialize_report(item),
            "artifact_path": str(artifact_path),
            "artifact_format": normalized_format,
            "artifact_download_url": f"/api/reports/{item.id}/download?format={normalized_format}",
        },
        message="report exported",
    )


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    artifact_format: str = Query(DEFAULT_REPORT_EXPORT_FORMAT, alias="format"),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    try:
        normalized_format = normalize_report_format(artifact_format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    item = _get_report_or_404(db, report_id)
    artifact_path = (
        resolve_report_path(item.file_path)
        if normalized_format == DEFAULT_REPORT_EXPORT_FORMAT
        else derive_report_variant_path(item.file_path, normalized_format)
    )
    if not artifact_path.exists():
        task = _get_task_or_404(db, item.task_id)
        event = _get_latest_event_for_task(db, task.id)
        try:
            artifact_path = export_report_artifact(
                db,
                item,
                task=task,
                event=event,
                artifact_format=normalized_format,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        db.commit()

    filename = artifact_path.name if artifact_path.name else f"report-{item.id}.{normalized_format}"
    return FileResponse(
        path=Path(artifact_path),
        media_type=REPORT_MEDIA_TYPES[normalized_format],
        filename=filename,
    )
