from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy.orm import Session

from ..core.config import BACKEND_DIR
from ..models import AttackTask, Report, SecurityEvent
from .report_export import export_report_artifact, normalize_report_formats
from .time_utils import format_beijing, utc_now

REPORT_BUNDLE_DIR = BACKEND_DIR / "data" / "reports" / "bundles"


def build_task_report_bundle(
    db: Session,
    tasks: list[AttackTask],
    *,
    formats: list[str] | None = None,
    include_manifest: bool = True,
) -> tuple[Path, dict]:
    REPORT_BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    normalized_formats = normalize_report_formats(formats)

    created_at = utc_now()
    bundle_path = REPORT_BUNDLE_DIR / f"report-bundle-{created_at:%Y%m%d%H%M%S%f}.zip"

    manifest_items: list[dict] = []
    included_entries: list[tuple[Path, str]] = []

    for task in tasks:
        manifest_item = {
            "task_id": task.id,
            "task_name": task.task_name,
            "status": task.status,
            "report_id": task.latest_report_id,
            "included": False,
            "reason": "",
            "artifacts": [],
        }

        if not task.latest_report_id:
            manifest_item["reason"] = "no_report"
            manifest_items.append(manifest_item)
            continue

        report = db.query(Report).get(task.latest_report_id)
        if report is None:
            manifest_item["reason"] = "report_record_missing"
            manifest_items.append(manifest_item)
            continue

        event = _resolve_event_for_task(db, task)
        manifest_item["included"] = True
        manifest_item["reason"] = "ok"
        manifest_item["formats"] = list(normalized_formats)

        for artifact_format in normalized_formats:
            artifact_path = export_report_artifact(
                db,
                report,
                task=task,
                event=event,
                artifact_format=artifact_format,
            )
            archive_name = f"task-{task.id}/{artifact_path.name}"
            manifest_item["artifacts"].append(
                {
                    "format": artifact_format,
                    "archive_name": archive_name,
                    "file_path": str(artifact_path),
                }
            )
            included_entries.append((artifact_path, archive_name))

        if len(manifest_item["artifacts"]) == 1:
            manifest_item["archive_name"] = manifest_item["artifacts"][0]["archive_name"]
            manifest_item["file_path"] = manifest_item["artifacts"][0]["file_path"]
        manifest_items.append(manifest_item)

    if not included_entries:
        raise ValueError("no report artifacts available for the selected tasks")

    included_task_count = sum(1 for item in manifest_items if item.get("included"))

    with ZipFile(bundle_path, mode="w", compression=ZIP_DEFLATED) as archive:
        for artifact_path, archive_name in included_entries:
            archive.write(artifact_path, arcname=archive_name)

        if include_manifest:
            archive.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "created_at": format_beijing(created_at),
                        "task_count": len(tasks),
                        "included_count": included_task_count,
                        "artifact_count": len(included_entries),
                        "formats": normalized_formats,
                        "items": manifest_items,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )

    return bundle_path, {
        "task_count": len(tasks),
        "included_count": included_task_count,
        "artifact_count": len(included_entries),
        "formats": normalized_formats,
        "items": manifest_items,
    }


def _resolve_event_for_task(db: Session, task: AttackTask) -> SecurityEvent | None:
    if task.latest_event_id:
        event = db.query(SecurityEvent).get(task.latest_event_id)
        if event is not None:
            return event

    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.task_id == task.id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .first()
    )
