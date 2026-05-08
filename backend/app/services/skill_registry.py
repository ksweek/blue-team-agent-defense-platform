from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy.orm import Session

from ..core.config import PROJECT_ROOT
from ..models import Skill

SKILL_MARKER_FILES = {
    "SKILL.md",
    "skill.md",
    "prompt.md",
}

SkillImportAction = Literal["create", "update", "skip"]


@dataclass
class SkillImportResult:
    created: list[Skill]
    updated: list[Skill]
    skipped: list[dict[str, str]]


@dataclass
class SkillImportPreviewItem:
    skill_name: str
    source_path: str
    action: SkillImportAction
    action_label: str
    action_tone: str
    reason: str
    reason_label: str
    reason_tone: str
    existing_skill_id: int | None = None


@dataclass
class SkillImportPreviewResult:
    base_directory: str
    detected: int
    created: int
    updated: int
    skipped: int
    items: list[SkillImportPreviewItem]


@dataclass
class SkillImportPlan:
    skill_name: str
    skill_type: str
    provider: str
    source_path: str
    trust_status: str
    action: SkillImportAction
    reason: str
    existing_skill_id: int | None = None


IMPORT_ACTION_META: dict[SkillImportAction, tuple[str, str]] = {
    "create": ("新增", "safe"),
    "update": ("更新", "info"),
    "skip": ("跳过", "warn"),
}

IMPORT_REASON_META: dict[str, tuple[str, str]] = {
    "new_directory": ("新目录", "safe"),
    "already_registered": ("已纳管", "info"),
    "metadata_changed": ("更新字段", "info"),
    "matched_by_path": ("按路径归并", "info"),
    "matched_by_name": ("按名称归并", "info"),
}


def normalize_skill_source_path(source_path: str) -> str:
    value = source_path.strip()
    if not value:
        return ""

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    try:
        return candidate.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(candidate)


def resolve_directory_input(directory_path: str) -> Path:
    value = directory_path.strip()
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()
    return candidate


def create_or_update_skill(
    db: Session,
    *,
    skill_name: str,
    skill_type: str,
    provider: str,
    source_path: str,
    trust_status: str,
) -> tuple[Skill, bool]:
    normalized_source = normalize_skill_source_path(source_path)
    existing = _find_existing_skill(db, skill_name=skill_name, source_path=normalized_source)
    created = existing is None

    if existing is None:
        existing = Skill(
            skill_name=skill_name,
            skill_type=skill_type,
            provider=provider,
            source_path=normalized_source,
            trust_status=trust_status,
        )
        db.add(existing)
    else:
        existing.skill_name = skill_name
        existing.skill_type = skill_type
        existing.provider = provider
        existing.source_path = normalized_source
        existing.trust_status = trust_status

    db.flush()
    return existing, created


def preview_skills_from_directory(
    db: Session,
    *,
    directory_path: str,
    skill_type: str,
    provider: str,
    trust_status: str,
    recursive: bool,
) -> SkillImportPreviewResult:
    base_dir = resolve_directory_input(directory_path)
    if not base_dir.exists():
        raise FileNotFoundError(f"directory does not exist: {base_dir}")
    if not base_dir.is_dir():
        raise NotADirectoryError(f"not a directory: {base_dir}")

    items: list[SkillImportPreviewItem] = []
    created = 0
    updated = 0
    skipped = 0

    for skill_dir in detect_skill_directories(base_dir, recursive=recursive):
        plan = _build_import_plan(
            db,
            skill_dir=skill_dir,
            skill_type=skill_type,
            provider=provider,
            trust_status=trust_status,
        )
        items.append(
            SkillImportPreviewItem(
                skill_name=plan.skill_name,
                source_path=plan.source_path,
                action=plan.action,
                action_label=_import_action_label(plan.action),
                action_tone=_import_action_tone(plan.action),
                reason=plan.reason,
                reason_label=_import_reason_label(plan.reason),
                reason_tone=_import_reason_tone(plan.reason),
                existing_skill_id=plan.existing_skill_id,
            )
        )
        if plan.action == "create":
            created += 1
        elif plan.action == "update":
            updated += 1
        else:
            skipped += 1

    return SkillImportPreviewResult(
        base_directory=normalize_skill_source_path(str(base_dir)),
        detected=len(items),
        created=created,
        updated=updated,
        skipped=skipped,
        items=items,
    )


def import_skills_from_directory(
    db: Session,
    *,
    directory_path: str,
    skill_type: str,
    provider: str,
    trust_status: str,
    recursive: bool,
) -> SkillImportResult:
    preview = preview_skills_from_directory(
        db,
        directory_path=directory_path,
        skill_type=skill_type,
        provider=provider,
        trust_status=trust_status,
        recursive=recursive,
    )
    created: list[Skill] = []
    updated: list[Skill] = []
    skipped: list[dict[str, str]] = []

    for item in preview.items:
        if item.action == "skip":
            skipped.append(
                {
                    "skill_name": item.skill_name,
                    "source_path": item.source_path,
                    "action": item.action,
                    "action_label": item.action_label,
                    "action_tone": item.action_tone,
                    "reason": item.reason,
                    "reason_label": item.reason_label,
                    "reason_tone": item.reason_tone,
                }
            )
            continue

        skill, is_created = create_or_update_skill(
            db,
            skill_name=item.skill_name,
            skill_type=skill_type,
            provider=provider,
            source_path=item.source_path,
            trust_status=trust_status,
        )
        if is_created:
            created.append(skill)
        else:
            updated.append(skill)

    return SkillImportResult(created=created, updated=updated, skipped=skipped)


def detect_skill_directories(base_dir: Path, *, recursive: bool) -> list[Path]:
    if looks_like_skill_directory(base_dir):
        return [base_dir]

    candidates: list[Path] = []
    if recursive:
        for marker_name in SKILL_MARKER_FILES:
            for marker in base_dir.rglob(marker_name):
                candidates.append(marker.parent.resolve())
    else:
        for child in base_dir.iterdir():
            if child.is_dir() and looks_like_skill_directory(child):
                candidates.append(child.resolve())

    unique: list[Path] = []
    seen: set[str] = set()
    for item in candidates:
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return sorted(unique, key=lambda item: str(item).lower())


def looks_like_skill_directory(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    return any((path / marker_name).exists() for marker_name in SKILL_MARKER_FILES)


def _build_import_plan(
    db: Session,
    *,
    skill_dir: Path,
    skill_type: str,
    provider: str,
    trust_status: str,
) -> SkillImportPlan:
    source_path = normalize_skill_source_path(str(skill_dir))
    skill_name = skill_dir.name.strip()
    existing = _find_existing_skill(db, skill_name=skill_name, source_path=source_path)
    action, reason = _classify_import_action(
        existing=existing,
        skill_name=skill_name,
        skill_type=skill_type,
        provider=provider,
        source_path=source_path,
        trust_status=trust_status,
    )
    return SkillImportPlan(
        skill_name=skill_name,
        skill_type=skill_type,
        provider=provider,
        source_path=source_path,
        trust_status=trust_status,
        action=action,
        reason=reason,
        existing_skill_id=existing.id if existing is not None else None,
    )


def _classify_import_action(
    *,
    existing: Skill | None,
    skill_name: str,
    skill_type: str,
    provider: str,
    source_path: str,
    trust_status: str,
) -> tuple[SkillImportAction, str]:
    if existing is None:
        return "create", "new_directory"

    same_name = (existing.skill_name or "").strip() == skill_name
    same_source = (existing.source_path or "").strip() == source_path
    same_config = (
        (existing.skill_type or "").strip() == skill_type
        and (existing.provider or "").strip() == provider
        and (existing.trust_status or "").strip() == trust_status
    )

    if same_name and same_source and same_config:
        return "skip", "already_registered"
    if same_name and same_source:
        return "update", "metadata_changed"
    if same_source:
        return "update", "matched_by_path"
    return "update", "matched_by_name"


def _import_action_label(action: SkillImportAction) -> str:
    return IMPORT_ACTION_META.get(action, (action, "info"))[0]


def _import_action_tone(action: SkillImportAction) -> str:
    return IMPORT_ACTION_META.get(action, (action, "info"))[1]


def _import_reason_label(reason: str) -> str:
    return IMPORT_REASON_META.get(reason, (reason, "info"))[0]


def _import_reason_tone(reason: str) -> str:
    return IMPORT_REASON_META.get(reason, (reason, "info"))[1]


def _find_existing_skill(db: Session, *, skill_name: str, source_path: str) -> Skill | None:
    if source_path:
        existing = db.query(Skill).filter(Skill.source_path == source_path).order_by(Skill.id.asc()).first()
        if existing is not None:
            return existing
    return db.query(Skill).filter(Skill.skill_name == skill_name).order_by(Skill.id.asc()).first()
