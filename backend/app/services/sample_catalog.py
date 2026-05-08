from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..core.config import PROJECT_ROOT
from .security_taxonomy import (
    build_catalog_group_summary,
    build_pack_classification,
    build_sample_classification,
    build_section_classification,
)

DATASET_ROOT = PROJECT_ROOT / "datasets" / "github_attack_sets"
CURATED_ROOT = DATASET_ROOT / "curated"
logger = logging.getLogger("app.samples")


def catalog_summary() -> dict[str, Any]:
    payload = dict(_load_json("catalog_summary.json"))
    payload["classification_groups"] = build_catalog_group_summary(section_index())
    return payload


def section_index() -> list[dict[str, Any]]:
    payload = _load_json("section_index.json")
    return [
        {
            **dict(item),
            "classification": build_section_classification(
                str(item.get("section_name") or ""),
                risk_level=str(item.get("risk_level") or ""),
                attack_stage=str(item.get("attack_stage") or ""),
            ),
        }
        for item in payload.get("sections", [])
    ]


def focused_pack_index() -> list[dict[str, Any]]:
    payload = _load_json("focused_pack_index.json")
    return [{**dict(item), "classification": build_pack_classification(dict(item))} for item in payload.get("packs", [])]


def query_samples(
    *,
    section: str | None = None,
    pack: str | None = None,
    attack_family: str | None = None,
    risk_level: str | None = None,
    test_mode: str | None = None,
    source_repo: str | None = None,
    keyword: str | None = None,
) -> list[dict[str, Any]]:
    items = list(_select_source_items(section=section, pack=pack))

    if attack_family:
        items = [item for item in items if str(item.get("attack_family", "")).lower() == attack_family.lower()]
    if risk_level:
        items = [item for item in items if str(item.get("risk_level", "")).lower() == risk_level.lower()]
    if test_mode:
        items = [item for item in items if str(item.get("test_mode", "")).lower() == test_mode.lower()]
    if source_repo:
        items = [item for item in items if str(item.get("source_repo", "")).lower() == source_repo.lower()]
    if keyword:
        keyword_lower = keyword.lower()
        items = [item for item in items if _sample_matches_keyword(item, keyword_lower)]

    return items


def get_sample(sample_id: str) -> dict[str, Any] | None:
    normalized = sample_id.strip()
    if not normalized:
        return None

    for item in _catalog_entries():
        if str(item.get("id")) == normalized:
            serialized = dict(item)
            serialized["classification"] = build_sample_classification(serialized)
            return serialized
    return None


def serialize_sample_list_item(item: dict[str, Any]) -> dict[str, Any]:
    turns = item.get("turns")
    if not isinstance(turns, list):
        turns = []

    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "attack_family": item.get("attack_family"),
        "mapped_section": item.get("mapped_section"),
        "risk_level": item.get("risk_level"),
        "attack_stage": item.get("attack_stage"),
        "expected_behavior": item.get("expected_behavior"),
        "source_repo": item.get("source_repo"),
        "source_file": item.get("source_file"),
        "test_mode": item.get("test_mode") or metadata.get("test_mode") or ("multi_turn" if turns else "single_turn"),
        "turn_count": len(turns) or int(metadata.get("turn_count") or 0) or 1,
        "content_preview": _truncate(str(item.get("content") or ""), 220),
        "tags": list(metadata.get("tags") or []),
        "classification": build_sample_classification(item),
    }


def build_task_payload_from_sample(sample: dict[str, Any], overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = sample.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    turns = sample.get("turns")
    if not isinstance(turns, list) or not turns:
        content = str(sample.get("content") or "")
        turns = [{"role": "user", "stage": "attack_prompt", "content": content}]

    payload = {
        "source_type": "dataset_sample",
        "sample_id": sample.get("id"),
        "title": sample.get("title"),
        "content": sample.get("content"),
        "turns": turns,
        "test_mode": sample.get("test_mode") or metadata.get("test_mode") or ("multi_turn" if len(turns) > 1 else "single_turn"),
        "source_repo": sample.get("source_repo"),
        "source_file": sample.get("source_file"),
        "source_family": sample.get("source_family"),
        "attack_family": sample.get("attack_family"),
        "mapped_section": sample.get("mapped_section"),
        "risk_level": sample.get("risk_level"),
        "attack_stage": sample.get("attack_stage"),
        "expected_behavior": sample.get("expected_behavior"),
        "metadata": metadata,
        "classification": build_sample_classification(sample),
    }
    if overrides:
        payload.update(overrides)
    return payload


def _select_source_items(*, section: str | None, pack: str | None) -> list[dict[str, Any]]:
    if pack:
        pack_meta = _resolve_pack(pack)
        if pack_meta is not None:
            return _load_jsonl(pack_meta["pack_file"])

    if section:
        section_meta = _resolve_section(section)
        if section_meta is not None:
            return _load_jsonl(section_meta["catalog_file"])

    return list(_catalog_entries())


def _resolve_section(value: str) -> dict[str, Any] | None:
    normalized = value.strip().lower()
    for item in section_index():
        section_name = str(item.get("section_name") or "").strip().lower()
        catalog_file = Path(str(item.get("catalog_file") or "")).name.lower()
        if normalized in {section_name, catalog_file}:
            return item
    return None


def _resolve_pack(value: str) -> dict[str, Any] | None:
    normalized = value.strip().lower()
    for item in focused_pack_index():
        pack_name = str(item.get("pack_name") or "").strip().lower()
        pack_file = Path(str(item.get("pack_file") or "")).name.lower()
        if normalized in {pack_name, pack_file}:
            return item
    return None


def _sample_matches_keyword(item: dict[str, Any], keyword: str) -> bool:
    fields = [
        item.get("id"),
        item.get("title"),
        item.get("content"),
        item.get("attack_family"),
        item.get("mapped_section"),
        item.get("source_repo"),
        item.get("expected_behavior"),
    ]
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        fields.extend(
            [
                metadata.get("description"),
                " ".join(str(tag) for tag in metadata.get("tags") or []),
                metadata.get("technique"),
                metadata.get("source_id"),
            ]
        )

    turns = item.get("turns")
    if isinstance(turns, list):
        fields.extend(str(turn.get("content") or "") for turn in turns if isinstance(turn, dict))

    return any(keyword in str(field or "").lower() for field in fields)


@lru_cache
def _catalog_entries() -> tuple[dict[str, Any], ...]:
    return tuple(_load_jsonl("github_attack_catalog.jsonl"))


@lru_cache
def _load_json(relative_path: str) -> dict[str, Any]:
    path = CURATED_ROOT / relative_path
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache
def _load_jsonl(relative_path: str) -> list[dict[str, Any]]:
    path = _resolve_curated_path(relative_path)
    entries: list[dict[str, Any]] = []
    skipped_lines: list[int] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    repaired = _repair_json_line(line)
                    try:
                        entries.append(json.loads(repaired))
                    except json.JSONDecodeError:
                        skipped_lines.append(line_number)
    if skipped_lines:
        logger.warning(
            "sample rows skipped | file=%s count=%s lines=%s",
            path.name,
            len(skipped_lines),
            ",".join(str(item) for item in skipped_lines[:10]),
        )
    return entries


def _resolve_curated_path(relative_path: str) -> Path:
    raw_path = Path(relative_path)
    if raw_path.is_absolute():
        return raw_path.resolve()

    normalized = relative_path.replace("\\", "/").strip("/")
    if normalized.startswith("curated/"):
        return (DATASET_ROOT / normalized).resolve()
    return (CURATED_ROOT / normalized).resolve()


def _truncate(value: str, limit: int) -> str:
    normalized = value.replace("\r", " ").replace("\n", " ").strip()
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 3]}..."


def _repair_json_line(line: str) -> str:
    repaired = line
    repaired = re.sub(r'("mapped_section":\s*"[^"]*?)(,\s*"risk_level":)', r'\1"\2', repaired)
    repaired = re.sub(r'("expected_behavior":\s*"[^"]*?)(,\s*"title":)', r'\1"\2', repaired)
    repaired = re.sub(r'("description":\s*"[^"]*?)(,\s*"source_label":)', r'\1"\2', repaired)
    return repaired
