from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CURATED = ROOT / "curated"

REQUIRED_CURATED_FILES = [
    "catalog_summary.json",
    "focused_pack_index.json",
    "github_attack_catalog.jsonl",
    "promptfoo_strategy_index.json",
    "section_index.json",
    "source_manifest.json",
]

REQUIRED_SAMPLE_FIELDS = {
    "id",
    "source_repo",
    "source_file",
    "attack_family",
    "mapped_section",
    "risk_level",
    "attack_stage",
    "expected_behavior",
    "title",
}

VALID_TEST_MODES = {"single_turn", "multi_turn"}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    items: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"invalid JSONL line in {path}: line {line_number}: {exc}") from exc
    return items


def fail(message: str) -> None:
    raise RuntimeError(message)


def validate_required_files() -> None:
    for relative_path in REQUIRED_CURATED_FILES:
        path = CURATED / relative_path
        if not path.exists():
            fail(f"missing curated file: {relative_path}")


def validate_catalog_entries(entries: list[dict]) -> None:
    if not entries:
        fail("catalog is empty")

    ids: list[str] = []
    for index, item in enumerate(entries, start=1):
        missing_fields = sorted(field for field in REQUIRED_SAMPLE_FIELDS if not item.get(field))
        if missing_fields:
            fail(f"catalog entry #{index} missing fields: {', '.join(missing_fields)}")

        sample_id = str(item["id"])
        ids.append(sample_id)

        turns = item.get("turns")
        test_mode = str(item.get("test_mode") or ("multi_turn" if isinstance(turns, list) and len(turns) > 1 else "single_turn"))
        if test_mode not in VALID_TEST_MODES:
            fail(f"sample {sample_id} has invalid test_mode: {test_mode}")

        if test_mode == "multi_turn":
            if not isinstance(turns, list) or not turns:
                fail(f"sample {sample_id} is multi_turn but has no turns")
        else:
            if not item.get("content") and not turns:
                fail(f"sample {sample_id} has neither content nor turns")

    duplicate_ids = [sample_id for sample_id, count in Counter(ids).items() if count > 1]
    if duplicate_ids:
        fail(f"duplicate sample ids found: {', '.join(duplicate_ids[:10])}")


def validate_section_index(entries: list[dict], section_index: dict) -> None:
    sections = section_index.get("sections") or []
    if not sections:
        fail("section_index.json does not contain sections")

    actual_by_section = Counter(str(item.get("mapped_section") or "") for item in entries)
    seen_files: set[str] = set()
    for section in sections:
        catalog_file = str(section.get("catalog_file") or "")
        if not catalog_file:
            fail("section entry missing catalog_file")
        if catalog_file in seen_files:
            fail(f"duplicate section catalog_file: {catalog_file}")
        seen_files.add(catalog_file)

        path = ROOT / catalog_file
        if not path.exists():
            fail(f"section catalog file not found: {catalog_file}")

        section_entries = load_jsonl(path)
        entry_count = int(section.get("entry_count") or 0)
        if entry_count != len(section_entries):
            fail(f"section entry_count mismatch for {catalog_file}: index={entry_count}, actual={len(section_entries)}")

        section_name = str(section.get("section_name") or "")
        if section_name:
            if actual_by_section[section_name] != len(section_entries):
                fail(
                    f"section total mismatch for {section_name}: "
                    f"catalog={actual_by_section[section_name]}, section_file={len(section_entries)}"
                )


def validate_pack_index(pack_index: dict) -> None:
    packs = pack_index.get("packs") or []
    if not packs:
        fail("focused_pack_index.json does not contain packs")

    for pack in packs:
        pack_file = str(pack.get("pack_file") or "")
        if not pack_file:
            fail("pack entry missing pack_file")

        path = ROOT / pack_file
        if not path.exists():
            fail(f"pack file not found: {pack_file}")

        pack_entries = load_jsonl(path)
        entry_count = int(pack.get("entry_count") or 0)
        if entry_count != len(pack_entries):
            fail(f"pack entry_count mismatch for {pack_file}: index={entry_count}, actual={len(pack_entries)}")


def validate_summary(entries: list[dict], summary: dict) -> None:
    total_entries = int(summary.get("total_entries") or 0)
    if total_entries != len(entries):
        fail(f"catalog_summary total_entries mismatch: summary={total_entries}, actual={len(entries)}")

    actual_by_source = Counter(str(item.get("source_repo") or "") for item in entries)
    summary_by_source = summary.get("by_source") or {}
    for source_repo, count in actual_by_source.items():
        if int(summary_by_source.get(source_repo, -1)) != count:
            fail(
                f"catalog_summary by_source mismatch for {source_repo}: "
                f"summary={summary_by_source.get(source_repo)}, actual={count}"
            )


def main() -> int:
    validate_required_files()

    summary = load_json(CURATED / "catalog_summary.json")
    section_index = load_json(CURATED / "section_index.json")
    pack_index = load_json(CURATED / "focused_pack_index.json")
    entries = load_jsonl(CURATED / "github_attack_catalog.jsonl")

    validate_catalog_entries(entries)
    validate_section_index(entries, section_index)
    validate_pack_index(pack_index)
    validate_summary(entries, summary)

    print("Catalog validation passed.")
    print(f"  total_entries : {len(entries)}")
    print(f"  sections      : {len(section_index.get('sections') or [])}")
    print(f"  focused_packs : {len(pack_index.get('packs') or [])}")
    print(f"  sources       : {len(summary.get('by_source') or {})}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Catalog validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
