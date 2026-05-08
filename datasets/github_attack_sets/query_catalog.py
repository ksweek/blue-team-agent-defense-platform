from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CURATED = ROOT / "curated"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    entries: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                entries.append(json.loads(line))
    return entries


def catalog_entries() -> list[dict]:
    return load_jsonl(CURATED / "github_attack_catalog.jsonl")


def section_items() -> list[dict]:
    return list((load_json(CURATED / "section_index.json").get("sections") or []))


def pack_items() -> list[dict]:
    return list((load_json(CURATED / "focused_pack_index.json").get("packs") or []))


def resolve_section(section: str) -> dict | None:
    normalized = section.strip().lower()
    for item in section_items():
        if normalized in {
            str(item.get("section_name") or "").strip().lower(),
            Path(str(item.get("catalog_file") or "")).name.lower(),
        }:
            return item
    return None


def resolve_pack(pack: str) -> dict | None:
    normalized = pack.strip().lower()
    for item in pack_items():
        if normalized in {
            str(item.get("pack_name") or "").strip().lower(),
            Path(str(item.get("pack_file") or "")).name.lower(),
        }:
            return item
    return None


def select_entries(section: str | None, pack: str | None) -> list[dict]:
    if pack:
        pack_meta = resolve_pack(pack)
        if pack_meta is None:
            raise RuntimeError(f"pack not found: {pack}")
        return load_jsonl(ROOT / str(pack_meta["pack_file"]))

    if section:
        section_meta = resolve_section(section)
        if section_meta is None:
            raise RuntimeError(f"section not found: {section}")
        return load_jsonl(ROOT / str(section_meta["catalog_file"]))

    return catalog_entries()


def filter_entries(
    entries: list[dict],
    *,
    keyword: str | None,
    risk_level: str | None,
    test_mode: str | None,
    source_repo: str | None,
) -> list[dict]:
    filtered = list(entries)

    if risk_level:
        filtered = [item for item in filtered if str(item.get("risk_level") or "").lower() == risk_level.lower()]
    if test_mode:
        filtered = [item for item in filtered if str(item.get("test_mode") or "").lower() == test_mode.lower()]
    if source_repo:
        filtered = [item for item in filtered if str(item.get("source_repo") or "").lower() == source_repo.lower()]
    if keyword:
        keyword_lower = keyword.lower()
        filtered = [
            item
            for item in filtered
            if keyword_lower in " ".join(
                [
                    str(item.get("id") or ""),
                    str(item.get("title") or ""),
                    str(item.get("content") or ""),
                    str(item.get("attack_family") or ""),
                    str(item.get("mapped_section") or ""),
                    str(item.get("source_repo") or ""),
                    str(item.get("expected_behavior") or ""),
                ]
            ).lower()
        ]

    return filtered


def command_summary(_: argparse.Namespace) -> int:
    summary = load_json(CURATED / "catalog_summary.json")
    sections = section_items()
    packs = pack_items()

    print("Attack catalog summary")
    print(f"  total_entries : {summary.get('total_entries')}")
    print(f"  sources       : {len(summary.get('by_source') or {})}")
    print(f"  sections      : {len(sections)}")
    print(f"  focused_packs : {len(packs)}")
    print("")
    print("Sections")
    for item in sections:
        print(f"  - {item.get('section_name')} ({item.get('entry_count')})")
    print("")
    print("Focused packs")
    for item in packs:
        print(f"  - {item.get('pack_name')} ({item.get('entry_count')}) [{item.get('test_mode')}]")
    return 0


def command_list(args: argparse.Namespace) -> int:
    entries = select_entries(args.section, args.pack)
    entries = filter_entries(
        entries,
        keyword=args.keyword,
        risk_level=args.risk_level,
        test_mode=args.test_mode,
        source_repo=args.source_repo,
    )

    limit = max(1, args.limit)
    print(f"Matched entries: {len(entries)}")
    print("")
    for item in entries[:limit]:
        sample_id = item.get("id")
        title = str(item.get("title") or "").replace("\r", " ").replace("\n", " ").strip()
        if len(title) > 100:
            title = f"{title[:97]}..."
        print(
            f"- {sample_id} | {item.get('mapped_section')} | {item.get('attack_family')} | "
            f"{item.get('risk_level')} | {item.get('test_mode') or 'single_turn'}"
        )
        print(f"  {title}")
    return 0


def command_show(args: argparse.Namespace) -> int:
    entries = catalog_entries()
    target = next((item for item in entries if str(item.get("id")) == args.sample_id), None)
    if target is None:
        raise RuntimeError(f"sample not found: {args.sample_id}")

    print(json.dumps(target, ensure_ascii=False, indent=2))
    return 0


def command_export_ids(args: argparse.Namespace) -> int:
    entries = select_entries(args.section, args.pack)
    entries = filter_entries(
        entries,
        keyword=args.keyword,
        risk_level=args.risk_level,
        test_mode=args.test_mode,
        source_repo=args.source_repo,
    )
    ids = [str(item.get("id")) for item in entries[: args.limit or None]]

    output_path = Path(args.output).resolve()
    output_path.write_text("\n".join(ids) + ("\n" if ids else ""), encoding="utf-8")
    print(f"Exported {len(ids)} sample ids to {output_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query the local GitHub AI attack catalog.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("summary", help="Show overall catalog summary.").set_defaults(func=command_summary)

    list_parser = subparsers.add_parser("list", help="List matched catalog entries.")
    list_parser.add_argument("--section", help="Section name or section jsonl filename.")
    list_parser.add_argument("--pack", help="Focused pack name or pack jsonl filename.")
    list_parser.add_argument("--keyword", help="Keyword search across title/content/metadata.")
    list_parser.add_argument("--risk-level", help="Filter by risk level.")
    list_parser.add_argument("--test-mode", help="Filter by test mode.")
    list_parser.add_argument("--source-repo", help="Filter by source repo.")
    list_parser.add_argument("--limit", type=int, default=20, help="Max rows to print.")
    list_parser.set_defaults(func=command_list)

    show_parser = subparsers.add_parser("show", help="Print a full sample JSON object by id.")
    show_parser.add_argument("sample_id", help="Sample id such as VJL-00001.")
    show_parser.set_defaults(func=command_show)

    export_parser = subparsers.add_parser("export-ids", help="Export matched sample ids to a text file.")
    export_parser.add_argument("--section", help="Section name or section jsonl filename.")
    export_parser.add_argument("--pack", help="Focused pack name or pack jsonl filename.")
    export_parser.add_argument("--keyword", help="Keyword search across title/content/metadata.")
    export_parser.add_argument("--risk-level", help="Filter by risk level.")
    export_parser.add_argument("--test-mode", help="Filter by test mode.")
    export_parser.add_argument("--source-repo", help="Filter by source repo.")
    export_parser.add_argument("--limit", type=int, default=0, help="Max ids to export. 0 means all matched ids.")
    export_parser.add_argument("--output", required=True, help="Output text file path.")
    export_parser.set_defaults(func=command_export_ids)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Query failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
