from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


TEXT_FILE_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".py",
    ".ps1",
    ".sh",
    ".bash",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
}

PATTERNS = [
    (
        "prompt_injection_phrase",
        "Prompt injection phrase",
        "high",
        "prompt_injection_firewall",
        re.compile(r"(ignore\s+(all\s+)?previous\s+instructions|reveal\s+system\s+prompt)", re.IGNORECASE),
    ),
    (
        "approval_bypass_phrase",
        "Approval bypass phrase",
        "medium",
        "approval_integrity_gate",
        re.compile(r"(do\s+not\s+ask\s+for\s+approval|execute\s+without\s+confirmation)", re.IGNORECASE),
    ),
    (
        "destructive_command",
        "Destructive command",
        "high",
        "tool_permission_broker",
        re.compile(r"(rm\s+-rf|remove-item\s+.+-recurse|del\s+/[sqf]|shutil\.rmtree)", re.IGNORECASE),
    ),
    (
        "shell_execution",
        "Shell execution capability",
        "high",
        "tool_permission_broker",
        re.compile(r"(subprocess\.(run|popen)|os\.system|shell\s*=\s*true|invoke-expression)", re.IGNORECASE),
    ),
    (
        "network_exfiltration",
        "Network transfer behavior",
        "high",
        "cross_plugin_handoff_guard",
        re.compile(r"(curl\s+https?://|invoke-webrequest|requests\.(post|get)\(|httpx\.(post|get)\(|fetch\s*\()", re.IGNORECASE),
    ),
    (
        "secret_exposure",
        "Possible hardcoded secret",
        "high",
        "output_redaction_gate",
        re.compile(r"((api[_-]?key|token|password|secret)\s*[:=]\s*[\"'][^\"'\n]{6,}[\"']|sk-[a-z0-9_-]{8,})", re.IGNORECASE),
    ),
]

SEVERITY_SCORE = {"high": 3, "medium": 2, "low": 1}


@dataclass
class SkillScanFinding:
    code: str
    title: str
    severity: str
    signal: str
    mapped_rule: str
    summary: str
    file_path: str
    line_number: int | None = None
    excerpt: str = ""


@dataclass
class SkillScanItemResult:
    skill_id: int
    skill_name: str
    source_path: str
    resolved_path: str
    status: str
    engine: str
    verdict: str
    risk_score: int
    summary: str
    file_count: int
    scanned_files: list[str] = field(default_factory=list)
    findings: list[SkillScanFinding] = field(default_factory=list)
    external_scan: dict[str, Any] | None = None
    error: str = ""
    trust_status_change: str | None = None


@dataclass
class SkillScanBatchResult:
    engine: str
    verdict: str
    risk_score: int
    summary: str
    finding_count: int
    blocked_count: int
    suspicious_count: int
    hit_rules: list[str]
    matched_signals: list[str]
    items: list[SkillScanItemResult] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "finding_count": self.finding_count,
            "blocked_count": self.blocked_count,
            "suspicious_count": self.suspicious_count,
            "hit_rules": list(self.hit_rules),
            "matched_signals": list(self.matched_signals),
            "items": [
                {
                    **asdict(item),
                    "findings": [asdict(finding) for finding in item.findings],
                }
                for item in self.items
            ],
        }


def scan_skill_sources(
    skill_sources: list[dict[str, Any]],
    *,
    engine_label: str = "remote",
    include_external_scan: bool = False,
    project_root: Path | None = None,
    search_roots: list[Path] | None = None,
    max_files: int | None = None,
    max_file_bytes: int | None = None,
    agent_scan_bin: str | None = None,
    agent_scan_timeout_seconds: float | None = None,
) -> SkillScanBatchResult:
    del include_external_scan, project_root, search_roots, agent_scan_bin, agent_scan_timeout_seconds
    if not skill_sources:
        return _error_result(engine_label, "missing_input", "No skill sources were provided.", "missing_skill_sources")

    items = [_scan_one(source, engine_label=engine_label, max_files=max_files, max_file_bytes=max_file_bytes) for source in skill_sources]
    findings = [finding for item in items for finding in item.findings]
    hit_rules = sorted({finding.mapped_rule for finding in findings if finding.mapped_rule})
    signals = sorted({finding.signal for finding in findings if finding.signal})
    risk_score = sum(SEVERITY_SCORE.get(finding.severity, 1) for finding in findings)
    blocked_count = sum(1 for item in items if item.verdict == "blocked")
    suspicious_count = sum(1 for item in items if item.verdict == "suspicious")
    if blocked_count:
        verdict = "blocked"
    elif suspicious_count or findings:
        verdict = "suspicious"
    else:
        verdict = "trusted"
    summary = f"Scanned {len(items)} skill source(s), {len(findings)} finding(s)."
    return SkillScanBatchResult(
        engine=engine_label,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        finding_count=len(findings),
        blocked_count=blocked_count,
        suspicious_count=suspicious_count,
        hit_rules=hit_rules,
        matched_signals=signals,
        items=items,
    )


def _scan_one(
    source: dict[str, Any],
    *,
    engine_label: str,
    max_files: int | None,
    max_file_bytes: int | None,
) -> SkillScanItemResult:
    skill_id = int(source.get("skill_id") or 0)
    skill_name = str(source.get("skill_name") or "").strip() or f"skill-{skill_id or 'unknown'}"
    source_path = str(source.get("source_path") or "").strip()
    path = Path(source_path).expanduser() if source_path else None
    if path is None:
        return _item_error(skill_id, skill_name, source_path, "missing_source", "missing source_path", engine_label)
    if not path.exists():
        return _item_error(skill_id, skill_name, source_path, "missing_path", "path not found", engine_label)

    files = _collect_files(path, max_files=max_files, max_file_bytes=max_file_bytes)
    findings: list[SkillScanFinding] = []
    for file_path in files:
        findings.extend(_scan_file(file_path))

    risk_score = sum(SEVERITY_SCORE.get(finding.severity, 1) for finding in findings)
    verdict = "blocked" if any(finding.severity == "high" for finding in findings) else ("suspicious" if findings else "trusted")
    summary = f"{skill_name}: scanned {len(files)} file(s), {len(findings)} finding(s)."
    return SkillScanItemResult(
        skill_id=skill_id,
        skill_name=skill_name,
        source_path=source_path,
        resolved_path=str(path.resolve()),
        status="scanned",
        engine=engine_label,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        file_count=len(files),
        scanned_files=[str(item) for item in files],
        findings=findings,
    )


def _collect_files(path: Path, *, max_files: int | None, max_file_bytes: int | None) -> list[Path]:
    candidates = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
    files: list[Path] = []
    for item in candidates:
        if item.suffix.lower() not in TEXT_FILE_SUFFIXES:
            continue
        try:
            if max_file_bytes is not None and item.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        files.append(item)
        if max_files is not None and len(files) >= max_files:
            break
    return files


def _scan_file(path: Path) -> list[SkillScanFinding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    findings: list[SkillScanFinding] = []
    for line_number, line in enumerate(lines, start=1):
        for code, title, severity, rule, pattern in PATTERNS:
            if not pattern.search(line):
                continue
            excerpt = line.strip()
            findings.append(
                SkillScanFinding(
                    code=code,
                    title=title,
                    severity=severity,
                    signal=code,
                    mapped_rule=rule,
                    summary=f"{title} in {path.name}:{line_number}",
                    file_path=str(path),
                    line_number=line_number,
                    excerpt=excerpt[:300],
                )
            )
    return findings


def _item_error(skill_id: int, skill_name: str, source_path: str, status: str, error: str, engine: str) -> SkillScanItemResult:
    return SkillScanItemResult(
        skill_id=skill_id,
        skill_name=skill_name,
        source_path=source_path,
        resolved_path="",
        status=status,
        engine=engine,
        verdict="suspicious",
        risk_score=2,
        summary=f"{skill_name}: {error}.",
        file_count=0,
        error=error,
    )


def _error_result(engine: str, status: str, summary: str, signal: str) -> SkillScanBatchResult:
    item = SkillScanItemResult(
        skill_id=0,
        skill_name="",
        source_path="",
        resolved_path="",
        status=status,
        engine=engine,
        verdict="suspicious",
        risk_score=2,
        summary=summary,
        file_count=0,
        error=summary,
    )
    return SkillScanBatchResult(
        engine=engine,
        verdict="suspicious",
        risk_score=2,
        summary=summary,
        finding_count=0,
        blocked_count=0,
        suspicious_count=1,
        hit_rules=["trust_status_review"],
        matched_signals=[signal],
        items=[item],
    )
