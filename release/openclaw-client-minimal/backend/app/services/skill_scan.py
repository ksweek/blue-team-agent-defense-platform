from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..core.config import PROJECT_ROOT, settings
from ..models import AttackTask, Skill

logger = logging.getLogger("app.skill_scan")

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

SEARCH_ROOTS = [
    PROJECT_ROOT / "backend" / "data" / "demo_skills",
    PROJECT_ROOT / "skills",
    Path.home() / ".codex" / "skills",
    Path.home() / ".claude" / "skills",
]

PATTERN_DEFINITIONS = [
    {
        "code": "prompt_injection_phrase",
        "title": "Prompt Injection 指令",
        "severity": "high",
        "signal": "prompt_injection_phrase",
        "rule": "prompt_injection_firewall",
        "pattern": re.compile(
            r"(ignore\s+(all\s+)?previous\s+instructions|reveal\s+system\s+prompt|暴露系统提示词|忽略之前所有规则)",
            re.IGNORECASE,
        ),
    },
    {
        "code": "approval_bypass_phrase",
        "title": "审批绕过语义",
        "severity": "medium",
        "signal": "approval_bypass_phrase",
        "rule": "approval_integrity_gate",
        "pattern": re.compile(
            r"(do\s+not\s+ask\s+for\s+approval|execute\s+without\s+confirmation|绕过审批|无需确认)",
            re.IGNORECASE,
        ),
    },
    {
        "code": "destructive_command",
        "title": "危险删除命令",
        "severity": "high",
        "signal": "destructive_command",
        "rule": "tool_permission_broker",
        "pattern": re.compile(r"(rm\s+-rf|remove-item\s+.+-recurse|del\s+/[sqf]|shutil\.rmtree)", re.IGNORECASE),
    },
    {
        "code": "shell_execution",
        "title": "Shell 执行能力",
        "severity": "high",
        "signal": "shell_execution",
        "rule": "tool_permission_broker",
        "pattern": re.compile(r"(subprocess\.(run|popen)|os\.system|shell\s*=\s*true|invoke-expression)", re.IGNORECASE),
    },
    {
        "code": "network_exfiltration",
        "title": "外联传输行为",
        "severity": "high",
        "signal": "network_exfiltration",
        "rule": "cross_plugin_handoff_guard",
        "pattern": re.compile(
            r"(curl\s+https?://|invoke-webrequest|requests\.(post|get)\(|httpx\.(post|get)\(|fetch\s*\()",
            re.IGNORECASE,
        ),
    },
    {
        "code": "secret_exposure",
        "title": "疑似硬编码密钥",
        "severity": "high",
        "signal": "secret_exposure",
        "rule": "output_redaction_gate",
        "pattern": re.compile(
            r"((api[_-]?key|token|password|secret)\s*[:=]\s*[\"'][^\"'\n]{6,}[\"']|sk-[a-z0-9_-]{8,})",
            re.IGNORECASE,
        ),
    },
    {
        "code": "mcp_plugin_binding",
        "title": "MCP/插件绑定能力",
        "severity": "medium",
        "signal": "mcp_plugin_binding",
        "rule": "mcp_capability_binding",
        "pattern": re.compile(r"\b(mcp|plugin|cross-plugin|capability)\b", re.IGNORECASE),
    },
]

SEVERITY_SCORE = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


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

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SkillScanFinding":
        return cls(
            code=str(payload.get("code") or "").strip(),
            title=str(payload.get("title") or "").strip(),
            severity=str(payload.get("severity") or "low").strip() or "low",
            signal=str(payload.get("signal") or "").strip(),
            mapped_rule=str(payload.get("mapped_rule") or "").strip(),
            summary=str(payload.get("summary") or "").strip(),
            file_path=str(payload.get("file_path") or "").strip(),
            line_number=payload.get("line_number") if isinstance(payload.get("line_number"), int) else None,
            excerpt=str(payload.get("excerpt") or "").strip(),
        )


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

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SkillScanItemResult":
        findings_payload = payload.get("findings")
        findings = [
            SkillScanFinding.from_payload(item)
            for item in findings_payload
            if isinstance(item, dict)
        ] if isinstance(findings_payload, list) else []
        return cls(
            skill_id=int(payload.get("skill_id") or 0),
            skill_name=str(payload.get("skill_name") or "").strip(),
            source_path=str(payload.get("source_path") or "").strip(),
            resolved_path=str(payload.get("resolved_path") or "").strip(),
            status=str(payload.get("status") or "").strip(),
            engine=str(payload.get("engine") or "").strip() or "local",
            verdict=str(payload.get("verdict") or "suspicious").strip() or "suspicious",
            risk_score=int(payload.get("risk_score") or 0),
            summary=str(payload.get("summary") or "").strip(),
            file_count=int(payload.get("file_count") or 0),
            scanned_files=[
                str(item).strip()
                for item in payload.get("scanned_files") or []
                if str(item).strip()
            ],
            findings=findings,
            external_scan=payload.get("external_scan") if isinstance(payload.get("external_scan"), dict) else None,
            error=str(payload.get("error") or "").strip(),
            trust_status_change=str(payload.get("trust_status_change") or "").strip() or None,
        )


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

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SkillScanBatchResult":
        items_payload = payload.get("items")
        items = [
            SkillScanItemResult.from_payload(item)
            for item in items_payload
            if isinstance(item, dict)
        ] if isinstance(items_payload, list) else []
        return cls(
            engine=str(payload.get("engine") or "").strip() or "local",
            verdict=str(payload.get("verdict") or "suspicious").strip() or "suspicious",
            risk_score=int(payload.get("risk_score") or 0),
            summary=str(payload.get("summary") or "").strip(),
            finding_count=int(payload.get("finding_count") or 0),
            blocked_count=int(payload.get("blocked_count") or 0),
            suspicious_count=int(payload.get("suspicious_count") or 0),
            hit_rules=[
                str(item).strip()
                for item in payload.get("hit_rules") or []
                if str(item).strip()
            ],
            matched_signals=[
                str(item).strip()
                for item in payload.get("matched_signals") or []
                if str(item).strip()
            ],
            items=items,
        )


def serialize_skill_scan_source(skill: Skill) -> dict[str, Any]:
    return {
        "skill_id": int(skill.id),
        "skill_name": str(skill.skill_name or "").strip(),
        "skill_type": str(skill.skill_type or "").strip(),
        "provider": str(skill.provider or "").strip(),
        "source_path": str(skill.source_path or "").strip(),
    }


def deserialize_skill_scan_batch_result(payload: dict[str, Any]) -> SkillScanBatchResult:
    if not isinstance(payload, dict):
        raise ValueError("skill scan payload must be a JSON object")
    return SkillScanBatchResult.from_payload(payload)


def resolve_skill_source_path(skill: Skill) -> Path | None:
    return resolve_skill_source_path_values(
        skill_name=str(skill.skill_name or "").strip(),
        source_path=str(skill.source_path or "").strip(),
    )


def resolve_skill_source_path_values(
    *,
    skill_name: str,
    source_path: str,
    project_root: Path | None = None,
    search_roots: list[Path] | None = None,
) -> Path | None:
    effective_project_root = project_root or PROJECT_ROOT
    effective_search_roots = search_roots or SEARCH_ROOTS
    if source_path:
        candidate = Path(source_path).expanduser()
        if not candidate.is_absolute():
            candidate = (effective_project_root / candidate).resolve()
        return candidate

    if not skill_name:
        return None

    normalized_name = skill_name.lower()
    for root in effective_search_roots:
        if not root.exists():
            continue
        direct = root / skill_name
        if direct.exists():
            return direct.resolve()
        for child in root.iterdir():
            if child.name.lower() == normalized_name:
                return child.resolve()
    return None


def describe_skill_source(skill: Skill) -> dict[str, str | bool]:
    source_path = (skill.source_path or "").strip()
    resolved_path = resolve_skill_source_path(skill)
    exists = bool(resolved_path and resolved_path.exists())

    if not source_path:
        state = "unconfigured"
    elif exists:
        state = "ready"
    else:
        state = "missing"

    return {
        "state": state,
        "exists": exists,
        "resolved_path": str(resolved_path) if resolved_path is not None else "",
    }


def scan_skill_task(db: Session, task: AttackTask) -> SkillScanBatchResult:
    skill_ids = task.params.get("skill_ids")
    if not isinstance(skill_ids, list) or not skill_ids:
        return _build_skill_scan_error_result(
            status="missing_input",
            summary="任务参数中没有 skill_ids，无法执行 skill 扫描。",
            error="missing skill_ids",
            matched_signal="missing_skill_ids",
        )

    items = db.query(Skill).filter(Skill.id.in_(skill_ids)).order_by(Skill.id.asc()).all()
    if not items:
        return _build_skill_scan_error_result(
            status="not_found",
            summary="没有找到需要扫描的技能记录。",
            error="skills not found",
            matched_signal="missing_skill_records",
        )

    return scan_skill_sources(
        [serialize_skill_scan_source(skill) for skill in items],
        engine_label="local",
        include_external_scan=settings.skill_scan_provider == "agent_scan",
        max_files=settings.skill_scan_max_files,
        max_file_bytes=settings.skill_scan_max_file_bytes,
        agent_scan_bin=settings.skill_scan_agent_scan_bin,
        agent_scan_timeout_seconds=settings.skill_scan_timeout_seconds,
    )


def apply_skill_scan_trust_updates(db: Session, result: SkillScanBatchResult) -> int:
    updated_count = 0
    for item in result.items:
        if item.verdict == "clean" or item.skill_id <= 0:
            continue
        skill = db.get(Skill, item.skill_id)
        if skill is None or skill.trust_status == "pending":
            continue
        skill.trust_status = "pending"
        item.trust_status_change = "pending"
        updated_count += 1
    return updated_count


def build_rule_assessment_payload(result: SkillScanBatchResult) -> dict[str, Any]:
    if result.verdict == "blocked":
        event_status = "intercepted"
        event_level = "high"
    elif result.verdict == "suspicious":
        event_status = "suspicious"
        event_level = "medium"
    else:
        event_status = "allowed"
        event_level = "low"

    return {
        "verdict": result.verdict,
        "score": result.risk_score,
        "summary": result.summary,
        "detail": result.summary,
        "event_type": "skill_scan",
        "event_level": event_level,
        "event_status": event_status,
        "hit_rules": result.hit_rules or ["trust_status_review"],
        "matched_signals": result.matched_signals,
    }


def _scan_single_skill(skill: Skill) -> SkillScanItemResult:
    return _scan_single_skill_source(
        serialize_skill_scan_source(skill),
        engine_label="local",
        include_external_scan=settings.skill_scan_provider == "agent_scan",
        max_files=settings.skill_scan_max_files,
        max_file_bytes=settings.skill_scan_max_file_bytes,
        agent_scan_bin=settings.skill_scan_agent_scan_bin,
        agent_scan_timeout_seconds=settings.skill_scan_timeout_seconds,
    )


def scan_skill_sources(
    skill_sources: list[dict[str, Any]],
    *,
    engine_label: str = "local",
    include_external_scan: bool = False,
    project_root: Path | None = None,
    search_roots: list[Path] | None = None,
    max_files: int | None = None,
    max_file_bytes: int | None = None,
    agent_scan_bin: str | None = None,
    agent_scan_timeout_seconds: float | None = None,
) -> SkillScanBatchResult:
    if not skill_sources:
        return _build_skill_scan_error_result(
            status="missing_input",
            summary="没有收到可扫描的技能源配置。",
            error="missing skill_sources",
            matched_signal="missing_skill_sources",
            engine=engine_label,
        )

    results = [
        _scan_single_skill_source(
            source,
            engine_label=engine_label,
            include_external_scan=include_external_scan,
            project_root=project_root,
            search_roots=search_roots,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            agent_scan_bin=agent_scan_bin,
            agent_scan_timeout_seconds=agent_scan_timeout_seconds,
        )
        for source in skill_sources
    ]
    return _aggregate_results(results, default_engine=engine_label)


def _build_skill_scan_error_result(
    *,
    status: str,
    summary: str,
    error: str,
    matched_signal: str,
    engine: str = "local",
) -> SkillScanBatchResult:
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
        error=error,
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
        matched_signals=[matched_signal],
        items=[item],
    )


def _scan_single_skill_source(
    source: dict[str, Any],
    *,
    engine_label: str,
    include_external_scan: bool,
    project_root: Path | None = None,
    search_roots: list[Path] | None = None,
    max_files: int | None = None,
    max_file_bytes: int | None = None,
    agent_scan_bin: str | None = None,
    agent_scan_timeout_seconds: float | None = None,
) -> SkillScanItemResult:
    skill_id = int(source.get("skill_id") or 0)
    skill_name = str(source.get("skill_name") or "").strip() or f"skill-{skill_id or 'unknown'}"
    source_path = str(source.get("source_path") or "").strip()
    resolved_path = resolve_skill_source_path_values(
        skill_name=skill_name,
        source_path=source_path,
        project_root=project_root,
        search_roots=search_roots,
    )
    if not source_path and resolved_path is None:
        return SkillScanItemResult(
            skill_id=skill_id,
            skill_name=skill_name,
            source_path="",
            resolved_path="",
            status="missing_source",
            engine=engine_label,
            verdict="suspicious",
            risk_score=2,
            summary=f"{skill_name} 未配置可扫描路径。",
            file_count=0,
            error="missing source_path",
        )

    if resolved_path is None or not resolved_path.exists():
        return SkillScanItemResult(
            skill_id=skill_id,
            skill_name=skill_name,
            source_path=source_path,
            resolved_path=str(resolved_path) if resolved_path else "",
            status="missing_path",
            engine=engine_label,
            verdict="suspicious",
            risk_score=2,
            summary=f"{skill_name} 的扫描路径不存在。",
            file_count=0,
            error="path not found",
        )

    findings: list[SkillScanFinding] = []
    scanned_files: list[str] = []
    file_paths = _collect_scan_files(
        resolved_path,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
    )
    for file_path in file_paths:
        scanned_files.append(_relative_display_path(file_path, project_root=project_root))
        findings.extend(_scan_file(file_path, project_root=project_root))

    verdict = _verdict_from_findings(findings)
    risk_score = sum(SEVERITY_SCORE.get(item.severity, 1) for item in findings)
    summary = _build_item_summary(skill_name, findings, len(file_paths))
    engine = engine_label
    external_scan = None

    if include_external_scan:
        external_scan = _run_agent_scan(
            resolved_path,
            agent_scan_bin=agent_scan_bin,
            timeout_seconds=agent_scan_timeout_seconds,
        )
        engine = f"{engine_label}+agent_scan"

    return SkillScanItemResult(
        skill_id=skill_id,
        skill_name=skill_name,
        source_path=source_path,
        resolved_path=str(resolved_path),
        status="scanned",
        engine=engine,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        file_count=len(file_paths),
        scanned_files=scanned_files,
        findings=findings,
        external_scan=external_scan,
    )


def _collect_scan_files(
    path: Path,
    *,
    max_files: int | None = None,
    max_file_bytes: int | None = None,
) -> list[Path]:
    effective_max_files = max(1, int(max_files if max_files is not None else settings.skill_scan_max_files))
    effective_max_file_bytes = max(
        1024,
        int(max_file_bytes if max_file_bytes is not None else settings.skill_scan_max_file_bytes),
    )
    if path.is_file():
        return [path]

    files: list[Path] = []
    for child in sorted(path.rglob("*")):
        if len(files) >= effective_max_files:
            break
        if not child.is_file():
            continue
        if child.suffix.lower() not in TEXT_FILE_SUFFIXES:
            continue
        try:
            if child.stat().st_size > effective_max_file_bytes:
                continue
        except OSError:
            continue
        files.append(child)
    return files


def _scan_file(path: Path, *, project_root: Path | None = None) -> list[SkillScanFinding]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [
            SkillScanFinding(
                code="scan_read_error",
                title="文件读取失败",
                severity="medium",
                signal="scan_read_error",
                mapped_rule="trust_status_review",
                summary=str(exc),
                file_path=_relative_display_path(path, project_root=project_root),
            )
        ]

    findings: list[SkillScanFinding] = []
    seen: set[tuple[str, int | None]] = set()
    lines = content.splitlines()
    for definition in PATTERN_DEFINITIONS:
        for match in definition["pattern"].finditer(content):
            line_number = _line_number(content, match.start())
            key = (str(definition["code"]), line_number)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                SkillScanFinding(
                    code=str(definition["code"]),
                    title=str(definition["title"]),
                    severity=str(definition["severity"]),
                    signal=str(definition["signal"]),
                    mapped_rule=str(definition["rule"]),
                    summary=f"命中 {definition['title']}",
                    file_path=_relative_display_path(path, project_root=project_root),
                    line_number=line_number,
                    excerpt=_line_excerpt(lines, line_number),
                )
            )
    return findings


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _line_excerpt(lines: list[str], line_number: int | None) -> str:
    if line_number is None or line_number <= 0 or line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()[:220]


def _verdict_from_findings(findings: list[SkillScanFinding]) -> str:
    if any(item.severity == "high" for item in findings):
        return "blocked"
    if findings:
        return "suspicious"
    return "clean"


def _build_item_summary(skill_name: str, findings: list[SkillScanFinding], file_count: int) -> str:
    if not findings:
        return f"{skill_name} 已扫描 {file_count} 个文件，未发现明确风险。"

    high_count = sum(1 for item in findings if item.severity == "high")
    medium_count = sum(1 for item in findings if item.severity == "medium")
    return (
        f"{skill_name} 已扫描 {file_count} 个文件，命中 {len(findings)} 项风险，"
        f"其中高风险 {high_count} 项，中风险 {medium_count} 项。"
    )


def _aggregate_results(items: list[SkillScanItemResult], *, default_engine: str = "local") -> SkillScanBatchResult:
    blocked_count = sum(1 for item in items if item.verdict == "blocked")
    suspicious_count = sum(1 for item in items if item.verdict == "suspicious")
    findings = [finding for item in items for finding in item.findings]
    hit_rules = _unique_preserve_order(finding.mapped_rule for finding in findings)
    matched_signals = _unique_preserve_order(finding.signal for finding in findings)
    risk_score = sum(item.risk_score for item in items)

    if blocked_count:
        verdict = "blocked"
        summary = f"Skill 扫描发现 {len(findings)} 项风险，{blocked_count} 个技能建议拦截。"
    elif suspicious_count:
        verdict = "suspicious"
        summary = f"Skill 扫描发现 {len(findings)} 项可疑点，建议人工复核。"
    else:
        verdict = "clean"
        summary = "Skill 扫描已完成，未发现明确风险。"

    item_engines = _unique_preserve_order(item.engine for item in items)
    engine = item_engines[0] if len(item_engines) == 1 else default_engine

    if not hit_rules:
        hit_rules = ["trust_status_review"]
    if not matched_signals and suspicious_count:
        matched_signals = ["skill_source_review"]

    return SkillScanBatchResult(
        engine=engine,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
        finding_count=len(findings),
        blocked_count=blocked_count,
        suspicious_count=suspicious_count,
        hit_rules=hit_rules,
        matched_signals=matched_signals,
        items=items,
    )


def _run_agent_scan(
    path: Path,
    *,
    agent_scan_bin: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    configured_binary = str(agent_scan_bin or settings.skill_scan_agent_scan_bin).strip()
    configured_timeout = float(timeout_seconds if timeout_seconds is not None else settings.skill_scan_timeout_seconds)
    binary = shutil.which(configured_binary)
    if not binary:
        return {
            "status": "unavailable",
            "message": f"未找到 {configured_binary}，已跳过外接 agent-scan。",
        }

    command = [binary, "--skills", str(path), "--output", "json"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=configured_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "message": f"agent-scan 超时，超过 {configured_timeout:.0f} 秒。",
        }
    except OSError as exc:
        return {
            "status": "error",
            "message": str(exc),
        }

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    payload: Any = stdout
    if stdout.startswith("{") or stdout.startswith("["):
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = stdout

    return {
        "status": "ok" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "command": command,
        "stdout": payload,
        "stderr": stderr,
    }


def _relative_display_path(path: Path, *, project_root: Path | None = None) -> str:
    effective_project_root = project_root or PROJECT_ROOT
    try:
        return str(path.resolve().relative_to(effective_project_root))
    except ValueError:
        return str(path.resolve())


def _unique_preserve_order(values) -> list[str]:
    items: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if not normalized or normalized in items:
            continue
        items.append(normalized)
    return items
