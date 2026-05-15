from __future__ import annotations

import json
import re
from html import escape
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..core.config import BACKEND_DIR
from ..models import AttackTask, Report, SecurityEvent
from .attack_patterns import collect_detection_hits
from .guard_trace import build_task_guard_trace
from .security_taxonomy import (
    build_policy_reference,
    build_policy_reference_auto,
    build_signal_reference,
    display_policy_label,
    display_signal_label,
    partition_policy_keys,
)
from .time_utils import format_beijing, utc_now

REPORT_EXPORT_DIR = BACKEND_DIR / "data" / "reports"
DEFAULT_REPORT_EXPORT_FORMAT = "json"
SUPPORTED_REPORT_FORMATS = ("json", "html", "docx")
REPORT_MEDIA_TYPES = {
    "json": "application/json",
    "html": "text/html",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
REPORT_FILE_EXTENSIONS = {
    "json": ".json",
    "html": ".html",
    "docx": ".docx",
}
REPORT_TEMPLATE_META = {
    "template_key": "cn_full_security_report_v2",
    "template_name": "中文完整安全报告",
    "template_version": "2.0",
}

CONTROL_LABELS = {
    "prompt_injection_firewall": "提示注入防火墙",
    "indirect_content_isolation": "外部内容隔离",
    "tool_permission_broker": "工具权限代理",
    "mcp_capability_binding": "MCP 能力绑定",
    "cross_plugin_handoff_guard": "跨插件交接防护",
    "memory_taint_guard": "上下文污染防护",
    "output_redaction_gate": "输出脱敏闸门",
    "approval_integrity_gate": "审批完整性校验",
}

RULE_LABELS = {
    "intent-scan": "意图扫描",
    "secret-pattern-scan": "敏感信息模式扫描",
    "approval-persuasion-scan": "审批绕过说服扫描",
    "approval-social-engineering-scan": "审批社工扫描",
    "external-content-scan": "外部内容扫描",
    "indirect-instruction-quarantine": "间接指令隔离扫描",
    "retrieval-boundary-scan": "检索边界扫描",
    "tool-result-scan": "工具结果扫描",
    "tool-poisoning-scan": "工具投毒扫描",
    "tool-approval-gate": "工具审批闸门",
    "workspace-scan": "工作区与插件扫描",
    "mcp-tool-poisoning-scan": "MCP 能力投毒扫描",
    "mcp-session-bind": "MCP 会话绑定校验",
    "cross-plugin-proof": "跨插件交接校验",
    "memory-write-guard": "记忆写入防护",
    "memory-escalation-scan": "多轮污染扫描",
    "output-sanitize": "输出脱敏",
    "prompt-leakage-scan": "提示词泄露扫描",
    "pii-exfiltration-scan": "PII 与密钥外传扫描",
    "canary-leak-scan": "蜜标泄露扫描",
    "encoding-evasion-scan": "编码绕过扫描",
    "ansi-control-scan": "控制字符扫描",
    "input_filtering": "输入过滤",
    "permission_control": "权限控制",
    "sanity_check": "语义校验",
    "manual_review": "人工复核",
    "workspace_scan": "工作区扫描",
    "trust_status_review": "信任状态复核",
}

SENSITIVE_CATEGORY_LABELS = {
    "authorization": "鉴权凭据",
    "query_secret": "URL 密钥参数",
    "secret_field": "敏感字段",
    "cookie": "Cookie",
    "jwt": "JWT",
    "openai_key": "OpenAI Key",
    "anthropic_key": "Anthropic Key",
    "email": "邮箱",
    "windows_path": "Windows 路径",
    "unix_path": "Unix 路径",
}

AUTHORIZATION_VALUE_RE = re.compile(r"(\bAuthorization\b\s*[:=]\s*(?:Bearer|Basic)\s+)([^\s\"',]+)", re.IGNORECASE)
QUERY_SECRET_RE = re.compile(
    r"([?&](?:api[_-]?key|access_token|refresh_token|token|sig(?:nature)?|auth|password)=)([^&#\s]+)",
    re.IGNORECASE,
)
JSON_SECRET_VALUE_RE = re.compile(
    r"(\"?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|smtp_password|qq_email_auth_code|password|secret|handoff_token|x-api-key)\"?\s*:\s*\")([^\"]+)(\")",
    re.IGNORECASE,
)
TEXT_SECRET_VALUE_RE = re.compile(
    r"(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|smtp_password|qq_email_auth_code|password|secret|handoff_token|x-api-key)\b\s*[:=]\s*)([^\s\"',}]+)",
    re.IGNORECASE,
)
COOKIE_RE = re.compile(r"(\b(?:cookie|set-cookie)\b\s*[:=]\s*)([^\r\n]+)", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b")
ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
WINDOWS_PATH_RE = re.compile(r"\b(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+")
UNIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9:])((?:\/[^\/\s\"'`]+){2,})")


def normalize_report_format(value: str | None) -> str:
    candidate = str(value or DEFAULT_REPORT_EXPORT_FORMAT).strip().lower()
    if candidate not in SUPPORTED_REPORT_FORMATS:
        raise ValueError(f"unsupported report format: {value}")
    return candidate


def normalize_report_formats(values: list[str] | tuple[str, ...] | None) -> list[str]:
    if not values:
        return [DEFAULT_REPORT_EXPORT_FORMAT]

    normalized: list[str] = []
    for item in values:
        artifact_format = normalize_report_format(item)
        if artifact_format not in normalized:
            normalized.append(artifact_format)
    return normalized or [DEFAULT_REPORT_EXPORT_FORMAT]


def export_report_artifact(
    db: Session,
    report: Report,
    *,
    task: AttackTask | None = None,
    event: SecurityEvent | None = None,
    artifact_format: str = DEFAULT_REPORT_EXPORT_FORMAT,
) -> Path:
    task = task or db.get(AttackTask, report.task_id)
    if task is None:
        raise ValueError(f"task {report.task_id} not found for report export")

    event = event or _resolve_event_for_task(db, task, report)
    artifact_format = normalize_report_format(artifact_format)

    REPORT_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    relative_path = build_report_relative_path(report, task, artifact_format)
    output_path = (BACKEND_DIR / relative_path).resolve()

    payload = build_report_artifact_payload(report=report, task=task, event=event)
    if artifact_format == "json":
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        report.file_path = relative_path.as_posix()
        db.flush()
        return output_path

    if artifact_format == "html":
        output_path.write_text(build_report_html_artifact(payload), encoding="utf-8")
        return output_path

    if artifact_format == "docx":
        try:
            from .report_docx import build_report_docx_artifact
        except ModuleNotFoundError as exc:
            raise ValueError("docx export requires python-docx to be installed") from exc
        build_report_docx_artifact(payload, output_path)
        return output_path

    raise ValueError(f"unsupported report format: {artifact_format}")


def resolve_report_path(file_path: str) -> Path:
    path = Path(file_path)
    if path.is_absolute():
        return path
    return (BACKEND_DIR / path).resolve()


def derive_report_variant_path(file_path: str, artifact_format: str) -> Path:
    normalized_format = normalize_report_format(artifact_format)
    base_path = resolve_report_path(file_path)
    target_suffix = REPORT_FILE_EXTENSIONS[normalized_format]
    if base_path.suffix:
        return base_path.with_suffix(target_suffix)
    return base_path.with_name(f"{base_path.name}{target_suffix}")


def build_report_relative_path(report: Report, task: AttackTask, artifact_format: str) -> Path:
    normalized_format = normalize_report_format(artifact_format)
    return Path("data") / "reports" / _build_report_filename(report, task, normalized_format)


def build_report_artifact_payload(
    *,
    report: Report,
    task: AttackTask,
    event: SecurityEvent | None,
) -> dict[str, Any]:
    exported_at = format_beijing(utc_now()) or ""
    payload: dict[str, Any] = {
        "template": {
            **REPORT_TEMPLATE_META,
            "available_formats": list(SUPPORTED_REPORT_FORMATS),
        },
        "report": {
            "id": report.id,
            "report_name": report.report_name,
            "report_type": report.report_type,
            "summary_text": report.summary_text,
            "created_by": report.created_by,
            "created_at": format_beijing(report.created_at) or "",
            "exported_at": exported_at,
        },
        "task": {
            "id": task.id,
            "task_name": task.task_name,
            "attack_type": task.attack_type,
            "target_agent": task.target_agent,
            "status": task.status,
            "source_type": task.source_type,
            "source_ref": task.source_ref,
            "execution_mode": task.execution_mode,
            "runtime_name": task.runtime_name,
            "runtime_task_ref": task.runtime_task_ref,
            "params": task.params,
            "result_summary": task.result_summary,
            "raw_response": _parse_json_if_possible(task.raw_response),
            "created_by": task.created_by,
            "scheduled_at": _format_datetime(task.scheduled_at),
            "started_at": _format_datetime(task.started_at),
            "finished_at": _format_datetime(task.finished_at),
            "created_at": _format_datetime(task.created_at),
            "updated_at": _format_datetime(task.updated_at),
        },
        "event": _serialize_event(event),
    }
    payload["presentation"] = build_report_presentation(report=report, task=task, event=event, exported_at=exported_at)
    return payload


def build_report_presentation(
    *,
    report: Report,
    task: AttackTask,
    event: SecurityEvent | None,
    exported_at: str,
) -> dict[str, Any]:
    guard_trace = build_task_guard_trace(task) or {}
    status_badge = _event_status_badge(event.status if event else "")
    risk_badge = _risk_badge(event.event_level if event else "")
    review_badge = _review_badge(guard_trace)
    raw_sections = _build_raw_sections(event=event, task=task)
    payload_hits = _build_payload_hits(event=event, guard_trace=guard_trace, raw_sections=raw_sections)
    sensitive_hits = _build_sensitive_hits(raw_sections)
    summary_text = _build_chinese_summary(
        report=report,
        task=task,
        event=event,
        status_badge=status_badge,
        risk_badge=risk_badge,
        review_badge=review_badge,
        payload_hits=payload_hits,
        sensitive_hits=sensitive_hits,
    )
    timeline = _build_timeline(report=report, task=task, event=event, exported_at=exported_at)
    recommendations = _build_recommendations(
        event=event,
        guard_trace=guard_trace,
        payload_hits=payload_hits,
        sensitive_hits=sensitive_hits,
    )

    return {
        "report_type_label": _report_type_label(report.report_type),
        "task_status_label": _task_status_label(task.status),
        "event_status": status_badge,
        "risk_level": risk_badge,
        "review_status": review_badge,
        "summary_text": summary_text,
        "highlights": [
            {
                "label": "处置结论",
                "value": status_badge["label"],
                "tone": status_badge["tone"],
                "detail": _status_explanation(status_badge["code"]),
            },
            {
                "label": "风险等级",
                "value": risk_badge["label"],
                "tone": risk_badge["tone"],
                "detail": "根据任务命中规则、攻击信号和事件等级综合生成。",
            },
            {
                "label": "AI 复核",
                "value": review_badge["label"],
                "tone": review_badge["tone"],
                "detail": review_badge["detail"],
            },
            {
                "label": "关键命中",
                "value": f"{len(payload_hits)} 项",
                "tone": "warn" if payload_hits else "info",
                "detail": f"其中敏感数据痕迹 {len(sensitive_hits)} 项。",
            },
        ],
        "object_summary": [
            ("报告名称", report.report_name),
            ("报告类型", _report_type_label(report.report_type)),
            ("任务名称", task.task_name),
            ("攻击类型", _humanize_code(task.attack_type)),
            ("目标对象", task.target_agent),
            ("任务状态", _task_status_label(task.status)),
            ("来源类型", _source_type_label(task.source_type)),
            ("执行模式", _execution_mode_label(task.execution_mode)),
            ("运行时名称", task.runtime_name or "-"),
            ("运行时任务号", task.runtime_task_ref or "-"),
        ],
        "decision_summary": {
            "title": "关键结论",
            "summary": summary_text,
            "detail": _best_text(
                str(guard_trace.get("detail") or ""),
                event.detail if event else "",
                task.result_summary,
                "当前记录未附带更细的处置说明。",
            ),
        },
        "trace_summary": [
            {
                "label": "授权决策",
                "value": _authorization_decision_label(guard_trace.get("decision")),
                "detail": _best_text(str(guard_trace.get("summary") or ""), str(guard_trace.get("detail") or ""), "未记录。"),
                "tone": _decision_tone(str(guard_trace.get("decision") or "")),
            },
            {
                "label": "授权来源",
                "value": _guard_source_label(guard_trace.get("source")),
                "detail": "用于区分是执行前预检复用、运行态快照，还是本次执行阶段重新评估。",
                "tone": "info",
            },
            {
                "label": "规则判定",
                "value": _rule_verdict_label(guard_trace.get("rule_verdict")),
                "detail": _best_text(
                    _guard_rule_text(guard_trace, "summary"),
                    _guard_rule_text(guard_trace, "detail"),
                    "未记录。",
                ),
                "tone": _rule_verdict_tone(str(guard_trace.get("rule_verdict") or "")),
            },
            {
                "label": "复核策略",
                "value": _ai_review_mode_label(guard_trace.get("ai_review_mode")),
                "detail": review_badge["detail"],
                "tone": review_badge["tone"],
            },
        ],
        "matched_controls": [_policy_label(item) for item in _string_list(guard_trace.get("matched_controls"))],
        "matched_rules": [_policy_label(item) for item in _collect_rules(event=event, guard_trace=guard_trace)],
        "matched_signals": [_signal_label(item) for item in _guard_signals(guard_trace)],
        "payload_hits": payload_hits,
        "sensitive_hits": sensitive_hits,
        "timeline": timeline,
        "recommendations": recommendations,
        "appendix_sections": raw_sections,
    }


def build_report_html_artifact(payload: dict[str, Any]) -> str:
    template_meta = payload.get("template") or {}
    report = payload.get("report") or {}
    presentation = payload.get("presentation") or {}
    event_status = presentation.get("event_status") or {"label": "-", "tone": "info"}
    risk_level = presentation.get("risk_level") or {"label": "-", "tone": "info"}
    review_status = presentation.get("review_status") or {"label": "-", "tone": "info"}
    highlights = presentation.get("highlights") or []
    object_summary = presentation.get("object_summary") or []
    decision_summary = presentation.get("decision_summary") or {}
    trace_summary = presentation.get("trace_summary") or []
    matched_controls = presentation.get("matched_controls") or []
    matched_rules = presentation.get("matched_rules") or []
    matched_signals = presentation.get("matched_signals") or []
    payload_hits = presentation.get("payload_hits") or []
    sensitive_hits = presentation.get("sensitive_hits") or []
    timeline = presentation.get("timeline") or []
    recommendations = presentation.get("recommendations") or []
    appendix_sections = presentation.get("appendix_sections") or []
    summary_text = str(presentation.get("summary_text") or "")
    title = str(report.get("report_name") or presentation.get("report_type_label") or "安全报告")

    html_parts = [
        "<!doctype html>",
        '<html lang="zh-CN">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title>",
        "<style>",
        """
        :root {
          color-scheme: light;
          --bg: #0d1624;
          --shell: #101c2c;
          --card: #f7fafc;
          --card-strong: #ffffff;
          --line: #d8e3f0;
          --text: #12263f;
          --muted: #5d718a;
          --safe: #0b8f61;
          --warn: #c77a10;
          --danger: #c13d33;
          --info: #1d62c7;
          --safe-soft: #ddf6ea;
          --warn-soft: #fff1d6;
          --danger-soft: #ffe0db;
          --info-soft: #e3efff;
          --hero-grad: linear-gradient(135deg, #12243b 0%, #1f436f 48%, #2d6ad8 100%);
          --code-bg: #0c1623;
          --code-text: #e8eef7;
          --shadow: 0 18px 48px rgba(7, 22, 41, 0.18);
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at top left, rgba(62, 130, 255, 0.18), transparent 28%),
            radial-gradient(circle at top right, rgba(36, 214, 156, 0.16), transparent 24%),
            linear-gradient(180deg, #0a1422 0%, #101a2a 100%);
          color: var(--text);
        }
        .page {
          max-width: 1260px;
          margin: 0 auto;
          padding: 28px 20px 48px;
        }
        .hero {
          position: relative;
          overflow: hidden;
          background: var(--hero-grad);
          color: #f4f8ff;
          border-radius: 24px;
          padding: 28px 28px 24px;
          box-shadow: var(--shadow);
          margin-bottom: 18px;
        }
        .hero::after {
          content: "";
          position: absolute;
          inset: auto -80px -90px auto;
          width: 260px;
          height: 260px;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.08);
          filter: blur(2px);
        }
        .hero-top {
          display: flex;
          justify-content: space-between;
          gap: 18px;
          align-items: flex-start;
        }
        .hero-copy h1 {
          margin: 0;
          font-size: 30px;
          line-height: 1.25;
          letter-spacing: 0.02em;
        }
        .hero-copy p {
          margin: 10px 0 0;
          max-width: 820px;
          color: rgba(244, 248, 255, 0.88);
          line-height: 1.7;
          white-space: pre-wrap;
        }
        .hero-meta {
          min-width: 280px;
          padding: 16px 18px;
          border-radius: 18px;
          border: 1px solid rgba(255, 255, 255, 0.12);
          background: rgba(255, 255, 255, 0.08);
          backdrop-filter: blur(8px);
        }
        .hero-meta strong {
          display: block;
          font-size: 15px;
          margin-bottom: 10px;
        }
        .hero-meta span {
          display: block;
          color: rgba(244, 248, 255, 0.82);
          font-size: 13px;
          line-height: 1.65;
        }
        .status-strip {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 12px;
          margin-top: 18px;
        }
        .status-card {
          padding: 14px 16px;
          border-radius: 16px;
          background: rgba(255, 255, 255, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.12);
        }
        .status-card span {
          display: block;
          color: rgba(244, 248, 255, 0.8);
          font-size: 12px;
        }
        .status-card strong {
          display: block;
          margin-top: 6px;
          font-size: 22px;
          line-height: 1.2;
        }
        .grid {
          display: grid;
          grid-template-columns: repeat(12, minmax(0, 1fr));
          gap: 16px;
        }
        .card {
          grid-column: span 12;
          background: var(--card);
          border: 1px solid rgba(216, 227, 240, 0.9);
          border-radius: 22px;
          box-shadow: var(--shadow);
          overflow: hidden;
        }
        .card-head {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: flex-start;
          padding: 20px 22px 0;
        }
        .card-head h2 {
          margin: 0;
          font-size: 18px;
          line-height: 1.3;
        }
        .card-head p {
          margin: 6px 0 0;
          color: var(--muted);
          font-size: 13px;
        }
        .card-body {
          padding: 18px 22px 22px;
        }
        .span-4 { grid-column: span 4; }
        .span-5 { grid-column: span 5; }
        .span-6 { grid-column: span 6; }
        .span-7 { grid-column: span 7; }
        .span-8 { grid-column: span 8; }
        .pill {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 5px 12px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 700;
          border: 1px solid transparent;
          white-space: nowrap;
        }
        .tone-safe { color: var(--safe); background: var(--safe-soft); border-color: rgba(11, 143, 97, 0.18); }
        .tone-warn { color: var(--warn); background: var(--warn-soft); border-color: rgba(199, 122, 16, 0.18); }
        .tone-danger { color: var(--danger); background: var(--danger-soft); border-color: rgba(193, 61, 51, 0.18); }
        .tone-info { color: var(--info); background: var(--info-soft); border-color: rgba(29, 98, 199, 0.18); }
        .summary-block {
          padding: 18px 20px;
          border-radius: 18px;
          background: linear-gradient(180deg, #ffffff 0%, #f4f8ff 100%);
          border: 1px solid var(--line);
        }
        .summary-block strong {
          display: block;
          margin-bottom: 8px;
          font-size: 18px;
        }
        .summary-block p {
          margin: 0;
          color: var(--text);
          line-height: 1.8;
          white-space: pre-wrap;
        }
        .kv-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px 18px;
        }
        .kv-item {
          padding-bottom: 12px;
          border-bottom: 1px dashed var(--line);
        }
        .kv-item strong {
          display: block;
          margin-bottom: 6px;
          color: var(--muted);
          font-size: 12px;
          font-weight: 700;
        }
        .kv-item span {
          display: block;
          white-space: pre-wrap;
          word-break: break-word;
          line-height: 1.7;
        }
        .stack {
          display: grid;
          gap: 12px;
        }
        .hit-row,
        .recommend-row,
        .trace-row,
        .sensitive-row {
          padding: 14px 16px;
          border-radius: 16px;
          border: 1px solid var(--line);
          background: var(--card-strong);
        }
        .row-top {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: flex-start;
          margin-bottom: 8px;
        }
        .row-top strong {
          font-size: 15px;
          line-height: 1.4;
        }
        .row-top span {
          color: var(--muted);
          font-size: 12px;
        }
        .row-detail {
          color: var(--text);
          line-height: 1.75;
          white-space: pre-wrap;
        }
        .row-meta {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-top: 10px;
        }
        .chip {
          display: inline-flex;
          align-items: center;
          padding: 4px 10px;
          border-radius: 999px;
          background: #eff4fb;
          color: #294462;
          font-size: 12px;
          border: 1px solid #d5dfec;
        }
        pre {
          margin: 10px 0 0;
          padding: 14px 16px;
          border-radius: 16px;
          background: var(--code-bg);
          color: var(--code-text);
          overflow: auto;
          font-family: "Cascadia Code", "Consolas", monospace;
          font-size: 12.5px;
          line-height: 1.6;
          white-space: pre-wrap;
          word-break: break-word;
        }
        .timeline {
          display: grid;
          gap: 12px;
        }
        .timeline-item {
          position: relative;
          padding-left: 18px;
        }
        .timeline-item::before {
          content: "";
          position: absolute;
          left: 0;
          top: 8px;
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--info);
        }
        .timeline-item strong {
          display: block;
          font-size: 14px;
        }
        .timeline-item span {
          display: block;
          margin-top: 4px;
          color: var(--muted);
          font-size: 12px;
        }
        details {
          border: 1px solid var(--line);
          border-radius: 16px;
          background: var(--card-strong);
          overflow: hidden;
        }
        summary {
          cursor: pointer;
          list-style: none;
          padding: 14px 16px;
          font-weight: 700;
        }
        summary::-webkit-details-marker { display: none; }
        .details-body { padding: 0 16px 16px; }
        .empty {
          color: var(--muted);
        }
        @media (max-width: 1080px) {
          .status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
          .span-4, .span-5, .span-6, .span-7, .span-8 { grid-column: span 12; }
          .kv-grid { grid-template-columns: 1fr; }
          .hero-top { flex-direction: column; }
          .hero-meta { width: 100%; }
        }
        @media (max-width: 680px) {
          .page { padding: 20px 12px 36px; }
          .hero { padding: 22px 18px 18px; border-radius: 20px; }
          .status-strip { grid-template-columns: 1fr; }
          .card-head, .card-body { padding-left: 16px; padding-right: 16px; }
        }
        """,
        "</style>",
        "</head>",
        "<body>",
        '<main class="page">',
        '<section class="hero">',
        '<div class="hero-top">',
        '<div class="hero-copy">',
        f"<h1>{escape(title)}</h1>",
        f"<p>{escape(summary_text)}</p>",
        "</div>",
        '<div class="hero-meta">',
        f"<strong>{escape(str(template_meta.get('template_name') or '中文安全报告模板'))}</strong>",
        f"<span>模板版本：{escape(str(template_meta.get('template_version') or '-'))}</span>",
        f"<span>报告编号：{escape(str(report.get('id') or '-'))}</span>",
        f"<span>导出时间：{escape(str(report.get('exported_at') or '-'))}</span>",
        "</div>",
        "</div>",
        '<div class="status-strip">',
        _render_status_card("处置结论", event_status["label"], event_status["tone"]),
        _render_status_card("风险等级", risk_level["label"], risk_level["tone"]),
        _render_status_card("AI 复核", review_status["label"], review_status["tone"]),
        _render_status_card("关键命中", f"{len(payload_hits)} 项 / 敏感 {len(sensitive_hits)} 项", "info"),
        "</div>",
        "</section>",
        '<section class="grid">',
        '<article class="card span-7">',
        '<div class="card-head"><div><h2>关键结论</h2><p>面向人工研判的中文摘要</p></div></div>',
        '<div class="card-body">',
        f"<div class=\"summary-block\"><strong>{escape(str(decision_summary.get('title') or '关键结论'))}</strong><p>{escape(str(decision_summary.get('summary') or '-'))}</p><p style=\"margin-top:10px;color:var(--muted);\">{escape(str(decision_summary.get('detail') or '-'))}</p></div>",
        "</div>",
        "</article>",
        '<article class="card span-5">',
        '<div class="card-head"><div><h2>摘要指标</h2><p>重点信息已直接标出</p></div></div>',
        '<div class="card-body stack">',
        _render_highlights(highlights),
        "</div>",
        "</article>",
        '<article class="card span-6">',
        '<div class="card-head"><div><h2>对象信息</h2><p>报告、任务与目标对象概览</p></div></div>',
        f"<div class=\"card-body\">{_render_kv_grid(object_summary)}</div>",
        "</article>",
        '<article class="card span-6">',
        '<div class="card-head"><div><h2>执行链判断</h2><p>授权、规则与复核状态</p></div></div>',
        f"<div class=\"card-body stack\">{_render_trace_rows(trace_summary)}</div>",
        "</article>",
        '<article class="card span-4">',
        '<div class="card-head"><div><h2>命中控制面</h2><p>前置授权或执行守卫</p></div></div>',
        f"<div class=\"card-body\">{_render_chip_list(matched_controls, '当前没有记录到命中控制面。')}</div>",
        "</article>",
        '<article class="card span-4">',
        '<div class="card-head"><div><h2>命中规则</h2><p>规则引擎与事件规则</p></div></div>',
        f"<div class=\"card-body\">{_render_chip_list(matched_rules, '当前没有记录到命中规则。')}</div>",
        "</article>",
        '<article class="card span-4">',
        '<div class="card-head"><div><h2>攻击信号</h2><p>规则引擎识别出的攻击特征</p></div></div>',
        f"<div class=\"card-body\">{_render_chip_list(matched_signals, '当前没有记录到攻击信号。')}</div>",
        "</article>",
        '<article class="card span-8">',
        '<div class="card-head"><div><h2>重点命中与证据</h2><p>包含命中类型、位置、证据片段与来源</p></div></div>',
        f"<div class=\"card-body stack\">{_render_payload_hits(payload_hits)}</div>",
        "</article>",
        '<article class="card span-4">',
        '<div class="card-head"><div><h2>敏感数据痕迹</h2><p>导出报告默认只展示脱敏后的痕迹</p></div></div>',
        f"<div class=\"card-body stack\">{_render_sensitive_hits(sensitive_hits)}</div>",
        "</article>",
        '<article class="card span-5">',
        '<div class="card-head"><div><h2>执行时间线</h2><p>按北京时间整理任务与报告节点</p></div></div>',
        f"<div class=\"card-body timeline\">{_render_timeline(timeline)}</div>",
        "</article>",
        '<article class="card span-7">',
        '<div class="card-head"><div><h2>处置建议</h2><p>根据当前结论自动生成的人工处置建议</p></div></div>',
        f"<div class=\"card-body stack\">{_render_recommendations(recommendations)}</div>",
        "</article>",
        '<article class="card span-12">',
        '<div class="card-head"><div><h2>原始数据附录</h2><p>保留任务输入、执行结果与原始返回，便于复盘</p></div></div>',
        f"<div class=\"card-body stack\">{_render_appendix_sections(appendix_sections)}</div>",
        "</article>",
        "</section>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "".join(html_parts)


def _build_report_filename(report: Report, task: AttackTask, artifact_format: str) -> str:
    extension = REPORT_FILE_EXTENSIONS[artifact_format]
    return f"{report.report_type}-task-{task.id}-report-{report.id}{extension}"


def _resolve_event_for_task(db: Session, task: AttackTask, report: Report) -> SecurityEvent | None:
    if task.latest_event_id:
        item = db.get(SecurityEvent, task.latest_event_id)
        if item is not None:
            return item

    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.task_id == report.task_id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .first()
    )


def _serialize_event(event: SecurityEvent | None) -> dict[str, Any] | None:
    if event is None:
        return None

    return {
        "id": event.id,
        "task_id": event.task_id,
        "event_type": event.event_type,
        "event_level": event.event_level,
        "source": event.source,
        "target": event.target,
        "status": event.status,
        "detail": event.detail,
        "hit_rules": event.hit_rules,
        "raw_input": event.raw_input,
        "result": event.result,
        "operation_logs": event.operation_logs,
        "created_at": _format_datetime(event.created_at),
    }


def _parse_json_if_possible(value: str) -> Any:
    if not value:
        return value

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _format_datetime(value) -> str | None:
    return format_beijing(value)


def _build_raw_sections(event: SecurityEvent | None, task: AttackTask) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    if event is not None:
        _append_section(sections, "event_raw_input", "事件原始输入", _normalize_content(event.raw_input))
        _append_section(sections, "event_result", "事件处理结果", _normalize_content(event.result))
    _append_section(sections, "task_params", "任务传递参数", task.params)
    task_raw_response = _normalize_content(task.raw_response)
    _append_section(sections, "task_raw_response", "执行原始响应", task_raw_response)

    if isinstance(task_raw_response, dict):
        skill_scan = task_raw_response.get("skill_scan")
        if isinstance(skill_scan, dict):
            _append_section(sections, "skill_scan_result", "Skill 扫描结果", skill_scan)
        provider = task_raw_response.get("provider")
        if isinstance(provider, dict):
            _append_section(
                sections,
                "provider_output_text",
                "模型原始输出",
                _normalize_content(provider.get("output_text")),
            )
            _append_section(
                sections,
                "provider_raw_response",
                "Provider 原始返回",
                provider.get("raw_response"),
            )
    return sections


def _build_payload_hits(
    *,
    event: SecurityEvent | None,
    guard_trace: dict[str, Any],
    raw_sections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add_item(
        kind: str,
        label: str,
        source: str,
        detail: str,
        location: str = "",
        evidence: str = "",
        *,
        detail_label: str | None = None,
        category_key: str | None = None,
        category_label: str | None = None,
        tone: str | None = None,
        mapped_rule_key: str | None = None,
        mapped_rule_label: str | None = None,
    ) -> None:
        item_key = (kind, label, source, location)
        if item_key in seen:
            return
        seen.add(item_key)
        items.append(
            {
                "kind": kind,
                "label": label,
                "display_label": _display_label(kind, label),
                "source": source,
                "detail": detail,
                "detail_label": detail_label or detail,
                "category_key": category_key,
                "category_label": category_label,
                "tone": tone or "info",
                "location": location,
                "location_label": _location_label(location),
                "source_label": source,
                "mapped_rule_key": mapped_rule_key,
                "mapped_rule_label": mapped_rule_label,
                "evidence": evidence,
            }
        )

    hit_rule_controls, _ = partition_policy_keys(_string_list(event.hit_rules if event else []))
    matched_rule_controls, _ = partition_policy_keys(_string_list(guard_trace.get("matched_rules")))
    rule_assessment = guard_trace.get("rule_assessment")
    assessed_controls, _ = partition_policy_keys(
        _string_list(rule_assessment.get("hit_rules")) if isinstance(rule_assessment, dict) else []
    )

    for item in _unique_strings(_string_list(guard_trace.get("matched_controls")) + hit_rule_controls + matched_rule_controls + assessed_controls):
        reference = build_policy_reference(item, kind="control")
        add_item(
            "control",
            item,
            "授权链路",
            "授权链路命中的控制面。",
            detail_label=reference["detail"] or "授权链路命中的控制面。",
            category_key=reference["category_key"],
            category_label=reference["category_label"],
            tone=reference["tone"],
        )

    for item in _collect_rules(event=event, guard_trace=guard_trace):
        reference = build_policy_reference_auto(item)
        add_item(
            "rule",
            item,
            "规则命中",
            "事件或规则评估命中的规则。",
            detail_label=reference["detail"] or "事件或规则评估命中的规则。",
            category_key=reference["category_key"],
            category_label=reference["category_label"],
            tone=reference["tone"],
        )

    for item in _guard_signals(guard_trace):
        reference = build_signal_reference(item)
        add_item(
            "signal",
            item,
            "攻击信号",
            "规则引擎识别出的攻击信号。",
            detail_label=reference["detail"] or "规则引擎识别出的攻击信号。",
            tone=reference["tone"],
        )

    scan_section_keys = {"event_raw_input", "task_params", "provider_output_text"}
    for section in raw_sections:
        if section["key"] not in scan_section_keys:
            continue
        for location, text in _iter_text_nodes(section["content"]):
            for hit in collect_detection_hits(text):
                mapped_rule = build_policy_reference_auto(hit.rule_key)
                add_item(
                    "pattern",
                    hit.pattern,
                    section["title"],
                    f"{'强攻击' if hit.severity == 'strong' else '可疑'}特征，映射规则 {hit.rule_key}，命中视图 {hit.view}。",
                    location,
                    hit.snippet or _build_snippet(text, hit.pattern.strip().lower()),
                    detail_label=f"{'强攻击' if hit.severity == 'strong' else '可疑'}特征，对应规则：{mapped_rule['label']}，命中视图：{hit.view}。",
                    category_key=mapped_rule["category_key"],
                    category_label=mapped_rule["category_label"],
                    tone="danger" if hit.severity == "strong" else "warn",
                    mapped_rule_key=hit.rule_key,
                    mapped_rule_label=mapped_rule["label"],
                )
    return items


def _build_sensitive_hits(raw_sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add_item(category: str, source: str, location: str, preview: str) -> None:
        normalized_preview = preview.strip()
        if not normalized_preview:
            return
        item_key = (category, source, location, normalized_preview)
        if item_key in seen:
            return
        seen.add(item_key)
        items.append(
            {
                "category": category,
                "label": SENSITIVE_CATEGORY_LABELS.get(category, category),
                "source": source,
                "location": location,
                "location_label": _location_label(location),
                "preview": normalized_preview,
            }
        )

    def scan_value(value: Any, *, source: str, location: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                child_location = f"{location}.{key}" if location else str(key)
                if isinstance(item, str) and _looks_sensitive_key(key):
                    add_item("secret_field", source, child_location, _mask_middle(item, 4, 2))
                scan_value(item, source=source, location=child_location)
            return

        if isinstance(value, list):
            for index, item in enumerate(value):
                child_location = f"{location}[{index}]"
                scan_value(item, source=source, location=child_location)
            return

        if not isinstance(value, str) or not value.strip():
            return

        text = value
        for matched in AUTHORIZATION_VALUE_RE.finditer(text):
            add_item("authorization", source, location, f"{matched.group(1)}{_mask_middle(matched.group(2), 6, 4)}")
        for matched in QUERY_SECRET_RE.finditer(text):
            add_item("query_secret", source, location, f"{matched.group(1)}{_mask_middle(matched.group(2), 4, 2)}")
        for matched in JSON_SECRET_VALUE_RE.finditer(text):
            add_item("secret_field", source, location, f"{matched.group(1)}{_mask_middle(matched.group(2), 4, 2)}{matched.group(3)}")
        for matched in TEXT_SECRET_VALUE_RE.finditer(text):
            add_item("secret_field", source, location, f"{matched.group(1)}{_mask_middle(matched.group(2), 4, 2)}")
        for matched in COOKIE_RE.finditer(text):
            add_item("cookie", source, location, f"{matched.group(1)}{_mask_middle(matched.group(2), 8, 4)}")
        for matched in JWT_RE.finditer(text):
            add_item("jwt", source, location, _mask_middle(matched.group(0), 10, 6))
        for matched in OPENAI_KEY_RE.finditer(text):
            add_item("openai_key", source, location, _mask_middle(matched.group(0), 8, 4))
        for matched in ANTHROPIC_KEY_RE.finditer(text):
            add_item("anthropic_key", source, location, _mask_middle(matched.group(0), 8, 4))
        for matched in EMAIL_RE.finditer(text):
            add_item("email", source, location, _mask_email(matched.group(0)))
        for matched in WINDOWS_PATH_RE.finditer(text):
            add_item("windows_path", source, location, _mask_windows_path(matched.group(0)))
        for matched in UNIX_PATH_RE.finditer(text):
            path = matched.group(1)
            if _should_mask_unix_path(path):
                add_item("unix_path", source, location, _mask_unix_path(path))

    for section in raw_sections:
        scan_value(section["content"], source=section["title"])
    return items


def _build_timeline(
    *,
    report: Report,
    task: AttackTask,
    event: SecurityEvent | None,
    exported_at: str,
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []

    def add_item(label: str, value: str | None, detail: str) -> None:
        text = str(value or "").strip()
        if not text:
            return
        items.append({"label": label, "value": text, "detail": detail})

    add_item("任务创建", _format_datetime(task.created_at), "任务入库并等待执行。")
    add_item("计划执行", _format_datetime(task.scheduled_at), "任务进入调度队列。")
    add_item("开始执行", _format_datetime(task.started_at), "开始进入执行或运行时回传阶段。")
    add_item("任务完成", _format_datetime(task.finished_at), "执行结果、事件和报告已归档。")
    add_item("安全事件记录", _format_datetime(event.created_at) if event else None, "安全事件已写入审计链路。")
    add_item("报告生成", _format_datetime(report.created_at), "报告记录已创建。")
    add_item("报告导出", exported_at, "导出为当前报告工件。")
    return items


def _build_recommendations(
    *,
    event: SecurityEvent | None,
    guard_trace: dict[str, Any],
    payload_hits: list[dict[str, Any]],
    sensitive_hits: list[dict[str, Any]],
) -> list[dict[str, str]]:
    status = str(event.status if event else "").strip().lower()
    recommendations: list[dict[str, str]] = []

    def add_item(title: str, detail: str, tone: str) -> None:
        recommendations.append({"title": title, "detail": detail, "tone": tone})

    if status == "intercepted":
        add_item("维持拦截", "本次已被判定为拦截，建议先不要恢复放行，优先复核命中规则与控制面。", "danger")
    elif status == "suspicious":
        add_item("人工复核", "当前结论为可疑，建议分析员结合命中证据、上游请求链和原始输入做进一步研判。", "warn")
    elif status == "allowed":
        add_item("审计留痕", "本次已放行，但仍建议保留该报告并关注同源后续请求是否出现重复命中。", "safe")
    else:
        add_item("补充核验", "当前未形成稳定处置结论，建议结合原始数据和运行态链路补充核验。", "info")

    if sensitive_hits:
        add_item("检查脱敏策略", f"检测到 {len(sensitive_hits)} 处敏感数据痕迹，建议检查输出脱敏、日志脱敏与回传字段裁剪策略。", "warn")

    if payload_hits:
        add_item("固化命中规则", f"已识别 {len(payload_hits)} 项关键命中，建议将高置信命中纳入后续阻断或复核策略。", "info")

    if _string_list(guard_trace.get("matched_controls")):
        add_item("回看授权链", "本报告显示已有执行守卫命中，建议核查授权链是否需要前置到更早的统一代理入口。", "info")

    if not recommendations:
        add_item("保持观察", "当前未发现额外异常，建议继续保持样本回归与运行态审计。", "safe")
    return recommendations


def _event_status_badge(status: str | None) -> dict[str, str]:
    key = str(status or "").strip().lower()
    if key == "intercepted":
        return {"code": key, "label": "拦截", "tone": "danger"}
    if key == "suspicious":
        return {"code": key, "label": "可疑", "tone": "warn"}
    if key == "allowed":
        return {"code": key, "label": "放行", "tone": "safe"}
    return {"code": key or "unknown", "label": "未判定", "tone": "info"}


def _risk_badge(level: str | None) -> dict[str, str]:
    key = str(level or "").strip().lower()
    if key == "high":
        return {"code": key, "label": "高危", "tone": "danger"}
    if key == "medium":
        return {"code": key, "label": "中危", "tone": "warn"}
    if key == "low":
        return {"code": key, "label": "低危", "tone": "info"}
    return {"code": key or "unknown", "label": "未分级", "tone": "info"}


def _review_badge(guard_trace: dict[str, Any]) -> dict[str, str]:
    if not guard_trace:
        return {"label": "未记录", "tone": "info", "detail": "当前报告没有可用的 AI 复核链路数据。"}

    if bool(guard_trace.get("ai_review_invoked")):
        return {"label": "已触发", "tone": "warn", "detail": "执行阶段已触发 AI 复核。"}

    review_decision = str(guard_trace.get("review_decision") or "").strip().lower()
    if review_decision == "no_ai_endpoint_configured":
        return {"label": "未触发", "tone": "info", "detail": "当前未配置可用 AI 目标，执行链已退化为规则判定。"}
    if review_decision == "target_protection_disabled":
        return {"label": "未启用", "tone": "info", "detail": "目标保护未启用 AI 复核。"}
    if review_decision == "confirmed_by_policy":
        return {"label": "策略直断", "tone": "danger", "detail": "当前已被策略明确判定，无需再进入 AI 复核。"}
    if review_decision == "rules_only_mode":
        return {"label": "规则模式", "tone": "info", "detail": "当前策略配置为仅规则判定。"}
    if review_decision == "review_suspicious_only":
        return {"label": "按需复核", "tone": "info", "detail": "仅在规则判定为可疑时进入 AI 复核。"}
    if review_decision == "review_all_remaining":
        return {"label": "全量复核", "tone": "info", "detail": "剩余请求将进入 AI 复核。"}
    return {"label": "未触发", "tone": "info", "detail": "当前记录显示未进入 AI 复核。"}


def _report_type_label(value: str | None) -> str:
    mapping = {
        "task_execution": "任务执行报告",
        "runtime_execution": "运行时执行报告",
        "preflight_block": "预检阻断报告",
        "worker_failed": "执行失败报告",
        "worker_dead_letter": "死信归档报告",
        "security_evaluation": "安全评估报告",
    }
    key = str(value or "").strip()
    return mapping.get(key, _humanize_code(key) or "报告")


def _task_status_label(value: str | None) -> str:
    mapping = {
        "ready": "待执行",
        "queued": "排队中",
        "scheduled": "已调度",
        "running": "执行中",
        "done": "已完成",
        "failed": "执行失败",
        "dead_letter": "死信归档",
        "cancelled": "已取消",
        "paused_ready": "已暂停（待执行）",
        "paused_scheduled": "已暂停（已调度）",
    }
    key = str(value or "").strip().lower()
    return mapping.get(key, value or "未记录")


def _source_type_label(value: str | None) -> str:
    mapping = {
        "manual": "手动创建",
        "dataset_sample": "攻击样本",
        "runtime_smoke": "运行时回传",
        "runtime_callback": "运行时回调",
    }
    key = str(value or "").strip().lower()
    return mapping.get(key, value or "未记录")


def _execution_mode_label(value: str | None) -> str:
    mapping = {
        "worker": "平台 Worker",
        "runtime_callback": "运行时回调",
        "scheduled": "定时调度",
    }
    key = str(value or "").strip().lower()
    return mapping.get(key, value or "未记录")


def _authorization_decision_label(value: Any) -> str:
    key = str(value or "").strip().lower()
    if key == "deny":
        return "阻断"
    if key == "review":
        return "复核"
    if key == "allow":
        return "放行"
    return "未记录"


def _ai_review_mode_label(value: Any) -> str:
    key = str(value or "").strip().lower()
    if key == "rules_only":
        return "仅规则直断"
    if key == "suspicious_review":
        return "仅可疑复核"
    if key == "review_all_remaining":
        return "剩余全量复核"
    return "未记录"


def _rule_verdict_label(value: Any) -> str:
    key = str(value or "").strip().lower()
    if key == "blocked":
        return "规则命中阻断"
    if key == "suspicious":
        return "规则判定可疑"
    if key == "clean":
        return "规则未命中阻断"
    return "未记录"


def _rule_verdict_tone(value: str) -> str:
    key = str(value or "").strip().lower()
    if key == "blocked":
        return "danger"
    if key == "suspicious":
        return "warn"
    if key == "clean":
        return "safe"
    return "info"


def _decision_tone(value: str) -> str:
    key = str(value or "").strip().lower()
    if key == "deny":
        return "danger"
    if key == "review":
        return "warn"
    if key == "allow":
        return "safe"
    return "info"


def _guard_source_label(value: Any) -> str:
    key = str(value or "").strip()
    mapping = {
        "worker_preflight_reused": "复用 Worker 预检结果",
        "worker_preflight_blocked": "Worker 预检已阻断",
        "runtime_authorization_snapshot": "运行时授权快照",
        "task_runner_evaluated": "执行阶段重新评估",
        "raw_response_embedded": "响应内嵌结果",
    }
    return mapping.get(key, key or "未记录")


def _status_explanation(code: str) -> str:
    if code == "intercepted":
        return "当前请求已被平台明确拦截，不建议直接恢复执行。"
    if code == "suspicious":
        return "当前请求被标记为可疑，建议人工复核后再决定是否放行。"
    if code == "allowed":
        return "当前请求已放行，但仍建议保留审计记录以便追踪。"
    return "当前尚未形成稳定的事件处置结论。"


def _collect_rules(*, event: SecurityEvent | None, guard_trace: dict[str, Any]) -> list[str]:
    _, items = partition_policy_keys(_string_list(event.hit_rules if event else []))
    _, matched_rule_items = partition_policy_keys(_string_list(guard_trace.get("matched_rules")))
    items.extend(matched_rule_items)
    rule_assessment = guard_trace.get("rule_assessment")
    if isinstance(rule_assessment, dict):
        _, assessed_items = partition_policy_keys(_string_list(rule_assessment.get("hit_rules")))
        items.extend(assessed_items)
    return _unique_strings(items)


def _guard_signals(guard_trace: dict[str, Any]) -> list[str]:
    rule_assessment = guard_trace.get("rule_assessment")
    if not isinstance(rule_assessment, dict):
        return []
    return _unique_strings(_string_list(rule_assessment.get("matched_signals")))


def _display_label(kind: str, value: str) -> str:
    if kind in {"control", "rule"}:
        return _policy_label(value)
    if kind == "signal":
        return _signal_label(value)
    return value


def _policy_label(value: str | None) -> str:
    key = str(value or "").strip()
    return display_policy_label(key) or "未命名项"


def _signal_label(value: str | None) -> str:
    signal = str(value or "").strip()
    return display_signal_label(signal) or "未记录"


def _location_label(value: str | None) -> str:
    location = str(value or "").strip()
    if not location or location == "content":
        return "正文"
    return (
        location.replace("params", "任务参数", 1)
        .replace("runtime", "运行时", 1)
        .replace("provider", "模型返回", 1)
        .replace("metadata", "元数据", 1)
        .replace("result", "处理结果", 1)
        .replace("raw_response", "原始响应", 1)
        .replace(".", " / ")
    )


def _guard_rule_text(guard_trace: dict[str, Any], key: str) -> str:
    rule_assessment = guard_trace.get("rule_assessment")
    if not isinstance(rule_assessment, dict):
        return ""
    return str(rule_assessment.get(key) or "").strip()


def _best_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _build_chinese_summary(
    *,
    report: Report,
    task: AttackTask,
    event: SecurityEvent | None,
    status_badge: dict[str, str],
    risk_badge: dict[str, str],
    review_badge: dict[str, str],
    payload_hits: list[dict[str, Any]],
    sensitive_hits: list[dict[str, Any]],
) -> str:
    task_name = str(task.task_name or f"任务 #{task.id}").strip()
    target_name = str(task.target_agent or "目标对象").strip()
    raw_text = _best_text(event.detail if event else "", task.result_summary, report.summary_text)

    parts = [
        f"任务“{task_name}”面向“{target_name}”执行后，综合判定为{status_badge['label']}，风险等级为{risk_badge['label']}。"
    ]

    outcome_text = _derive_execution_outcome(raw_text=raw_text, event=event, task=task)
    if outcome_text:
        parts.append(outcome_text)

    if payload_hits or sensitive_hits:
        parts.append(f"本次共识别 {len(payload_hits)} 项关键命中，并发现 {len(sensitive_hits)} 项敏感数据痕迹。")
    else:
        parts.append("当前未识别到额外的关键命中或敏感数据痕迹。")

    review_label = str(review_badge.get("label") or "").strip()
    if review_label and review_label not in {"未记录", "-"}:
        parts.append(f"AI 复核状态：{review_label}。")

    return "".join(parts)


def _derive_execution_outcome(*, raw_text: str, event: SecurityEvent | None, task: AttackTask) -> str:
    text = str(raw_text or "").strip()
    lowered = text.lower()

    if any(keyword in lowered for keyword in ("connection failed", "connection refused", "winerror 10061", "actively refused")):
        return "执行阶段出现上游连接失败，目标服务未成功建立连接或未返回有效结果。"
    if "timeout" in lowered or "timed out" in lowered:
        return "执行阶段出现超时，未在预期时间内取得目标响应。"
    if any(keyword in lowered for keyword in ("traceback", "exception", "provider error")):
        return "执行阶段出现运行异常，原始错误回传已保留在正文证据和附录中。"
    if task.status and str(task.status).strip().lower() in {"failed", "dead_letter"}:
        return "任务未正常完成，平台已保留执行上下文以便复盘和复测。"

    event_status = str(event.status if event else "").strip().lower()
    if event_status == "intercepted":
        return "防护链已在执行前或执行中完成拦截，当前不建议直接恢复放行。"
    if event_status == "suspicious":
        return "防护链未直接拦截，但已标记为可疑，建议进入人工复核。"
    if event_status == "allowed":
        return "当前请求已放行，但建议结合审计记录持续观察同源后续请求。"

    if text:
        return f"原始执行摘要显示：{_clip_text(text, 72)}"
    return "本次执行链已完成归档，可结合下方证据与附录继续复盘。"


def _clip_text(value: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}..."


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _unique_strings(items: list[str]) -> list[str]:
    unique: list[str] = []
    for item in items:
        normalized = str(item).strip()
        if normalized and normalized not in unique:
            unique.append(normalized)
    return unique


def _append_section(sections: list[dict[str, Any]], key: str, title: str, content: Any) -> None:
    if _is_empty_content(content):
        return
    sections.append(
        {
            "key": key,
            "title": title,
            "format": "json" if isinstance(content, (dict, list)) else "text",
            "content": content,
        }
    )


def _normalize_content(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return value

    text = value.strip()
    if not text:
        return ""
    if text.startswith("{") or text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, (dict, list)):
                return parsed
        except json.JSONDecodeError:
            return value
    return value


def _is_empty_content(value: Any) -> bool:
    return value in (None, "", [], {})


def _iter_text_nodes(value: Any, path: str = "") -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_path = f"{path}.{key}" if path else str(key)
            items.extend(_iter_text_nodes(item, next_path))
        return items

    if isinstance(value, list):
        for index, item in enumerate(value):
            next_path = f"{path}[{index}]"
            items.extend(_iter_text_nodes(item, next_path))
        return items

    if isinstance(value, str) and value.strip():
        items.append((path or "content", value))
    return items


def _build_snippet(text: str, pattern: str, radius: int = 48) -> str:
    lowered = text.lower()
    index = lowered.find(pattern)
    if index < 0:
        return text[: radius * 2].strip()

    start = max(index - radius, 0)
    end = min(index + len(pattern) + radius, len(text))
    snippet = text[start:end].strip()
    if start > 0:
        snippet = f"...{snippet}"
    if end < len(text):
        snippet = f"{snippet}..."
    return snippet


def _looks_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower()
    return any(token in normalized for token in ("password", "secret", "token", "api_key", "apikey", "authorization"))


def _mask_middle(value: str, visible_start: int = 4, visible_end: int = 2) -> str:
    text = value.strip()
    if not text:
        return ""
    if len(text) <= visible_start + visible_end + 1:
        return "***"
    return f"{text[:visible_start]}***{text[-visible_end:]}"


def _mask_email(value: str) -> str:
    local_part, _, domain = value.partition("@")
    local = local_part.strip()
    if not local:
        return f"***@{domain or '***'}"
    visible = local[:1] if len(local) <= 2 else local[:2]
    return f"{visible}***@{domain or '***'}"


def _mask_windows_path(value: str) -> str:
    normalized = value.replace("/", "\\")
    segments = [item for item in re.split(r"\\+", normalized) if item]
    tail = segments[-1] if segments else "***"
    if re.match(r"^[A-Za-z]:\\", normalized):
        return f"{normalized[:2]}\\...\\{tail}"
    return f"\\\\...\\{tail}"


def _mask_unix_path(value: str) -> str:
    segments = [item for item in value.split("/") if item]
    tail = segments[-1] if segments else "***"
    return f"/.../{tail}"


def _should_mask_unix_path(value: str) -> bool:
    return re.match(r"^/(?:api|@vite|src|assets|node_modules)\b", value, re.IGNORECASE) is None


def _humanize_code(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.replace("_", " ").replace("-", " ")


def _render_status_card(label: str, value: str, tone: str) -> str:
    return (
        '<div class="status-card">'
        f"<span>{escape(label)}</span>"
        f"<strong class=\"tone-{escape(tone)}\">{escape(value)}</strong>"
        "</div>"
    )


def _render_highlights(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">当前没有可展示的摘要指标。</p>'
    parts: list[str] = []
    for item in items:
        parts.append(
            f'<div class="trace-row tone-{escape(str(item.get("tone") or "info"))}">'
            '<div class="row-top">'
            f"<strong>{escape(str(item.get('label') or '-'))}</strong>"
            f'<span class="pill tone-{escape(str(item.get("tone") or "info"))}">{escape(str(item.get("value") or "-"))}</span>'
            "</div>"
            f'<div class="row-detail">{escape(str(item.get("detail") or "-"))}</div>'
            "</div>"
        )
    return "".join(parts)


def _render_kv_grid(items: list[tuple[str, Any]]) -> str:
    if not items:
        return '<p class="empty">当前没有对象信息。</p>'
    parts = ['<div class="kv-grid">']
    for label, value in items:
        parts.append(
            '<div class="kv-item">'
            f"<strong>{escape(str(label))}</strong>"
            f"<span>{escape(str(value or '-'))}</span>"
            "</div>"
        )
    parts.append("</div>")
    return "".join(parts)


def _render_trace_rows(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">当前没有执行链判断数据。</p>'
    parts: list[str] = []
    for item in items:
        parts.append(
            f'<div class="trace-row tone-{escape(str(item.get("tone") or "info"))}">'
            '<div class="row-top">'
            f"<strong>{escape(str(item.get('label') or '-'))}</strong>"
            f'<span class="pill tone-{escape(str(item.get("tone") or "info"))}">{escape(str(item.get("value") or "-"))}</span>'
            "</div>"
            f'<div class="row-detail">{escape(str(item.get("detail") or "-"))}</div>'
            "</div>"
        )
    return "".join(parts)


def _render_chip_list(items: list[str], empty_text: str) -> str:
    if not items:
        return f'<p class="empty">{escape(empty_text)}</p>'
    return "".join(f'<span class="chip">{escape(item)}</span>' for item in items)


def _render_payload_hits(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">当前没有可展示的关键命中项。</p>'
    parts: list[str] = []
    for item in items:
        tone = _payload_tone(str(item.get("kind") or "info"))
        category_chip = ""
        if item.get("category_label"):
            category_chip = f'<span class="chip">分类：{escape(str(item.get("category_label") or "-"))}</span>'
        parts.append(
            f'<div class="hit-row tone-{tone}">'
            '<div class="row-top">'
            f"<div><strong>{escape(str(item.get('display_label') or item.get('label') or '-'))}</strong>"
            f"<span>{escape(str(item.get('source_label') or item.get('source') or '-'))}</span></div>"
            f'<span class="pill tone-{tone}">{escape(str(item.get("kind") or "-"))}</span>'
            "</div>"
            f'<div class="row-detail">{escape(str(item.get("detail_label") or item.get("detail") or "-"))}</div>'
            '<div class="row-meta">'
            f'<span class="chip">位置：{escape(str(item.get("location_label") or "正文"))}</span>'
            f'<span class="chip">来源：{escape(str(item.get("source_label") or item.get("source") or "-"))}</span>'
            f"{category_chip}"
            "</div>"
            f"{_render_optional_code_block(str(item.get('evidence') or ''))}"
            "</div>"
        )
    return "".join(parts)


def _render_sensitive_hits(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">当前没有识别到敏感数据痕迹。</p>'
    parts: list[str] = []
    for item in items:
        parts.append(
            '<div class="sensitive-row tone-warn">'
            '<div class="row-top">'
            f"<strong>{escape(str(item.get('label') or '-'))}</strong>"
            f'<span>{escape(str(item.get("source") or "-"))}</span>'
            "</div>"
            f'<div class="row-meta"><span class="chip">位置：{escape(str(item.get("location_label") or "正文"))}</span></div>'
            f"<pre>{escape(str(item.get('preview') or '-'))}</pre>"
            "</div>"
        )
    return "".join(parts)


def _render_timeline(items: list[dict[str, str]]) -> str:
    if not items:
        return '<p class="empty">当前没有时间线数据。</p>'
    parts: list[str] = []
    for item in items:
        parts.append(
            '<div class="timeline-item">'
            f"<strong>{escape(str(item.get('label') or '-'))}</strong>"
            f"<span>{escape(str(item.get('value') or '-'))}</span>"
            f"<span>{escape(str(item.get('detail') or '-'))}</span>"
            "</div>"
        )
    return "".join(parts)


def _render_recommendations(items: list[dict[str, str]]) -> str:
    if not items:
        return '<p class="empty">当前没有处置建议。</p>'
    parts: list[str] = []
    for item in items:
        tone = str(item.get("tone") or "info")
        parts.append(
            f'<div class="recommend-row tone-{escape(tone)}">'
            '<div class="row-top">'
            f"<strong>{escape(str(item.get('title') or '-'))}</strong>"
            f'<span class="pill tone-{escape(tone)}">{escape(str(item.get("title") or "-"))}</span>'
            "</div>"
            f'<div class="row-detail">{escape(str(item.get("detail") or "-"))}</div>'
            "</div>"
        )
    return "".join(parts)


def _render_appendix_sections(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">当前没有附录数据。</p>'
    parts: list[str] = []
    for item in items:
        content = item.get("content")
        parts.append(
            "<details>"
            f"<summary>{escape(str(item.get('title') or '-'))}</summary>"
            '<div class="details-body">'
            f"{_render_block_value(content)}"
            "</div>"
            "</details>"
        )
    return "".join(parts)


def _render_optional_code_block(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    return f"<pre>{escape(text)}</pre>"


def _render_block_value(value: Any) -> str:
    if value in (None, "", [], {}):
        return '<p class="empty">没有可展示的数据。</p>'
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            value = parsed
        except json.JSONDecodeError:
            return f"<pre>{escape(value)}</pre>"
    return f"<pre>{escape(json.dumps(value, ensure_ascii=False, indent=2))}</pre>"


def _payload_tone(kind: str) -> str:
    if kind == "control":
        return "safe"
    if kind == "rule":
        return "warn"
    if kind == "signal":
        return "danger"
    return "info"
