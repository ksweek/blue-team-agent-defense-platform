from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from ..models import AttackTask, Report, SecurityEvent
from .attack_patterns import collect_detection_hits
from .guard_trace import build_task_guard_trace
from .report_export import build_report_artifact_payload, resolve_report_path
from .security_taxonomy import (
    build_policy_reference,
    build_policy_reference_auto,
    build_signal_reference,
    partition_policy_keys,
)

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


def build_security_event_report_view(
    db: Session,
    *,
    event: SecurityEvent,
    task: AttackTask | None = None,
    report: Report | None = None,
) -> dict[str, Any]:
    task = task or _resolve_task(db, event)
    report = report or _resolve_report(db, task)
    guard_trace = build_task_guard_trace(task)
    report_artifact = _load_report_artifact(report=report, task=task, event=event)
    raw_sections = _build_raw_sections(event=event, task=task, report_artifact=report_artifact)

    return {
        "payload_detection": _build_payload_detection(
            event=event,
            task=task,
            guard_trace=guard_trace,
            raw_sections=raw_sections,
        ),
        "sensitive_findings": _build_sensitive_findings(raw_sections),
        "raw_sections": raw_sections,
    }


def _resolve_task(db: Session, event: SecurityEvent) -> AttackTask | None:
    if not event.task_id:
        return None
    return db.get(AttackTask, event.task_id)


def _resolve_report(db: Session, task: AttackTask | None) -> Report | None:
    if task is None:
        return None

    if task.latest_report_id:
        item = db.get(Report, task.latest_report_id)
        if item is not None:
            return item

    return (
        db.query(Report)
        .filter(Report.task_id == task.id)
        .order_by(Report.created_at.desc(), Report.id.desc())
        .first()
    )


def _load_report_artifact(
    *,
    report: Report | None,
    task: AttackTask | None,
    event: SecurityEvent,
) -> dict[str, Any] | None:
    if report is None or task is None:
        return None

    if report.file_path:
        artifact_path = resolve_report_path(report.file_path)
        if artifact_path.exists():
            try:
                payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    return payload
            except (OSError, json.JSONDecodeError):
                pass

    try:
        return build_report_artifact_payload(report=report, task=task, event=event)
    except ValueError:
        return None


def _build_raw_sections(
    *,
    event: SecurityEvent,
    task: AttackTask | None,
    report_artifact: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []

    _append_section(sections, "event_raw_input", "事件原始输入", _normalize_content(event.raw_input))
    _append_section(sections, "event_result", "事件处理结果", _normalize_content(event.result))

    if task is not None:
        _append_section(sections, "task_params", "任务传递参数", task.params)
        task_raw_response = _normalize_content(task.raw_response)
        _append_section(sections, "task_raw_response", "执行原始响应", task_raw_response)

        if isinstance(task_raw_response, dict):
            skill_scan = task_raw_response.get("skill_scan")
            if isinstance(skill_scan, dict):
                _append_section(
                    sections,
                    "skill_scan_result",
                    "Skill 扫描结果",
                    skill_scan,
                )
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

    _append_section(sections, "report_artifact", "归档安全报告", report_artifact)
    return sections


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


def _build_payload_detection(
    *,
    event: SecurityEvent,
    task: AttackTask | None,
    guard_trace: dict[str, Any] | None,
    raw_sections: list[dict[str, Any]],
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []

    hit_rule_controls, hit_rule_rules = partition_policy_keys(_normalize_string_list(event.hit_rules))
    matched_rule_controls, matched_rule_rules = partition_policy_keys(
        _normalize_string_list((guard_trace or {}).get("matched_rules"))
    )
    matched_controls = _unique_strings(
        _normalize_string_list((guard_trace or {}).get("matched_controls")) + hit_rule_controls + matched_rule_controls
    )
    matched_rules = _unique_strings(hit_rule_rules + matched_rule_rules)

    rule_assessment = (guard_trace or {}).get("rule_assessment")
    rule_assessment_dict = rule_assessment if isinstance(rule_assessment, dict) else {}
    matched_signals = _normalize_string_list(rule_assessment_dict.get("matched_signals"))
    assessed_controls, assessed_rules = partition_policy_keys(_normalize_string_list(rule_assessment_dict.get("hit_rules")))
    matched_controls = _unique_strings(matched_controls + assessed_controls)
    matched_rules = _unique_strings(matched_rules + assessed_rules)

    for item in matched_controls:
        reference = build_policy_reference(item, kind="control")
        items.append(
            {
                "kind": "control",
                "label": item,
                "display_label": reference["label"],
                "detail": "授权链路命中的控制面",
                "detail_label": reference["detail"] or "授权链路命中的控制面",
                "category_key": reference["category_key"],
                "category_label": reference["category_label"],
                "tone": reference["tone"],
                "source": "授权链路",
                "source_label": "授权链路",
                "location": "",
                "location_label": "",
                "evidence": "",
            }
        )

    for item in matched_rules:
        reference = build_policy_reference_auto(item)
        items.append(
            {
                "kind": "rule",
                "label": item,
                "display_label": reference["label"],
                "detail": "事件或评估命中的规则",
                "detail_label": reference["detail"] or "事件或评估命中的规则",
                "category_key": reference["category_key"],
                "category_label": reference["category_label"],
                "tone": reference["tone"],
                "source": "规则命中",
                "source_label": "规则命中",
                "location": "",
                "location_label": "",
                "evidence": "",
            }
        )

    for item in matched_signals:
        reference = build_signal_reference(item)
        items.append(
            {
                "kind": "signal",
                "label": item,
                "display_label": reference["label"],
                "detail": "规则引擎识别出的攻击信号",
                "detail_label": reference["detail"] or "规则引擎识别出的攻击信号",
                "tone": reference["tone"],
                "source": "Payload 识别",
                "source_label": "攻击信号",
                "location": "",
                "location_label": "",
                "evidence": "",
            }
        )

    items.extend(_scan_payload_patterns(raw_sections))

    summary_segments = [
        f"控制面 {len(matched_controls)} 项",
        f"规则 {len(matched_rules)} 项",
        f"信号 {len(matched_signals)} 项",
        f"内容特征 {sum(1 for item in items if item['kind'] == 'pattern')} 项",
    ]
    if task is not None and (guard_trace or {}).get("decision"):
        summary_segments.append(f"最终判定 {str((guard_trace or {}).get('decision') or '').upper()}")

    return {
        "summary_text": "，".join(summary_segments),
        "total": len(items),
        "items": items,
    }


def _scan_payload_patterns(raw_sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    scan_section_keys = {"event_raw_input", "task_params", "provider_output_text"}

    for section in raw_sections:
        if section["key"] not in scan_section_keys:
            continue
        for location, text in _iter_text_nodes(section["content"]):
            for hit in collect_detection_hits(text):
                mapped_rule = build_policy_reference_auto(hit.rule_key)
                key = (section["key"], hit.pattern, hit.rule_key)
                if key in seen:
                    continue

                seen.add(key)
                items.append(
                    {
                        "kind": "pattern",
                        "label": hit.pattern,
                        "display_label": hit.pattern,
                        "detail": f"{hit.severity} 特征，映射规则 {hit.rule_key}，命中视图 {hit.view}",
                        "detail_label": f"{'强攻击' if hit.severity == 'strong' else '可疑'}特征，对应规则：{mapped_rule['label']}，命中视图：{hit.view}",
                        "mapped_rule_key": hit.rule_key,
                        "mapped_rule_label": mapped_rule["label"],
                        "category_key": mapped_rule["category_key"],
                        "category_label": mapped_rule["category_label"],
                        "tone": "danger" if hit.severity == "strong" else "warn",
                        "source": section["title"],
                        "source_label": section["title"],
                        "location": location,
                        "location_label": _location_label(location),
                        "evidence": hit.snippet or _build_snippet(text, hit.pattern.strip().lower()),
                    }
                )

    return items


def _build_sensitive_findings(raw_sections: list[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add_item(category: str, source: str, location: str, preview: str) -> None:
        normalized_preview = preview.strip()
        if not normalized_preview:
            return
        key = (category, source, location, normalized_preview)
        if key in seen:
            return
        seen.add(key)
        items.append(
            {
                "category": category,
                "label": SENSITIVE_CATEGORY_LABELS.get(category, category),
                "source": source,
                "location": location,
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

    counter = Counter(item["category"] for item in items)
    categories = [
        {
            "category": category,
            "label": SENSITIVE_CATEGORY_LABELS.get(category, category),
            "count": count,
        }
        for category, count in counter.most_common()
    ]

    summary_text = f"检测到 {len(items)} 处敏感数据痕迹"
    if categories:
        summary_text = f"{summary_text}，覆盖 {len(categories)} 类"

    return {
        "summary_text": summary_text,
        "total": len(items),
        "categories": categories,
        "items": items,
    }


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


def _normalize_string_list(value: Any) -> list[str]:
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


def _location_label(value: str | None) -> str:
    location = str(value or "").strip()
    if not location or location == "content":
        return "正文"

    labels = {
        "params": "任务参数",
        "runtime": "运行时",
        "provider": "模型返回",
        "metadata": "元数据",
        "result": "处理结果",
        "raw_response": "原始响应",
        "content": "正文",
    }

    parts = [item for item in location.replace("[", ".[").split(".") if item]
    return " / ".join(labels.get(part, part) for part in parts)


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
