from __future__ import annotations

import json
from typing import Any

from ..models import AttackTask


def build_task_guard_trace(task: AttackTask | None) -> dict[str, Any] | None:
    if task is None:
        return None

    params = task.params if isinstance(task.params, dict) else {}
    runtime = params.get("runtime")
    runtime_state = runtime if isinstance(runtime, dict) else {}
    last_authorization = runtime_state.get("last_authorization")
    last_snapshot = last_authorization if isinstance(last_authorization, dict) else {}
    last_result = last_snapshot.get("result")
    snapshot_result = last_result if isinstance(last_result, dict) else {}

    payload = _parse_payload(task.raw_response)
    authorization = _first_dict(payload.get("authorization"), payload.get("preflight_authorization"))
    if not authorization:
        authorization = snapshot_result

    rule_assessment = _first_dict(
        payload.get("rule_assessment"),
        authorization.get("task_rule_assessment") if authorization else None,
        snapshot_result.get("task_rule_assessment") if snapshot_result else None,
    )

    if not authorization and not rule_assessment:
        return None

    matched_controls = _normalize_string_list(authorization.get("matched_controls") if authorization else [])
    matched_rules = _normalize_string_list(
        authorization.get("matched_rules") if authorization else rule_assessment.get("hit_rules") if rule_assessment else []
    )
    reused = bool(
        authorization
        and snapshot_result
        and payload.get("authorization")
        and _same_authorization_decision(authorization, snapshot_result)
    )

    if payload.get("preflight_authorization"):
        source = "worker_preflight_blocked"
    elif reused:
        source = "worker_preflight_reused"
    elif snapshot_result and not payload.get("authorization"):
        source = "runtime_authorization_snapshot"
    elif payload.get("authorization"):
        source = "task_runner_evaluated"
    else:
        source = "raw_response_embedded"

    summary = str((authorization or {}).get("summary") or (rule_assessment or {}).get("summary") or "").strip()
    detail = str((authorization or {}).get("detail") or (rule_assessment or {}).get("detail") or "").strip()
    decision = str((authorization or {}).get("decision") or "").strip().lower()
    rule_verdict = str((rule_assessment or {}).get("verdict") or "").strip().lower()

    return {
        "decision": decision,
        "summary": summary,
        "detail": detail,
        "matched_controls": matched_controls,
        "matched_rules": matched_rules,
        "source": source,
        "reused": reused,
        "ai_review_mode": str(payload.get("ai_review_mode") or "").strip(),
        "ai_review_invoked": bool(payload.get("ai_review_invoked", False)),
        "review_decision": str(payload.get("review_decision") or "").strip(),
        "rule_verdict": rule_verdict,
        "rule_assessment": {
            "verdict": rule_verdict,
            "summary": summary_text(rule_assessment, "summary"),
            "detail": summary_text(rule_assessment, "detail"),
            "hit_rules": _normalize_string_list((rule_assessment or {}).get("hit_rules") if rule_assessment else []),
            "matched_signals": _normalize_string_list(
                (rule_assessment or {}).get("matched_signals") if rule_assessment else []
            ),
        }
        if rule_assessment
        else None,
    }


def summary_text(payload: dict[str, Any] | None, key: str) -> str:
    return str((payload or {}).get(key) or "").strip()


def _parse_payload(raw_response: str | None) -> dict[str, Any]:
    if not raw_response:
        return {}

    try:
        payload = json.loads(raw_response)
    except json.JSONDecodeError:
        return {}

    if not isinstance(payload, dict):
        return {}
    return payload


def _first_dict(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, dict):
            return dict(value)
    return {}


def _normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def _same_authorization_decision(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        str(left.get("decision") or "").strip().lower() == str(right.get("decision") or "").strip().lower()
        and _normalize_string_list(left.get("matched_controls")) == _normalize_string_list(right.get("matched_controls"))
        and _normalize_string_list(left.get("matched_rules")) == _normalize_string_list(right.get("matched_rules"))
    )
