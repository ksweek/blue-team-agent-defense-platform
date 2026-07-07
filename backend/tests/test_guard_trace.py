from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.tests._test_env import configure_test_environment

configure_test_environment()

from app.models import AttackTask
from app.services.guard_trace import build_task_guard_trace


def test_build_task_guard_trace_exposes_ai_review_fields():
    task = AttackTask(
        task_name="review-check",
        attack_type="prompt_injection",
        target_agent="openclaw",
        params_json=json.dumps({}),
        raw_response=json.dumps(
            {
                "ai_review_mode": "review_all_remaining",
                "ai_review_invoked": True,
                "review_decision": "review_all_remaining",
                "authorization": {
                    "decision": "review",
                    "summary": "Rule engine requested review.",
                    "detail": "Potential prompt injection.",
                    "matched_controls": ["prompt_injection_firewall"],
                    "matched_rules": ["intent-scan"],
                },
                "rule_assessment": {
                    "verdict": "suspicious",
                    "summary": "Suspicious payload.",
                    "detail": "Suspicious payload detail.",
                    "hit_rules": ["intent-scan"],
                    "matched_signals": ["prompt_injection_surface"],
                },
                "ai_review": {
                    "invoked": True,
                    "status": "completed",
                    "decision_reason": "review_all_remaining",
                    "adjustments": [
                        "review_cannot_downgrade_status:allowed->intercepted",
                        "review_cannot_downgrade_level:low->high",
                    ],
                    "error": "",
                    "result": {
                        "event_status": "allowed",
                        "event_level": "low",
                        "hit_rules": ["intent-scan", "output-sanitize"],
                    },
                },
            }
        ),
    )

    trace = build_task_guard_trace(task)

    assert trace is not None
    assert trace["ai_review_status"] == "completed"
    assert trace["ai_review_adjustments"] == [
        "review_cannot_downgrade_status:allowed->intercepted",
        "review_cannot_downgrade_level:low->high",
    ]
    assert trace["ai_review_error"] == ""
    assert trace["ai_review_result_status"] == "allowed"
    assert trace["ai_review_result_level"] == "low"
    assert trace["ai_review_result_rules"] == ["intent-scan", "output-sanitize"]


def test_build_task_guard_trace_keeps_ai_review_fallback_without_authorization():
    task = AttackTask(
        task_name="review-fallback",
        attack_type="runtime_execution",
        target_agent="openclaw",
        params_json=json.dumps({}),
        raw_response=json.dumps(
            {
                "ai_review_mode": "review_all_remaining",
                "ai_review_invoked": True,
                "review_decision": "review_all_remaining",
                "ai_review": {
                    "invoked": True,
                    "status": "fallback_to_rules",
                    "adjustments": [],
                    "error": "reviewer timeout",
                    "result": {
                        "event_status": "suspicious",
                        "event_level": "medium",
                        "hit_rules": ["manual_review"],
                    },
                },
            }
        ),
    )

    trace = build_task_guard_trace(task)

    assert trace is not None
    assert trace["ai_review_status"] == "fallback_to_rules"
    assert trace["ai_review_error"] == "reviewer timeout"
    assert trace["ai_review_result_status"] == "suspicious"


if __name__ == "__main__":
    from backend.tests.run_backend_tests_cn import main as run_cn_tests

    raise SystemExit(run_cn_tests([str(Path(__file__).resolve())]))
