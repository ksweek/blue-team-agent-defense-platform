import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import asyncio
from pathlib import Path
from typing import Optional
from zipfile import ZipFile

try:
    import websockets
except Exception:
    websockets = None


BASE_BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
FRONTEND_CANDIDATES = [
    value
    for value in [
        os.getenv("FRONTEND_URL"),
        "http://127.0.0.1:5173",
        "http://127.0.0.1:4173",
    ]
    if value
]


def _build_request(method: str, url: str, payload=None, token: Optional[str] = None, headers: Optional[dict[str, str]] = None):
    data = None
    request_headers: dict[str, str] = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if token:
        request_headers["Authorization"] = f"Bearer {token}"

    return urllib.request.Request(url, data=data, headers=request_headers, method=method)


def request(method: str, url: str, payload=None, token: Optional[str] = None, headers: Optional[dict[str, str]] = None):
    req = _build_request(method, url, payload=payload, token=token, headers=headers)
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode("utf-8")
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return resp.status, json.loads(body)
        return resp.status, body


def request_bytes(
    method: str,
    url: str,
    payload=None,
    token: Optional[str] = None,
    headers: Optional[dict[str, str]] = None,
):
    req = _build_request(method, url, payload=payload, token=token, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read(), {key.lower(): value for key, value in resp.headers.items()}


def assert_ok(name: str, condition: bool, detail: str):
    safe_detail = _safe_console_text(detail)
    if condition:
        print(f"[PASS] {name}: {safe_detail}")
        return
    print(f"[FAIL] {name}: {safe_detail}")
    raise SystemExit(1)


def _safe_console_text(value: str) -> str:
    encoding = sys.stdout.encoding or "utf-8"
    return value.encode(encoding, errors="backslashreplace").decode(encoding, errors="ignore")


def resolve_frontend_base() -> Optional[str]:
    for base_url in FRONTEND_CANDIDATES:
        try:
            request("GET", f"{base_url}/")
            return base_url
        except Exception:
            continue
    return None


def resolve_provider_execution_readiness(token: str) -> tuple[bool, str]:
    try:
        status, endpoints_payload = request("GET", f"{BASE_BACKEND}/api/ai-endpoints?page_size=20", token=token)
        if status != 200:
            return False, f"list ai endpoints failed: status={status}"
        items = list((endpoints_payload.get("data") or {}).get("items") or [])
        enabled_items = [item for item in items if bool(item.get("enabled"))]
        if not enabled_items:
            return False, "no enabled ai endpoint is available for provider-backed smoke checks"
        candidate = next((item for item in enabled_items if bool(item.get("is_default"))), enabled_items[0])
        endpoint_id = candidate.get("id")
        if not endpoint_id:
            return False, "no testable ai endpoint id was returned by the list route"
        try:
            status, test_payload = request(
                "POST",
                f"{BASE_BACKEND}/api/ai-endpoints/{endpoint_id}/test",
                {},
                token,
            )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            return False, f"endpoint #{endpoint_id} provider test failed: status={exc.code} body={body[:240]}"
        if status != 200:
            return False, f"endpoint #{endpoint_id} provider test returned unexpected status={status}"
        data = test_payload.get("data") if isinstance(test_payload, dict) else None
        model = ""
        if isinstance(data, dict):
            model = str(data.get("model") or "")
        return True, f"endpoint #{endpoint_id} provider test passed{f' model={model}' if model else ''}"
    except Exception as exc:
        return False, f"provider readiness probe failed: {exc}"


def _setting_value(items: list[dict], setting_key: str, default: str = "") -> str:
    for item in items:
        if str(item.get("setting_key") or "").strip() == setting_key:
            return str(item.get("setting_value") or "").strip()
    return default


def wait_for_task_terminal_state(
    task_id: int,
    token: str,
    timeout_seconds: int = 45,
    terminal_states: Optional[set[str]] = None,
):
    deadline = time.time() + timeout_seconds
    last_payload = None
    accepted_states = terminal_states or {"done", "failed", "dead_letter", "cancelled"}
    while time.time() < deadline:
        status, task_payload = request("GET", f"{BASE_BACKEND}/api/attack-tasks/{task_id}", token=token)
        if status == 200:
            last_payload = task_payload["data"]
            if last_payload["status"] in accepted_states:
                return last_payload
        time.sleep(1)

    raise RuntimeError(f"task {task_id} did not reach terminal state: {json.dumps(last_payload, ensure_ascii=False)}")


def backend_ws_base() -> str:
    if BASE_BACKEND.startswith("https://"):
        return "wss://" + BASE_BACKEND[len("https://") :]
    if BASE_BACKEND.startswith("http://"):
        return "ws://" + BASE_BACKEND[len("http://") :]
    return BASE_BACKEND


async def websocket_gateway_smoke(token: str) -> dict[str, list[str]]:
    if websockets is None:
        raise RuntimeError("websockets client library is unavailable")

    headers = [("Authorization", f"Bearer {token}")]
    ws_base = f"{backend_ws_base()}/gateway/v1/ws"

    results: dict[str, list[str]] = {}

    async with websockets.connect(f"{ws_base}/chat/completions", extra_headers=headers) as ws:
        await ws.send(json.dumps({"model": "smoke-model", "messages": [{"role": "user", "content": "ws chat smoke"}], "stream": True}))
        events: list[str] = []
        while True:
            try:
                raw_message = await ws.recv()
            except websockets.ConnectionClosed:
                break
            message = json.loads(raw_message)
            event = str(message.get("event") or "")
            events.append(event or "unknown")
            if event in {"done", "error"}:
                break
        results["chat"] = events

    async with websockets.connect(f"{ws_base}/responses", extra_headers=headers) as ws:
        await ws.send(json.dumps({"model": "smoke-model", "input": "ws responses smoke", "stream": True}))
        events = []
        while True:
            try:
                raw_message = await ws.recv()
            except websockets.ConnectionClosed:
                break
            message = json.loads(raw_message)
            event = str(message.get("event") or "")
            events.append(event or "unknown")
            if event in {"done", "error"}:
                break
        results["responses"] = events

    async with websockets.connect(f"{ws_base}/agents/run", extra_headers=headers) as ws:
        await ws.send(json.dumps({"model": "smoke-model", "input_text": "ws agent smoke", "stream": True}))
        events = []
        while True:
            try:
                raw_message = await ws.recv()
            except websockets.ConnectionClosed:
                break
            message = json.loads(raw_message)
            event = str(message.get("event") or "")
            events.append(event or "unknown")
            if event in {"done", "error"}:
                break
        results["agent"] = events

    return results


def main():
    status, health = request("GET", f"{BASE_BACKEND}/health")
    assert_ok("health", status == 200 and health.get("status") == "ok", json.dumps(health, ensure_ascii=False))
    skip_provider_checks = os.getenv("SMOKE_SKIP_PROVIDER", "").strip().lower() in {"1", "true", "yes"}
    ai_provider_ready = (
        (not skip_provider_checks)
        and health.get("ai_provider") != "disabled"
        and health.get("ai_configured") == "true"
    )
    provider_execution_ready = False
    provider_skip_reason = "provider checks disabled by SMOKE_SKIP_PROVIDER" if skip_provider_checks else "ai provider not ready"
    assert_ok(
        "provider-mode",
        True,
        f"provider={health.get('ai_provider')} configured={health.get('ai_configured')}",
    )

    status, admin_login = request(
        "POST",
        f"{BASE_BACKEND}/api/auth/login",
        {"username": "admin", "password": "admin123"},
    )
    admin_token = admin_login["data"]["access_token"]
    assert_ok("admin-login", status == 200 and bool(admin_token), admin_login["data"]["user"]["username"])

    status, me = request("GET", f"{BASE_BACKEND}/api/auth/me", token=admin_token)
    assert_ok("auth-me", status == 200 and "admin" in me["data"]["roles"], ",".join(me["data"]["roles"]))

    if ai_provider_ready:
        provider_execution_ready, provider_skip_reason = resolve_provider_execution_readiness(admin_token)
        if provider_execution_ready:
            print(f"[PASS] provider-connectivity: {_safe_console_text(provider_skip_reason)}")
        else:
            print(f"[SKIP] provider-dependent-checks: {_safe_console_text(provider_skip_reason)}")

    if provider_execution_ready and websockets is not None:
        websocket_results = asyncio.run(websocket_gateway_smoke(admin_token))
        assert_ok(
            "gateway-websocket-chat",
            websocket_results["chat"][-2:] == ["chat.completion.completed", "done"],
            json.dumps(websocket_results["chat"], ensure_ascii=False),
        )
        assert_ok(
            "gateway-websocket-responses",
            websocket_results["responses"][-2:] == ["response.completed", "done"],
            json.dumps(websocket_results["responses"], ensure_ascii=False),
        )
        assert_ok(
            "gateway-websocket-agent",
            websocket_results["agent"][-2:] == ["agent.run.completed", "done"],
            json.dumps(websocket_results["agent"], ensure_ascii=False),
        )
    elif provider_execution_ready:
        print("[SKIP] gateway-websocket-checks: websockets client library unavailable")
    else:
        print(f"[SKIP] gateway-websocket-checks: {_safe_console_text(provider_skip_reason)}")

    status, users_before = request("GET", f"{BASE_BACKEND}/api/users?page_size=20", token=admin_token)
    assert_ok(
        "users-list",
        status == 200 and users_before["data"]["total"] >= 2,
        json.dumps(users_before["data"], ensure_ascii=False),
    )

    temp_username = f"smoke-user-{int(time.time())}"
    status, created_user = request(
        "POST",
        f"{BASE_BACKEND}/api/users",
        {
            "username": temp_username,
            "real_name": "Smoke User",
            "email": f"{temp_username}@example.com",
            "password": "SmokePass123",
            "roles": ["analyst"],
            "status": "active",
        },
        admin_token,
    )
    temp_user_id = created_user["data"]["id"]
    assert_ok(
        "users-create",
        status == 200 and created_user["data"]["username"] == temp_username,
        json.dumps(created_user["data"], ensure_ascii=False),
    )

    status, updated_user = request(
        "PUT",
        f"{BASE_BACKEND}/api/users/{temp_user_id}",
        {
            "real_name": "Smoke User Updated",
            "email": f"{temp_username}.updated@example.com",
        },
        admin_token,
    )
    assert_ok(
        "users-update",
        status == 200 and updated_user["data"]["real_name"] == "Smoke User Updated",
        json.dumps(updated_user["data"], ensure_ascii=False),
    )

    status, role_updated_user = request(
        "POST",
        f"{BASE_BACKEND}/api/users/{temp_user_id}/roles",
        {
            "roles": ["admin", "analyst"],
        },
        admin_token,
    )
    assert_ok(
        "users-set-roles",
        status == 200 and "admin" in role_updated_user["data"]["roles"],
        json.dumps(role_updated_user["data"], ensure_ascii=False),
    )

    status, reset_user = request(
        "POST",
        f"{BASE_BACKEND}/api/users/{temp_user_id}/reset-password",
        {
            "new_password": "SmokePass456",
        },
        admin_token,
    )
    assert_ok(
        "users-reset-password",
        status == 200 and reset_user["data"]["id"] == temp_user_id,
        json.dumps(reset_user["data"], ensure_ascii=False),
    )

    status, temp_user_login = request(
        "POST",
        f"{BASE_BACKEND}/api/auth/login",
        {"username": temp_username, "password": "SmokePass456"},
    )
    assert_ok(
        "users-login-reset-password",
        status == 200 and temp_user_login["data"]["user"]["username"] == temp_username,
        json.dumps(temp_user_login["data"], ensure_ascii=False),
    )

    status, disabled_user = request(
        "POST",
        f"{BASE_BACKEND}/api/users/{temp_user_id}/status",
        {
            "status": "disabled",
        },
        admin_token,
    )
    assert_ok(
        "users-disable",
        status == 200 and disabled_user["data"]["status"] == "disabled",
        json.dumps(disabled_user["data"], ensure_ascii=False),
    )

    try:
        request(
            "POST",
            f"{BASE_BACKEND}/api/auth/login",
            {"username": temp_username, "password": "SmokePass456"},
        )
        assert_ok("users-disabled-login", False, "disabled user unexpectedly logged in")
    except urllib.error.HTTPError as exc:
        assert_ok("users-disabled-login", exc.code == 403, f"status={exc.code}")

    request(
        "POST",
        f"{BASE_BACKEND}/api/users/{temp_user_id}/status",
        {"status": "active"},
        admin_token,
    )

    if provider_execution_ready:
        status, gateway_chat_stream_bytes, gateway_chat_stream_headers = request_bytes(
            "POST",
            f"{BASE_BACKEND}/gateway/v1/chat/completions",
            {
                "model": "smoke-model",
                "messages": [{"role": "user", "content": "gateway stream smoke"}],
                "stream": True,
            },
            admin_token,
        )
        gateway_chat_stream_text = gateway_chat_stream_bytes.decode("utf-8")
        assert_ok(
            "gateway-chat-stream",
            status == 200
            and gateway_chat_stream_headers.get("content-type", "").startswith("text/event-stream")
            and "data: " in gateway_chat_stream_text
            and "Mock provider completed review." in gateway_chat_stream_text
            and "[DONE]" in gateway_chat_stream_text,
            gateway_chat_stream_text,
        )

        status, gateway_responses_stream_bytes, gateway_responses_stream_headers = request_bytes(
            "POST",
            f"{BASE_BACKEND}/gateway/v1/responses",
            {
                "model": "smoke-model",
                "input": "gateway responses stream smoke",
                "stream": True,
            },
            admin_token,
        )
        gateway_responses_stream_text = gateway_responses_stream_bytes.decode("utf-8")
        assert_ok(
            "gateway-responses-stream",
            status == 200
            and gateway_responses_stream_headers.get("content-type", "").startswith("text/event-stream")
            and "event: response.created" in gateway_responses_stream_text
            and "event: response.completed" in gateway_responses_stream_text
            and "[DONE]" in gateway_responses_stream_text,
            gateway_responses_stream_text,
        )

        status, gateway_agent_stream_bytes, gateway_agent_stream_headers = request_bytes(
            "POST",
            f"{BASE_BACKEND}/gateway/v1/agents/run",
            {
                "model": "smoke-model",
                "input_text": "gateway agent stream smoke",
                "stream": True,
            },
            admin_token,
        )
        gateway_agent_stream_text = gateway_agent_stream_bytes.decode("utf-8")
        assert_ok(
            "gateway-agent-stream",
            status == 200
            and gateway_agent_stream_headers.get("content-type", "").startswith("text/event-stream")
            and "event: agent.run.started" in gateway_agent_stream_text
            and "event: agent.run.completed" in gateway_agent_stream_text
            and "[DONE]" in gateway_agent_stream_text,
            gateway_agent_stream_text,
        )
    else:
        print(f"[SKIP] gateway-stream-checks: {_safe_console_text(provider_skip_reason)}")

    status, sample_summary = request("GET", f"{BASE_BACKEND}/api/samples/summary", token=admin_token)
    assert_ok(
        "samples-summary",
        status == 200 and sample_summary["data"]["total_entries"] >= 1,
        json.dumps(sample_summary["data"], ensure_ascii=False),
    )

    status, sample_sections = request("GET", f"{BASE_BACKEND}/api/samples/sections", token=admin_token)
    assert_ok(
        "samples-sections",
        status == 200 and len(sample_sections["data"]["items"]) >= 1,
        json.dumps(sample_sections["data"]["items"][:2], ensure_ascii=False),
    )

    status, sample_list = request("GET", f"{BASE_BACKEND}/api/samples?page_size=2", token=admin_token)
    sample_items = sample_list["data"]["items"]
    sample_item = sample_items[0]
    assert_ok(
        "samples-list",
        status == 200 and bool(sample_item["id"]) and sample_item["turn_count"] >= 1,
        json.dumps(sample_item, ensure_ascii=False),
    )

    batch_sample_ids = [sample_item["id"]]
    batch_sample_ids.append(sample_items[1]["id"] if len(sample_items) > 1 else sample_item["id"])
    status, batch_tasks = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/batch-from-samples",
        {
            "sample_ids": batch_sample_ids,
            "target_agent": "smoke-agent",
            "params_json": {"batch_label": "smoke-batch"},
            "auto_run": False,
        },
        admin_token,
    )
    assert_ok(
        "task-batch-from-samples",
        status == 200
        and batch_tasks["data"]["created"] == len(batch_sample_ids)
        and len(batch_tasks["data"]["items"]) == len(batch_sample_ids)
        and all(item["source_type"] == "dataset_sample" for item in batch_tasks["data"]["items"])
        and all(item["params_json"].get("batch_label") == "smoke-batch" for item in batch_tasks["data"]["items"]),
        json.dumps(batch_tasks["data"], ensure_ascii=False),
    )

    status, task_from_sample = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/from-sample",
        {
            "sample_id": sample_item["id"],
            "target_agent": "smoke-agent",
            "auto_run": False,
        },
        admin_token,
    )
    sample_task = task_from_sample["data"]["task"]
    assert_ok(
        "task-from-sample",
        status == 200 and sample_task["status"] == "ready" and sample_task["source_type"] == "dataset_sample",
        json.dumps(sample_task, ensure_ascii=False),
    )

    status, paused_ready_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/pause",
        token=admin_token,
    )
    assert_ok(
        "task-pause-ready",
        status == 200 and paused_ready_task["data"]["task"]["status"] == "paused_ready",
        json.dumps(paused_ready_task["data"], ensure_ascii=False),
    )

    status, resumed_ready_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/resume",
        token=admin_token,
    )
    assert_ok(
        "task-resume-ready",
        status == 200
        and resumed_ready_task["data"]["task"]["status"] == "ready"
        and resumed_ready_task["data"]["enqueued"] is False,
        json.dumps(resumed_ready_task["data"], ensure_ascii=False),
    )

    schedule_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 600))
    status, dispatched_sample_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/dispatch",
        {
            "task_ids": [sample_task["id"]],
            "schedule_at": schedule_at,
        },
        admin_token,
    )
    assert_ok(
        "task-dispatch-scheduled",
        status == 200 and dispatched_sample_task["data"]["items"][0]["status"] == "scheduled",
        json.dumps(dispatched_sample_task["data"], ensure_ascii=False),
    )

    status, paused_scheduled_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/pause",
        token=admin_token,
    )
    assert_ok(
        "task-pause-scheduled",
        status == 200 and paused_scheduled_task["data"]["task"]["status"] == "paused_scheduled",
        json.dumps(paused_scheduled_task["data"], ensure_ascii=False),
    )

    status, resumed_scheduled_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/resume",
        token=admin_token,
    )
    assert_ok(
        "task-resume-scheduled",
        status == 200
        and resumed_scheduled_task["data"]["task"]["status"] == "scheduled"
        and resumed_scheduled_task["data"]["enqueued"] is False,
        json.dumps(resumed_scheduled_task["data"], ensure_ascii=False),
    )

    status, live_log_payload = request(
        "GET",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/live-log",
        token=admin_token,
    )
    live_log_items = live_log_payload["data"]["live_log"]["items"]
    live_log_messages = {item["message"] for item in live_log_items}
    assert_ok(
        "task-live-log",
        status == 200
        and live_log_payload["data"]["task"]["id"] == sample_task["id"]
        and len(live_log_items) >= 4
        and "Task was paused before execution." in live_log_messages
        and any("Task was resumed" in message for message in live_log_messages),
        json.dumps(live_log_payload["data"], ensure_ascii=False),
    )

    status, cancelled_sample_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/cancel",
        token=admin_token,
    )
    assert_ok(
        "task-cancel",
        status == 200 and cancelled_sample_task["data"]["task"]["status"] == "cancelled",
        json.dumps(cancelled_sample_task["data"], ensure_ascii=False),
    )

    retry_schedule_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 900))
    status, retried_sample_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}/retry",
        {
            "schedule_at": retry_schedule_at,
        },
        admin_token,
    )
    assert_ok(
        "task-retry",
        status == 200
        and retried_sample_task["data"]["task"]["status"] == "scheduled"
        and retried_sample_task["data"]["enqueued"] is False,
        json.dumps(retried_sample_task["data"], ensure_ascii=False),
    )

    status, deleted_sample_task = request(
        "DELETE",
        f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}",
        token=admin_token,
    )
    assert_ok(
        "task-delete",
        status == 200 and deleted_sample_task["data"]["id"] == sample_task["id"],
        json.dumps(deleted_sample_task["data"], ensure_ascii=False),
    )

    try:
        request("GET", f"{BASE_BACKEND}/api/attack-tasks/{sample_task['id']}", token=admin_token)
        assert_ok("task-delete-verify", False, "deleted task was still returned")
    except urllib.error.HTTPError as exc:
        assert_ok("task-delete-verify", exc.code == 404, f"status={exc.code}")

    status, worker_status = request("GET", f"{BASE_BACKEND}/api/attack-tasks/worker/status", token=admin_token)
    assert_ok(
        "worker-status",
        status == 200 and "scheduled_tasks" in worker_status["data"],
        json.dumps(worker_status["data"], ensure_ascii=False),
    )

    status, profile = request("GET", f"{BASE_BACKEND}/api/defense-configs/profile", token=admin_token)
    assert_ok("profile-read", status == 200 and len(profile["data"]["guard_rules"]) >= 1, "profile loaded")
    assert_ok(
        "defense-metadata-read",
        status == 200
        and profile["data"]["guard_rules"][0]["field_meta"]["mode"]["control"] == "segmented"
        and profile["data"]["global_field_meta"]["mode"]["control"] == "segmented"
        and len(profile["data"]["resource_groups"]) == 3,
        "profile metadata loaded",
    )

    marker = "/tmp/smoke-path"
    payload = profile["data"]
    payload["protected_paths"] = [item for item in payload["protected_paths"] if item != marker] + [marker]
    status, updated = request("PUT", f"{BASE_BACKEND}/api/defense-configs/profile", payload, admin_token)
    assert_ok(
        "profile-write",
        status == 200 and marker in updated["data"]["protected_paths"],
        "marker written",
    )

    status, reloaded = request("GET", f"{BASE_BACKEND}/api/defense-configs/profile", token=admin_token)
    assert_ok(
        "profile-persist",
        status == 200 and marker in reloaded["data"]["protected_paths"],
        "marker persisted",
    )

    cleanup = reloaded["data"]
    cleanup["protected_paths"] = [item for item in cleanup["protected_paths"] if item != marker]
    request("PUT", f"{BASE_BACKEND}/api/defense-configs/profile", cleanup, admin_token)

    status, defense_configs = request("GET", f"{BASE_BACKEND}/api/defense-configs", token=admin_token)
    assert_ok(
        "defense-configs-metadata",
        status == 200
        and defense_configs["data"]["items"][0]["field_meta"]["mode"]["control"] == "segmented"
        and defense_configs["data"]["items"][0]["field_meta"]["enabled"]["control"] == "toggle",
        "defense config items expose field metadata",
    )

    status, skills = request("GET", f"{BASE_BACKEND}/api/skills", token=admin_token)
    skill_items = skills["data"]["items"]
    assert_ok(
        "skills-metadata-read",
        status == 200
        and len(skill_items) >= 1
        and skill_items[0]["field_meta"]["trust_status"]["control"] == "segmented"
        and len(skill_items[0]["field_meta"]["trust_status"]["options"]) >= 2,
        "skills expose trust-status field metadata",
    )
    original_trust_status = skill_items[0]["trust_status"]
    updated_trust_status = "pending" if original_trust_status != "pending" else "trusted"
    status, skill_update = request(
        "PUT",
        f"{BASE_BACKEND}/api/skills/{skill_items[0]['id']}/trust-status",
        {"trust_status": updated_trust_status},
        admin_token,
    )
    assert_ok(
        "skills-metadata-write",
        status == 200
        and skill_update["data"]["trust_status"] == updated_trust_status
        and skill_update["data"]["field_meta"]["trust_status"]["control"] == "segmented",
        updated_trust_status,
    )
    request(
        "PUT",
        f"{BASE_BACKEND}/api/skills/{skill_items[0]['id']}/trust-status",
        {"trust_status": original_trust_status},
        admin_token,
    )

    status, queued_task = request(
        "POST",
        f"{BASE_BACKEND}/api/skills/scan",
        {"skill_ids": [skill_items[0]["id"]]},
        admin_token,
    )
    queued_task_id = queued_task["data"]["id"]
    assert_ok(
        "skill-scan-queue",
        status == 200 and queued_task["data"]["status"] == "queued",
        f"task_id={queued_task_id}",
    )

    status, executed_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks/{queued_task_id}/run",
        token=admin_token,
    )
    assert_ok(
        "task-run-enqueue",
        status == 200 and executed_task["data"]["task"]["status"] in {"queued", "running"},
        json.dumps(executed_task["data"], ensure_ascii=False),
    )
    terminal_task = wait_for_task_terminal_state(queued_task_id, admin_token)
    if provider_execution_ready:
        assert_ok(
            "task-run-pipeline",
            terminal_task["status"] == "done",
            json.dumps(terminal_task, ensure_ascii=False),
        )
        assert_ok(
            "task-run-artifacts",
            bool(terminal_task.get("latest_event_id")) and bool(terminal_task.get("latest_report_id")),
            json.dumps(terminal_task, ensure_ascii=False),
        )
    else:
        assert_ok(
            "task-run-pipeline",
            terminal_task["status"] in {"done", "failed"},
            json.dumps(terminal_task, ensure_ascii=False),
        )
        if terminal_task["status"] == "done":
            assert_ok(
                "task-run-artifacts",
                bool(terminal_task.get("latest_event_id")) and bool(terminal_task.get("latest_report_id")),
                json.dumps(terminal_task, ensure_ascii=False),
            )
        else:
            assert_ok(
                "task-run-failure-detail",
                bool(terminal_task.get("result_summary")),
                json.dumps(terminal_task, ensure_ascii=False),
            )

        print("[SKIP] legacy-no-ai-fallback: deterministic fallback validation runs below")

    status, system_settings_for_fallback = request("GET", f"{BASE_BACKEND}/api/system-settings", token=admin_token)
    assert_ok(
        "system-settings-read-for-fallback",
        status == 200 and len(system_settings_for_fallback["data"]["items"]) >= 1,
        f"total={system_settings_for_fallback['data']['total']}",
    )
    original_review_ai_url = _setting_value(system_settings_for_fallback["data"]["items"], "review_ai_api_url")
    original_review_ai_key = _setting_value(system_settings_for_fallback["data"]["items"], "review_ai_api_key")

    temp_endpoint_key = f"smoke-no-ai-{int(time.time())}"
    status, fallback_endpoint = request(
        "POST",
        f"{BASE_BACKEND}/api/ai-endpoints",
        {
            "endpoint_key": temp_endpoint_key,
            "display_name": "Smoke No-AI Fallback Target",
            "endpoint_group": "smoke",
            "target_type": "openclaw_control",
            "description": "Deterministic no-AI fallback validation target.",
        },
        admin_token,
    )
    fallback_endpoint_id = fallback_endpoint["data"]["id"]
    assert_ok(
        "no-ai-endpoint-create",
        status == 200 and fallback_endpoint_id > 0,
        json.dumps(fallback_endpoint["data"], ensure_ascii=False),
    )

    status, fallback_profile = request(
        "GET",
        f"{BASE_BACKEND}/api/defense-configs/profile?ai_endpoint_id={fallback_endpoint_id}",
        token=admin_token,
    )
    assert_ok(
        "no-ai-profile-read",
        status == 200 and bool(fallback_profile["data"]["ai_review_policy"]),
        json.dumps(fallback_profile["data"]["ai_review_policy"], ensure_ascii=False),
    )

    def _rule_payload(rule: dict) -> dict:
        mode = str(rule.get("mode") or "observe").strip().lower()
        if mode not in {"enforce", "observe", "off"}:
            mode = "observe"
        return {
            "key": rule["key"],
            "title": rule["title"],
            "description": rule["description"],
            "enabled": bool(rule.get("enabled", True)),
            "mode": mode,
        }

    status, _ = request(
        "PUT",
        f"{BASE_BACKEND}/api/defense-configs/profile?ai_endpoint_id={fallback_endpoint_id}",
        {
            "guard_rules": [_rule_payload(rule) for rule in fallback_profile["data"]["guard_rules"]],
            "scan_rules": [_rule_payload(rule) for rule in fallback_profile["data"]["scan_rules"]],
            "advanced_rule": _rule_payload(fallback_profile["data"]["advanced_rule"]),
            "ai_review_policy": {
                "key": fallback_profile["data"]["ai_review_policy"]["key"],
                "title": fallback_profile["data"]["ai_review_policy"]["title"],
                "description": fallback_profile["data"]["ai_review_policy"]["description"],
                "mode": "review_all_remaining",
                "reviewer_ai_endpoint_id": None,
            },
            "protected_paths": fallback_profile["data"]["protected_paths"],
            "protected_skills": fallback_profile["data"]["protected_skills"],
            "protected_plugins": fallback_profile["data"]["protected_plugins"],
        },
        admin_token,
    )
    assert_ok("no-ai-profile-update", status == 200, f"endpoint_id={fallback_endpoint_id}")

    try:
        request(
            "PUT",
            f"{BASE_BACKEND}/api/system-settings/review_ai_api_url",
            {"setting_value": ""},
            admin_token,
        )
        request(
            "PUT",
            f"{BASE_BACKEND}/api/system-settings/review_ai_api_key",
            {"setting_value": ""},
            admin_token,
        )

        status, no_ai_task = request(
            "POST",
            f"{BASE_BACKEND}/api/attack-tasks",
            {
                "task_name": "no-ai-fallback-smoke",
                "attack_type": "manual_review_probe",
                "target_agent": "offline-agent",
                "ai_endpoint_id": fallback_endpoint_id,
                "params_json": {
                    "title": "No AI fallback smoke",
                    "content": "This request simulates suspicious multi-turn context carry-over and should still complete without reviewer AI.",
                    "expected_behavior": "The platform should keep the event and report chain while skipping AI review because reviewer settings are absent.",
                    "mapped_section": "multi_turn_context",
                    "risk_level": "medium",
                    "test_mode": "multi_turn",
                },
            },
            admin_token,
        )
        no_ai_task_id = no_ai_task["data"]["id"]
        assert_ok(
            "no-ai-task-create",
            status == 200 and no_ai_task["data"]["status"] in {"queued", "running"},
            json.dumps(no_ai_task["data"], ensure_ascii=False),
        )

        no_ai_terminal = wait_for_task_terminal_state(no_ai_task_id, admin_token)
        no_ai_raw_response = json.loads(no_ai_terminal.get("raw_response") or "{}")
        assert_ok(
            "no-ai-review-fallback",
            no_ai_terminal["status"] == "done"
            and no_ai_raw_response.get("review_decision")
            in {"review_ai_api_url_not_configured", "review_ai_api_key_not_configured"}
            and no_ai_raw_response.get("ai_review_invoked") is False
            and bool(no_ai_terminal.get("latest_event_id"))
            and bool(no_ai_terminal.get("latest_report_id")),
            json.dumps(
                {
                    "task": no_ai_terminal,
                    "raw_response": no_ai_raw_response,
                },
                ensure_ascii=False,
            ),
        )
    finally:
        request(
            "PUT",
            f"{BASE_BACKEND}/api/system-settings/review_ai_api_url",
            {"setting_value": original_review_ai_url},
            admin_token,
        )
        request(
            "PUT",
            f"{BASE_BACKEND}/api/system-settings/review_ai_api_key",
            {"setting_value": original_review_ai_key},
            admin_token,
        )

    status, reports = request("GET", f"{BASE_BACKEND}/api/reports?page_size=1", token=admin_token)
    assert_ok(
        "reports-list",
        status == 200 and len(reports["data"]["items"]) >= 1,
        json.dumps(reports["data"]["items"], ensure_ascii=False),
    )
    report_id = reports["data"]["items"][0]["id"]

    status, exported_report = request("POST", f"{BASE_BACKEND}/api/reports/{report_id}/export", token=admin_token)
    assert_ok(
        "report-export",
        status == 200 and exported_report["data"]["artifact_exists"] is True,
        json.dumps(exported_report["data"], ensure_ascii=False),
    )

    status, exported_html_report = request(
        "POST",
        f"{BASE_BACKEND}/api/reports/{report_id}/export?format=html",
        token=admin_token,
    )
    assert_ok(
        "report-export-html",
        status == 200
        and exported_html_report["data"]["artifact_format"] == "html"
        and "html" in exported_html_report["data"].get("supported_formats", [])
        and "html" in exported_html_report["data"].get("available_formats", []),
        json.dumps(exported_html_report["data"], ensure_ascii=False),
    )

    status, exported_docx_report = request(
        "POST",
        f"{BASE_BACKEND}/api/reports/{report_id}/export?format=docx",
        token=admin_token,
    )
    assert_ok(
        "report-export-docx",
        status == 200
        and exported_docx_report["data"]["artifact_format"] == "docx"
        and "docx" in exported_docx_report["data"].get("supported_formats", [])
        and "docx" in exported_docx_report["data"].get("available_formats", []),
        json.dumps(exported_docx_report["data"], ensure_ascii=False),
    )

    status, html_report_bytes, html_report_headers = request_bytes(
        "GET",
        f"{BASE_BACKEND}/api/reports/{report_id}/download?format=html",
        token=admin_token,
    )
    html_report_text = html_report_bytes.decode("utf-8", errors="ignore")
    assert_ok(
        "report-download-html",
        status == 200
        and html_report_headers.get("content-type", "").startswith("text/html")
        and "<!doctype html>" in html_report_text.lower()
        and "task-" in html_report_text.lower(),
        html_report_text[:400],
    )

    status, docx_report_bytes, docx_report_headers = request_bytes(
        "GET",
        f"{BASE_BACKEND}/api/reports/{report_id}/download?format=docx",
        token=admin_token,
    )
    assert_ok(
        "report-download-docx",
        status == 200
        and docx_report_headers.get("content-type", "").startswith(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        and docx_report_bytes[:2] == b"PK",
        f"content_type={docx_report_headers.get('content-type', '-')} bytes={len(docx_report_bytes)}",
    )

    status, runtime_task = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks",
        {
            "task_name": "runtime-callback-smoke",
            "attack_type": "runtime-smoke",
            "target_agent": "external-agent",
            "params_json": {"source_type": "runtime_smoke", "execution_mode": "runtime_callback"},
        },
        admin_token,
    )
    runtime_task_id = runtime_task["data"]["id"]
    assert_ok(
        "runtime-task-create",
        status == 200 and runtime_task["data"]["status"] == "ready",
        json.dumps(runtime_task["data"], ensure_ascii=False),
    )

    status, runtime_heartbeat = request(
        "POST",
        f"{BASE_BACKEND}/api/runtime/tasks/{runtime_task_id}/heartbeat",
        {
            "runtime_name": "smoke-runtime",
            "status": "running",
            "message": "started",
            "progress": 25,
        },
        token=admin_token,
    )
    assert_ok(
        "runtime-heartbeat",
        status == 200 and runtime_heartbeat["data"]["status"] == "running",
        json.dumps(runtime_heartbeat["data"], ensure_ascii=False),
    )

    status, runtime_complete = request(
        "POST",
        f"{BASE_BACKEND}/api/runtime/tasks/{runtime_task_id}/complete",
        {
            "runtime_name": "smoke-runtime",
            "status": "done",
            "summary": "runtime callback completed",
            "raw_response_json": {"reply": "blocked"},
            "report_type": "runtime_execution",
        },
        token=admin_token,
    )
    assert_ok(
        "runtime-complete",
        status == 200
        and runtime_complete["data"]["task"]["status"] == "done"
        and bool(runtime_complete["data"]["event"]["id"])
        and bool(runtime_complete["data"]["report"]["id"]),
        json.dumps(runtime_complete["data"], ensure_ascii=False),
    )
    runtime_bundle_task_id = runtime_complete["data"]["task"]["id"]

    status, runtime_task_batch = request(
        "POST",
        f"{BASE_BACKEND}/api/attack-tasks",
        {
            "task_name": "runtime-callback-batch-smoke",
            "attack_type": "runtime-smoke",
            "target_agent": "external-agent",
            "params_json": {"source_type": "runtime_smoke", "execution_mode": "runtime_callback"},
        },
        admin_token,
    )
    runtime_batch_task_id = runtime_task_batch["data"]["id"]
    assert_ok(
        "runtime-task-batch-create",
        status == 200 and runtime_task_batch["data"]["status"] == "ready",
        json.dumps(runtime_task_batch["data"], ensure_ascii=False),
    )

    status, runtime_batch_complete = request(
        "POST",
        f"{BASE_BACKEND}/api/runtime/tasks/{runtime_batch_task_id}/complete",
        {
            "runtime_name": "smoke-runtime",
            "status": "done",
            "summary": "runtime callback batch completed",
            "raw_response_json": {"reply": "blocked"},
            "report_type": "runtime_execution",
        },
        token=admin_token,
    )
    assert_ok(
        "runtime-task-batch-complete",
        status == 200
        and runtime_batch_complete["data"]["task"]["status"] == "done"
        and bool(runtime_batch_complete["data"]["event"]["id"])
        and bool(runtime_batch_complete["data"]["report"]["id"]),
        json.dumps(runtime_batch_complete["data"], ensure_ascii=False),
    )

    bundle_task_ids = [runtime_bundle_task_id, runtime_batch_task_id]
    status, bundle_bytes, bundle_headers = request_bytes(
        "POST",
        f"{BASE_BACKEND}/api/reports/batch-download",
        {
            "task_ids": bundle_task_ids,
            "include_manifest": True,
            "formats": ["json", "html", "docx"],
        },
        admin_token,
    )
    assert_ok(
        "report-batch-download",
        status == 200
        and bundle_headers.get("content-type", "").startswith("application/zip")
        and len(bundle_bytes) > 0,
        f"content_type={bundle_headers.get('content-type', '-')} bytes={len(bundle_bytes)}",
    )
    with ZipFile(io.BytesIO(bundle_bytes)) as archive:
        archive_names = archive.namelist()
    assert_ok(
        "report-batch-download-contents",
        "manifest.json" in archive_names
        and any(name.startswith(f"task-{runtime_bundle_task_id}/") and name.endswith(".json") for name in archive_names)
        and any(name.startswith(f"task-{runtime_bundle_task_id}/") and name.endswith(".html") for name in archive_names)
        and any(name.startswith(f"task-{runtime_bundle_task_id}/") and name.endswith(".docx") for name in archive_names)
        and any(name.startswith(f"task-{runtime_batch_task_id}/") and name.endswith(".json") for name in archive_names)
        and any(name.startswith(f"task-{runtime_batch_task_id}/") and name.endswith(".html") for name in archive_names)
        and any(name.startswith(f"task-{runtime_batch_task_id}/") and name.endswith(".docx") for name in archive_names),
        json.dumps(archive_names, ensure_ascii=False),
    )

    status, assets = request("GET", f"{BASE_BACKEND}/api/assets", token=admin_token)
    asset_items = assets["data"]["items"]
    assert_ok(
        "assets-metadata-read",
        status == 200
        and len(asset_items) >= 1
        and asset_items[0]["field_meta"]["status"]["control"] == "segmented"
        and asset_items[0]["field_meta"]["risk_level"]["control"] == "segmented",
        "assets expose status and risk field metadata",
    )
    status, whitelists = request(
        "GET",
        f"{BASE_BACKEND}/api/assets/{asset_items[0]['id']}/whitelists",
        token=admin_token,
    )
    assert_ok(
        "asset-whitelist-metadata",
        status == 200
        and whitelists["data"]["field_meta"]["whitelist_type"]["control"] == "select"
        and whitelists["data"]["field_meta"]["rule_value"]["control"] == "text",
        "asset whitelist form metadata loaded",
    )

    status, settings = request("GET", f"{BASE_BACKEND}/api/system-settings", token=admin_token)
    setting_items = {item["setting_key"]: item for item in settings["data"]["items"]}
    assert_ok(
        "system-settings-read",
        status == 200
        and settings["data"]["total"] >= 1
        and setting_items["log_level"]["field_meta"]["control"] == "select"
        and len(setting_items["log_level"]["field_meta"]["options"]) >= 4
        and setting_items["notify_email"]["field_meta"]["control"] == "select",
        "admin can read with field metadata",
    )
    original_log_level = setting_items["log_level"]["setting_value"]
    updated_log_level = "DEBUG" if original_log_level != "DEBUG" else "INFO"

    status, setting_update = request(
        "PUT",
        f"{BASE_BACKEND}/api/system-settings/log_level",
        {"setting_value": updated_log_level},
        admin_token,
    )
    assert_ok(
        "system-setting-write",
        status == 200
        and setting_update["data"]["setting"]["setting_key"] == "log_level"
        and setting_update["data"]["setting"]["setting_value"] == updated_log_level
        and setting_update["data"]["audit_log"]["module"] == "system-settings",
        updated_log_level,
    )

    status, settings_reloaded = request("GET", f"{BASE_BACKEND}/api/system-settings", token=admin_token)
    reloaded_setting_items = {item["setting_key"]: item for item in settings_reloaded["data"]["items"]}
    assert_ok(
        "system-setting-persist",
        status == 200 and reloaded_setting_items["log_level"]["setting_value"] == updated_log_level,
        updated_log_level,
    )

    request(
        "PUT",
        f"{BASE_BACKEND}/api/system-settings/log_level",
        {"setting_value": original_log_level},
        admin_token,
    )

    status, system_actions = request("GET", f"{BASE_BACKEND}/api/system-settings/actions", token=admin_token)
    action_keys = {item["action_key"] for item in system_actions["data"]["items"]}
    action_tones = {item["action_key"]: item["tone"] for item in system_actions["data"]["items"]}
    assert_ok(
        "system-actions-read",
        status == 200
        and {"export-defense-config", "platform-backup", "refresh-permission-cache"}.issubset(action_keys)
        and action_tones.get("export-defense-config") == "info"
        and action_tones.get("platform-backup") == "warn"
        and action_tones.get("refresh-permission-cache") == "safe",
        f"actions={sorted(action_tones.items())}",
    )

    status, action_result = request(
        "POST",
        f"{BASE_BACKEND}/api/system-settings/actions/export-defense-config",
        token=admin_token,
    )
    assert_ok(
        "system-action-run",
        status == 200
        and action_result["data"]["action_key"] == "export-defense-config"
        and action_result["data"]["tone"] == "info"
        and action_result["data"]["audit_log"]["module"] == "system-settings",
        action_result["data"]["output"],
    )
    export_path = Path("backend") / action_result["data"]["output"]
    export_payload = json.loads(export_path.read_text(encoding="utf-8")) if export_path.exists() else {}
    assert_ok(
        "system-export-artifact-file",
        export_path.exists() and export_payload.get("scope") == "defense" and export_payload.get("secret_mode") == "redacted",
        str(export_path),
    )

    status, backup_action_result = request(
        "POST",
        f"{BASE_BACKEND}/api/system-settings/actions/platform-backup",
        token=admin_token,
    )
    assert_ok(
        "system-action-backup",
        status == 200 and backup_action_result["data"]["action_key"] == "platform-backup",
        json.dumps(backup_action_result["data"], ensure_ascii=False),
    )
    backup_path = Path("backend") / backup_action_result["data"]["output"]
    assert_ok(
        "system-backup-artifact-file",
        backup_path.exists() and backup_path.read_bytes()[:2] == b"PK",
        str(backup_path),
    )

    status, dashboard_overview = request("GET", f"{BASE_BACKEND}/api/dashboard/overview", token=admin_token)
    assert_ok(
        "dashboard-overview",
        status == 200
        and dashboard_overview["data"]["attack_count"] >= 1
        and dashboard_overview["data"]["enabled_defense_count"] >= 1,
        json.dumps(dashboard_overview["data"], ensure_ascii=False),
    )

    status, dashboard_trends = request("GET", f"{BASE_BACKEND}/api/dashboard/trends?range=7d", token=admin_token)
    assert_ok(
        "dashboard-trends",
        status == 200 and len(dashboard_trends["data"]["items"]) == 7,
        json.dumps(dashboard_trends["data"]["items"], ensure_ascii=False),
    )

    status, dashboard_sessions = request("GET", f"{BASE_BACKEND}/api/dashboard/sessions", token=admin_token)
    session_levels = {item["risk_level"] for item in dashboard_sessions["data"]["items"]}
    assert_ok(
        "dashboard-sessions",
        status == 200 and session_levels.issubset({"high", "medium", "low"}),
        json.dumps(dashboard_sessions["data"], ensure_ascii=False),
    )

    _, analyst_login = request(
        "POST",
        f"{BASE_BACKEND}/api/auth/login",
        {"username": "analyst", "password": "analyst123"},
    )
    analyst_token = analyst_login["data"]["access_token"]
    try:
        request("GET", f"{BASE_BACKEND}/api/system-settings", token=analyst_token)
        assert_ok("rbac-admin-only", False, "analyst unexpectedly accessed system-settings")
    except urllib.error.HTTPError as exc:
        assert_ok("rbac-admin-only", exc.code == 403, f"status={exc.code}")

    try:
        request("GET", f"{BASE_BACKEND}/api/system-settings/actions", token=analyst_token)
        assert_ok("rbac-system-actions", False, "analyst unexpectedly accessed system actions")
    except urllib.error.HTTPError as exc:
        assert_ok("rbac-system-actions", exc.code == 403, f"status={exc.code}")

    status, deleted_user = request(
        "DELETE",
        f"{BASE_BACKEND}/api/users/{temp_user_id}",
        token=admin_token,
    )
    assert_ok(
        "users-delete",
        status == 200 and deleted_user["data"]["id"] == temp_user_id,
        json.dumps(deleted_user["data"], ensure_ascii=False),
    )

    frontend_base = resolve_frontend_base()
    if frontend_base:
        status, _ = request("GET", f"{frontend_base}/")
        assert_ok("frontend-root", status == 200, f"frontend home reachable at {frontend_base}")

        status, _ = request("GET", f"{frontend_base}/login")
        assert_ok("frontend-login-route", status == 200, "frontend login route reachable")
    else:
        print(f"[SKIP] frontend-checks: frontend not reachable, checked: {', '.join(FRONTEND_CANDIDATES)}")

    print("Smoke test completed successfully.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
