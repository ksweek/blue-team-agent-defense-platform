#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn
import websockets


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_LOG_DIR = PROJECT_ROOT / "run_logs"
CONNECT_SCRIPT = PROJECT_ROOT / "tools" / "openclaw_control_connect.py"
BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(message: str, **fields: Any) -> None:
    suffix = ""
    if fields:
        suffix = " | " + " ".join(f"{key}={value}" for key, value in fields.items() if value not in (None, ""))
    print(f"[{now_text()}] {message}{suffix}")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_request(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
    timeout: float = 20,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body_text = response.read().decode("utf-8", errors="replace")
            status = int(response.getcode())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {body_text}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} -> connect failed: {exc}") from exc

    try:
        body = json.loads(body_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{method} {url} -> non-json response: {body_text[:300]}") from exc
    return status, body


def api_request(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
    timeout: float = 20,
) -> dict[str, Any]:
    status, body = http_request(method, f"{BASE_URL}{path}", payload=payload, token=token, timeout=timeout)
    if status < 200 or status >= 300:
        raise RuntimeError(f"{method} {path} -> unexpected HTTP status {status}")
    if body.get("code") != 0:
        raise RuntimeError(f"{method} {path} -> business error: {body}")
    return dict(body.get("data") or {})


def backend_health() -> dict[str, Any]:
    status, body = http_request("GET", f"{BASE_URL}/health", timeout=5)
    if status != 200:
        raise RuntimeError(f"backend /health returned {status}")
    return body


def admin_login() -> str:
    data = api_request(
        "POST",
        "/api/auth/login",
        payload={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    token = str(data.get("access_token") or "").strip()
    if not token:
        raise RuntimeError("admin login succeeded but access_token is missing")
    return token


def build_policy_update_payload(profile: dict[str, Any], *, protected_paths: list[str]) -> dict[str, Any]:
    def clean_rule(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "key": str(item.get("key") or ""),
            "title": str(item.get("title") or ""),
            "description": str(item.get("description") or ""),
            "enabled": bool(item.get("enabled")),
            "mode": str(item.get("mode") or "off"),
        }

    return {
        "guard_rules": [clean_rule(item) for item in list(profile.get("guard_rules") or [])],
        "scan_rules": [clean_rule(item) for item in list(profile.get("scan_rules") or [])],
        "advanced_rule": clean_rule(dict(profile.get("advanced_rule") or {})),
        "ai_review_policy": {
            "key": str((profile.get("ai_review_policy") or {}).get("key") or ""),
            "title": str((profile.get("ai_review_policy") or {}).get("title") or ""),
            "description": str((profile.get("ai_review_policy") or {}).get("description") or ""),
            "mode": str((profile.get("ai_review_policy") or {}).get("mode") or "rules_only"),
        },
        "protected_paths": list(protected_paths),
        "protected_skills": list(profile.get("protected_skills") or []),
        "protected_plugins": list(profile.get("protected_plugins") or []),
    }


class FakeOpenClawUpstream:
    def __init__(self, port: int):
        self.port = port
        self._thread: threading.Thread | None = None
        self._server: uvicorn.Server | None = None
        self._state: dict[str, Any] = {
            "ws_connections": 0,
            "ws_messages": [],
        }
        self.app = FastAPI()
        self._register_routes()

    def _register_routes(self) -> None:
        @self.app.get("/")
        async def root() -> dict[str, Any]:
            return {"ok": True, "service": "fake-openclaw-upstream"}

        @self.app.get("/health")
        async def health() -> dict[str, Any]:
            return {"ok": True}

        @self.app.get("/__stats")
        async def stats() -> dict[str, Any]:
            return {
                "ws_connections": int(self._state["ws_connections"]),
                "ws_message_count": len(self._state["ws_messages"]),
                "messages": list(self._state["ws_messages"]),
            }

        @self.app.websocket("/{full_path:path}")
        async def websocket_entry(websocket: WebSocket, full_path: str) -> None:
            await websocket.accept()
            self._state["ws_connections"] += 1
            try:
                while True:
                    text = await websocket.receive_text()
                    payload = json.loads(text)
                    self._state["ws_messages"].append(
                        {
                            "path": f"/{full_path}",
                            "method": str(payload.get("method") or ""),
                            "id": payload.get("id"),
                            "params": payload.get("params"),
                        }
                    )
                    response = {
                        "type": "res",
                        "id": payload.get("id"),
                        "ok": True,
                        "payload": {
                            "status": "started",
                            "echo_method": str(payload.get("method") or ""),
                        },
                    }
                    await websocket.send_text(json.dumps(response, ensure_ascii=False))
            except WebSocketDisconnect:
                return

    def start(self) -> None:
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="warning", access_log=False)
        self._server = uvicorn.Server(config)

        def run() -> None:
            assert self._server is not None
            self._server.run()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        wait_for_http_json(
            f"http://127.0.0.1:{self.port}/health",
            lambda payload: bool(payload.get("ok")),
            timeout_seconds=15,
        )

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)


def wait_for_http_json(
    url: str,
    predicate,
    *,
    timeout_seconds: float,
    interval_seconds: float = 1,
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            status, payload = http_request("GET", url, timeout=5)
            if status == 200 and predicate(payload):
                return payload
            last_error = f"predicate returned false: {payload}"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(interval_seconds)
    raise RuntimeError(f"timed out waiting for {url}: {last_error}")


def wait_for_runtime_by_name(admin_token: str, display_name: str, *, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        data = api_request("GET", "/api/runtime-registry", token=admin_token, timeout=10)
        for item in list(data.get("runtimes") or []):
            if str(item.get("display_name") or "").strip() == display_name:
                return dict(item)
        time.sleep(1)
    raise RuntimeError(f"runtime {display_name} did not appear in registry")


async def websocket_roundtrip(bridge_port: int, request_payload: dict[str, Any]) -> dict[str, Any]:
    url = f"ws://127.0.0.1:{bridge_port}/"
    async with websockets.connect(url, open_timeout=10, close_timeout=5, max_size=None) as websocket:
        await websocket.send(json.dumps(request_payload, ensure_ascii=False))
        raw = await asyncio.wait_for(websocket.recv(), timeout=10)
        if not isinstance(raw, str):
            raise RuntimeError(f"unexpected non-text websocket response: {type(raw)!r}")
        return json.loads(raw)


def stop_process(proc: subprocess.Popen[str] | None) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def read_tail(path: Path, *, lines: int = 40) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def main() -> int:
    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    suffix = str(int(time.time()))
    unique_key = f"openclaw-e2e-{suffix}"
    sensitive_path = f"C:/openclaw-sensitive-{suffix}"
    fake_upstream_port = find_free_port()
    bridge_port = find_free_port()
    bridge_display_name = f"OpenClaw E2E Bridge {suffix}"
    runtime_config_path = RUN_LOG_DIR / f"{unique_key}.runtime.json"
    bridge_stdout_path = RUN_LOG_DIR / f"{unique_key}.bridge.out.log"
    bridge_stderr_path = RUN_LOG_DIR / f"{unique_key}.bridge.err.log"

    health = backend_health()
    log("backend ready", database=health.get("database"), ai_provider=health.get("ai_provider"), ai_configured=health.get("ai_configured"))
    admin_token = admin_login()
    log("admin login ok")

    endpoint_id: int | None = None
    fake_upstream: FakeOpenClawUpstream | None = None
    bridge_proc: subprocess.Popen[str] | None = None

    try:
        endpoint = api_request(
            "POST",
            "/api/ai-endpoints",
            token=admin_token,
            payload={
                "endpoint_key": unique_key,
                "display_name": f"OpenClaw E2E {suffix}",
                "endpoint_group": "openclaw-e2e",
                "provider_type": "openai_compatible",
                "base_url": f"http://127.0.0.1:{fake_upstream_port}/v1",
                "api_key": "",
                "model_name": "smoke-model",
                "enabled": True,
                "is_default": False,
                "protection_enabled": True,
                "protection_mode": "enforce",
                "description": "OpenClaw bridge E2E smoke test endpoint",
                "config_json": {"headers": {}, "extra_body": {}},
                "config_public_json": {},
                "config_secret_updates": [],
                "config_secret_remove_paths": [],
            },
        )
        endpoint_id = int(endpoint["id"])
        log("created test ai endpoint", endpoint_id=endpoint_id, endpoint_key=endpoint["endpoint_key"])

        defenses = api_request("GET", f"/api/defense-configs?ai_endpoint_id={endpoint_id}", token=admin_token, timeout=10)
        tool_broker = next(
            (item for item in list((defenses.get("items") or [])) if str(item.get("defense_type") or "") == "tool_permission_broker"),
            None,
        )
        if tool_broker is None:
            raise RuntimeError("tool_permission_broker defense config was not found")
        api_request(
            "PUT",
            f"/api/defense-configs/{tool_broker['id']}?ai_endpoint_id={endpoint_id}",
            token=admin_token,
            payload={
                "enabled": True,
                "mode": "enforce",
                "config_json": dict(tool_broker.get("config_json") or {}),
            },
        )
        log("forced tool_permission_broker=enforce for test endpoint")

        profile = api_request("GET", f"/api/defense-configs/profile?ai_endpoint_id={endpoint_id}", token=admin_token, timeout=10)
        api_request(
            "PUT",
            f"/api/defense-configs/profile?ai_endpoint_id={endpoint_id}",
            token=admin_token,
            payload=build_policy_update_payload(profile, protected_paths=[sensitive_path]),
            timeout=20,
        )
        log("attached endpoint protected path", protected_path=sensitive_path)

        token_payload = api_request(
            "POST",
            "/api/runtime-registry/tokens",
            token=admin_token,
            payload={
                "token_label": f"{unique_key}-token",
                "runtime_type": "openclaw_control_bridge",
                "ai_endpoint_id": endpoint_id,
                "usage_limit": 1,
                "delivery_mode": "activation_code",
            },
        )
        activation_code = str(token_payload.get("activation_code") or "").strip()
        if not activation_code:
            raise RuntimeError("runtime activation code is missing")
        log("created endpoint-bound runtime activation code")

        fake_upstream = FakeOpenClawUpstream(fake_upstream_port)
        fake_upstream.start()
        log("fake upstream ready", port=fake_upstream_port)

        bridge_cmd = [
            sys.executable,
            str(CONNECT_SCRIPT),
            "--platform-base-url",
            BASE_URL,
            "--upstream-http-url",
            f"http://127.0.0.1:{fake_upstream_port}",
            "--gateway-token",
            "smoke-gateway-token",
            "--activation-code",
            activation_code,
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(bridge_port),
            "--access-host",
            "127.0.0.1",
            "--runtime-config",
            str(runtime_config_path),
            "--profile-name",
            unique_key,
            "--runtime-display-name",
            bridge_display_name,
            "--target-agent-name",
            f"OpenClaw Smoke Target {suffix}",
            "--max-capture-chars",
            "8000",
            "--no-remember",
        ]
        bridge_stdout = bridge_stdout_path.open("w", encoding="utf-8")
        bridge_stderr = bridge_stderr_path.open("w", encoding="utf-8")
        bridge_proc = subprocess.Popen(
            bridge_cmd,
            cwd=str(PROJECT_ROOT),
            stdout=bridge_stdout,
            stderr=bridge_stderr,
            text=True,
        )
        log("bridge process started", pid=bridge_proc.pid, port=bridge_port)

        runtime = wait_for_runtime_by_name(admin_token, bridge_display_name, timeout_seconds=30)
        log("runtime appeared in registry", runtime_id=runtime["id"], status=runtime["status"])
        if str(runtime.get("status") or "") != "active":
            raise RuntimeError(f"activation-code client flow should create an active runtime, got {runtime['status']}")

        bridge_health = wait_for_http_json(
            f"http://127.0.0.1:{bridge_port}/__bridge__/health",
            lambda payload: str(((payload.get("platform_state") or {}).get("mode") or "")) == "runtime_active",
            timeout_seconds=60,
        )
        log("bridge became runtime_active", platform_mode=(bridge_health.get("platform_state") or {}).get("mode"))

        deny_request = {
            "type": "req",
            "id": "deny-1",
            "method": "sessions.send",
            "params": {
                "sessionKey": "agent:main:main",
                "message": "status check",
                "cwd": sensitive_path,
            },
        }
        deny_response = asyncio.run(websocket_roundtrip(bridge_port, deny_request))
        _, upstream_stats_after_deny = http_request("GET", f"http://127.0.0.1:{fake_upstream_port}/__stats")
        log("deny response received", response=json.dumps(deny_response, ensure_ascii=False))
        log("upstream stats after deny", ws_message_count=upstream_stats_after_deny["ws_message_count"])

        if "error" not in deny_response:
            raise RuntimeError(f"expected denied websocket error response, got: {deny_response}")
        if int(upstream_stats_after_deny["ws_message_count"]) != 0:
            raise RuntimeError(f"expected fake upstream to receive 0 messages after deny, got: {upstream_stats_after_deny}")

        profile = api_request("GET", f"/api/defense-configs/profile?ai_endpoint_id={endpoint_id}", token=admin_token, timeout=10)
        api_request(
            "PUT",
            f"/api/defense-configs/profile?ai_endpoint_id={endpoint_id}",
            token=admin_token,
            payload=build_policy_update_payload(profile, protected_paths=[]),
            timeout=20,
        )
        log("removed endpoint protected path")
        time.sleep(1)

        allow_request = {
            "type": "req",
            "id": "allow-2",
            "method": "sessions.send",
            "params": {
                "sessionKey": "agent:main:main",
                "message": "status check",
                "cwd": sensitive_path,
            },
        }
        allow_response = asyncio.run(websocket_roundtrip(bridge_port, allow_request))
        _, upstream_stats_after_allow = http_request("GET", f"http://127.0.0.1:{fake_upstream_port}/__stats")
        log("allow response received", response=json.dumps(allow_response, ensure_ascii=False))
        log("upstream stats after allow", ws_message_count=upstream_stats_after_allow["ws_message_count"])

        if allow_response.get("ok") is not True:
            raise RuntimeError(f"expected allowed upstream response, got: {allow_response}")
        if int(upstream_stats_after_allow["ws_message_count"]) != 1:
            raise RuntimeError(f"expected fake upstream to receive exactly 1 forwarded message, got: {upstream_stats_after_allow}")

        print()
        print("=" * 72)
        print("E2E RESULT")
        print("1. The client launcher exchanged a short activation code for long-term runtime credentials.")
        print(f"2. With endpoint protected_paths = {sensitive_path}, sessions.send was blocked by platform review.")
        print("3. After clearing protected_paths, the same sessions.send was forwarded to the fake upstream successfully.")
        print("4. This proves the customer OpenClaw script path reaches endpoint-level platform protection.")
        print("=" * 72)
        return 0
    except Exception as exc:  # noqa: BLE001
        print()
        print("=" * 72)
        print("E2E RESULT: FAILED")
        print(str(exc))
        print("-" * 72)
        print("bridge stdout tail:")
        print(read_tail(bridge_stdout_path))
        print("-" * 72)
        print("bridge stderr tail:")
        print(read_tail(bridge_stderr_path))
        print("=" * 72)
        return 1
    finally:
        stop_process(bridge_proc)
        if fake_upstream is not None:
            fake_upstream.stop()
        if endpoint_id is not None:
            try:
                api_request("DELETE", f"/api/ai-endpoints/{endpoint_id}", token=admin_token, timeout=20)
                log("deleted test ai endpoint", endpoint_id=endpoint_id)
            except Exception as cleanup_exc:  # noqa: BLE001
                log("cleanup warning", action="delete_ai_endpoint", error=str(cleanup_exc))


if __name__ == "__main__":
    raise SystemExit(main())
