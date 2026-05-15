from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
RUN_LOG_DIR = REPO_ROOT / "run_logs"
TEMP_ROOT = Path(tempfile.mkdtemp(prefix="blue-team-api-audit-")).resolve()
TEST_DB_PATH = TEMP_ROOT / "app.db"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["APP_ENV"] = "test"
os.environ["BOOTSTRAP_MODE"] = "auto"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"
os.environ["DATABASE_ECHO"] = "false"
os.environ["DATABASE_POOL_PRE_PING"] = "true"
os.environ["SEED_SAMPLE_DATA"] = "true"
os.environ["TASK_WORKER_EMBEDDED"] = "false"
os.environ["AI_PROVIDER"] = "disabled"
os.environ["AI_BASE_URL"] = "https://api.openai.com/v1"
os.environ["AI_API_KEY"] = ""
os.environ["AI_MODEL"] = ""
os.environ["JWT_SECRET"] = "blue-team-audit-secret"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "admin123"
os.environ["BOOTSTRAP_ANALYST_PASSWORD"] = "analyst123"
os.environ["APP_LOG_LEVEL"] = "WARNING"

from app.main import app  # noqa: E402
from app.services.runtime_dispatch import RUNTIME_COMMAND_TYPE_REMOTE_SKILL_SCAN, enqueue_runtime_command  # noqa: E402
from app.services.task_worker import stop_task_worker  # noqa: E402


TERMINAL_TASK_STATUSES = {"done", "failed", "dead_letter", "cancelled"}

NEEDS_PREREQ_HTTP: set[tuple[str, str]] = {
    ("POST", "/api/ai-endpoints/{endpoint_id}/test"),
    ("POST", "/api/runtime-registry/tokens/{token_id}/bind"),
    ("POST", "/api/runtime-registry/runtimes/{runtime_id}/activation-code"),
    ("POST", "/api/runtime-registry/activate"),
    ("POST", "/api/runtime-registry/client-activate"),
    ("POST", "/api/runtime-registry/runtimes/{runtime_id}/approve"),
    ("POST", "/api/runtime-registry/runtimes/{runtime_id}/bind"),
    ("POST", "/api/runtime-registry/runtimes/{runtime_id}/reject"),
    ("POST", "/api/runtime-registry/runtimes/{runtime_id}/revoke"),
    ("POST", "/api/runtime-registry/runtimes/{runtime_id}/rotate"),
    ("POST", "/api/skills/import-directory"),
    ("POST", "/api/skills/import-directory/preview"),
    ("POST", "/gateway/v1/runtime/register"),
    ("POST", "/gateway/v1/runtime/register/status"),
}

INTERNAL_HTTP: set[tuple[str, str]] = {
    ("POST", "/api/runtime/tasks/{task_id}/authorize"),
    ("POST", "/api/runtime/tasks/{task_id}/heartbeat"),
    ("POST", "/api/runtime/tasks/{task_id}/complete"),
    ("GET", "/gateway/v1/runtime/session"),
    ("POST", "/gateway/v1/runtime/tasks"),
    ("POST", "/gateway/v1/runtime/authorize"),
    ("POST", "/gateway/v1/runtime/heartbeat"),
    ("POST", "/gateway/v1/runtime/complete"),
}

NEEDS_PREREQ_WS: set[str] = set()
INTERNAL_WS: set[str] = set()


class AuditFailure(RuntimeError):
    pass


@dataclass
class RouteResult:
    method: str
    path: str
    classification: str
    status: str
    status_code: int | None
    note: str


class FakeOpenAIHandler(BaseHTTPRequestHandler):
    server_version = "FakeOpenAI/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self._write_json(400, {"error": {"message": "invalid json"}})
            return

        if self.path.rstrip("/").endswith("/chat/completions"):
            message_text = self._build_message_text(payload)
            response = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": str(payload.get("model") or "audit-model"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": message_text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 7,
                    "completion_tokens": 1,
                    "total_tokens": 8,
                },
            }
            self._write_json(200, response)
            return

        self._write_json(404, {"error": {"message": f"unsupported path: {self.path}"}})

    def _build_message_text(self, payload: dict[str, Any]) -> str:
        messages = payload.get("messages") or []
        prompt = ""
        for item in messages:
            if isinstance(item, dict):
                prompt += f" {item.get('content', '')}"
        lowered = prompt.lower()
        if "exactly ok" in lowered or "reply with ok" in lowered or "short ok" in lowered:
            return "OK"
        if "responses" in lowered:
            return "responses-ok"
        if "agent" in lowered:
            return "agent-ok"
        return "audit-ok"

    def _write_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeOpenAIServer:
    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAIHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def discover_http_routes() -> list[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not (route.path == "/health" or route.path.startswith("/api/") or route.path.startswith("/gateway/v1/")):
            continue
        for method in sorted(route.methods):
            if method in {"HEAD", "OPTIONS"}:
                continue
            routes.add((method, route.path))
    return sorted(routes)


def discover_ws_routes() -> list[str]:
    routes: set[str] = set()
    for route in app.routes:
        if not isinstance(route, APIWebSocketRoute):
            continue
        if route.path.startswith("/gateway/v1/"):
            routes.add(route.path)
    return sorted(routes)


def create_skill_fixture(root: Path) -> Path:
    skill_root = root / f"skill-import-{uuid.uuid4().hex[:8]}"
    skill_dir = skill_root / "audit-skill"
    scripts_dir = skill_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        "\n".join(
            [
                "# Audit Skill",
                "",
                "A local skill used for interface auditing.",
                "",
                "It is intentionally simple and safe.",
            ]
        ),
        encoding="utf-8",
    )
    (scripts_dir / "runner.py").write_text(
        "\n".join(
            [
                "def run():",
                "    return 'ok'",
            ]
        ),
        encoding="utf-8",
    )
    return skill_root


def unwrap_success(response) -> Any:
    if response.status_code != 200:
        raise AuditFailure(f"{response.request.method} {response.request.url} -> {response.status_code}: {response.text}")
    payload = response.json()
    if payload.get("code") != 0:
        raise AuditFailure(f"{response.request.method} {response.request.url} wrapper failed: {payload}")
    return payload["data"]


def wait_for_task(client: TestClient, headers: dict[str, str], task_id: int, timeout_seconds: int = 45) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_payload: dict[str, Any] | None = None
    while time.time() < deadline:
        last_payload = unwrap_success(client.get(f"/api/attack-tasks/{task_id}", headers=headers))
        if last_payload["status"] in TERMINAL_TASK_STATUSES:
            return last_payload
        time.sleep(0.25)
    raise AuditFailure(f"task {task_id} did not finish in time: {last_payload}")


def choose_setting_key(settings_payload: list[dict[str, Any]]) -> tuple[str, str]:
    for item in settings_payload:
        key = str(item.get("setting_key") or "")
        field_meta = item.get("field_meta") or {}
        if field_meta.get("control") != "password":
            return key, str(item.get("setting_value") or "")
    first = settings_payload[0]
    return str(first.get("setting_key") or ""), str(first.get("setting_value") or "")


def classify_http(method: str, path: str) -> str:
    key = (method, path)
    if key in INTERNAL_HTTP:
        return "internal_only"
    if key in NEEDS_PREREQ_HTTP:
        return "needs_prereq"
    return "ok"


def classify_ws(path: str) -> str:
    if path in INTERNAL_WS:
        return "internal_only"
    if path in NEEDS_PREREQ_WS:
        return "needs_prereq"
    return "ok"


def render_markdown(
    http_results: dict[tuple[str, str], RouteResult],
    ws_results: dict[str, RouteResult],
    missing_http: Iterable[tuple[str, str]],
    missing_ws: Iterable[str],
) -> str:
    lines: list[str] = []
    lines.append(f"# API Interface Audit")
    lines.append("")
    lines.append(f"- Generated at: `{now_iso()}`")
    lines.append(f"- HTTP routes discovered: `{len(http_results) + len(list(missing_http))}`")
    lines.append(f"- WebSocket routes discovered: `{len(ws_results) + len(list(missing_ws))}`")
    lines.append("")

    failed_http = [item for item in http_results.values() if item.status != "passed"]
    failed_ws = [item for item in ws_results.values() if item.status != "passed"]
    needs_http = [item for item in http_results.values() if item.classification in {"needs_prereq", "internal_only"}]
    needs_ws = [item for item in ws_results.values() if item.classification in {"needs_prereq", "internal_only"}]

    lines.append("## Findings")
    if not failed_http and not failed_ws and not missing_http and not missing_ws:
        lines.append("")
        lines.append("- No broken interface was found in the exercised coverage.")
    else:
        lines.append("")
        if failed_http:
            lines.append("- Failed HTTP routes:")
            for item in failed_http:
                lines.append(f"  - `{item.method} {item.path}` -> `{item.status_code}` {item.note}")
        if failed_ws:
            lines.append("- Failed WebSocket routes:")
            for item in failed_ws:
                lines.append(f"  - `{item.path}` -> {item.note}")
        if missing_http:
            lines.append("- Untested HTTP routes:")
            for method, path in missing_http:
                lines.append(f"  - `{method} {path}`")
        if missing_ws:
            lines.append("- Untested WebSocket routes:")
            for path in missing_ws:
                lines.append(f"  - `{path}`")

    lines.append("")
    lines.append("## Prerequisite Or Internal Routes")
    lines.append("")
    if not needs_http and not needs_ws:
        lines.append("- None")
    else:
        for item in sorted(needs_http, key=lambda x: (x.method, x.path)):
            lines.append(f"- `{item.method} {item.path}` [{item.classification}] {item.note}")
        for item in sorted(needs_ws, key=lambda x: x.path):
            lines.append(f"- `{item.path}` [{item.classification}] {item.note}")

    lines.append("")
    lines.append("## HTTP Coverage")
    lines.append("")
    for item in sorted(http_results.values(), key=lambda x: (x.path, x.method)):
        lines.append(f"- `{item.method} {item.path}` [{item.classification}] `{item.status}` `{item.status_code}` {item.note}")

    lines.append("")
    lines.append("## WebSocket Coverage")
    lines.append("")
    if not ws_results:
        lines.append("- None")
    else:
        for item in sorted(ws_results.values(), key=lambda x: x.path):
            lines.append(f"- `{item.path}` [{item.classification}] `{item.status}` {item.note}")

    return "\n".join(lines) + "\n"


def main() -> int:
    http_discovered = discover_http_routes()
    ws_discovered = discover_ws_routes()
    http_results: dict[tuple[str, str], RouteResult] = {}
    ws_results: dict[str, RouteResult] = {}
    fake_server = FakeOpenAIServer()
    fake_server.start()

    def record_http(method: str, path: str, *, status_code: int | None, note: str, passed: bool = True) -> None:
        http_results[(method, path)] = RouteResult(
            method=method,
            path=path,
            classification=classify_http(method, path),
            status="passed" if passed else "failed",
            status_code=status_code,
            note=note,
        )

    def record_ws(path: str, *, note: str, passed: bool = True) -> None:
        ws_results[path] = RouteResult(
            method="WS",
            path=path,
            classification=classify_ws(path),
            status="passed" if passed else "failed",
            status_code=None,
            note=note,
        )

    try:
        with TestClient(app) as client:
            health = client.get("/health")
            if health.status_code != 200:
                raise AuditFailure(f"/health failed: {health.status_code} {health.text}")
            if health.json().get("status") != "ok":
                raise AuditFailure(f"/health unexpected payload: {health.json()}")
            record_http("GET", "/health", status_code=health.status_code, note="plain health check passed")

            admin_login = unwrap_success(
                client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
            )
            analyst_login = unwrap_success(
                client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
            )
            record_http(
                "POST",
                "/api/auth/login",
                status_code=200,
                note="verified both admin and analyst credential login",
            )

            admin_headers = {"Authorization": f"Bearer {admin_login['access_token']}"}
            analyst_headers = {"Authorization": f"Bearer {analyst_login['access_token']}"}

            admin_me = unwrap_success(client.get("/api/auth/me", headers=admin_headers))
            analyst_me = unwrap_success(client.get("/api/auth/me", headers=analyst_headers))
            if admin_me["username"] != "admin" or analyst_me["username"] != "analyst":
                raise AuditFailure("/api/auth/me returned unexpected users")
            record_http("GET", "/api/auth/me", status_code=200, note="verified admin and analyst session context")

            main_endpoint = unwrap_success(
                client.post(
                    "/api/ai-endpoints",
                    headers=admin_headers,
                    json={
                        "endpoint_key": "audit-endpoint-main",
                        "display_name": "Audit Endpoint Main",
                        "endpoint_group": "audit",
                        "provider_type": "openai_compatible",
                        "base_url": fake_server.base_url,
                        "api_key": "audit-key",
                        "model_name": "audit-model",
                        "enabled": True,
                        "is_default": True,
                        "protection_enabled": True,
                        "protection_mode": "observe",
                        "description": "Primary endpoint for interface audit",
                    },
                )
            )
            delete_endpoint = unwrap_success(
                client.post(
                    "/api/ai-endpoints",
                    headers=admin_headers,
                    json={
                        "endpoint_key": "audit-endpoint-delete",
                        "display_name": "Audit Endpoint Delete",
                        "endpoint_group": "audit",
                        "provider_type": "openai_compatible",
                        "base_url": fake_server.base_url,
                        "api_key": "audit-key",
                        "model_name": "audit-model",
                        "enabled": True,
                        "is_default": False,
                        "protection_enabled": False,
                        "protection_mode": "off",
                        "description": "Delete route coverage endpoint",
                    },
                )
            )
            cleanup_endpoint = unwrap_success(
                client.post(
                    "/api/ai-endpoints",
                    headers=admin_headers,
                    json={
                        "endpoint_key": "smoke-cleanup-endpoint",
                        "display_name": "Smoke Cleanup Endpoint",
                        "endpoint_group": "smoke",
                        "provider_type": "openai_compatible",
                        "base_url": "http://127.0.0.1:9/v1",
                        "api_key": "",
                        "model_name": "unused-model",
                        "enabled": True,
                        "is_default": False,
                        "protection_enabled": False,
                        "protection_mode": "off",
                        "description": "Demo cleanup candidate",
                    },
                )
            )
            main_endpoint_id = int(main_endpoint["id"])
            delete_endpoint_id = int(delete_endpoint["id"])
            cleanup_endpoint_id = int(cleanup_endpoint["id"])
            record_http(
                "POST",
                "/api/ai-endpoints",
                status_code=200,
                note="created main, delete-only, and cleanup-candidate endpoints",
            )

            ai_endpoint_list = unwrap_success(client.get("/api/ai-endpoints", headers=admin_headers))
            if int((ai_endpoint_list.get("summary") or {}).get("total") or 0) < 3:
                raise AuditFailure("ai endpoint list did not include created endpoints")
            record_http("GET", "/api/ai-endpoints", status_code=200, note="list route returned created endpoints")

            main_endpoint_detail = unwrap_success(client.get(f"/api/ai-endpoints/{main_endpoint_id}", headers=admin_headers))
            if main_endpoint_detail["endpoint_key"] != "audit-endpoint-main":
                raise AuditFailure("ai endpoint detail payload mismatch")
            record_http(
                "GET",
                "/api/ai-endpoints/{endpoint_id}",
                status_code=200,
                note=f"detail route verified with endpoint #{main_endpoint_id}",
            )

            initial_mcp_policy = unwrap_success(
                client.get(f"/api/ai-endpoints/{main_endpoint_id}/mcp-policy", headers=admin_headers)
            )
            if initial_mcp_policy["servers"] or initial_mcp_policy["capabilities"]:
                raise AuditFailure("fresh audit endpoint should not start with endpoint-level MCP rows")
            record_http(
                "GET",
                "/api/ai-endpoints/{endpoint_id}/mcp-policy",
                status_code=200,
                note=f"loaded empty MCP policy profile for endpoint #{main_endpoint_id}",
            )

            updated_mcp_policy = unwrap_success(
                client.put(
                    f"/api/ai-endpoints/{main_endpoint_id}/mcp-policy",
                    headers=admin_headers,
                    json={
                        "servers": [
                            {
                                "server_name": "filesystem",
                                "server_label": "Filesystem",
                                "enabled": True,
                                "trust_mode": "trusted",
                                "require_ticket": True,
                                "require_approval": False,
                                "allowed_scopes": ["read", "list"],
                            }
                        ],
                        "capabilities": [
                            {
                                "server_name": "filesystem",
                                "capability_name": "read_*",
                                "capability_label": "Read Files",
                                "enabled": True,
                                "risk_level": "low",
                                "approval_mode": "inherit",
                                "allowed_scopes": ["read", "list"],
                            }
                        ],
                    },
                )
            )
            if len(updated_mcp_policy["servers"]) != 1 or len(updated_mcp_policy["capabilities"]) != 1:
                raise AuditFailure("endpoint MCP policy update did not persist the supplied profile")
            record_http(
                "PUT",
                "/api/ai-endpoints/{endpoint_id}/mcp-policy",
                status_code=200,
                note=f"saved endpoint-scoped MCP server and capability policy for endpoint #{main_endpoint_id}",
            )

            templated_mcp_policy = unwrap_success(
                client.post(
                    f"/api/ai-endpoints/{main_endpoint_id}/mcp-policy/apply-template",
                    headers=admin_headers,
                    json={"template_key": "openclaw_balanced"},
                )
            )
            if templated_mcp_policy["policy_summary"]["matched_template_key"] != "openclaw_balanced":
                raise AuditFailure("endpoint MCP policy template apply did not report the matched template")
            record_http(
                "POST",
                "/api/ai-endpoints/{endpoint_id}/mcp-policy/apply-template",
                status_code=200,
                note=f"applied predefined MCP template openclaw_balanced to endpoint #{main_endpoint_id}",
            )

            batch_updated_endpoints = unwrap_success(
                client.post(
                    "/api/ai-endpoints/batch-update",
                    headers=admin_headers,
                    json={
                        "ids": [main_endpoint_id, delete_endpoint_id],
                        "enabled": True,
                        "protection_enabled": True,
                        "protection_mode": "observe",
                        "endpoint_group": "audit-batch",
                    },
                )
            )
            if int((batch_updated_endpoints.get("summary") or {}).get("total") or 0) < 2:
                raise AuditFailure("ai endpoint batch update did not return updated items")
            record_http(
                "POST",
                "/api/ai-endpoints/batch-update",
                status_code=200,
                note="batch updated endpoint group and protection flags",
            )

            updated_main_endpoint = unwrap_success(
                client.put(
                    f"/api/ai-endpoints/{main_endpoint_id}",
                    headers=admin_headers,
                    json={
                        "display_name": "Audit Endpoint Main Updated",
                        "description": "Updated during interface audit",
                        "protection_mode": "enforce",
                    },
                )
            )
            if updated_main_endpoint["display_name"] != "Audit Endpoint Main Updated":
                raise AuditFailure("ai endpoint update did not persist display_name")
            record_http(
                "PUT",
                "/api/ai-endpoints/{endpoint_id}",
                status_code=200,
                note=f"update route verified with endpoint #{main_endpoint_id}",
            )

            endpoint_test = unwrap_success(client.post(f"/api/ai-endpoints/{main_endpoint_id}/test", headers=admin_headers))
            if endpoint_test.get("raw_output_text") != "OK" or endpoint_test.get("request_verified") is not True:
                raise AuditFailure("ai endpoint test did not receive expected fake provider response")
            record_http(
                "POST",
                "/api/ai-endpoints/{endpoint_id}/test",
                status_code=200,
                note="requires reachable upstream; exercised against local fake OpenAI-compatible server",
            )

            cleanup_payload = unwrap_success(client.post("/api/ai-endpoints/cleanup-candidates", headers=admin_headers))
            deleted_cleanup_ids = {int(item["id"]) for item in cleanup_payload["items"]}
            if cleanup_endpoint_id not in deleted_cleanup_ids:
                raise AuditFailure("cleanup-candidates did not remove the demo cleanup endpoint")
            record_http(
                "POST",
                "/api/ai-endpoints/cleanup-candidates",
                status_code=200,
                note="removed demo-only endpoint candidates without active usage",
            )

            deleted_endpoint_payload = unwrap_success(
                client.delete(f"/api/ai-endpoints/{delete_endpoint_id}", headers=admin_headers)
            )
            if int(deleted_endpoint_payload["id"]) != delete_endpoint_id:
                raise AuditFailure("ai endpoint delete route returned unexpected endpoint id")
            record_http(
                "DELETE",
                "/api/ai-endpoints/{endpoint_id}",
                status_code=200,
                note=f"delete route verified with endpoint #{delete_endpoint_id}",
            )

            user_list = unwrap_success(client.get("/api/users", headers=admin_headers))
            if user_list["total"] < 2:
                raise AuditFailure("user list did not include bootstrap users")
            record_http("GET", "/api/users", status_code=200, note="listed bootstrap users")

            created_user = unwrap_success(
                client.post(
                    "/api/users",
                    headers=admin_headers,
                    json={
                        "username": f"audit_{uuid.uuid4().hex[:8]}",
                        "real_name": "API Audit User",
                        "email": f"audit-{uuid.uuid4().hex[:8]}@example.com",
                        "password": "AuditPass123",
                        "status": "active",
                        "roles": ["analyst"],
                    },
                )
            )
            created_user_id = int(created_user["id"])
            record_http("POST", "/api/users", status_code=200, note=f"created analyst user #{created_user_id}")

            fetched_user = unwrap_success(client.get(f"/api/users/{created_user_id}", headers=admin_headers))
            if int(fetched_user["id"]) != created_user_id:
                raise AuditFailure("get user route returned unexpected user")
            record_http(
                "GET",
                "/api/users/{user_id}",
                status_code=200,
                note=f"detail route verified with user #{created_user_id}",
            )

            updated_user = unwrap_success(
                client.put(
                    f"/api/users/{created_user_id}",
                    headers=admin_headers,
                    json={
                        "real_name": "API Audit User Updated",
                        "email": f"updated-{uuid.uuid4().hex[:8]}@example.com",
                        "status": "active",
                        "roles": ["analyst"],
                    },
                )
            )
            if "Updated" not in updated_user["real_name"]:
                raise AuditFailure("user update did not persist real_name")
            record_http(
                "PUT",
                "/api/users/{user_id}",
                status_code=200,
                note=f"update route verified with user #{created_user_id}",
            )

            unwrap_success(
                client.post(
                    f"/api/users/{created_user_id}/reset-password",
                    headers=admin_headers,
                    json={"new_password": "AuditPass456"},
                )
            )
            record_http(
                "POST",
                "/api/users/{user_id}/reset-password",
                status_code=200,
                note=f"password reset verified for user #{created_user_id}",
            )

            unwrap_success(
                client.post(
                    f"/api/users/{created_user_id}/status",
                    headers=admin_headers,
                    json={"status": "disabled"},
                )
            )
            record_http(
                "POST",
                "/api/users/{user_id}/status",
                status_code=200,
                note=f"status update verified for user #{created_user_id}",
            )

            unwrap_success(
                client.post(
                    f"/api/users/{created_user_id}/roles",
                    headers=admin_headers,
                    json={"roles": ["analyst"]},
                )
            )
            record_http(
                "POST",
                "/api/users/{user_id}/roles",
                status_code=200,
                note=f"role update verified for user #{created_user_id}",
            )

            deleted_user = unwrap_success(client.delete(f"/api/users/{created_user_id}", headers=admin_headers))
            if int(deleted_user["id"]) != created_user_id:
                raise AuditFailure("delete user route returned unexpected user id")
            record_http(
                "DELETE",
                "/api/users/{user_id}",
                status_code=200,
                note=f"delete route verified for user #{created_user_id}",
            )

            asset_list = unwrap_success(client.get("/api/assets", headers=admin_headers))
            record_http("GET", "/api/assets", status_code=200, note=f"listed {asset_list['total']} assets")

            created_asset = unwrap_success(
                client.post(
                    "/api/assets",
                    headers=admin_headers,
                    json={
                        "asset_name": "API Audit Asset",
                        "asset_type": "path",
                        "asset_path": "/srv/audit/asset",
                        "risk_level": "medium",
                        "status": "monitoring",
                    },
                )
            )
            created_asset_id = int(created_asset["id"])
            record_http("POST", "/api/assets", status_code=200, note=f"created asset #{created_asset_id}")

            updated_asset = unwrap_success(
                client.put(
                    f"/api/assets/{created_asset_id}",
                    headers=admin_headers,
                    json={
                        "asset_name": "API Audit Asset Updated",
                        "asset_type": "path",
                        "asset_path": "/srv/audit/asset-updated",
                        "risk_level": "high",
                        "status": "protected",
                    },
                )
            )
            if updated_asset["risk_level"] != "high":
                raise AuditFailure("asset update did not persist risk level")
            record_http(
                "PUT",
                "/api/assets/{asset_id}",
                status_code=200,
                note=f"update route verified with asset #{created_asset_id}",
            )

            whitelists = unwrap_success(client.get(f"/api/assets/{created_asset_id}/whitelists", headers=admin_headers))
            record_http(
                "GET",
                "/api/assets/{asset_id}/whitelists",
                status_code=200,
                note=f"whitelist list verified for asset #{created_asset_id}",
            )
            if "field_meta" not in whitelists:
                raise AuditFailure("asset whitelist list did not include field metadata")

            created_whitelist = unwrap_success(
                client.post(
                    f"/api/assets/{created_asset_id}/whitelists",
                    headers=admin_headers,
                    json={
                        "whitelist_type": "path",
                        "rule_value": "/srv/audit/**",
                        "description": "audit allow rule",
                    },
                )
            )
            whitelist_id = int(created_whitelist["id"])
            record_http(
                "POST",
                "/api/assets/{asset_id}/whitelists",
                status_code=200,
                note=f"created whitelist #{whitelist_id} for asset #{created_asset_id}",
            )

            deleted_whitelist = unwrap_success(
                client.delete(f"/api/assets/whitelists/{whitelist_id}", headers=admin_headers)
            )
            if int(deleted_whitelist["id"]) != whitelist_id:
                raise AuditFailure("asset whitelist delete returned unexpected whitelist id")
            record_http(
                "DELETE",
                "/api/assets/whitelists/{whitelist_id}",
                status_code=200,
                note=f"deleted whitelist #{whitelist_id}",
            )

            unwrap_success(client.get("/api/samples/summary", headers=admin_headers))
            record_http("GET", "/api/samples/summary", status_code=200, note="sample summary loaded")
            unwrap_success(client.get("/api/samples/sections", headers=admin_headers))
            record_http("GET", "/api/samples/sections", status_code=200, note="sample sections loaded")
            unwrap_success(client.get("/api/samples/packs", headers=admin_headers))
            record_http("GET", "/api/samples/packs", status_code=200, note="sample packs loaded")

            sample_list = unwrap_success(client.get("/api/samples?page=1&page_size=3", headers=admin_headers))
            sample_items = sample_list["items"]
            if not sample_items:
                raise AuditFailure("sample list is empty")
            sample_ids = [str(item["id"]) for item in sample_items[:2]]
            sample_id = sample_ids[0]
            record_http("GET", "/api/samples", status_code=200, note=f"listed samples including {sample_id}")

            sample_detail = unwrap_success(client.get(f"/api/samples/{sample_id}", headers=admin_headers))
            if str(sample_detail["id"]) != sample_id:
                raise AuditFailure("sample detail returned unexpected id")
            record_http(
                "GET",
                "/api/samples/{sample_id}",
                status_code=200,
                note=f"detail route verified with sample {sample_id}",
            )

            worker_status = unwrap_success(client.get("/api/attack-tasks/worker/status", headers=admin_headers))
            if "status" not in worker_status:
                raise AuditFailure("worker status payload missing status field")
            record_http("GET", "/api/attack-tasks/worker/status", status_code=200, note="worker status route responded")

            control_task = unwrap_success(
                client.post(
                    "/api/attack-tasks",
                    headers=admin_headers,
                    json={
                        "task_name": f"control-task-{uuid.uuid4().hex[:8]}",
                        "attack_type": "control_audit",
                        "target_agent": "audit-control",
                        "ai_endpoint_id": main_endpoint_id,
                        "params_json": {
                            "execution_mode": "runtime_callback",
                            "source_type": "api_audit_control",
                        },
                    },
                )
            )
            control_task_id = int(control_task["id"])
            record_http(
                "POST",
                "/api/attack-tasks",
                status_code=200,
                note=f"created runtime-callback control task #{control_task_id}",
            )

            control_detail = unwrap_success(client.get(f"/api/attack-tasks/{control_task_id}", headers=admin_headers))
            if int(control_detail["id"]) != control_task_id:
                raise AuditFailure("attack task detail returned unexpected id")
            record_http(
                "GET",
                "/api/attack-tasks/{task_id}",
                status_code=200,
                note=f"detail route verified with task #{control_task_id}",
            )

            live_log = unwrap_success(client.get(f"/api/attack-tasks/{control_task_id}/live-log", headers=admin_headers))
            if "live_log" not in live_log:
                raise AuditFailure("live log payload missing live_log field")
            record_http(
                "GET",
                "/api/attack-tasks/{task_id}/live-log",
                status_code=200,
                note=f"live log route verified with task #{control_task_id}",
            )

            paused = unwrap_success(client.post(f"/api/attack-tasks/{control_task_id}/pause", headers=admin_headers))
            if paused["task"]["status"] != "paused_ready":
                raise AuditFailure("pause route did not move task to paused_ready")
            record_http(
                "POST",
                "/api/attack-tasks/{task_id}/pause",
                status_code=200,
                note=f"paused ready task #{control_task_id}",
            )

            resumed = unwrap_success(client.post(f"/api/attack-tasks/{control_task_id}/resume", headers=admin_headers))
            if resumed["task"]["status"] != "ready":
                raise AuditFailure("resume route did not move task back to ready")
            record_http(
                "POST",
                "/api/attack-tasks/{task_id}/resume",
                status_code=200,
                note=f"resumed paused task #{control_task_id}",
            )

            cancelled = unwrap_success(client.post(f"/api/attack-tasks/{control_task_id}/cancel", headers=admin_headers))
            if cancelled["task"]["status"] != "cancelled":
                raise AuditFailure("cancel route did not move task to cancelled")
            record_http(
                "POST",
                "/api/attack-tasks/{task_id}/cancel",
                status_code=200,
                note=f"cancelled task #{control_task_id}",
            )

            retried = unwrap_success(
                client.post(
                    f"/api/attack-tasks/{control_task_id}/retry",
                    headers=admin_headers,
                    json={},
                )
            )
            if retried["task"]["status"] not in {"queued", "ready"}:
                raise AuditFailure("retry route returned unexpected status")
            record_http(
                "POST",
                "/api/attack-tasks/{task_id}/retry",
                status_code=200,
                note=f"retried cancelled task #{control_task_id}",
            )

            deleted_task = unwrap_success(client.delete(f"/api/attack-tasks/{control_task_id}", headers=admin_headers))
            if int(deleted_task["id"]) != control_task_id:
                raise AuditFailure("delete task route returned unexpected task id")
            record_http(
                "DELETE",
                "/api/attack-tasks/{task_id}",
                status_code=200,
                note=f"deleted task #{control_task_id}",
            )

            callback_task = unwrap_success(
                client.post(
                    "/api/attack-tasks",
                    headers=admin_headers,
                    json={
                        "task_name": f"runtime-callback-{uuid.uuid4().hex[:8]}",
                        "attack_type": "runtime_callback_audit",
                        "target_agent": "audit-runtime-callback",
                        "ai_endpoint_id": main_endpoint_id,
                        "params_json": {
                            "execution_mode": "runtime_callback",
                            "source_type": "api_runtime_callback",
                        },
                    },
                )
            )
            callback_task_id = int(callback_task["id"])

            callback_authorize = unwrap_success(
                client.post(
                    f"/api/runtime/tasks/{callback_task_id}/authorize",
                    headers=admin_headers,
                    json={
                        "runtime_name": "api-runtime",
                        "runtime_task_ref": f"ref-{callback_task_id}",
                        "action_type": "runtime_audit",
                        "input_text": "safe runtime callback request",
                        "requested_scopes": ["audit"],
                    },
                )
            )
            if int(callback_authorize["task"]["id"]) != callback_task_id:
                raise AuditFailure("runtime authorize route returned unexpected task id")
            record_http(
                "POST",
                "/api/runtime/tasks/{task_id}/authorize",
                status_code=200,
                note="runtime callback authorize works but only makes sense for runtime_callback tasks",
            )

            callback_heartbeat = unwrap_success(
                client.post(
                    f"/api/runtime/tasks/{callback_task_id}/heartbeat",
                    headers=admin_headers,
                    json={
                        "runtime_name": "api-runtime",
                        "runtime_task_ref": f"ref-{callback_task_id}",
                        "status": "running",
                        "message": "callback running",
                        "progress": 30,
                    },
                )
            )
            if callback_heartbeat["status"] != "running":
                raise AuditFailure("runtime heartbeat did not set task to running")
            record_http(
                "POST",
                "/api/runtime/tasks/{task_id}/heartbeat",
                status_code=200,
                note="runtime callback heartbeat is an internal actor endpoint",
            )

            callback_complete = unwrap_success(
                client.post(
                    f"/api/runtime/tasks/{callback_task_id}/complete",
                    headers=admin_headers,
                    json={
                        "runtime_name": "api-runtime",
                        "runtime_task_ref": f"ref-{callback_task_id}",
                        "status": "done",
                        "summary": "runtime callback complete",
                        "raw_response_json": {"result": "ok"},
                        "report_type": "runtime_execution",
                    },
                )
            )
            callback_event_id = int(callback_complete["event"]["id"])
            callback_report_id = int(callback_complete["report"]["id"])
            record_http(
                "POST",
                "/api/runtime/tasks/{task_id}/complete",
                status_code=200,
                note="runtime callback completion is internal and requires a callback task lifecycle",
            )

            sample_task_response = unwrap_success(
                client.post(
                    "/api/attack-tasks/from-sample",
                    headers=admin_headers,
                    json={
                        "sample_id": sample_id,
                        "target_agent": "audit-sample-agent",
                        "ai_endpoint_id": main_endpoint_id,
                        "task_name": f"audit-sample-{uuid.uuid4().hex[:8]}",
                        "auto_run": False,
                        "params_json": {"execution_mode": "worker"},
                    },
                )
            )
            sample_task_id = int(sample_task_response["task"]["id"])
            record_http(
                "POST",
                "/api/attack-tasks/from-sample",
                status_code=200,
                note=f"created sample task #{sample_task_id} without auto-run",
            )

            batch_from_samples = unwrap_success(
                client.post(
                    "/api/attack-tasks/batch-from-samples",
                    headers=admin_headers,
                    json={
                        "sample_ids": sample_ids,
                        "target_agent": "audit-batch-agent",
                        "ai_endpoint_id": main_endpoint_id,
                        "params_json": {"execution_mode": "worker"},
                        "auto_run": False,
                    },
                )
            )
            batch_task_ids = [int(item["id"]) for item in batch_from_samples["items"]]
            if not batch_task_ids:
                raise AuditFailure("batch-from-samples did not create any tasks")
            record_http(
                "POST",
                "/api/attack-tasks/batch-from-samples",
                status_code=200,
                note=f"created batch tasks {batch_task_ids}",
            )

            dispatch_payload = unwrap_success(
                client.post(
                    "/api/attack-tasks/dispatch",
                    headers=admin_headers,
                    json={"task_ids": batch_task_ids},
                )
            )
            if not dispatch_payload["items"]:
                raise AuditFailure("dispatch route did not return dispatched tasks")
            record_http(
                "POST",
                "/api/attack-tasks/dispatch",
                status_code=200,
                note=f"dispatched batch tasks {batch_task_ids}",
            )

            attack_task_list = unwrap_success(
                client.get(
                    f"/api/attack-tasks?page=1&page_size=10&ai_endpoint_id={main_endpoint_id}",
                    headers=admin_headers,
                )
            )
            if attack_task_list["total"] < 1:
                raise AuditFailure("attack task list did not return scoped tasks")
            record_http(
                "GET",
                "/api/attack-tasks",
                status_code=200,
                note="list route verified with ai_endpoint_id filter",
            )

            run_payload = unwrap_success(client.post(f"/api/attack-tasks/{sample_task_id}/run", headers=admin_headers))
            if int(run_payload["task"]["id"]) != sample_task_id:
                raise AuditFailure("run route returned unexpected task id")
            record_http(
                "POST",
                "/api/attack-tasks/{task_id}/run",
                status_code=200,
                note=f"queued sample task #{sample_task_id} for execution",
            )

            completed_sample_task = wait_for_task(client, admin_headers, sample_task_id)
            if completed_sample_task["status"] != "done":
                raise AuditFailure(f"sample task finished with status {completed_sample_task['status']}")
            sample_event_id = int(completed_sample_task["latest_event_id"])
            sample_report_id = int(completed_sample_task["latest_report_id"])

            reports_list = unwrap_success(client.get("/api/reports?page=1&page_size=20", headers=admin_headers))
            if reports_list["total"] < 1:
                raise AuditFailure("report list did not return generated reports")
            record_http("GET", "/api/reports", status_code=200, note="listed generated reports")

            fetched_report = unwrap_success(client.get(f"/api/reports/{sample_report_id}", headers=admin_headers))
            if int(fetched_report["id"]) != sample_report_id:
                raise AuditFailure("report detail returned unexpected id")
            record_http(
                "GET",
                "/api/reports/{report_id}",
                status_code=200,
                note=f"detail route verified with report #{sample_report_id}",
            )

            exported_report = unwrap_success(
                client.post(f"/api/reports/{sample_report_id}/export?format=docx", headers=admin_headers)
            )
            if exported_report["artifact_format"] != "docx":
                raise AuditFailure("report export did not return docx artifact metadata")
            record_http(
                "POST",
                "/api/reports/{report_id}/export",
                status_code=200,
                note=f"exported report #{sample_report_id} to docx",
            )

            downloaded_report = client.get(f"/api/reports/{sample_report_id}/download?format=docx", headers=admin_headers)
            if downloaded_report.status_code != 200 or downloaded_report.content[:2] != b"PK":
                raise AuditFailure("report download did not return a docx/zip payload")
            record_http(
                "GET",
                "/api/reports/{report_id}/download",
                status_code=downloaded_report.status_code,
                note=f"downloaded docx artifact for report #{sample_report_id}",
            )

            batched_report_download = client.post(
                "/api/reports/batch-download",
                headers=admin_headers,
                json={"task_ids": [sample_task_id], "include_manifest": True, "formats": ["json"]},
            )
            if batched_report_download.status_code != 200 or batched_report_download.content[:2] != b"PK":
                raise AuditFailure("report batch download did not return a zip payload")
            record_http(
                "POST",
                "/api/reports/batch-download",
                status_code=batched_report_download.status_code,
                note=f"downloaded bundled reports for task #{sample_task_id}",
            )

            security_event_list = unwrap_success(client.get("/api/security-events?page=1&page_size=20", headers=admin_headers))
            if security_event_list["total"] < 1:
                raise AuditFailure("security event list did not return events")
            record_http("GET", "/api/security-events", status_code=200, note="listed generated security events")

            fetched_event = unwrap_success(client.get(f"/api/security-events/{sample_event_id}", headers=admin_headers))
            if int(fetched_event["id"]) != sample_event_id:
                raise AuditFailure("security event detail returned unexpected id")
            record_http(
                "GET",
                "/api/security-events/{event_id}",
                status_code=200,
                note=f"detail route verified with event #{sample_event_id}",
            )

            event_report_view = unwrap_success(
                client.get(f"/api/security-events/{sample_event_id}/report-view", headers=admin_headers)
            )
            if int(event_report_view["event"]["id"]) != sample_event_id:
                raise AuditFailure("security event report view returned unexpected event id")
            record_http(
                "GET",
                "/api/security-events/{event_id}/report-view",
                status_code=200,
                note=f"report view route verified with event #{sample_event_id}",
            )

            updated_event = unwrap_success(
                client.put(
                    f"/api/security-events/{sample_event_id}/status",
                    headers=admin_headers,
                    json={"status": "allowed"},
                )
            )
            if updated_event["status"] != "allowed":
                raise AuditFailure("security event status update did not persist allowed status")
            record_http(
                "PUT",
                "/api/security-events/{event_id}/status",
                status_code=200,
                note=f"status update verified with event #{sample_event_id}",
            )

            batch_handled_events = unwrap_success(
                client.post(
                    "/api/security-events/batch-handle",
                    headers=admin_headers,
                    json={"ids": [sample_event_id, callback_event_id], "status": "suspicious"},
                )
            )
            if batch_handled_events["total"] < 2:
                raise AuditFailure("batch-handle did not return updated events")
            record_http(
                "POST",
                "/api/security-events/batch-handle",
                status_code=200,
                note=f"updated events #{sample_event_id} and #{callback_event_id}",
            )

            dashboard_overview = unwrap_success(client.get("/api/dashboard/overview", headers=admin_headers))
            if "attack_count" not in dashboard_overview:
                raise AuditFailure("dashboard overview payload missing attack_count")
            record_http("GET", "/api/dashboard/overview", status_code=200, note="dashboard overview loaded")

            dashboard_trends = unwrap_success(client.get("/api/dashboard/trends", headers=admin_headers))
            if "items" not in dashboard_trends:
                raise AuditFailure("dashboard trends payload missing items")
            record_http("GET", "/api/dashboard/trends", status_code=200, note="dashboard trends loaded")

            dashboard_sessions = unwrap_success(client.get("/api/dashboard/sessions", headers=admin_headers))
            if "items" not in dashboard_sessions:
                raise AuditFailure("dashboard sessions payload missing items")
            record_http("GET", "/api/dashboard/sessions", status_code=200, note="dashboard sessions loaded")

            defense_list = unwrap_success(client.get("/api/defense-configs?page=1&page_size=5", headers=admin_headers))
            defense_id = int(defense_list["items"][0]["id"])
            scoped_defense_list = unwrap_success(
                client.get(f"/api/defense-configs?page=1&page_size=5&ai_endpoint_id={main_endpoint_id}", headers=admin_headers)
            )
            if scoped_defense_list["total"] < 1:
                raise AuditFailure("scoped defense config list returned no items")
            record_http(
                "GET",
                "/api/defense-configs",
                status_code=200,
                note="verified both global and ai-scoped defense list variants",
            )

            batch_defense = unwrap_success(
                client.post(
                    f"/api/defense-configs/batch-update?ai_endpoint_id={main_endpoint_id}",
                    headers=admin_headers,
                    json={"ids": [defense_id], "enabled": True, "mode": "observe"},
                )
            )
            if batch_defense["total"] != 1:
                raise AuditFailure("defense batch update did not return one updated item")
            record_http(
                "POST",
                "/api/defense-configs/batch-update",
                status_code=200,
                note="verified ai-scoped batch update for defense config",
            )

            global_profile = unwrap_success(client.get("/api/defense-configs/profile", headers=admin_headers))
            scoped_profile = unwrap_success(
                client.get(f"/api/defense-configs/profile?ai_endpoint_id={main_endpoint_id}", headers=admin_headers)
            )
            if "guard_rules" not in scoped_profile:
                raise AuditFailure("scoped defense profile payload missing guard_rules")
            record_http(
                "GET",
                "/api/defense-configs/profile",
                status_code=200,
                note="verified both global and ai-scoped profile views",
            )

            scoped_profile["protected_paths"] = list(dict.fromkeys([*scoped_profile["protected_paths"], "/tmp/api-audit-path"]))
            updated_scoped_profile = unwrap_success(
                client.put(
                    f"/api/defense-configs/profile?ai_endpoint_id={main_endpoint_id}",
                    headers=admin_headers,
                    json=scoped_profile,
                )
            )
            if "/tmp/api-audit-path" not in updated_scoped_profile["protected_paths"]:
                raise AuditFailure("defense profile update did not persist protected path")
            record_http(
                "PUT",
                "/api/defense-configs/profile",
                status_code=200,
                note="verified ai-scoped defense profile update",
            )

            defense_detail = unwrap_success(
                client.get(f"/api/defense-configs/{defense_id}?ai_endpoint_id={main_endpoint_id}", headers=admin_headers)
            )
            if int(defense_detail["id"]) != defense_id:
                raise AuditFailure("defense detail returned unexpected id")
            record_http(
                "GET",
                "/api/defense-configs/{defense_id}",
                status_code=200,
                note=f"detail route verified with defense #{defense_id}",
            )

            updated_defense = unwrap_success(
                client.put(
                    f"/api/defense-configs/{defense_id}?ai_endpoint_id={main_endpoint_id}",
                    headers=admin_headers,
                    json={
                        "enabled": bool(defense_detail["enabled"]),
                        "mode": defense_detail["mode"],
                        "config_json": defense_detail["config_json"],
                    },
                )
            )
            if int(updated_defense["id"]) != defense_id:
                raise AuditFailure("defense update returned unexpected id")
            record_http(
                "PUT",
                "/api/defense-configs/{defense_id}",
                status_code=200,
                note=f"verified ai-scoped update for defense #{defense_id}",
            )

            skill_fixture_dir = create_skill_fixture(TEMP_ROOT)
            created_skill = unwrap_success(
                client.post(
                    "/api/skills",
                    headers=admin_headers,
                    json={
                        "skill_name": f"audit-skill-{uuid.uuid4().hex[:6]}",
                        "skill_type": "local",
                        "provider": "manual",
                        "source_path": str(skill_fixture_dir / "audit-skill"),
                        "trust_status": "pending",
                        "ai_endpoint_id": main_endpoint_id,
                    },
                )
            )
            direct_skill_id = int(created_skill["id"])
            record_http("POST", "/api/skills", status_code=200, note=f"created scoped skill #{direct_skill_id}")

            previewed_import = unwrap_success(
                client.post(
                    "/api/skills/import-directory/preview",
                    headers=admin_headers,
                    json={
                        "directory_path": str(skill_fixture_dir),
                        "skill_type": "plugin",
                        "provider": "imported",
                        "trust_status": "pending",
                        "recursive": True,
                        "ai_endpoint_id": main_endpoint_id,
                    },
                )
            )
            if previewed_import["detected"] < 1:
                raise AuditFailure("skill import preview detected no importable skills")
            record_http(
                "POST",
                "/api/skills/import-directory/preview",
                status_code=200,
                note="requires backend filesystem path; preview succeeded on local fixture directory",
            )

            imported_skills = unwrap_success(
                client.post(
                    "/api/skills/import-directory",
                    headers=admin_headers,
                    json={
                        "directory_path": str(skill_fixture_dir),
                        "skill_type": "plugin",
                        "provider": "imported",
                        "trust_status": "pending",
                        "recursive": True,
                        "ai_endpoint_id": main_endpoint_id,
                    },
                )
            )
            imported_skill_ids = [int(item["id"]) for item in imported_skills["items"]]
            if not imported_skill_ids:
                raise AuditFailure("skill import did not create or update any skills")
            record_http(
                "POST",
                "/api/skills/import-directory",
                status_code=200,
                note="requires backend filesystem path; import succeeded on local fixture directory",
            )

            scoped_skills = unwrap_success(
                client.get(
                    f"/api/skills?page=1&page_size=20&scan_task_page=1&scan_task_page_size=5&ai_endpoint_id={main_endpoint_id}",
                    headers=admin_headers,
                )
            )
            if scoped_skills["total"] < 1:
                raise AuditFailure("scoped skills list returned no items")
            record_http(
                "GET",
                "/api/skills",
                status_code=200,
                note="verified ai-scoped skill list with scan task metadata",
            )

            skill_id = int(imported_skill_ids[0])
            fetched_skill = unwrap_success(client.get(f"/api/skills/{skill_id}", headers=admin_headers))
            if int(fetched_skill["id"]) != skill_id:
                raise AuditFailure("skill detail returned unexpected id")
            record_http(
                "GET",
                "/api/skills/{skill_id}",
                status_code=200,
                note=f"detail route verified with skill #{skill_id}",
            )

            trusted_skill = unwrap_success(
                client.put(
                    f"/api/skills/{skill_id}/trust-status",
                    headers=admin_headers,
                    json={"trust_status": "trusted"},
                )
            )
            if trusted_skill["trust_status"] != "trusted":
                raise AuditFailure("skill trust-status update did not persist trusted")
            record_http(
                "PUT",
                "/api/skills/{skill_id}/trust-status",
                status_code=200,
                note=f"updated trust status for skill #{skill_id}",
            )

            updated_source_path = unwrap_success(
                client.put(
                    f"/api/skills/{skill_id}/source-path",
                    headers=admin_headers,
                    json={"source_path": str(skill_fixture_dir / "audit-skill" / "scripts")},
                )
            )
            if "scripts" not in updated_source_path["source_path"]:
                raise AuditFailure("skill source-path update did not persist scripts path")
            record_http(
                "PUT",
                "/api/skills/{skill_id}/source-path",
                status_code=200,
                note=f"updated source path for skill #{skill_id}",
            )

            scan_task = unwrap_success(
                client.post(
                    "/api/skills/scan",
                    headers=admin_headers,
                    json={"skill_ids": [skill_id], "ai_endpoint_id": main_endpoint_id},
                )
            )
            scan_task_id = int(scan_task["id"])
            record_http(
                "POST",
                "/api/skills/scan",
                status_code=200,
                note=f"queued skill scan task #{scan_task_id}",
            )
            unwrap_success(client.post(f"/api/attack-tasks/{scan_task_id}/run", headers=admin_headers))
            completed_scan_task = wait_for_task(client, admin_headers, scan_task_id)
            if completed_scan_task["status"] != "done":
                raise AuditFailure(f"skill scan task finished with status {completed_scan_task['status']}")

            activation_request = unwrap_success(
                client.post(
                    "/api/runtime-registry/activation-requests",
                    headers=admin_headers,
                    json={
                        "display_name": "Activation Flow Runtime",
                        "runtime_type": "agent",
                        "hostname": "activation-runtime",
                        "fingerprint": uuid.uuid4().hex,
                        "client_version": "1.0.0",
                        "ip_addresses": ["127.0.0.1"],
                        "requested_scopes": ["audit"],
                        "capabilities": ["connect"],
                        "metadata": {"origin": "api_audit"},
                        "ai_endpoint_id": main_endpoint_id,
                    },
                )
            )
            activation_runtime_id = int(activation_request["runtime"]["id"])
            activation_registration_id = str(activation_request["registration"]["registration_id"])
            record_http(
                "POST",
                "/api/runtime-registry/activation-requests",
                status_code=200,
                note=f"created activation request for runtime #{activation_runtime_id}",
            )

            issued_activation = unwrap_success(
                client.post(
                    f"/api/runtime-registry/runtimes/{activation_runtime_id}/activation-code",
                    headers=admin_headers,
                    json={
                        "display_name": "Activation Flow Runtime Updated",
                        "ai_endpoint_id": main_endpoint_id,
                        "expires_in_minutes": 10,
                    },
                )
            )
            activation_code = str(issued_activation["activation_code"])
            if not activation_code:
                raise AuditFailure("activation code issuance returned empty code")
            record_http(
                "POST",
                "/api/runtime-registry/runtimes/{runtime_id}/activation-code",
                status_code=200,
                note="requires activation_requested runtime; code issued successfully",
            )

            activate_without_auth = client.post(
                "/api/runtime-registry/activate",
                json={
                    "registration_id": activation_registration_id,
                    "activation_code": activation_code,
                },
            )
            if activate_without_auth.status_code == 200:
                activated_runtime = unwrap_success(activate_without_auth)
                record_http(
                    "POST",
                    "/api/runtime-registry/activate",
                    status_code=activate_without_auth.status_code,
                    note="bare client exchanged activation code for long-lived runtime credentials without platform login",
                )
            elif activate_without_auth.status_code == 401:
                record_http(
                    "POST",
                    "/api/runtime-registry/activate",
                    status_code=activate_without_auth.status_code,
                    note="activation-code exchange is currently protected by platform auth, so a bare client cannot use it directly",
                    passed=False,
                )
                activated_runtime = unwrap_success(
                    client.post(
                        "/api/runtime-registry/activate",
                        headers=admin_headers,
                        json={
                            "registration_id": activation_registration_id,
                            "activation_code": activation_code,
                        },
                    )
                )
            else:
                raise AuditFailure(
                    f"unexpected activation exchange status without auth: {activate_without_auth.status_code} {activate_without_auth.text}"
                )
            activation_runtime_key = str(activated_runtime["runtime_credentials"]["runtime_key"])
            activation_runtime_secret = str(activated_runtime["runtime_credentials"]["runtime_secret"])
            if not activation_runtime_key or not activation_runtime_secret:
                raise AuditFailure("runtime activation did not issue credentials")

            bound_activation_runtime = unwrap_success(
                client.post(
                    f"/api/runtime-registry/runtimes/{activation_runtime_id}/bind",
                    headers=admin_headers,
                    json={
                        "display_name": "Activation Flow Runtime Bound",
                        "ai_endpoint_id": main_endpoint_id,
                    },
                )
            )
            if int(bound_activation_runtime["runtime"]["id"]) != activation_runtime_id:
                raise AuditFailure("runtime bind returned unexpected runtime id")
            record_http(
                "POST",
                "/api/runtime-registry/runtimes/{runtime_id}/bind",
                status_code=200,
                note="requires existing runtime; binding update succeeded on active runtime",
            )

            rotated_runtime = unwrap_success(
                client.post(
                    f"/api/runtime-registry/runtimes/{activation_runtime_id}/rotate",
                    headers=admin_headers,
                )
            )
            if not rotated_runtime["runtime_secret"]:
                raise AuditFailure("runtime rotate did not return a new secret")
            record_http(
                "POST",
                "/api/runtime-registry/runtimes/{runtime_id}/rotate",
                status_code=200,
                note="requires active runtime; credential rotation succeeded",
            )

            revoked_runtime = unwrap_success(
                client.post(
                    f"/api/runtime-registry/runtimes/{activation_runtime_id}/revoke",
                    headers=admin_headers,
                )
            )
            if revoked_runtime["runtime"]["status"] != "revoked":
                raise AuditFailure("runtime revoke did not set status to revoked")
            record_http(
                "POST",
                "/api/runtime-registry/runtimes/{runtime_id}/revoke",
                status_code=200,
                note="requires existing runtime; revoked runtime credentials successfully",
            )

            rejected_request = unwrap_success(
                client.post(
                    "/api/runtime-registry/activation-requests",
                    headers=admin_headers,
                    json={
                        "display_name": "Rejected Runtime",
                        "runtime_type": "agent",
                        "hostname": "rejected-runtime",
                        "fingerprint": uuid.uuid4().hex,
                        "client_version": "1.0.0",
                        "ip_addresses": ["127.0.0.1"],
                        "requested_scopes": ["audit"],
                        "capabilities": ["connect"],
                        "metadata": {"origin": "api_audit"},
                        "ai_endpoint_id": main_endpoint_id,
                    },
                )
            )
            rejected_runtime_id = int(rejected_request["runtime"]["id"])
            rejected_runtime = unwrap_success(
                client.post(
                    f"/api/runtime-registry/runtimes/{rejected_runtime_id}/reject",
                    headers=admin_headers,
                    json={"reason": "api audit reject flow"},
                )
            )
            if rejected_runtime["runtime"]["status"] != "rejected":
                raise AuditFailure("runtime reject did not set status to rejected")
            record_http(
                "POST",
                "/api/runtime-registry/runtimes/{runtime_id}/reject",
                status_code=200,
                note="requires pending or activation-requested runtime; reject flow succeeded",
            )

            bootstrap_token = unwrap_success(
                client.post(
                    "/api/runtime-registry/tokens",
                    headers=admin_headers,
                    json={
                        "token_label": "API Audit Bootstrap Code",
                        "runtime_type": "openclaw",
                        "ai_endpoint_id": main_endpoint_id,
                        "usage_limit": 2,
                        "delivery_mode": "activation_code",
                    },
                )
            )
            bootstrap_code = str(bootstrap_token["activation_code"])
            if not bootstrap_code:
                raise AuditFailure("bootstrap token did not return activation_code")
            client_activated = unwrap_success(
                client.post(
                    "/api/runtime-registry/client-activate",
                    json={
                        "activation_code": bootstrap_code,
                        "display_name": "Bootstrap Client Runtime",
                        "runtime_type": "openclaw",
                        "hostname": "bootstrap-runtime",
                        "fingerprint": uuid.uuid4().hex,
                        "client_version": "1.0.0",
                        "ip_addresses": ["127.0.0.1"],
                        "requested_scopes": ["audit"],
                        "capabilities": ["connect"],
                        "metadata": {"origin": "api_audit"},
                    },
                )
            )
            if not client_activated["runtime_credentials"]["runtime_key"]:
                raise AuditFailure("client activation did not issue runtime credentials")
            record_http(
                "POST",
                "/api/runtime-registry/client-activate",
                status_code=200,
                note="short activation code exchanged for long-lived runtime credentials without platform login",
            )

            runtime_token = unwrap_success(
                client.post(
                    "/api/runtime-registry/tokens",
                    headers=admin_headers,
                    json={
                        "token_label": "API Audit Enrollment Token",
                        "runtime_type": "agent",
                        "ai_endpoint_id": main_endpoint_id,
                        "usage_limit": 5,
                    },
                )
            )
            token_id = int(runtime_token["token"]["id"])
            enrollment_token = str(runtime_token["enrollment_token"])
            record_http(
                "POST",
                "/api/runtime-registry/tokens",
                status_code=200,
                note=f"created enrollment token #{token_id}",
            )

            bound_token = unwrap_success(
                client.post(
                    f"/api/runtime-registry/tokens/{token_id}/bind",
                    headers=admin_headers,
                    json={"ai_endpoint_id": main_endpoint_id},
                )
            )
            if int(bound_token["token"]["id"]) != token_id:
                raise AuditFailure("token bind returned unexpected token id")
            record_http(
                "POST",
                "/api/runtime-registry/tokens/{token_id}/bind",
                status_code=200,
                note="requires existing enrollment token; bind succeeded",
            )

            gateway_registered_runtime = unwrap_success(
                client.post(
                    "/gateway/v1/runtime/register",
                    json={
                        "enrollment_token": enrollment_token,
                        "display_name": "Gateway Runtime",
                        "runtime_type": "agent",
                        "hostname": "gateway-runtime",
                        "fingerprint": uuid.uuid4().hex,
                        "client_version": "1.0.0",
                        "ip_addresses": ["127.0.0.1"],
                        "requested_scopes": ["audit"],
                        "capabilities": ["connect", "tasks"],
                        "metadata": {"origin": "api_audit"},
                    },
                )
            )
            gateway_runtime_id = int(gateway_registered_runtime["runtime"]["id"])
            gateway_registration_id = str(gateway_registered_runtime["registration"]["registration_id"])
            gateway_poll_secret = str(gateway_registered_runtime["registration"]["poll_secret"])
            record_http(
                "POST",
                "/gateway/v1/runtime/register",
                status_code=200,
                note="requires enrollment token; registration submitted and poll secret issued",
            )

            approved_gateway_runtime = unwrap_success(
                client.post(
                    f"/api/runtime-registry/runtimes/{gateway_runtime_id}/approve",
                    headers=admin_headers,
                    json={"display_name": "Gateway Runtime Approved", "ai_endpoint_id": main_endpoint_id},
                )
            )
            if approved_gateway_runtime["runtime"]["status"] != "approved":
                raise AuditFailure("runtime approve did not set status to approved")
            record_http(
                "POST",
                "/api/runtime-registry/runtimes/{runtime_id}/approve",
                status_code=200,
                note="requires pending runtime registration; approval succeeded",
            )

            runtime_registry = unwrap_success(client.get("/api/runtime-registry", headers=admin_headers))
            if not runtime_registry["runtimes"]:
                raise AuditFailure("runtime registry list returned no runtimes")
            record_http(
                "GET",
                "/api/runtime-registry",
                status_code=200,
                note="registry route returned runtimes and enrollment tokens",
            )

            gateway_status = unwrap_success(
                client.post(
                    "/gateway/v1/runtime/register/status",
                    json={"registration_id": gateway_registration_id, "poll_secret": gateway_poll_secret},
                )
            )
            runtime_credentials = gateway_status["runtime_credentials"]
            runtime_key = str(runtime_credentials["runtime_key"])
            runtime_secret = str(runtime_credentials["runtime_secret"])
            if not runtime_key or not runtime_secret:
                raise AuditFailure("gateway runtime register status did not return runtime credentials")
            record_http(
                "POST",
                "/gateway/v1/runtime/register/status",
                status_code=200,
                note="polling route only becomes useful after approval; exchanged pending registration for runtime credentials",
            )

            runtime_headers = {
                "X-Runtime-Key": runtime_key,
                "X-Runtime-Secret": runtime_secret,
                "X-Client-ID": "api-audit-runtime",
            }

            runtime_session = unwrap_success(client.get("/gateway/v1/runtime/session", headers=runtime_headers))
            if runtime_session["auth_mode"] != "runtime_secret":
                raise AuditFailure("gateway runtime session did not authenticate as runtime_secret")
            record_http(
                "GET",
                "/gateway/v1/runtime/session",
                status_code=200,
                note="internal runtime session endpoint verified with runtime credentials",
            )

            gateway_runtime_task = unwrap_success(
                client.post(
                    "/gateway/v1/runtime/tasks",
                    headers=runtime_headers,
                    json={
                        "task_name": f"gateway-runtime-task-{uuid.uuid4().hex[:8]}",
                        "attack_type": "runtime_gateway_audit",
                        "target_agent": "gateway-runtime-agent",
                        "params_json": {"source_type": "runtime_gateway"},
                    },
                )
            )
            gateway_runtime_task_id = int(gateway_runtime_task["id"])
            record_http(
                "POST",
                "/gateway/v1/runtime/tasks",
                status_code=200,
                note="internal runtime task creation succeeded after registration and approval",
            )

            gateway_authorized = unwrap_success(
                client.post(
                    "/gateway/v1/runtime/authorize",
                    headers=runtime_headers,
                    json={
                        "task_id": gateway_runtime_task_id,
                        "runtime_name": "gateway-runtime",
                        "runtime_task_ref": f"gw-{gateway_runtime_task_id}",
                        "action_type": "runtime_gateway",
                        "input_text": "safe runtime gateway operation",
                        "requested_scopes": ["audit"],
                    },
                )
            )
            if int(gateway_authorized["task"]["id"]) != gateway_runtime_task_id:
                raise AuditFailure("gateway runtime authorize returned unexpected task id")
            record_http(
                "POST",
                "/gateway/v1/runtime/authorize",
                status_code=200,
                note="internal runtime authorization callback succeeded",
            )

            gateway_heartbeat = unwrap_success(
                client.post(
                    "/gateway/v1/runtime/heartbeat",
                    headers=runtime_headers,
                    json={
                        "task_id": gateway_runtime_task_id,
                        "runtime_name": "gateway-runtime",
                        "runtime_task_ref": f"gw-{gateway_runtime_task_id}",
                        "status": "running",
                        "message": "gateway runtime running",
                        "progress": 50,
                    },
                )
            )
            if gateway_heartbeat["status"] != "running":
                raise AuditFailure("gateway runtime heartbeat did not set task running")
            record_http(
                "POST",
                "/gateway/v1/runtime/heartbeat",
                status_code=200,
                note="internal runtime heartbeat callback succeeded",
            )

            queued_runtime_command_id = enqueue_runtime_command(
                runtime_id=gateway_runtime_id,
                ai_endpoint_id=main_endpoint_id,
                source_task_id=gateway_runtime_task_id,
                command_type=RUNTIME_COMMAND_TYPE_REMOTE_SKILL_SCAN,
                payload={
                    "skill_sources": [
                        {
                            "skill_id": 0,
                            "skill_name": "audit-skill",
                            "source_path": str(REPO_ROOT),
                        }
                    ],
                    "origin": "api_interface_audit",
                },
            )
            next_runtime_command = unwrap_success(
                client.get("/gateway/v1/runtime/commands/next", headers=runtime_headers)
            )
            command_payload = next_runtime_command["command"] or {}
            if int(command_payload.get("id") or 0) != queued_runtime_command_id:
                raise AuditFailure("runtime command poll did not return the queued command")
            if str(command_payload.get("command_type") or "") != RUNTIME_COMMAND_TYPE_REMOTE_SKILL_SCAN:
                raise AuditFailure("runtime command poll returned an unexpected command type")
            record_http(
                "GET",
                "/gateway/v1/runtime/commands/next",
                status_code=200,
                note=f"runtime polled queued command #{queued_runtime_command_id} successfully",
            )

            completed_runtime_command = unwrap_success(
                client.post(
                    f"/gateway/v1/runtime/commands/{queued_runtime_command_id}/complete",
                    headers=runtime_headers,
                    json={
                        "status": "completed",
                        "summary": "audit runtime command completed",
                        "response_text": "runtime command ok",
                        "response_json": {
                            "status": "completed",
                            "command_type": RUNTIME_COMMAND_TYPE_REMOTE_SKILL_SCAN,
                        },
                        "metadata": {"origin": "api_interface_audit"},
                    },
                )
            )
            completed_command_payload = (completed_runtime_command.get("command") or {}).get("response") or {}
            if str(completed_command_payload.get("summary") or "") != "audit runtime command completed":
                raise AuditFailure("runtime command completion did not persist the completion summary")
            record_http(
                "POST",
                "/gateway/v1/runtime/commands/{command_id}/complete",
                status_code=200,
                note=f"runtime completed queued command #{queued_runtime_command_id} successfully",
            )

            gateway_completed = unwrap_success(
                client.post(
                    "/gateway/v1/runtime/complete",
                    headers=runtime_headers,
                    json={
                        "task_id": gateway_runtime_task_id,
                        "runtime_name": "gateway-runtime",
                        "runtime_task_ref": f"gw-{gateway_runtime_task_id}",
                        "status": "done",
                        "summary": "gateway runtime task completed",
                        "raw_response_json": {"reply": "ok"},
                        "report_type": "runtime_gateway",
                    },
                )
            )
            if int(gateway_completed["task"]["id"]) != gateway_runtime_task_id:
                raise AuditFailure("gateway runtime complete returned unexpected task id")
            record_http(
                "POST",
                "/gateway/v1/runtime/complete",
                status_code=200,
                note="internal runtime complete callback succeeded and produced event/report",
            )

            gateway_chat = client.post(
                "/gateway/v1/chat/completions",
                headers=admin_headers,
                json={
                    "model": "audit-model",
                    "messages": [{"role": "user", "content": "Reply with audit-ok only."}],
                    "target_selector": {"endpoint_id": main_endpoint_id},
                },
            )
            if gateway_chat.status_code != 200:
                raise AuditFailure(f"gateway chat failed: {gateway_chat.status_code} {gateway_chat.text}")
            gateway_chat_json = gateway_chat.json()
            if gateway_chat_json["choices"][0]["message"]["content"] != "audit-ok":
                raise AuditFailure("gateway chat returned unexpected completion text")
            record_http(
                "POST",
                "/gateway/v1/chat/completions",
                status_code=gateway_chat.status_code,
                note="gateway chat completion succeeded through managed AI endpoint",
            )

            gateway_responses = client.post(
                "/gateway/v1/responses",
                headers=admin_headers,
                json={
                    "model": "audit-model",
                    "input": "Return responses-ok only.",
                    "target_selector": {"endpoint_id": main_endpoint_id},
                },
            )
            if gateway_responses.status_code != 200:
                raise AuditFailure(f"gateway responses failed: {gateway_responses.status_code} {gateway_responses.text}")
            gateway_responses_json = gateway_responses.json()
            if gateway_responses_json["output"][0]["content"][0]["text"] != "responses-ok":
                raise AuditFailure("gateway responses returned unexpected content")
            record_http(
                "POST",
                "/gateway/v1/responses",
                status_code=gateway_responses.status_code,
                note="gateway responses compatibility endpoint succeeded",
            )

            gateway_agent_run = client.post(
                "/gateway/v1/agents/run",
                headers=admin_headers,
                json={
                    "model": "audit-model",
                    "runtime_name": "gateway-agent",
                    "input_text": "Return agent-ok only.",
                    "target_selector": {"endpoint_id": main_endpoint_id},
                },
            )
            if gateway_agent_run.status_code != 200:
                raise AuditFailure(f"gateway agents/run failed: {gateway_agent_run.status_code} {gateway_agent_run.text}")
            gateway_agent_run_json = gateway_agent_run.json()
            upstream_response = (gateway_agent_run_json.get("data") or {}).get("upstream_response") or {}
            upstream_choices = upstream_response.get("choices") or []
            if not upstream_choices or upstream_choices[0]["message"]["content"] != "agent-ok":
                raise AuditFailure("gateway agents/run returned unexpected output_text")
            record_http(
                "POST",
                "/gateway/v1/agents/run",
                status_code=gateway_agent_run.status_code,
                note="gateway agent run endpoint succeeded",
            )

            with client.websocket_connect(
                f"/gateway/v1/ws/chat/completions?access_token={admin_login['access_token']}"
            ) as websocket:
                websocket.send_json(
                    {
                        "model": "audit-model",
                        "messages": [{"role": "user", "content": "Reply with audit-ok only."}],
                        "target_selector": {"endpoint_id": main_endpoint_id},
                    }
                )
                seen_done = False
                while True:
                    message = websocket.receive_json()
                    if message.get("event") == "done":
                        seen_done = True
                        break
                if not seen_done:
                    raise AuditFailure("ws chat completion never emitted done")
            record_ws("/gateway/v1/ws/chat/completions", note="websocket chat completion completed successfully")

            with client.websocket_connect(
                f"/gateway/v1/ws/responses?access_token={admin_login['access_token']}"
            ) as websocket:
                websocket.send_json(
                    {
                        "model": "audit-model",
                        "input": "Return responses-ok only.",
                        "target_selector": {"endpoint_id": main_endpoint_id},
                    }
                )
                seen_done = False
                while True:
                    message = websocket.receive_json()
                    if message.get("event") == "done":
                        seen_done = True
                        break
                if not seen_done:
                    raise AuditFailure("ws responses never emitted done")
            record_ws("/gateway/v1/ws/responses", note="websocket responses completed successfully")

            with client.websocket_connect(
                f"/gateway/v1/ws/agents/run?access_token={admin_login['access_token']}"
            ) as websocket:
                websocket.send_json(
                    {
                        "model": "audit-model",
                        "runtime_name": "gateway-agent-ws",
                        "input_text": "Return agent-ok only.",
                        "target_selector": {"endpoint_id": main_endpoint_id},
                    }
                )
                seen_done = False
                while True:
                    message = websocket.receive_json()
                    if message.get("event") == "done":
                        seen_done = True
                        break
                if not seen_done:
                    raise AuditFailure("ws agents/run never emitted done")
            record_ws("/gateway/v1/ws/agents/run", note="websocket agent run completed successfully")

            settings_payload = unwrap_success(client.get("/api/system-settings", headers=admin_headers))
            if not settings_payload["items"]:
                raise AuditFailure("system settings list returned no settings")
            record_http("GET", "/api/system-settings", status_code=200, note="listed visible system settings")

            system_actions = unwrap_success(client.get("/api/system-settings/actions", headers=admin_headers))
            action_keys = {item["action_key"] for item in system_actions["items"]}
            if {"export-defense-config", "platform-backup"} - action_keys:
                raise AuditFailure("required system actions are missing from action registry")
            record_http(
                "GET",
                "/api/system-settings/actions",
                status_code=200,
                note="listed available system maintenance actions",
            )

            setting_key, setting_value = choose_setting_key(settings_payload["items"])
            updated_setting = unwrap_success(
                client.put(
                    f"/api/system-settings/{setting_key}",
                    headers=admin_headers,
                    json={"setting_value": setting_value},
                )
            )
            if (updated_setting.get("setting") or {}).get("setting_key") != setting_key:
                raise AuditFailure("system setting update returned unexpected setting key")
            record_http(
                "PUT",
                "/api/system-settings/{setting_key}",
                status_code=200,
                note=f"updated non-secret setting {setting_key} with current value",
            )

            export_action = unwrap_success(
                client.post("/api/system-settings/actions/export-defense-config", headers=admin_headers)
            )
            backup_action = unwrap_success(
                client.post("/api/system-settings/actions/platform-backup", headers=admin_headers)
            )
            if not str(export_action["output"]) or not str(backup_action["output"]):
                raise AuditFailure("system actions did not return artifact output paths")
            record_http(
                "POST",
                "/api/system-settings/actions/{action_key}",
                status_code=200,
                note="verified export-defense-config and platform-backup actions",
            )

            audit_logs = unwrap_success(client.get("/api/system-settings/audit-logs?page=1&page_size=20", headers=admin_headers))
            if audit_logs["total"] < 1:
                raise AuditFailure("audit log list returned no items")
            record_http(
                "GET",
                "/api/system-settings/audit-logs",
                status_code=200,
                note="listed audit logs after exercised write operations",
            )

    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, AuditFailure):
            error_text = str(exc)
        else:
            error_text = f"{type(exc).__name__}: {exc}"
        print(f"[api-audit] failed: {error_text}", file=sys.stderr)
        exit_code = 1
    else:
        exit_code = 0
    finally:
        try:
            stop_task_worker()
        except Exception:
            pass
        fake_server.stop()

    missing_http = [route for route in http_discovered if route not in http_results]
    missing_ws = [path for path in ws_discovered if path not in ws_results]

    report_payload = {
        "generated_at": now_iso(),
        "http_discovered": [
            {"method": method, "path": path}
            for method, path in http_discovered
        ],
        "ws_discovered": ws_discovered,
        "http_results": [
            {
                "method": item.method,
                "path": item.path,
                "classification": item.classification,
                "status": item.status,
                "status_code": item.status_code,
                "note": item.note,
            }
            for item in sorted(http_results.values(), key=lambda x: (x.path, x.method))
        ],
        "ws_results": [
            {
                "path": item.path,
                "classification": item.classification,
                "status": item.status,
                "note": item.note,
            }
            for item in sorted(ws_results.values(), key=lambda x: x.path)
        ],
        "missing_http_routes": [{"method": method, "path": path} for method, path in missing_http],
        "missing_ws_routes": missing_ws,
        "summary": {
            "http_total": len(http_discovered),
            "http_passed": sum(1 for item in http_results.values() if item.status == "passed"),
            "http_failed": sum(1 for item in http_results.values() if item.status != "passed"),
            "http_missing": len(missing_http),
            "ws_total": len(ws_discovered),
            "ws_passed": sum(1 for item in ws_results.values() if item.status == "passed"),
            "ws_failed": sum(1 for item in ws_results.values() if item.status != "passed"),
            "ws_missing": len(missing_ws),
        },
    }

    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    json_report_path = RUN_LOG_DIR / "api_interface_audit_latest.json"
    md_report_path = RUN_LOG_DIR / "api_interface_audit_latest.md"
    json_report_path.write_text(json.dumps(report_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_report_path.write_text(
        render_markdown(http_results, ws_results, missing_http, missing_ws),
        encoding="utf-8",
    )

    print(f"[api-audit] json report: {json_report_path}")
    print(f"[api-audit] markdown report: {md_report_path}")
    print(
        "[api-audit] summary: "
        f"http_passed={report_payload['summary']['http_passed']}/{report_payload['summary']['http_total']} "
        f"ws_passed={report_payload['summary']['ws_passed']}/{report_payload['summary']['ws_total']} "
        f"missing_http={report_payload['summary']['http_missing']} "
        f"missing_ws={report_payload['summary']['ws_missing']}"
    )

    shutil.rmtree(TEMP_ROOT, ignore_errors=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
