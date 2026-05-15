#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from openclaw_control_bridge import (  # noqa: E402
    BridgeConfig,
    DEFAULT_READ_ONLY_METHODS,
    build_runtime_bridge_config,
    default_profile_name,
    default_runtime_display_name,
    default_target_agent_name,
    host_and_port_from_url,
    normalize_base_url,
)
from agent_gateway_cli import (  # noqa: E402
    CLIENT_VERSION,
    PlatformClient,
    collect_local_ip_addresses,
    has_runtime_credentials,
    save_config_payload,
)


def configure_stdio_utf8() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(level: str, message: str, **fields: Any) -> None:
    suffix = ""
    if fields:
        suffix = " | " + " ".join(f"{key}={value}" for key, value in fields.items() if value not in (None, ""))
    print(f"[{now_text()}] [{level}] {message}{suffix}")


def env_text(name: str, default: str) -> str:
    value = str(os.getenv(name, default) or "").strip()
    return value or default


def env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, "") or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


PLATFORM_BASE_URL = env_text("BT_PLATFORM_BASE_URL", "http://127.0.0.1:8000")
ADMIN_USERNAME = env_text("BT_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = env_text("BT_ADMIN_PASSWORD", "admin123")
UPSTREAM_HTTP_URL = env_text("BT_OPENCLAW_UPSTREAM_HTTP_URL", "http://192.168.137.140:18789")
GATEWAY_TOKEN = env_text(
    "BT_OPENCLAW_GATEWAY_TOKEN",
    "",
)
LISTEN_HOST = env_text("BT_OPENCLAW_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = env_int("BT_OPENCLAW_LISTEN_PORT", 19090)
ACCESS_HOST = env_text("BT_OPENCLAW_ACCESS_HOST", "127.0.0.1")
REVIEW_ACTION = env_text("BT_OPENCLAW_REVIEW_ACTION", "block")
RUNTIME_TYPE = env_text("BT_OPENCLAW_RUNTIME_TYPE", "openclaw_control_bridge")
ATTACK_TYPE = env_text("BT_OPENCLAW_ATTACK_TYPE", "openclaw_control")
TOKEN_LABEL = env_text("BT_OPENCLAW_TOKEN_LABEL", "openclaw-direct-autoconnect")
MAX_CAPTURE_CHARS = env_int("BT_OPENCLAW_MAX_CAPTURE_CHARS", 16000)
PROFILE_NAME = env_text("BT_OPENCLAW_PROFILE_NAME", default_profile_name(UPSTREAM_HTTP_URL) + "-direct")
RUNTIME_DISPLAY_NAME = env_text(
    "BT_OPENCLAW_RUNTIME_DISPLAY_NAME",
    default_runtime_display_name(UPSTREAM_HTTP_URL),
)
TARGET_AGENT_NAME = env_text(
    "BT_OPENCLAW_TARGET_AGENT_NAME",
    default_target_agent_name(UPSTREAM_HTTP_URL),
)

host, port = host_and_port_from_url(UPSTREAM_HTTP_URL)
profile_slug = PROFILE_NAME.lower().replace(" ", "-").replace(":", "-").replace(".", "-")
RUNTIME_CONFIG_PATH = Path(
    env_text(
        "BT_OPENCLAW_RUNTIME_CONFIG",
        str(PROJECT_ROOT / "tools" / "agent_gateway" / "generated" / f"{profile_slug}.json"),
    )
).expanduser().resolve()
FRAME_LOG_PATH = Path(
    env_text(
        "BT_OPENCLAW_FRAME_LOG",
        str(PROJECT_ROOT / "run_logs" / f"openclaw-control-{host}-{port}.jsonl"),
    )
).expanduser().resolve()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def http_json(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    bearer_token: str | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body_text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body_text}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"连接失败: {exc}") from exc
    try:
        response_payload = json.loads(body_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"接口返回了非 JSON 内容: {body_text[:200]}") from exc
    if response_payload.get("code") != 0:
        raise RuntimeError(
            f"平台接口返回业务错误: code={response_payload.get('code')} message={response_payload.get('message')}"
        )
    return dict(response_payload.get("data") or {})


def login_admin() -> str:
    log("INFO", "正在登录保护平台管理员账号", platform=PLATFORM_BASE_URL, username=ADMIN_USERNAME)
    data = http_json(
        "POST",
        f"{normalize_base_url(PLATFORM_BASE_URL)}/api/auth/login",
        payload={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    token = str(data.get("access_token") or "").strip()
    if not token:
        raise RuntimeError("管理员登录成功，但没有拿到 access_token。")
    return token


def create_enrollment_token(admin_token: str) -> str:
    log("INFO", "正在生成一次性 Runtime 注册码", label=TOKEN_LABEL)
    data = http_json(
        "POST",
        f"{normalize_base_url(PLATFORM_BASE_URL)}/api/runtime-registry/tokens",
        payload={
            "token_label": TOKEN_LABEL,
            "runtime_type": RUNTIME_TYPE,
            "usage_limit": 1,
        },
        bearer_token=admin_token,
    )
    enrollment_token = str(data.get("enrollment_token") or "").strip()
    if not enrollment_token:
        raise RuntimeError("注册码创建成功，但没有返回 enrollment_token。")
    return enrollment_token


def approve_runtime(admin_token: str, runtime_id: int) -> None:
    log("INFO", "正在自动审批 Runtime 注册", runtime_id=runtime_id)
    http_json(
        "POST",
        f"{normalize_base_url(PLATFORM_BASE_URL)}/api/runtime-registry/runtimes/{runtime_id}/approve",
        payload={"display_name": RUNTIME_DISPLAY_NAME},
        bearer_token=admin_token,
    )


def build_runtime_config() -> dict[str, Any]:
    upstream_ws_url = (
        "wss://" + normalize_base_url(UPSTREAM_HTTP_URL).split("://", 1)[1]
        if normalize_base_url(UPSTREAM_HTTP_URL).startswith("https://")
        else "ws://" + normalize_base_url(UPSTREAM_HTTP_URL).split("://", 1)[1]
    )
    return build_runtime_bridge_config(
        profile_name=PROFILE_NAME,
        platform_base_url=PLATFORM_BASE_URL,
        verify_platform_tls=True,
        runtime_display_name=RUNTIME_DISPLAY_NAME,
        runtime_type=RUNTIME_TYPE,
        upstream_http_url=normalize_base_url(UPSTREAM_HTTP_URL),
        upstream_ws_url=upstream_ws_url,
        listen_host=LISTEN_HOST,
        listen_port=LISTEN_PORT,
        access_host=ACCESS_HOST,
        target_agent_name=TARGET_AGENT_NAME,
        review_action=REVIEW_ACTION,
        attack_type=ATTACK_TYPE,
        readonly_methods=set(DEFAULT_READ_ONLY_METHODS),
        max_capture_chars=MAX_CAPTURE_CHARS,
    )


def register_and_approve_runtime(config_path: Path, config: dict[str, Any]) -> dict[str, Any]:
    admin_token = login_admin()
    enrollment_token = create_enrollment_token(admin_token)
    client = PlatformClient(config)
    runtime = dict(config.get("runtime") or {})
    register_data = client.register_runtime(
        enrollment_token=enrollment_token,
        display_name=str(runtime.get("display_name") or ""),
        runtime_type=str(runtime.get("runtime_type") or RUNTIME_TYPE),
        hostname=str(runtime.get("hostname") or socket.gethostname() or ""),
        fingerprint=str(runtime.get("fingerprint") or ""),
        client_version=str(runtime.get("client_version") or CLIENT_VERSION),
        ip_addresses=list(runtime.get("ip_addresses") or collect_local_ip_addresses()),
        requested_scopes=list(runtime.get("requested_scopes") or []),
        capabilities=list(runtime.get("capabilities") or []),
        metadata=dict(runtime.get("metadata") or {}),
    )

    registration = dict(register_data.get("registration") or {})
    runtime_payload = dict(register_data.get("runtime") or {})
    runtime["registration_id"] = str(registration.get("registration_id") or "").strip()
    runtime["poll_secret"] = str(registration.get("poll_secret") or "").strip()
    runtime["status"] = str(registration.get("status") or runtime_payload.get("status") or "pending").strip() or "pending"
    runtime["status_summary"] = str(registration.get("status_summary") or "等待审批").strip() or "等待审批"
    if runtime_payload.get("display_name"):
        runtime["display_name"] = str(runtime_payload.get("display_name"))
    config["runtime"] = runtime
    save_config_payload(config_path, config)

    runtime_id = int(runtime_payload.get("id") or 0)
    if runtime_id <= 0:
        raise RuntimeError("注册成功，但没有返回 runtime id，无法继续自动审批。")
    approve_runtime(admin_token, runtime_id)

    registration_id = str(runtime.get("registration_id") or "").strip()
    poll_secret = str(runtime.get("poll_secret") or "").strip()
    if not registration_id or not poll_secret:
        raise RuntimeError("注册成功，但缺少 registration_id / poll_secret。")

    log("INFO", "正在轮询领取长期 Runtime 凭据", registration_id=registration_id)
    deadline = time.time() + 60
    while time.time() < deadline:
        status_data = client.poll_runtime_registration(registration_id, poll_secret)
        runtime_payload = dict(status_data.get("runtime") or {})
        credentials = dict(status_data.get("runtime_credentials") or {})
        runtime["status"] = str(status_data.get("status") or runtime_payload.get("status") or runtime.get("status") or "").strip()
        runtime["status_summary"] = str(status_data.get("status_summary") or runtime.get("status_summary") or "").strip()
        if runtime_payload.get("display_name"):
            runtime["display_name"] = str(runtime_payload.get("display_name"))
        runtime_key = str(credentials.get("runtime_key") or "").strip()
        runtime_secret = str(credentials.get("runtime_secret") or "").strip()
        if runtime_key and runtime_secret:
            runtime["runtime_key"] = runtime_key
            runtime["runtime_secret"] = runtime_secret
            runtime["poll_secret"] = ""
            runtime["status"] = "active"
            runtime["status_summary"] = str(status_data.get("status_summary") or "已领取 Runtime 凭据").strip()
            config["runtime"] = runtime
            save_config_payload(config_path, config)
            log("INFO", "Runtime 自动注册和审批完成", runtime_key=runtime_key)
            return config
        time.sleep(2)
    raise RuntimeError("自动审批已提交，但等待长期 Runtime 凭据超时。")


def launch_bridge(config_path: Path) -> int:
    ensure_parent(FRAME_LOG_PATH)
    command = [
        sys.executable,
        str(SCRIPT_DIR / "openclaw_control_bridge.py"),
        "--upstream-http-url",
        normalize_base_url(UPSTREAM_HTTP_URL),
        "--gateway-token",
        GATEWAY_TOKEN,
        "--listen-host",
        LISTEN_HOST,
        "--listen-port",
        str(LISTEN_PORT),
        "--access-host",
        ACCESS_HOST,
        "--runtime-config",
        str(config_path),
        "--log-jsonl",
        str(FRAME_LOG_PATH),
        "--max-capture-chars",
        str(MAX_CAPTURE_CHARS),
    ]
    print("=" * 72)
    print("OpenClaw 一键直连脚本")
    print("已自动完成平台注册/审批准备，下面将直接启动控制台桥接器。")
    print("=" * 72)
    print(f"保护平台 : {PLATFORM_BASE_URL}")
    print(f"OpenClaw  : {UPSTREAM_HTTP_URL}")
    print(f"本地入口 : http://{ACCESS_HOST}:{LISTEN_PORT}/")
    print(f"配置文件 : {config_path}")
    print(f"帧日志   : {FRAME_LOG_PATH}")
    print()
    print("后续请直接打开桥接器打印出的本地浏览器地址，不要再直连上游 OpenClaw。")
    print()
    return subprocess.call(command, cwd=str(PROJECT_ROOT))


def main() -> int:
    configure_stdio_utf8()
    ensure_parent(RUNTIME_CONFIG_PATH)
    ensure_parent(FRAME_LOG_PATH)

    if not GATEWAY_TOKEN.strip():
        print("缺少 OpenClaw gateway token，无法继续。")
        return 1

    if RUNTIME_CONFIG_PATH.exists():
        existing = read_json(RUNTIME_CONFIG_PATH)
        if has_runtime_credentials(existing):
            log("INFO", "发现已有 Runtime 凭据，直接启动桥接器", config=str(RUNTIME_CONFIG_PATH))
            return launch_bridge(RUNTIME_CONFIG_PATH)

    config = build_runtime_config()
    save_config_payload(RUNTIME_CONFIG_PATH, config)
    config = register_and_approve_runtime(RUNTIME_CONFIG_PATH, config)
    if not has_runtime_credentials(config):
        raise RuntimeError("自动接入流程结束后仍未拿到 Runtime 凭据。")
    return launch_bridge(RUNTIME_CONFIG_PATH)


if __name__ == "__main__":
    raise SystemExit(main())
