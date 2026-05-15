#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
AGENT_GATEWAY_DIR = SCRIPT_DIR / "agent_gateway"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(AGENT_GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_GATEWAY_DIR))

from agent_gateway_cli import (  # noqa: E402
    CLIENT_VERSION,
    PlatformClient,
    collect_local_ip_addresses,
    default_access_host,
    has_runtime_credentials,
    save_config_payload,
)
from openclaw_control_bridge import (  # noqa: E402
    DEFAULT_READ_ONLY_METHODS,
    RuntimeBridgeClient,
    build_runtime_bridge_config,
    configure_stdio_utf8,
    default_http_origin,
    default_profile_name,
    default_runtime_config_path,
    default_runtime_display_name,
    default_target_agent_name,
    default_ws_url_from_http,
    load_runtime_config,
    main as bridge_main,
    merge_runtime_state,
    normalize_base_url,
    normalize_platform_base_url,
    probe_openclaw_connectivity,
)


DEFAULT_CONFIG_DIR = AGENT_GATEWAY_DIR / "generated"
LAST_CONFIG_FILE = DEFAULT_CONFIG_DIR / "openclaw-control-last.json"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "openclaw-control-client.json"
DEFAULT_RUNTIME_TYPE = "openclaw_control_bridge"
DEFAULT_REVIEW_ACTION = "block"
DEFAULT_ATTACK_TYPE = "openclaw_control"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_last_config_path(config_path: Path) -> None:
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    save_config_payload(LAST_CONFIG_FILE, {"config_path": str(config_path)})


def read_last_config_path() -> Path | None:
    if not LAST_CONFIG_FILE.exists():
        return None
    try:
        payload = read_json(LAST_CONFIG_FILE)
    except Exception:
        return None
    value = str(payload.get("config_path") or "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    else:
        path = path.resolve()
    return path if path.exists() else None


def prompt_text(label: str, default: str = "", *, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value and default:
            value = default
        if value or not required:
            return value
        print("该项不能为空。")


def prompt_int(label: str, default: int) -> int:
    while True:
        raw = prompt_text(label, str(default), required=True)
        try:
            value = int(raw)
        except ValueError:
            print("请输入数字端口。")
            continue
        if 1 <= value <= 65535:
            return value
        print("端口范围必须是 1-65535。")


def normalize_activation_code(value: str) -> str:
    return str(value or "").strip().upper()


def resolve_config_path(args: argparse.Namespace, upstream_http_url: str | None = None) -> Path:
    explicit = str(getattr(args, "runtime_config", "") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()

    if not bool(getattr(args, "new", False)):
        existing = read_last_config_path()
        if existing is not None:
            return existing

    if upstream_http_url:
        return default_runtime_config_path(upstream_http_url).resolve()
    return DEFAULT_CONFIG_FILE.resolve()


def sync_runtime_binding_from_payload(runtime: dict[str, Any], runtime_payload: dict[str, Any]) -> None:
    endpoint = runtime_payload.get("ai_endpoint") if isinstance(runtime_payload.get("ai_endpoint"), dict) else None
    if endpoint:
        runtime["ai_endpoint_id"] = endpoint.get("id")
        runtime["ai_endpoint_key"] = str(endpoint.get("endpoint_key") or "")
        runtime["ai_endpoint_display_name"] = str(endpoint.get("display_name") or "")
        runtime["ai_endpoint_group"] = str(endpoint.get("endpoint_group") or "")
    elif "ai_endpoint" in runtime_payload:
        runtime["ai_endpoint_id"] = None
        runtime["ai_endpoint_key"] = ""
        runtime["ai_endpoint_display_name"] = ""
        runtime["ai_endpoint_group"] = ""


def build_base_config(
    *,
    platform_base_url: str,
    verify_platform_tls: bool,
    upstream_http_url: str,
    gateway_token: str,
    listen_host: str,
    listen_port: int,
    access_host: str,
    runtime_display_name: str,
    profile_name: str,
    target_agent_name: str,
    review_action: str,
    max_capture_chars: int,
) -> dict[str, Any]:
    upstream_http_url = normalize_base_url(upstream_http_url)
    config = build_runtime_bridge_config(
        profile_name=profile_name,
        platform_base_url=platform_base_url,
        verify_platform_tls=verify_platform_tls,
        runtime_display_name=runtime_display_name,
        runtime_type=DEFAULT_RUNTIME_TYPE,
        upstream_http_url=upstream_http_url,
        upstream_ws_url=default_ws_url_from_http(upstream_http_url),
        listen_host=listen_host,
        listen_port=listen_port,
        access_host=access_host,
        target_agent_name=target_agent_name,
        review_action=review_action,
        attack_type=DEFAULT_ATTACK_TYPE,
        readonly_methods=set(DEFAULT_READ_ONLY_METHODS),
        max_capture_chars=max_capture_chars,
    )
    bridge = dict(config.get("bridge") or {})
    bridge["gateway_token"] = gateway_token
    bridge["access_host"] = access_host
    bridge["listen_host"] = listen_host
    bridge["listen_port"] = listen_port
    config["bridge"] = bridge

    runtime = dict(config.get("runtime") or {})
    metadata = dict(runtime.get("metadata") or {})
    metadata["openclaw_gateway_token_present"] = bool(gateway_token)
    runtime["metadata"] = metadata
    runtime["onboarding_mode"] = "activation_code"
    config["runtime"] = runtime
    return config


def test_openclaw_connectivity(config: dict[str, Any]) -> None:
    bridge = dict(config.get("bridge") or {})
    upstream_http_url = normalize_base_url(str(bridge.get("upstream_http_url") or ""))
    upstream_ws_url = normalize_base_url(str(bridge.get("upstream_ws_url") or ""))
    gateway_token = str(bridge.get("gateway_token") or "").strip()
    if not upstream_http_url:
        raise RuntimeError("缺少 OpenClaw 控制台地址，无法测试连通性")
    if not upstream_ws_url:
        upstream_ws_url = default_ws_url_from_http(upstream_http_url)
    if not gateway_token:
        raise RuntimeError("缺少 OpenClaw gateway token，无法测试 WebSocket 鉴权连通性")

    print("[INFO] 正在测试 OpenClaw 上游真实连通性...")
    result = asyncio.run(
        probe_openclaw_connectivity(
            upstream_http_url=upstream_http_url,
            upstream_ws_url=upstream_ws_url,
            gateway_token=gateway_token,
            upstream_origin=default_http_origin(upstream_http_url),
            timeout_seconds=8,
        )
    )

    http_attempts = list((result.get("http") or {}).get("attempts") or [])
    http_ok = next((item for item in http_attempts if item.get("ok")), None)
    if http_ok:
        print(f"[INFO] OpenClaw HTTP 可达: {http_ok.get('url')} -> {http_ok.get('status')}")
    else:
        compact_errors = []
        for item in http_attempts:
            compact_errors.append(f"{item.get('url')} -> {item.get('status') or item.get('error')}")
        print("[WARN] OpenClaw HTTP 页面探测未通过，继续以 WebSocket 握手为准: " + " ; ".join(compact_errors))

    ws_result = dict(result.get("ws") or {})
    if not ws_result.get("ok"):
        raise RuntimeError(
            "OpenClaw WebSocket 握手失败。"
            f"上游 WS={upstream_ws_url}，原因={ws_result.get('error') or 'unknown'}。"
            "请检查 OpenClaw gateway token、虚拟机网络、防火墙和 OpenClaw 是否正在运行。"
        )
    print(f"[INFO] OpenClaw WebSocket 握手通过: {upstream_ws_url}")


def update_connection_settings(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    bridge = dict(config.get("bridge") or {})
    gateway = dict(config.get("gateway") or {})
    runtime = dict(config.get("runtime") or {})
    metadata = dict(runtime.get("metadata") or {})

    upstream_http_url = str(getattr(args, "upstream_http_url", "") or bridge.get("upstream_http_url") or metadata.get("upstream_http_url") or "").strip()
    if upstream_http_url:
        upstream_http_url = normalize_base_url(upstream_http_url)
        bridge["upstream_http_url"] = upstream_http_url
        bridge["upstream_ws_url"] = default_ws_url_from_http(upstream_http_url)
        metadata["upstream_http_url"] = upstream_http_url
        metadata["upstream_ws_url"] = bridge["upstream_ws_url"]

    gateway_token = str(getattr(args, "gateway_token", "") or "").strip()
    if gateway_token:
        bridge["gateway_token"] = gateway_token

    listen_host = str(getattr(args, "listen_host", "") or "").strip()
    if listen_host:
        gateway["listen_host"] = listen_host
        bridge["listen_host"] = listen_host
        metadata["listen_host"] = listen_host

    listen_port = getattr(args, "listen_port", None)
    if listen_port:
        gateway["listen_port"] = int(listen_port)
        bridge["listen_port"] = int(listen_port)
        metadata["listen_port"] = int(listen_port)

    access_host = str(getattr(args, "access_host", "") or "").strip()
    if access_host:
        bridge["access_host"] = access_host
        metadata["access_host"] = access_host

    platform_base_url = str(getattr(args, "platform_base_url", "") or "").strip()
    if platform_base_url:
        platform = dict(config.get("platform") or {})
        platform["base_url"] = normalize_platform_base_url(platform_base_url)
        config["platform"] = platform

    runtime["metadata"] = metadata
    config["runtime"] = runtime
    config["gateway"] = gateway
    config["bridge"] = bridge
    return config


def ensure_openclaw_connection_settings(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Fill local OpenClaw bridge settings without touching Runtime credentials."""
    config = update_connection_settings(config, args)
    bridge = dict(config.get("bridge") or {})
    gateway = dict(config.get("gateway") or {})
    runtime = dict(config.get("runtime") or {})
    metadata = dict(runtime.get("metadata") or {})
    interactive = sys.stdin.isatty()

    upstream_http_url = str(
        bridge.get("upstream_http_url") or metadata.get("upstream_http_url") or ""
    ).strip()
    if not upstream_http_url:
        if not interactive:
            raise RuntimeError("本地配置缺少 OpenClaw 控制台地址，请传 --upstream-http-url 后重试；不需要重新激活 Runtime。")
        upstream_http_url = prompt_text("请输入 OpenClaw 控制台地址，例如 http://192.168.137.140:18789")
    upstream_http_url = normalize_base_url(upstream_http_url)
    upstream_ws_url = default_ws_url_from_http(upstream_http_url)
    bridge["upstream_http_url"] = upstream_http_url
    bridge["upstream_ws_url"] = upstream_ws_url
    metadata["upstream_http_url"] = upstream_http_url
    metadata["upstream_ws_url"] = upstream_ws_url

    gateway_token = str(bridge.get("gateway_token") or "").strip()
    if not gateway_token:
        if not interactive:
            raise RuntimeError("本地配置缺少 OpenClaw gateway token，请传 --gateway-token 后重试；不需要重新激活 Runtime。")
        gateway_token = prompt_text("请输入 OpenClaw gateway token")
    bridge["gateway_token"] = gateway_token
    metadata["openclaw_gateway_token_present"] = bool(gateway_token)

    listen_host = str(gateway.get("listen_host") or bridge.get("listen_host") or "").strip()
    if not listen_host:
        listen_host = "0.0.0.0"
    gateway["listen_host"] = listen_host
    bridge["listen_host"] = listen_host
    metadata["listen_host"] = listen_host

    listen_port_value = gateway.get("listen_port") or bridge.get("listen_port") or 19090
    try:
        listen_port = int(listen_port_value)
    except (TypeError, ValueError):
        listen_port = 19090
    if listen_port < 1 or listen_port > 65535:
        listen_port = 19090
    gateway["listen_port"] = listen_port
    bridge["listen_port"] = listen_port
    metadata["listen_port"] = listen_port

    access_host = str(bridge.get("access_host") or metadata.get("access_host") or "").strip()
    if not access_host:
        access_host = default_access_host(listen_host)
    bridge["access_host"] = access_host
    metadata["access_host"] = access_host

    runtime["metadata"] = metadata
    config["runtime"] = runtime
    config["gateway"] = gateway
    config["bridge"] = bridge
    return config


def activate_with_short_code(config_path: Path, config: dict[str, Any], activation_code: str) -> dict[str, Any]:
    code = normalize_activation_code(activation_code)
    if not code:
        raise RuntimeError("缺少短期接入激活码。")

    runtime = dict(config.get("runtime") or {})
    client = PlatformClient(config)
    data = client._request(
        "POST",
        "/api/runtime-registry/client-activate",
        payload={
            "activation_code": code,
            "display_name": str(runtime.get("display_name") or ""),
            "runtime_type": str(runtime.get("runtime_type") or DEFAULT_RUNTIME_TYPE),
            "hostname": str(runtime.get("hostname") or socket.gethostname() or ""),
            "fingerprint": str(runtime.get("fingerprint") or ""),
            "client_version": str(runtime.get("client_version") or CLIENT_VERSION),
            "ip_addresses": list(runtime.get("ip_addresses") or collect_local_ip_addresses()),
            "requested_scopes": list(runtime.get("requested_scopes") or []),
            "capabilities": list(runtime.get("capabilities") or []),
            "metadata": dict(runtime.get("metadata") or {}),
        },
        with_auth=False,
    )
    runtime_payload = dict(data.get("runtime") or {})
    credentials = dict(data.get("runtime_credentials") or {})
    runtime_key = str(credentials.get("runtime_key") or "").strip()
    runtime_secret = str(credentials.get("runtime_secret") or "").strip()
    if not runtime_key or not runtime_secret:
        raise RuntimeError("激活成功但平台没有返回长期 Runtime 凭据。")

    runtime["managed_runtime_id"] = int(runtime_payload.get("id") or 0) if runtime_payload.get("id") is not None else None
    runtime["registration_id"] = str(runtime_payload.get("registration_id") or runtime.get("registration_id") or "").strip()
    runtime["runtime_key"] = runtime_key
    runtime["runtime_secret"] = runtime_secret
    runtime["poll_secret"] = ""
    runtime["status"] = str(data.get("status") or runtime_payload.get("status") or "active").strip() or "active"
    runtime["status_summary"] = str(data.get("status_summary") or runtime_payload.get("status_summary") or "已领取长期 Runtime 凭据").strip()
    runtime["activation_code_hint"] = ""
    if runtime_payload.get("display_name"):
        runtime["display_name"] = str(runtime_payload.get("display_name"))
    sync_runtime_binding_from_payload(runtime, runtime_payload)
    config["runtime"] = runtime
    save_config_payload(config_path, config)
    return config


def validate_runtime_session(config_path: Path, config: dict[str, Any]) -> dict[str, Any]:
    client = RuntimeBridgeClient(config_path, config)
    return client.validate_session()


def endpoint_label(session: dict[str, Any]) -> str:
    runtime = session.get("runtime") if isinstance(session.get("runtime"), dict) else {}
    endpoint = runtime.get("ai_endpoint") if isinstance(runtime.get("ai_endpoint"), dict) else None
    if not endpoint:
        return "未绑定 AI endpoint"
    name = str(endpoint.get("display_name") or "").strip()
    key = str(endpoint.get("endpoint_key") or "").strip()
    if name and key:
        return f"{name} ({key})"
    return name or key or "已绑定 AI endpoint"


def assert_listen_port_available(listen_host: str, listen_port: int) -> None:
    host = listen_host.strip() or "0.0.0.0"
    family = socket.AF_INET6 if ":" in host and host not in {"0.0.0.0"} else socket.AF_INET
    bind_host = "" if host in {"0.0.0.0", "::"} else host
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_host, listen_port))
        except OSError as exc:
            raise RuntimeError(
                f"本地端口 {listen_port} 已被占用。请先关闭旧的 OpenClaw 桥接窗口，或使用 --listen-port 指定其他端口。"
            ) from exc


def bridge_argv_from_config(config_path: Path, config: dict[str, Any], args: argparse.Namespace) -> list[str]:
    config = update_connection_settings(config, args)
    bridge = dict(config.get("bridge") or {})
    gateway = dict(config.get("gateway") or {})
    platform = dict(config.get("platform") or {})

    upstream_http_url = str(bridge.get("upstream_http_url") or "").strip()
    gateway_token = str(bridge.get("gateway_token") or "").strip()
    listen_host = str(gateway.get("listen_host") or bridge.get("listen_host") or "0.0.0.0").strip() or "0.0.0.0"
    listen_port = int(gateway.get("listen_port") or bridge.get("listen_port") or 19090)
    access_host = str(bridge.get("access_host") or "").strip() or default_access_host(listen_host)
    max_capture_chars = int(gateway.get("max_capture_chars") or getattr(args, "max_capture_chars", 16000) or 16000)

    if not upstream_http_url:
        raise RuntimeError("配置里缺少 OpenClaw 控制台地址。请重新运行脚本补填，或传 --upstream-http-url。")
    if not gateway_token:
        raise RuntimeError("配置里缺少 OpenClaw gateway token。请重新运行脚本补填，或传 --gateway-token。")

    argv = [
        "--upstream-http-url",
        upstream_http_url,
        "--gateway-token",
        gateway_token,
        "--listen-host",
        listen_host,
        "--listen-port",
        str(listen_port),
        "--access-host",
        access_host,
        "--runtime-config",
        str(config_path),
        "--max-capture-chars",
        str(max_capture_chars),
    ]
    if platform.get("verify_tls") is False:
        argv.append("--insecure-platform")
    if getattr(args, "log_jsonl", None):
        argv.extend(["--log-jsonl", str(Path(args.log_jsonl).expanduser().resolve())])
    return argv


def collect_first_run_config(args: argparse.Namespace) -> tuple[Path, dict[str, Any], str]:
    platform_base_url = str(args.platform_base_url or "").strip()
    upstream_http_url = str(args.upstream_http_url or "").strip()
    gateway_token = str(args.gateway_token or "").strip()
    activation_code = normalize_activation_code(str(args.activation_code or ""))

    interactive = sys.stdin.isatty()
    if not platform_base_url and interactive:
        platform_base_url = prompt_text("请输入管理端地址，例如 http://127.0.0.1:8000", "http://127.0.0.1:8000")
    if not upstream_http_url and interactive:
        upstream_http_url = prompt_text("请输入 OpenClaw 控制台地址，例如 http://192.168.137.140:18789")
    if not gateway_token and interactive:
        gateway_token = prompt_text("请输入 OpenClaw gateway token")
    if not activation_code and interactive:
        activation_code = normalize_activation_code(prompt_text("请输入平台生成的短期接入激活码"))

    missing = [
        name
        for name, value in (
            ("管理端地址", platform_base_url),
            ("OpenClaw 控制台地址", upstream_http_url),
            ("OpenClaw gateway token", gateway_token),
            ("短期接入激活码", activation_code),
        )
        if not str(value or "").strip()
    ]
    if missing:
        raise RuntimeError("缺少必要参数: " + ", ".join(missing))

    upstream_http_url = normalize_base_url(upstream_http_url)
    listen_host = str(args.listen_host or "").strip()
    if not listen_host:
        listen_host = "0.0.0.0"
    access_host = str(args.access_host or "").strip()
    if not access_host and interactive:
        access_host = prompt_text("请输入浏览器访问本机桥接器的地址", default_access_host(listen_host))
    if not access_host:
        access_host = default_access_host(listen_host)
    listen_port = int(args.listen_port or 0)
    if not listen_port and interactive:
        listen_port = prompt_int("请输入本地桥接监听端口", 19090)
    if not listen_port:
        listen_port = 19090

    profile_name = str(args.profile_name or default_profile_name(upstream_http_url)).strip()
    runtime_display_name = str(args.runtime_display_name or default_runtime_display_name(upstream_http_url)).strip()
    target_agent_name = str(args.target_agent_name or default_target_agent_name(upstream_http_url)).strip()
    config_path = resolve_config_path(args, upstream_http_url)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = build_base_config(
        platform_base_url=normalize_platform_base_url(platform_base_url),
        verify_platform_tls=not bool(args.insecure_platform),
        upstream_http_url=upstream_http_url,
        gateway_token=gateway_token,
        listen_host=listen_host,
        listen_port=listen_port,
        access_host=access_host,
        runtime_display_name=runtime_display_name,
        profile_name=profile_name,
        target_agent_name=target_agent_name,
        review_action=str(args.review_action or DEFAULT_REVIEW_ACTION),
        max_capture_chars=int(args.max_capture_chars or 16000),
    )
    return config_path, config, activation_code


def load_existing_config(args: argparse.Namespace) -> tuple[Path, dict[str, Any]] | None:
    if bool(args.new):
        return None
    config_path = resolve_config_path(args)
    if not config_path.exists():
        return None
    config = load_runtime_config(config_path)
    config = update_connection_settings(config, args)
    if not has_runtime_credentials(config):
        return None
    return config_path, config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenClaw Control UI 客户端接入脚本：用短期激活码换长期 Runtime 凭据，并启动平台审查桥接器。",
    )
    parser.add_argument("--platform-base-url", help="管理端地址，例如 http://127.0.0.1:8000")
    parser.add_argument("--upstream-http-url", help="OpenClaw 控制台地址，例如 http://192.168.137.140:18789")
    parser.add_argument("--gateway-token", help="OpenClaw gateway.auth.token")
    parser.add_argument("--activation-code", help="平台生成的短期接入激活码，仅首次接入需要")
    parser.add_argument("--listen-host", help="本地监听地址，默认 0.0.0.0")
    parser.add_argument("--listen-port", type=int, help="本地监听端口，默认 19090")
    parser.add_argument("--access-host", help="浏览器访问桥接器时使用的地址/IP")
    parser.add_argument("--runtime-config", help="本地 Runtime 配置文件路径")
    parser.add_argument("--profile-name", help="本地配置名称")
    parser.add_argument("--runtime-display-name", help="平台里显示的客户端名称")
    parser.add_argument("--target-agent-name", help="平台任务里显示的受保护目标名称")
    parser.add_argument("--review-action", choices=["block", "allow"], default=DEFAULT_REVIEW_ACTION)
    parser.add_argument("--max-capture-chars", type=int, default=16000)
    parser.add_argument("--log-jsonl", help="可选：记录 OpenClaw WS 帧到 jsonl 文件")
    parser.add_argument("--insecure-platform", action="store_true", help="不校验管理端 HTTPS 证书")
    parser.add_argument("--new", action="store_true", help="忽略已有凭据，重新输入并激活")
    parser.add_argument("--no-start", action="store_true", help="只完成激活和会话校验，不启动桥接器")
    parser.add_argument("--no-remember", action="store_true", help="不更新上次使用的配置指针，主要用于自动化测试")
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdio_utf8()
    args = build_parser().parse_args(argv)

    try:
        existing = load_existing_config(args)
        if existing is not None:
            config_path, config = existing
            print(f"[INFO] 发现已有 Runtime 凭据，直接复用: {config_path}")
        else:
            config_path, config, activation_code = collect_first_run_config(args)
            if config_path.exists() and not bool(args.new):
                old_config = load_runtime_config(config_path)
                config = merge_runtime_state(config, old_config)
            save_config_payload(config_path, config)
            print(f"[INFO] 正在使用短期激活码换取长期 Runtime 凭据: {config_path}")
            config = activate_with_short_code(config_path, config, activation_code)

        session = validate_runtime_session(config_path, config)
        if not bool(args.no_remember):
            write_last_config_path(config_path)
        print(f"[INFO] Runtime 会话校验通过，绑定目标: {endpoint_label(session)}")

        config = ensure_openclaw_connection_settings(config, args)
        test_openclaw_connectivity(config)
        save_config_payload(config_path, config)
        print(f"[INFO] 本地配置已保存，后续运行将直接复用: {config_path}")

        if bool(args.no_start):
            return 0

        bridge_args = bridge_argv_from_config(config_path, config, args)
        if "--listen-host" in bridge_args and "--listen-port" in bridge_args:
            listen_host = bridge_args[bridge_args.index("--listen-host") + 1]
            listen_port = int(bridge_args[bridge_args.index("--listen-port") + 1])
            assert_listen_port_available(listen_host, listen_port)
        print("[INFO] 正在启动 OpenClaw 安全审查桥接器...")
        return bridge_main(bridge_args)
    except KeyboardInterrupt:
        print("\n[INFO] 已取消。")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] OpenClaw 接入失败: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
