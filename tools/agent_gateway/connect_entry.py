#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

import agent_gateway_cli as core


STATE_FILE_NAME = ".connect_entry_state"



def prompt_text(label: str, default: str | None = None, *, allow_empty: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if allow_empty:
            return ""
        print("请输入有效内容。")


def prompt_secret(label: str, *, allow_empty: bool = False) -> str:
    while True:
        value = input(f"{label}: ").strip()
        if value or allow_empty:
            return value
        print("该字段不能为空。")


def prompt_yes_no(label: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{label} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "1"}:
            return True
        if raw in {"n", "no", "0"}:
            return False
        print("请输入 y 或 n。")


def state_file_path() -> Path:
    core.ensure_generated_dir()
    return core.GENERATED_DIR / STATE_FILE_NAME


def load_connect_state() -> dict[str, Any]:
    path = state_file_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_connect_state(payload: dict[str, Any]) -> None:
    state_file_path().write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def remember_preferred_config(config_path: Path, config: dict[str, Any] | None = None) -> None:
    payload = load_connect_state()
    payload["last_config_path"] = str(config_path.resolve())
    payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
    if config is not None:
        payload["last_profile_name"] = str(config.get("profile_name") or "").strip()
    save_connect_state(payload)


def preferred_config_path() -> Path | None:
    payload = load_connect_state()
    raw_path = str(payload.get("last_config_path") or "").strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser().resolve()
    if path.exists():
        return path
    payload.pop("last_config_path", None)
    payload.pop("last_profile_name", None)
    save_connect_state(payload)
    return None


def clone_config(config: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(config, ensure_ascii=False))


def http_request(
    *,
    base_url: str,
    path: str,
    method: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    verify_tls: bool,
    timeout_seconds: float,
) -> dict[str, Any]:
    request_headers = {"Accept": "application/json"}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        f"{core.normalize_platform_base_url(base_url)}{path}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None,
        headers=request_headers,
        method=method.upper(),
    )
    context = core.build_ssl_context(verify_tls)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
            body_text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        detail = extract_error_detail(body_text) or body_text[:300]
        raise RuntimeError(f"{method.upper()} {path} 返回 HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"无法连接到后端平台: {exc}") from exc

    try:
        response_payload = json.loads(body_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{method.upper()} {path} 返回了非 JSON 响应: {body_text[:300]}") from exc

    if "code" in response_payload:
        if response_payload.get("code") != 0:
            message = str(response_payload.get("message") or "unknown error")
            raise RuntimeError(f"{method.upper()} {path} 返回业务错误: {message}")
        return dict(response_payload.get("data") or {})
    return dict(response_payload or {})


def extract_error_detail(body_text: str) -> str:
    try:
        payload = json.loads(body_text)
    except json.JSONDecodeError:
        return body_text[:300]
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
        message = payload.get("message")
        if isinstance(message, str):
            return message
    return body_text[:300]


def platform_login(config: dict[str, Any]) -> str:
    platform = dict(config.get("platform") or {})
    username = str(platform.get("username") or "").strip()
    password = str(platform.get("password") or "").strip()
    if not username or not password:
        raise RuntimeError("当前配置没有平台账号密码，无法向管理端发起新的激活申请。")
    data = http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/api/auth/login",
        method="POST",
        payload={"username": username, "password": password},
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    token = str(data.get("access_token") or "").strip()
    if not token:
        raise RuntimeError("平台登录成功，但没有返回 access_token。")
    return token


def validate_platform_login(config: dict[str, Any]) -> str:
    platform = dict(config.get("platform") or {})
    token = platform_login(config)
    http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/api/auth/me",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    return token


def validate_platform_health(config: dict[str, Any]) -> dict[str, Any]:
    platform = dict(config.get("platform") or {})
    return http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/health",
        method="GET",
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=15,
    )


def list_ai_endpoints(config: dict[str, Any], platform_token: str) -> list[dict[str, Any]]:
    platform = dict(config.get("platform") or {})
    data = http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/api/ai-endpoints",
        method="GET",
        headers={"Authorization": f"Bearer {platform_token}"},
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    items = data.get("items")
    if not isinstance(items, list):
        return []
    return [dict(item) for item in items if isinstance(item, dict)]


def format_ai_endpoint_label(endpoint: dict[str, Any] | None) -> str:
    if not endpoint:
        return "未绑定"
    display_name = str(endpoint.get("display_name") or "").strip()
    endpoint_key = str(endpoint.get("endpoint_key") or "").strip()
    endpoint_id = endpoint.get("id")
    if display_name and endpoint_key:
        return f"{display_name} ({endpoint_key})"
    if display_name:
        return display_name
    if endpoint_key:
        return endpoint_key
    if endpoint_id is not None:
        return f"endpoint #{endpoint_id}"
    return "未绑定"


def apply_runtime_ai_endpoint(runtime: dict[str, Any], endpoint: dict[str, Any] | None) -> None:
    if not endpoint:
        runtime["ai_endpoint_id"] = None
        runtime["ai_endpoint_key"] = ""
        runtime["ai_endpoint_display_name"] = ""
        runtime["ai_endpoint_binding_state"] = "unbound"
        return
    runtime["ai_endpoint_id"] = endpoint.get("id")
    runtime["ai_endpoint_key"] = str(endpoint.get("endpoint_key") or "").strip()
    runtime["ai_endpoint_display_name"] = str(endpoint.get("display_name") or "").strip()
    runtime["ai_endpoint_binding_state"] = "bound"


def sync_runtime_binding_from_payload(runtime: dict[str, Any], runtime_payload: dict[str, Any]) -> None:
    ai_endpoint = runtime_payload.get("ai_endpoint")
    if isinstance(ai_endpoint, dict):
        apply_runtime_ai_endpoint(runtime, ai_endpoint)
        return
    binding_state = str(runtime_payload.get("binding_state") or "").strip().lower()
    if binding_state == "unbound":
        apply_runtime_ai_endpoint(runtime, None)


def runtime_binding_label(config: dict[str, Any]) -> str:
    runtime = dict(config.get("runtime") or {})
    endpoint = {
        "id": runtime.get("ai_endpoint_id"),
        "endpoint_key": runtime.get("ai_endpoint_key"),
        "display_name": runtime.get("ai_endpoint_display_name"),
    }
    if (
        not endpoint["id"]
        and not endpoint["endpoint_key"]
        and not endpoint["display_name"]
        and str(runtime.get("onboarding_mode") or "").strip().lower() == "activation_code"
        and not core.has_runtime_credentials(config)
    ):
        return "将由激活码自动绑定"
    if not endpoint["id"] and not endpoint["endpoint_key"] and not endpoint["display_name"]:
        return "未绑定"
    return format_ai_endpoint_label(endpoint)


def describe_ai_endpoint_for_choice(item: dict[str, Any]) -> str:
    summary = format_ai_endpoint_label(item)
    provider = str(item.get("provider_type") or "").strip()
    mode = str(item.get("protection_mode") or "").strip()
    enabled = "enabled" if bool(item.get("enabled", True)) else "disabled"
    extra_parts = [part for part in [provider, mode, enabled] if part]
    if extra_parts:
        return f"{summary} | {' | '.join(extra_parts)}"
    return summary


def resolve_ai_endpoint_by_args(
    items: list[dict[str, Any]],
    *,
    ai_endpoint_id: int | None,
    ai_endpoint_key: str,
) -> dict[str, Any] | None:
    if ai_endpoint_id is not None and ai_endpoint_key:
        raise RuntimeError("--ai-endpoint-id 和 --ai-endpoint-key 不能同时使用。")
    if ai_endpoint_id is not None:
        for item in items:
            if item.get("id") == ai_endpoint_id:
                return item
        raise RuntimeError(f"管理端不存在 id={ai_endpoint_id} 的 AI endpoint。")
    normalized_key = ai_endpoint_key.strip().lower()
    if not normalized_key:
        return None
    for item in items:
        endpoint_key = str(item.get("endpoint_key") or "").strip().lower()
        display_name = str(item.get("display_name") or "").strip().lower()
        if normalized_key in {endpoint_key, display_name}:
            return item
    raise RuntimeError(f"管理端不存在 key/display_name 为 {ai_endpoint_key!r} 的 AI endpoint。")


def prompt_ai_endpoint_choice(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not items:
        print("管理端当前还没有可绑定的 AI endpoint，本次接入将先以未绑定方式提交。")
        return None

    print("可绑定的 AI endpoint：")
    print("  [0] 暂不绑定，后续再在前端处理")
    for index, item in enumerate(items, start=1):
        print(f"  [{index}] {describe_ai_endpoint_for_choice(item)}")

    while True:
        choice = input("请选择要绑定的 AI endpoint 编号 [0]: ").strip()
        if not choice or choice == "0":
            return None
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(items):
                return items[index - 1]
        print("编号无效，请重新输入。")


def resolve_ai_endpoint_binding(
    config: dict[str, Any],
    args: argparse.Namespace,
    *,
    platform_token: str,
) -> dict[str, Any] | None:
    wants_binding = args.ai_endpoint_id is not None or bool(str(args.ai_endpoint_key or "").strip())
    should_prompt = sys.stdin.isatty() and not wants_binding

    if not wants_binding and not should_prompt:
        return None

    items = list_ai_endpoints(config, platform_token)
    if wants_binding:
        endpoint = resolve_ai_endpoint_by_args(
            items,
            ai_endpoint_id=args.ai_endpoint_id,
            ai_endpoint_key=str(args.ai_endpoint_key or ""),
        )
        if endpoint is not None:
            print(f"本次接入将直接绑定 AI: {format_ai_endpoint_label(endpoint)}")
        return endpoint

    if not items:
        print("管理端当前还没有可绑定的 AI endpoint，本次接入将先以未绑定方式提交。")
        return None
    if not prompt_yes_no("是否将这台客户端直接绑定到某个 AI endpoint", False):
        return None
    endpoint = prompt_ai_endpoint_choice(items)
    if endpoint is not None:
        print(f"本次接入将直接绑定 AI: {format_ai_endpoint_label(endpoint)}")
    return endpoint


def validate_runtime_session(config: dict[str, Any]) -> dict[str, Any]:
    platform = dict(config.get("platform") or {})
    runtime = dict(config.get("runtime") or {})
    runtime_key = str(runtime.get("runtime_key") or "").strip()
    runtime_secret = str(runtime.get("runtime_secret") or "").strip()
    if not runtime_key or not runtime_secret:
        raise RuntimeError("当前配置还没有长期 Runtime 凭据。")
    return http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/gateway/v1/runtime/session",
        method="GET",
        headers={
            "X-Runtime-Key": runtime_key,
            "X-Runtime-Secret": runtime_secret,
            "X-Client-ID": str(
                runtime.get("display_name")
                or dict(config.get("gateway") or {}).get("runtime_name")
                or runtime_key
            ).strip(),
        },
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )


def print_runtime_session_success(config: dict[str, Any], session: dict[str, Any]) -> None:
    runtime = dict(config.get("runtime") or {})
    session_runtime = dict(session.get("runtime") or {})
    auth_mode = str(session.get("auth_mode") or "runtime_secret").strip() or "runtime_secret"
    display_name = str(
        session_runtime.get("display_name")
        or runtime.get("display_name")
        or dict(config.get("gateway") or {}).get("runtime_name")
        or runtime.get("runtime_key")
        or "-"
    ).strip()
    ai_endpoint = session_runtime.get("ai_endpoint") if isinstance(session_runtime.get("ai_endpoint"), dict) else None
    binding = format_ai_endpoint_label(ai_endpoint) if ai_endpoint else runtime_binding_label(config)
    print(f"Runtime 会话校验通过，鉴权模式: {auth_mode}，客户端: {display_name}，绑定 AI: {binding}")


def activate_with_bootstrap_code(config_path: Path, config: dict[str, Any], activation_code: str) -> dict[str, Any]:
    platform = dict(config.get("platform") or {})
    runtime = core.runtime_section(config)
    data = http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/api/runtime-registry/client-activate",
        method="POST",
        payload={
            "activation_code": activation_code,
            "display_name": str(runtime.get("display_name") or ""),
            "runtime_type": str(runtime.get("runtime_type") or "agent_gateway"),
            "hostname": str(runtime.get("hostname") or ""),
            "fingerprint": str(runtime.get("fingerprint") or ""),
            "client_version": str(runtime.get("client_version") or core.CLIENT_VERSION),
            "ip_addresses": list(runtime.get("ip_addresses") or []),
            "requested_scopes": list(runtime.get("requested_scopes") or []),
            "capabilities": list(runtime.get("capabilities") or []),
            "metadata": dict(runtime.get("metadata") or {}),
        },
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    runtime_payload = dict(data.get("runtime") or {})
    credentials = dict(data.get("runtime_credentials") or {})
    runtime_key = str(credentials.get("runtime_key") or "").strip()
    runtime_secret = str(credentials.get("runtime_secret") or "").strip()
    if not runtime_key or not runtime_secret:
        raise RuntimeError("激活成功，但平台没有返回长期 Runtime 凭据。")

    runtime["managed_runtime_id"] = int(runtime_payload.get("id") or 0) if runtime_payload.get("id") is not None else None
    runtime["registration_id"] = str(runtime_payload.get("registration_id") or runtime.get("registration_id") or "").strip()
    runtime["runtime_key"] = runtime_key
    runtime["runtime_secret"] = runtime_secret
    runtime["poll_secret"] = ""
    runtime["status"] = str(data.get("status") or runtime_payload.get("status") or "active").strip() or "active"
    runtime["status_summary"] = (
        str(data.get("status_summary") or runtime_payload.get("status_summary") or "已领取 Runtime 长期凭据").strip()
        or "已领取 Runtime 长期凭据"
    )
    runtime["activation_code_hint"] = str(runtime_payload.get("activation_code_hint") or "")
    if runtime_payload.get("display_name"):
        runtime["display_name"] = str(runtime_payload.get("display_name"))
    sync_runtime_binding_from_payload(runtime, runtime_payload)
    core.save_config_payload(config_path, config)
    return config


def reset_runtime_for_reactivation(config: dict[str, Any]) -> dict[str, Any]:
    working = clone_config(config)
    runtime = core.runtime_section(working)
    runtime["runtime_key"] = ""
    runtime["runtime_secret"] = ""
    runtime["managed_runtime_id"] = None
    runtime["registration_id"] = ""
    runtime["poll_secret"] = ""
    runtime["activation_code_hint"] = ""
    runtime["activation_steps"] = []
    runtime["status"] = "draft"
    runtime["status_summary"] = "等待重新发起激活申请"
    return working


def ensure_platform_credentials_for_reactivation(config: dict[str, Any]) -> dict[str, Any]:
    working = clone_config(config)
    platform = dict(working.get("platform") or {})
    if not str(platform.get("base_url") or "").strip():
        platform["base_url"] = prompt_text("请输入管理端地址，例如 http://127.0.0.1:8000")
    if not str(platform.get("username") or "").strip():
        platform["username"] = prompt_text("请输入管理端用户名")
    if not str(platform.get("password") or "").strip():
        platform["password"] = prompt_secret("请输入管理端密码，用于重新发起激活申请")
    working["platform"] = platform
    return working


def complete_bootstrap_activation(
    config_path: Path,
    config: dict[str, Any],
    *,
    activation_code: str,
    start_gateway: bool,
) -> int:
    code = str(activation_code or "").strip()
    if not code and sys.stdin.isatty():
        code = prompt_secret("请输入短期接入激活码", allow_empty=False)
    if not code:
        print("缺少短期接入激活码，无法继续。")
        return 1

    try:
        config = activate_with_bootstrap_code(config_path, config, code)
    except Exception as exc:  # noqa: BLE001
        print(f"激活失败: {exc}")
        print(f"配置已保留，可稍后继续: {config_path}")
        return 1

    print("激活成功，长期 Runtime 凭据已写入本地配置。")
    try:
        session = validate_runtime_session(config)
    except Exception as exc:  # noqa: BLE001
        print(f"激活后的 Runtime 会话校验失败: {exc}")
        print(f"配置已保留，可稍后继续: {config_path}")
        return 1
    remember_preferred_config(config_path, config)
    print_runtime_session_success(config, session)
    if start_gateway:
        print("正在启动本地网关...")
        return core.run_gateway(argparse.Namespace(config=str(config_path)))
    return 0


def complete_activation_after_request(
    config_path: Path,
    config: dict[str, Any],
    *,
    activation_code: str,
    start_gateway: bool,
) -> int:
    code = str(activation_code or "").strip()
    if not code and sys.stdin.isatty():
        code = prompt_secret("如果你已经拿到激活码，现在可以直接输入（回车可稍后再激活）", allow_empty=True)
    if not code:
        print()
        print("当前仅完成了激活申请。后续你只需要输入一次激活码，不需要再重填平台和上游信息。")
        print(f"继续激活命令: python tools/agent_gateway/connect_entry.py activate --config \"{config_path}\"")
        return 0

    try:
        config = activate_with_code(config_path, config, code)
    except Exception as exc:  # noqa: BLE001
        print(f"激活失败: {exc}")
        print(f"配置已保留，可稍后继续: {config_path}")
        return 1

    print("激活成功，长期 Runtime 凭据已写入本地配置。")
    try:
        session = validate_runtime_session(config)
    except Exception as exc:  # noqa: BLE001
        print(f"激活后的 Runtime 会话校验失败: {exc}")
        print(f"配置已保留，可稍后继续: {config_path}")
        return 1
    remember_preferred_config(config_path, config)
    print_runtime_session_success(config, session)
    if start_gateway:
        print("正在启动本地网关...")
        return core.run_gateway(argparse.Namespace(config=str(config_path)))
    return 0


def issue_activation_code(config_path: Path, config: dict[str, Any], *, platform_token: str) -> tuple[dict[str, Any], str]:
    platform = dict(config.get("platform") or {})
    runtime = core.runtime_section(config)
    runtime_id = int(runtime.get("managed_runtime_id") or 0)
    if runtime_id <= 0:
        raise RuntimeError("当前配置没有 managed_runtime_id，无法自动签发激活码。")

    data = http_request(
        base_url=str(platform.get("base_url") or ""),
        path=f"/api/runtime-registry/runtimes/{runtime_id}/activation-code",
        method="POST",
        payload={
            "display_name": str(runtime.get("display_name") or ""),
            "ai_endpoint_id": runtime.get("ai_endpoint_id"),
            "expires_in_minutes": 10,
        },
        headers={"Authorization": f"Bearer {platform_token}"},
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    runtime_payload = dict(data.get("runtime") or {})
    activation_code = str(data.get("activation_code") or "").strip()
    if not activation_code:
        raise RuntimeError("管理端已完成签发，但没有返回激活码。")

    runtime["status"] = str(runtime_payload.get("status") or runtime.get("status") or "activation_issued").strip() or "activation_issued"
    runtime["status_summary"] = (
        str(data.get("status_summary") or runtime_payload.get("status_summary") or "激活码已签发").strip()
        or "激活码已签发"
    )
    runtime["activation_code_hint"] = str(runtime_payload.get("activation_code_hint") or "")
    if runtime_payload.get("display_name"):
        runtime["display_name"] = str(runtime_payload.get("display_name"))
    if runtime_payload.get("id"):
        runtime["managed_runtime_id"] = int(runtime_payload.get("id") or 0)
    sync_runtime_binding_from_payload(runtime, runtime_payload)
    core.save_config_payload(config_path, config)
    return config, activation_code


def maybe_auto_issue_activation_code(
    config_path: Path,
    config: dict[str, Any],
    *,
    platform_token: str,
) -> tuple[dict[str, Any], str]:
    try:
        updated_config, activation_code = issue_activation_code(config_path, config, platform_token=platform_token)
    except Exception as exc:  # noqa: BLE001
        print(f"自动签发激活码失败，将回退到人工签发: {exc}")
        return config, ""

    print("已由管理端自动签发激活码，正在继续完成激活。")
    return updated_config, activation_code


def reissue_activation_request_for_existing_config(config_path: Path, config: dict[str, Any], *, start_gateway: bool) -> int:
    if not sys.stdin.isatty():
        print("当前 Runtime 凭据失效，且当前环境不可交互，无法自动重新发起激活申请。")
        print("请改用 connect --new 或在交互式终端里重新执行 connect。")
        return 1

    print("检测到当前 Runtime 凭据可能已失效或已被管理端撤销。")
    print(f"将沿用现有上游配置重新发起接入申请，绑定 AI: {runtime_binding_label(config)}")
    if not prompt_yes_no("是否现在重新发起一次激活申请", True):
        print("已取消自动恢复。你可以稍后手动执行 connect --new 重新接入。")
        return 1

    try:
        working = ensure_platform_credentials_for_reactivation(reset_runtime_for_reactivation(config))
        platform_token = validate_platform_login(working)
        working = request_activation(config_path, working, platform_token=platform_token)
    except Exception as exc:  # noqa: BLE001
        print(f"重新发起激活申请失败: {exc}")
        return 1

    working, auto_activation_code = maybe_auto_issue_activation_code(
        config_path,
        working,
        platform_token=platform_token,
    )
    remember_preferred_config(config_path, working)
    onboarding_summary(config_path, working)
    if auto_activation_code:
        print("已基于原配置重新提交接入申请，并自动签发激活码。")
    else:
        print("已基于原配置重新提交接入申请。请在管理端为该客户端签发新的激活码。")
    return complete_activation_after_request(
        config_path,
        working,
        activation_code=auto_activation_code,
        start_gateway=start_gateway,
    )


def request_activation(config_path: Path, config: dict[str, Any], *, platform_token: str) -> dict[str, Any]:
    platform = dict(config.get("platform") or {})
    runtime = core.runtime_section(config)
    data = http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/api/runtime-registry/activation-requests",
        method="POST",
        payload={
            "display_name": str(runtime.get("display_name") or ""),
            "runtime_type": str(runtime.get("runtime_type") or "agent_gateway"),
            "hostname": str(runtime.get("hostname") or ""),
            "fingerprint": str(runtime.get("fingerprint") or ""),
            "client_version": str(runtime.get("client_version") or core.CLIENT_VERSION),
            "ip_addresses": list(runtime.get("ip_addresses") or []),
            "requested_scopes": list(runtime.get("requested_scopes") or []),
            "capabilities": list(runtime.get("capabilities") or []),
            "metadata": dict(runtime.get("metadata") or {}),
            "ai_endpoint_id": runtime.get("ai_endpoint_id"),
        },
        headers={"Authorization": f"Bearer {platform_token}"},
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    registration = dict(data.get("registration") or {})
    runtime_payload = dict(data.get("runtime") or {})
    runtime["onboarding_mode"] = "activation_code"
    runtime["managed_runtime_id"] = int(runtime_payload.get("id") or 0) if runtime_payload.get("id") is not None else None
    runtime["registration_id"] = str(registration.get("registration_id") or "").strip()
    runtime["poll_secret"] = ""
    runtime["status"] = (
        str(registration.get("status") or runtime_payload.get("status") or "activation_requested").strip()
        or "activation_requested"
    )
    runtime["status_summary"] = (
        str(registration.get("status_summary") or "等待管理端签发激活码").strip() or "等待管理端签发激活码"
    )
    runtime["activation_steps"] = list(data.get("onboarding_steps") or [])
    if runtime_payload.get("display_name"):
        runtime["display_name"] = str(runtime_payload.get("display_name"))
    sync_runtime_binding_from_payload(runtime, runtime_payload)
    platform["password"] = ""
    config["platform"] = platform
    core.save_config_payload(config_path, config)
    return config


def activate_with_code(config_path: Path, config: dict[str, Any], activation_code: str) -> dict[str, Any]:
    platform = dict(config.get("platform") or {})
    runtime = core.runtime_section(config)
    registration_id = str(runtime.get("registration_id") or "").strip()
    if not registration_id:
        raise RuntimeError("当前配置没有 registration_id，无法执行激活。")
    data = http_request(
        base_url=str(platform.get("base_url") or ""),
        path="/api/runtime-registry/activate",
        method="POST",
        payload={"registration_id": registration_id, "activation_code": activation_code},
        verify_tls=bool(platform.get("verify_tls", True)),
        timeout_seconds=30,
    )
    runtime_payload = dict(data.get("runtime") or {})
    credentials = dict(data.get("runtime_credentials") or {})
    runtime_key = str(credentials.get("runtime_key") or "").strip()
    runtime_secret = str(credentials.get("runtime_secret") or "").strip()
    if not runtime_key or not runtime_secret:
        raise RuntimeError("激活成功，但平台没有返回长期 Runtime 凭据。")

    runtime["runtime_key"] = runtime_key
    runtime["runtime_secret"] = runtime_secret
    runtime["poll_secret"] = ""
    runtime["status"] = str(data.get("status") or runtime_payload.get("status") or "active").strip() or "active"
    runtime["status_summary"] = (
        str(data.get("status_summary") or "已领取 Runtime 长期凭据").strip() or "已领取 Runtime 长期凭据"
    )
    runtime["activation_code_hint"] = str(runtime_payload.get("activation_code_hint") or "")
    if runtime_payload.get("display_name"):
        runtime["display_name"] = str(runtime_payload.get("display_name"))
    sync_runtime_binding_from_payload(runtime, runtime_payload)

    platform["password"] = ""
    config["platform"] = platform
    core.save_config_payload(config_path, config)
    return config


def generated_config_paths() -> list[Path]:
    core.ensure_generated_dir()
    return sorted(core.GENERATED_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)


def config_status_label(config: dict[str, Any]) -> str:
    if core.has_runtime_credentials(config):
        return "active"
    if core.has_pending_runtime_activation(config):
        return "pending-activation"
    if core.has_pending_runtime_registration(config):
        return "pending-approval"
    runtime = dict(config.get("runtime") or {})
    return str(runtime.get("status") or "draft").strip() or "draft"


def select_generated_config_path(paths: list[Path]) -> Path | None:
    if not paths:
        return None
    if len(paths) == 1 or not sys.stdin.isatty():
        return paths[0]

    print("检测到多个已有接入配置：")
    for index, path in enumerate(paths, start=1):
        try:
            config = core.load_config(path)
            status = config_status_label(config)
            upstream = str(dict(config.get("upstream") or {}).get("base_url") or "-")
        except Exception:
            status = "invalid"
            upstream = "-"
        print(f"  [{index}] {path.name} | status={status} | upstream={upstream}")
    print("  [0] 新建接入配置")

    while True:
        choice = input("请选择要复用的配置编号 [1]: ").strip()
        if not choice:
            return paths[0]
        if choice == "0":
            return None
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(paths):
                return paths[index - 1]
        print("编号无效，请重新输入。")


def has_onboarding_inputs(args: argparse.Namespace) -> bool:
    return bool(
        str(args.platform_base_url or "").strip()
        or str(args.platform_username or "").strip()
        or str(args.platform_password or "").strip()
        or str(args.upstream_base_url or "").strip()
        or str(args.upstream_token or "").strip()
        or str(args.auth_header_value or "").strip()
        or str(args.ai_endpoint_key or "").strip()
        or args.ai_endpoint_id is not None
    )


def build_connect_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="connect_agent_gateway",
        description="优先复用已有网关配置；首次接入时走当前后端的激活码流程。",
    )
    parser.add_argument("--config", help="指定已有配置文件路径；不填则自动复用 generated 目录里的配置")
    parser.add_argument("--new", action="store_true", help="忽略默认配置，强制走首次接入流程")
    parser.add_argument("--platform-base-url", help="管理端地址，例如 http://127.0.0.1:8000")
    parser.add_argument("--platform-username", help="管理端用户名")
    parser.add_argument("--platform-password", help="管理端密码")
    parser.add_argument("--activation-code", help="如果已经拿到激活码，可直接完成长期凭据换取")
    parser.add_argument("--ai-endpoint-id", type=int, help="首次接入时直接绑定到指定 AI endpoint ID")
    parser.add_argument("--ai-endpoint-key", help="首次接入时直接绑定到指定 AI endpoint key 或显示名称")
    parser.add_argument("--upstream-base-url", help="上游 Agent/OpenClaw 地址，例如 http://127.0.0.1:18789")
    parser.add_argument("--upstream-token", help="上游 Bearer Token，会自动写成 Authorization: Bearer <token>")
    parser.add_argument("--auth-header-name", default="Authorization", help="上游鉴权 Header 名称")
    parser.add_argument("--auth-header-value", help="上游鉴权 Header 原始值；若同时传 --upstream-token，则优先用 token")
    parser.add_argument("--profile-name", help="接入名称；不填则按上游地址自动生成")
    parser.add_argument("--runtime-display-name", help="Runtime 显示名称；不填则自动生成")
    parser.add_argument("--runtime-type", help="Runtime 类型；默认自动根据 OpenClaw 预设生成")
    parser.add_argument("--listen-host", default="0.0.0.0", help="本地监听地址，默认 0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=9010, help="本地监听端口，默认 9010")
    parser.add_argument("--access-host", help="业务侧访问网关时使用的地址/IP，不填则自动推断")
    parser.add_argument("--review-action", choices=["block", "allow"], default="block", help="review 判定时是阻断还是放行")
    parser.add_argument("--attack-type", default="prompt_injection", help="任务攻击类型")
    parser.add_argument("--request-timeout-seconds", type=int, default=120, help="上游请求超时秒数")
    parser.add_argument("--max-capture-chars", type=int, default=8000, help="请求/响应截断长度")
    parser.add_argument("--insecure-platform", action="store_true", help="不校验管理端 HTTPS 证书")
    parser.add_argument("--insecure-upstream", action="store_true", help="不校验上游 HTTPS 证书")
    parser.add_argument("--no-start", action="store_true", help="只完成接入或校验，不自动启动本地网关")
    for action in parser._actions:
        if action.dest in {"platform_username", "platform_password", "ai_endpoint_id", "ai_endpoint_key"}:
            action.help = argparse.SUPPRESS
    return parser


def resolve_requested_config_path(args: argparse.Namespace) -> tuple[Path | None, str]:
    config_value = str(args.config or "").strip()
    if config_value:
        return Path(config_value).expanduser().resolve(), "explicit"
    if bool(args.new):
        return None, "new"
    if has_onboarding_inputs(args):
        return None, "new"
    preferred = preferred_config_path()
    if preferred is not None:
        return preferred, "remembered"
    selected = select_generated_config_path(generated_config_paths())
    if selected is None:
        return None, "new"
    return selected, "generated"


def onboarding_summary(config_path: Path, config: dict[str, Any]) -> None:
    handoff = dict(config.get("client_handoff") or {})
    print()
    print("接入配置已生成。")
    print(f"配置文件: {config_path}")
    print(f"Windows 启动脚本: {config_path.with_name(f'run-{config_path.stem}.cmd')}")
    print(f"Linux/macOS 启动脚本: {config_path.with_name(f'run-{config_path.stem}.sh')}")
    print(f"业务侧新 base_url: {handoff.get('protected_base_url') or '-'}")
    print(f"绑定 AI: {runtime_binding_label(config)}")
    print("本地不保存管理端账号密码。后续如需重新接入，只需要新的短期接入激活码。")


def run_existing_config(
    config_path: Path,
    *,
    activation_code: str,
    start_gateway: bool,
    reuse_reason: str,
) -> int:
    if not config_path.exists():
        print(f"配置文件不存在: {config_path}")
        return 1

    config = core.load_config(config_path)
    if reuse_reason == "remembered":
        print(f"默认复用上次使用的配置: {config_path}")
    elif reuse_reason == "explicit":
        print(f"使用指定配置: {config_path}")
    else:
        print(f"复用已有配置: {config_path}")

    if core.has_runtime_credentials(config):
        try:
            session = validate_runtime_session(config)
        except Exception as exc:  # noqa: BLE001
            print(f"现有 Runtime 凭据校验失败: {exc}")
            print("当前将尝试使用新的短期接入激活码重新换取长期凭据。")
            return complete_bootstrap_activation(
                config_path,
                reset_runtime_for_reactivation(config),
                activation_code=activation_code,
                start_gateway=start_gateway,
            )
        remember_preferred_config(config_path, config)
        print_runtime_session_success(config, session)
        if start_gateway:
            print("正在启动本地网关...")
            return core.run_gateway(argparse.Namespace(config=str(config_path)))
        return 0

    if core.has_pending_runtime_activation(config):
        runtime = dict(config.get("runtime") or {})
        code = str(activation_code or "").strip()
        if not code:
            hint = str(runtime.get("activation_code_hint") or "").strip()
            label = "请输入激活码"
            if hint:
                label = f"请输入激活码（提示: {hint}）"
            if sys.stdin.isatty():
                code = prompt_secret(label, allow_empty=False)
            else:
                print("当前配置仍在等待激活码，请通过 --activation-code 提供。")
                return 1
        try:
            config = activate_with_code(config_path, config, code)
        except Exception as exc:  # noqa: BLE001
            print(f"激活失败: {exc}")
            return 1
        print("激活成功，长期 Runtime 凭据已落地到本地配置。")
        try:
            session = validate_runtime_session(config)
        except Exception as exc:  # noqa: BLE001
            print(f"激活后的 Runtime 会话校验失败: {exc}")
            return 1
        remember_preferred_config(config_path, config)
        print_runtime_session_success(config, session)
        if start_gateway:
            print("正在启动本地网关...")
            return core.run_gateway(argparse.Namespace(config=str(config_path)))
        return 0

    if str(activation_code or "").strip():
        print("检测到提供了新的短期接入激活码，正在直接换取长期凭据。")
        return complete_bootstrap_activation(
            config_path,
            reset_runtime_for_reactivation(config),
            activation_code=activation_code,
            start_gateway=start_gateway,
        )

    if core.has_pending_runtime_registration(config):
        print("当前配置属于旧版 enrollment token 流程，正在继续轮询审批结果...")
        try:
            config = core.ensure_runtime_credentials(config_path, config, wait_for_approval=True)
        except Exception as exc:  # noqa: BLE001
            print(f"旧版注册流程继续失败: {exc}")
            return 1
        if core.has_runtime_credentials(config):
            try:
                session = validate_runtime_session(config)
            except Exception as exc:  # noqa: BLE001
                print(f"审批通过后的 Runtime 会话校验失败: {exc}")
                return 1
            remember_preferred_config(config_path, config)
            print_runtime_session_success(config, session)
            if start_gateway:
                print("审批已通过，正在启动本地网关...")
                return core.run_gateway(argparse.Namespace(config=str(config_path)))
        return 0

    print("当前配置没有可复用的长期凭据，将改用短期接入激活码继续完成初始化。")
    return complete_bootstrap_activation(
        config_path,
        reset_runtime_for_reactivation(config),
        activation_code=activation_code,
        start_gateway=start_gateway,
    )


def build_new_config_from_args(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    core.ensure_generated_dir()
    preset_key = "openclaw_generic"

    platform_base_url = core.normalize_platform_base_url(
        str(args.platform_base_url or prompt_text("请输入管理端地址，例如 http://127.0.0.1:8000"))
    )
    upstream_base_url = core.normalize_base_url(
        str(args.upstream_base_url or prompt_text("请输入上游 Agent/OpenClaw 地址，例如 http://127.0.0.1:18789"))
    )
    upstream_auth_header_name = str(args.auth_header_name or "Authorization").strip() or "Authorization"

    upstream_token = str(args.upstream_token or "").strip()
    auth_header_value = str(args.auth_header_value or "").strip()
    legacy_auth_prompt = not upstream_token and not auth_header_value and sys.stdin.isatty()
    if legacy_auth_prompt:
        if upstream_auth_header_name.lower() == "authorization":
            upstream_token = prompt_secret("请输入上游 Bearer Token（没有可直接回车）", allow_empty=True)
        else:
            auth_header_value = prompt_secret(
                f"请输入上游 Header 值（{upstream_auth_header_name}，没有可直接回车）",
                allow_empty=True,
            )
    if False and not upstream_token and not auth_header_value and sys.stdin.isatty():
        if prompt_yes_no("上游接口是否需要鉴权 Header", True):
            if upstream_auth_header_name.lower() == "authorization":
                upstream_token = prompt_secret("请输入上游 Bearer Token", allow_empty=False)
            else:
                auth_header_value = prompt_secret(f"请输入上游 Header 值（{upstream_auth_header_name}）", allow_empty=False)

    normalized_auth_value = core.normalize_upstream_auth_value(
        upstream_auth_header_name,
        upstream_token or auth_header_value,
    )

    listen_host = str(args.listen_host or "0.0.0.0").strip() or "0.0.0.0"
    listen_port = int(args.listen_port or 9010)
    access_host = str(args.access_host or core.default_access_host(listen_host)).strip()
    profile_name = str(args.profile_name or core.build_default_profile_name(preset_key, upstream_base_url)).strip()
    runtime_display_name = str(
        args.runtime_display_name or core.build_default_runtime_display_name(preset_key, upstream_base_url)
    ).strip()
    runtime_type = str(args.runtime_type or core.default_runtime_type_for_preset(preset_key)).strip()
    verify_platform_tls = not bool(args.insecure_platform)
    verify_upstream_tls = not bool(args.insecure_upstream)

    print()
    print("正在测试上游连通性...")
    probe = core.probe_upstream_target(
        upstream_base_url,
        auth_header_name=upstream_auth_header_name,
        auth_header_value=normalized_auth_value,
        verify_tls=verify_upstream_tls,
        timeout_seconds=8,
    )
    if probe.get("health_status") is not None:
        print(f"- /health: {probe['health_status']}")
    elif probe.get("health_error"):
        print(f"- /health 失败: {probe['health_error']}")
    if probe.get("root_status") is not None:
        print(f"- /: {probe['root_status']}")
    elif probe.get("root_error"):
        print(f"- / 失败: {probe['root_error']}")
    if not probe.get("ok"):
        raise RuntimeError("上游连通性探测失败，已中止接入。")

    config = core.build_runtime_gateway_config(
        profile_name=profile_name,
        preset_key=preset_key,
        platform_base_url=platform_base_url,
        verify_platform_tls=verify_platform_tls,
        runtime_display_name=runtime_display_name,
        runtime_type=runtime_type,
        upstream_base_url=upstream_base_url,
        upstream_auth_header_name=upstream_auth_header_name,
        upstream_auth_header_value=normalized_auth_value,
        verify_upstream_tls=verify_upstream_tls,
        listen_host=listen_host,
        listen_port=listen_port,
        access_host=access_host,
        attack_type=str(args.attack_type or "prompt_injection").strip() or "prompt_injection",
        review_action=str(args.review_action or "block").strip().lower() or "block",
        request_timeout_seconds=int(args.request_timeout_seconds or 120),
        max_capture_chars=int(args.max_capture_chars or 8000),
        mapping=core.build_mapping(preset_key),
        platform_username="",
        platform_password="",
    )

    config_path = core.GENERATED_DIR / f"{config['profile_slug']}.json"
    core.save_config_payload(config_path, config)
    core.generate_run_scripts(config_path)
    return config_path, config


def run_new_connect(args: argparse.Namespace, *, start_gateway: bool) -> int:
    try:
        config_path, config = build_new_config_from_args(args)
    except Exception as exc:  # noqa: BLE001
        print(f"首次接入准备失败: {exc}")
        return 1

    try:
        health = validate_platform_health(config)
        print(f"管理端健康检查通过: {health.get('status') or 'ok'}")
    except Exception as exc:  # noqa: BLE001
        print(f"管理端连接失败: {exc}")
        return 1

    remember_preferred_config(config_path, config)
    onboarding_summary(config_path, config)
    print("请使用管理员预先生成并绑定到目标 AI 的短期接入激活码完成首次接入。")
    return complete_bootstrap_activation(
        config_path,
        config,
        activation_code=str(args.activation_code or "").strip(),
        start_gateway=start_gateway,
    )


def run_connect(argv: list[str]) -> int:
    parser = build_connect_parser()
    args = parser.parse_args(argv)
    start_gateway = not bool(args.no_start)
    config_path, reuse_reason = resolve_requested_config_path(args)
    activation_code = str(args.activation_code or "").strip()

    if config_path is not None:
        if args.ai_endpoint_id is not None or str(args.ai_endpoint_key or "").strip():
            print("已进入现有配置复用流程，--ai-endpoint-id / --ai-endpoint-key 仅对首次接入生效，将忽略。")
        return run_existing_config(
            config_path,
            activation_code=activation_code,
            start_gateway=start_gateway,
            reuse_reason=reuse_reason,
        )
    return run_new_connect(args, start_gateway=start_gateway)


def build_activate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="connect_agent_gateway activate",
        description="为待激活配置输入激活码，并换取长期 Runtime 凭据。",
    )
    parser.add_argument("--config", required=True, help="待激活配置文件路径")
    parser.add_argument("--code", help="激活码；不填则进入交互式输入")
    parser.add_argument("--start-gateway", action="store_true", help="激活成功后直接启动本地网关")
    return parser


def build_validate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="connect_agent_gateway validate",
        description="校验现有配置是否仍可与当前后端正常通信。",
    )
    parser.add_argument("--config", required=True, help="配置文件路径")
    parser.add_argument("--code", help="如果配置仍待激活，可直接附带激活码")
    return parser


def build_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="connect_agent_gateway run",
        description="使用现有配置直接启动本地防护网关。",
    )
    parser.add_argument("--config", required=True, help="配置文件路径")
    return parser


def build_doctor_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="connect_agent_gateway doctor",
        description="对当前连接配置做一次自检，帮助排查平台、上游和 Runtime 状态问题。",
    )
    parser.add_argument("--config", help="配置文件路径；不填则优先检查上次成功使用的配置")
    parser.add_argument("--repair", action="store_true", help="若发现 Runtime 凭据失效，则尝试沿用原配置重新发起激活申请")
    return parser


def run_activate(argv: list[str]) -> int:
    parser = build_activate_parser()
    args = parser.parse_args(argv)
    return run_existing_config(
        Path(args.config).expanduser().resolve(),
        activation_code=str(getattr(args, "code", "") or "").strip(),
        start_gateway=bool(getattr(args, "start_gateway", False)),
        reuse_reason="explicit",
    )


def run_validate(argv: list[str]) -> int:
    parser = build_validate_parser()
    args = parser.parse_args(argv)
    exit_code = core.validate_config(args)
    if exit_code == 0:
        remember_preferred_config(Path(args.config).expanduser().resolve(), core.load_config(Path(args.config).expanduser().resolve()))
    return exit_code


def run_gateway_command(argv: list[str]) -> int:
    parser = build_run_parser()
    args = parser.parse_args(argv)
    config_path = Path(args.config).expanduser().resolve()
    exit_code = core.run_gateway(args)
    if exit_code == 0 and config_path.exists():
        remember_preferred_config(config_path, core.load_config(config_path))
    return exit_code


def resolve_doctor_config_path(config_value: str) -> tuple[Path | None, str]:
    raw = str(config_value or "").strip()
    if raw:
        return Path(raw).expanduser().resolve(), "explicit"
    preferred = preferred_config_path()
    if preferred is not None:
        return preferred, "remembered"
    selected = select_generated_config_path(generated_config_paths())
    if selected is None:
        return None, "missing"
    return selected, "generated"


def run_doctor(argv: list[str]) -> int:
    parser = build_doctor_parser()
    args = parser.parse_args(argv)
    config_path, source = resolve_doctor_config_path(str(args.config or ""))
    if config_path is None:
        print("当前没有可自检的本地接入配置。请先执行 connect 完成首次接入。")
        return 1
    if not config_path.exists():
        print(f"配置文件不存在: {config_path}")
        return 1

    config = core.load_config(config_path)
    platform = dict(config.get("platform") or {})
    upstream = dict(config.get("upstream") or {})
    listen_host = str(dict(config.get("gateway") or {}).get("listen_host") or "-")
    listen_port = str(dict(config.get("gateway") or {}).get("listen_port") or "-")

    if source == "remembered":
        print(f"自检目标: 上次成功使用的配置 {config_path}")
    elif source == "explicit":
        print(f"自检目标: 指定配置 {config_path}")
    else:
        print(f"自检目标: 现有配置 {config_path}")
    print(f"当前状态: {config_status_label(config)}")
    print(f"上游地址: {upstream.get('base_url') or '-'}")
    print(f"管理端地址: {platform.get('base_url') or '-'}")
    print(f"网关监听: {listen_host}:{listen_port}")
    print(f"绑定 AI: {runtime_binding_label(config)}")
    print()

    failures: list[str] = []

    try:
        health = validate_platform_health(config)
        print(f"[OK] 管理端健康检查: {health.get('status') or 'ok'}")
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 管理端健康检查失败: {exc}")
        failures.append("platform-health")

    if str(platform.get("username") or "").strip() and str(platform.get("password") or "").strip():
        try:
            validate_platform_login(config)
            print("[OK] 管理端账号登录: 可用")
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] 管理端账号登录失败: {exc}")
            failures.append("platform-login")
    else:
        print("[INFO] 本地未保存管理端密码；如需重新申请激活，届时再输入即可。")

    probe = core.probe_upstream_target(
        str(upstream.get("base_url") or ""),
        auth_header_name=str(upstream.get("auth_header_name") or ""),
        auth_header_value=str(upstream.get("auth_header_value") or ""),
        verify_tls=bool(upstream.get("verify_tls", True)),
        timeout_seconds=8,
    )
    if probe.get("ok"):
        health_status = probe.get("health_status")
        root_status = probe.get("root_status")
        print(f"[OK] 上游连通性: /health={health_status if health_status is not None else '-'} /={root_status if root_status is not None else '-'}")
    else:
        detail = probe.get("health_error") or probe.get("root_error") or "unknown error"
        print(f"[FAIL] 上游连通性失败: {detail}")
        failures.append("upstream")

    if core.has_runtime_credentials(config):
        try:
            session = validate_runtime_session(config)
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] Runtime 会话校验失败: {exc}")
            failures.append("runtime-session")
            if bool(args.repair):
                print()
                return complete_bootstrap_activation(
                    config_path,
                    reset_runtime_for_reactivation(config),
                    activation_code="",
                    start_gateway=False,
                )
            print(f"[NEXT] 可尝试重新接入: python tools/agent_gateway/connect_entry.py connect --config \"{config_path}\"")
        else:
            print_runtime_session_success(config, session)
    elif core.has_pending_runtime_activation(config):
        runtime = dict(config.get("runtime") or {})
        print("[INFO] 当前配置已提交激活申请，正在等待激活码。")
        if str(runtime.get("activation_code_hint") or "").strip():
            print(f"[INFO] 激活码提示: {runtime['activation_code_hint']}")
        print(f"[NEXT] 继续激活: python tools/agent_gateway/connect_entry.py activate --config \"{config_path}\"")
    elif core.has_pending_runtime_registration(config):
        print("[INFO] 当前配置处于旧版 enrollment token 注册流程，尚未完成审批。")
        print(f"[NEXT] 可继续校验: python tools/agent_gateway/connect_entry.py validate --config \"{config_path}\"")
    else:
        print("[INFO] 当前配置没有长期 Runtime 凭据，也没有待继续的注册状态。")
        print("[NEXT] 请重新执行首次接入。")

    if failures:
        print()
        print(f"自检完成，发现 {len(failures)} 项阻断性问题。")
        return 1

    remember_preferred_config(config_path, config)
    print()
    print("自检完成，当前配置未发现阻断性问题。")
    return 0


def print_top_level_help() -> None:
    parser = build_connect_parser()
    parser.print_help()
    print()
    print("常用子命令：")
    print("  connect_agent_gateway.cmd connect [--new] [--config <path>]")
    print("  connect_agent_gateway.cmd activate --config <path>")
    print("  connect_agent_gateway.cmd validate --config <path>")
    print("  connect_agent_gateway.cmd doctor [--config <path>] [--repair]")
    print("  connect_agent_gateway.cmd run --config <path>")
    print()
    print("其他高级命令仍会透传给 tools/agent_gateway/agent_gateway_cli.py，例如：")
    print("  connect_agent_gateway.cmd quick-openclaw ...")
    print("  connect_agent_gateway.cmd presets")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return run_connect([])
    if args[0] in {"-h", "--help", "help"}:
        print_top_level_help()
        return 0
    if args[0] == "connect":
        return run_connect(args[1:])
    if args[0] == "activate":
        return run_activate(args[1:])
    if args[0] == "validate":
        return run_validate(args[1:])
    if args[0] == "doctor":
        return run_doctor(args[1:])
    if args[0] == "run":
        return run_gateway_command(args[1:])
    return core.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
