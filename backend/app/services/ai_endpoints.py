from __future__ import annotations

import re
from copy import deepcopy
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from ..core.config import settings
from ..models import AiEndpoint, AttackTask, ManagedRuntime, RuntimeEnrollmentToken
from .model_provider import ProviderConfigurationError, ProviderEndpoint
from .time_utils import format_beijing, utc_now


SUPPORTED_PROVIDER_TYPES = {
    "openai_compatible",
    "anthropic",
    "azure_openai",
    "gemini",
    "ollama",
    "bedrock",
}
SUPPORTED_PROTECTION_MODES = {"enforce", "observe", "off"}
NORMALIZED_SENSITIVE_CONFIG_KEYS = {
    "apikey",
    "accesstoken",
    "refreshtoken",
    "auth",
    "authorization",
    "bearertoken",
    "sessiontoken",
    "jwt",
    "password",
    "passwd",
    "pwd",
    "secret",
    "clientsecret",
    "smtppassword",
    "privatekey",
    "cookie",
    "setcookie",
    "handofftoken",
    "xapikey",
}
SENSITIVE_CONFIG_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:api(?:[_\-.]?key)?|access(?:[_\-.]?token)?|refresh(?:[_\-.]?token)?|auth(?:orization)?|bearer(?:[_\-.]?token)?|session(?:[_\-.]?token)?|jwt|password|passwd|pwd|secret|client(?:[_\-.]?secret)?|smtp(?:[_\-.]?password)?|private(?:[_\-.]?key)?|cookie|set[_\-.]?cookie|handoff(?:[_\-.]?token)?|x[_\-.]?api[_\-.]?key)(?:$|[_\-.])",
    re.IGNORECASE,
)
PROVIDER_TEMPLATES = {
    "deepseek": {
        "provider_type": "openai_compatible",
        "display_name": "DeepSeek Compatible",
        "endpoint_group": "compatible",
        "base_url_hint": "https://api.deepseek.com/v1",
        "config_json": {"headers": {}, "extra_body": {}},
    },
    "moonshot": {
        "provider_type": "openai_compatible",
        "display_name": "Moonshot Compatible",
        "endpoint_group": "compatible",
        "base_url_hint": "https://api.moonshot.cn/v1",
        "config_json": {"headers": {}, "extra_body": {}},
    },
    "vllm": {
        "provider_type": "openai_compatible",
        "display_name": "vLLM OpenAI Compatible",
        "endpoint_group": "self-hosted",
        "base_url_hint": "http://127.0.0.1:8000/v1",
        "config_json": {"headers": {}, "extra_body": {}},
    },
    "oneapi": {
        "provider_type": "openai_compatible",
        "display_name": "One API Compatible",
        "endpoint_group": "gateway",
        "base_url_hint": "http://127.0.0.1:3000/v1",
        "config_json": {"headers": {}, "extra_body": {}},
    },
}
GATEWAY_BASE_PATH = "/api/gateway/v1"
GATEWAY_WS_BASE_PATH = "/api/gateway/v1/ws"


def normalize_endpoint_key(value: str) -> str:
    normalized = "".join(char.lower() if char.isalnum() else "-" for char in value.strip())
    normalized = "-".join(part for part in normalized.split("-") if part)
    return normalized


def normalize_endpoint_group(value: str | None) -> str:
    normalized = " ".join(str(value or "").replace("\n", " ").split()).strip()
    return normalized[:64] or "default"


def normalize_provider_type(value: str) -> str:
    provider_type = value.strip().lower()
    if provider_type not in SUPPORTED_PROVIDER_TYPES:
        raise ValueError(f"Unsupported provider_type: {value}")
    return provider_type


def normalize_protection_mode(value: str) -> str:
    protection_mode = value.strip().lower()
    if protection_mode not in SUPPORTED_PROTECTION_MODES:
        raise ValueError(f"Unsupported protection_mode: {value}")
    return protection_mode


def mask_api_key(value: str) -> str:
    secret = value.strip()
    if not secret:
        return ""
    if len(secret) <= 8:
        return f"{secret[:2]}***"
    return f"{secret[:4]}***{secret[-4:]}"


def is_sensitive_config_key(value: str | None) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    normalized = re.sub(r"[^A-Za-z0-9]", "", raw).lower()
    return normalized in NORMALIZED_SENSITIVE_CONFIG_KEYS or bool(SENSITIVE_CONFIG_KEY_RE.search(raw))


def _join_config_path(base: str, token: str | int) -> str:
    if isinstance(token, int):
        return f"{base}[{token}]" if base else f"[{token}]"
    return f"{base}.{token}" if base else token


def _last_path_key(path: str) -> str:
    if not path:
        return ""
    cleaned = re.sub(r"\[\d+\]$", "", path)
    return cleaned.split(".")[-1] if cleaned else path


def _mask_secret_text(value: str) -> str:
    secret = value.strip()
    if not secret:
        return "***"
    if len(secret) <= 6:
        return "***"
    return f"{secret[:4]}***{secret[-2:]}"


def _mask_secret_value(value: Any) -> str:
    if isinstance(value, str):
        return _mask_secret_text(value)
    if isinstance(value, bool):
        return "***"
    if isinstance(value, (int, float)):
        return "***"
    if value is None:
        return "null"
    if isinstance(value, list):
        return f"隐藏列表({len(value)})"
    if isinstance(value, dict):
        return f"隐藏对象({len(value)})"
    return "***"


def _secret_value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _build_secret_item(path: str, value: Any) -> dict[str, Any]:
    return {
        "path": path,
        "key": _last_path_key(path),
        "masked_value": _mask_secret_value(value),
        "value_type": _secret_value_type(value),
    }


def _strip_sensitive_config(value: Any, *, parent_sensitive: bool = False) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if parent_sensitive or is_sensitive_config_key(key_str):
                continue
            result[key_str] = _strip_sensitive_config(item, parent_sensitive=False)
        return result
    if isinstance(value, list):
        return [_strip_sensitive_config(item, parent_sensitive=parent_sensitive) for item in value]
    return deepcopy(value)


def _collect_sensitive_leaf_values(value: Any, path: str = "", *, parent_sensitive: bool = False) -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_str = str(key)
            next_path = _join_config_path(path, key_str)
            sensitive = parent_sensitive or is_sensitive_config_key(key_str)
            items.extend(_collect_sensitive_leaf_values(item, next_path, parent_sensitive=sensitive))
        return items
    if isinstance(value, list):
        if parent_sensitive and not value and path:
            return [(path, [])]
        for index, item in enumerate(value):
            items.extend(_collect_sensitive_leaf_values(item, _join_config_path(path, index), parent_sensitive=parent_sensitive))
        return items
    if parent_sensitive and path:
        return [(path, deepcopy(value))]
    return items


def _collect_sensitive_config_items(value: Any) -> list[dict[str, Any]]:
    return [_build_secret_item(path, item) for path, item in _collect_sensitive_leaf_values(value)]


def _parse_config_path(path: str) -> list[str | int]:
    normalized = path.strip()
    if not normalized:
        raise ValueError(f"Invalid config path: {path}")

    tokens: list[str | int] = []
    index = 0
    length = len(normalized)

    while index < length:
        char = normalized[index]
        if char == ".":
            index += 1
            if index >= length:
                raise ValueError(f"Invalid config path: {path}")
            continue

        if char == "[":
            closing = normalized.find("]", index + 1)
            if closing <= index + 1:
                raise ValueError(f"Invalid config path: {path}")
            raw_index = normalized[index + 1 : closing]
            if not raw_index.isdigit():
                raise ValueError(f"Invalid config path: {path}")
            tokens.append(int(raw_index))
            index = closing + 1
            continue

        next_index = index
        while next_index < length and normalized[next_index] not in ".[":
            next_index += 1
        segment = normalized[index:next_index].strip()
        if not segment:
            raise ValueError(f"Invalid config path: {path}")
        tokens.append(segment)
        index = next_index

    return tokens


def _ensure_list_size(value: list[Any], index: int) -> None:
    while len(value) <= index:
        value.append(None)


def _set_config_path(target: dict[str, Any], path: str, value: Any) -> None:
    tokens = _parse_config_path(path)
    if not isinstance(tokens[0], str):
        raise ValueError(f"Config path must start with an object key: {path}")

    current: Any = target
    for index, token in enumerate(tokens[:-1]):
        next_token = tokens[index + 1]
        if isinstance(token, str):
            if not isinstance(current, dict):
                raise ValueError(f"Config path expects object segment before {token}: {path}")
            next_value = current.get(token)
            if isinstance(next_token, int):
                if not isinstance(next_value, list):
                    next_value = []
                    current[token] = next_value
            else:
                if not isinstance(next_value, dict):
                    next_value = {}
                    current[token] = next_value
            current = next_value
            continue

        if not isinstance(current, list):
            raise ValueError(f"Config path expects list segment before [{token}]: {path}")
        _ensure_list_size(current, token)
        next_value = current[token]
        if isinstance(next_token, int):
            if not isinstance(next_value, list):
                next_value = []
                current[token] = next_value
        else:
            if not isinstance(next_value, dict):
                next_value = {}
                current[token] = next_value
        current = next_value

    last_token = tokens[-1]
    if isinstance(last_token, str):
        if not isinstance(current, dict):
            raise ValueError(f"Config path expects object at leaf: {path}")
        current[last_token] = deepcopy(value)
        return

    if not isinstance(current, list):
        raise ValueError(f"Config path expects list at leaf: {path}")
    _ensure_list_size(current, last_token)
    current[last_token] = deepcopy(value)


def _delete_config_path(target: Any, path: str) -> None:
    tokens = _parse_config_path(path)

    def _delete(node: Any, remaining: list[str | int]) -> bool:
        token = remaining[0]
        is_leaf = len(remaining) == 1

        if isinstance(token, str):
            if not isinstance(node, dict) or token not in node:
                return False
            if is_leaf:
                node.pop(token, None)
            else:
                should_prune = _delete(node[token], remaining[1:])
                if should_prune:
                    node.pop(token, None)
            return isinstance(node, dict) and not node

        if not isinstance(node, list) or token >= len(node):
            return False
        if is_leaf:
            node.pop(token)
        else:
            should_prune = _delete(node[token], remaining[1:])
            if should_prune:
                node.pop(token)
        return isinstance(node, list) and not node

    _delete(target, tokens)


def build_endpoint_config_payload(
    current_config: dict[str, Any] | None,
    *,
    raw_config: dict[str, Any] | None = None,
    public_config: dict[str, Any] | None = None,
    secret_updates: list[dict[str, Any]] | None = None,
    secret_remove_paths: list[str] | None = None,
) -> dict[str, Any]:
    if raw_config is not None:
        return dict(raw_config)

    current = dict(current_config or {})
    base_public = _strip_sensitive_config(current if public_config is None else public_config)
    if not isinstance(base_public, dict):
        raise ValueError("config_public_json must be a JSON object")

    merged = deepcopy(base_public)
    for path, value in _collect_sensitive_leaf_values(current):
        _set_config_path(merged, path, value)

    for path in secret_remove_paths or []:
        normalized_path = str(path or "").strip()
        if normalized_path:
            _delete_config_path(merged, normalized_path)

    for item in secret_updates or []:
        normalized_path = str(item.get("path") or "").strip()
        if not normalized_path:
            continue
        _set_config_path(merged, normalized_path, item.get("value"))

    return merged


def build_ai_endpoint_config_view(config: dict[str, Any]) -> dict[str, Any]:
    secret_items = _collect_sensitive_config_items(config)
    return {
        "config_public_json": _strip_sensitive_config(config),
        "config_secret_items": secret_items,
        "config_secret_count": len(secret_items),
        "config_secret_summary": "未发现隐藏敏感配置" if not secret_items else f"已隐藏 {len(secret_items)} 项敏感配置",
    }


def build_ai_endpoint_integration_view(item: AiEndpoint) -> dict[str, Any]:
    endpoint_group = normalize_endpoint_group(item.endpoint_group)
    endpoint_key = item.endpoint_key

    if not item.enabled:
        protection_summary = "当前端点已停用，不参与统一入口路由，也不会承接在线防护流量。"
    elif not item.protection_enabled or item.protection_mode == "off":
        protection_summary = "当前端点会承接统一入口流量，但仅做路由转发，不执行前置防护判定。"
    elif item.protection_mode == "observe":
        protection_summary = "当前端点会先经过规则和 AI 复核，命中后以可疑告警留痕为主，默认继续放行。"
    else:
        protection_summary = "当前端点会先经过规则和 AI 复核，命中高风险请求时可直接拦截，再决定是否转发到上游模型。"

    default_route_summary = (
        "当前端点就是默认回退路由；调用方可以不显式指定目标。"
        if item.is_default
        else "建议显式指定 endpoint_key；如果省略路由选择，请求会回退到平台默认端点。"
    )

    route_selector_items = [
        {
            "key": "header_endpoint",
            "label": "显式路由",
            "value": f"X-Target-Endpoint: {endpoint_key}",
            "detail": "最直接的在线接入方式，适合模型 SDK、反向代理和服务端调用。",
        },
        {
            "key": "body_selector",
            "label": "请求体路由",
            "value": f'"target_selector": {{"endpoint_key": "{endpoint_key}"}}',
            "detail": "适合 OpenAI Chat / Responses / Agents 兼容请求体直接携带路由选择。",
        },
        {
            "key": "group_route",
            "label": "分组回退",
            "value": f"X-Route-Group: {endpoint_group}",
            "detail": "同组多端点场景可按分组切流，再由组内默认目标承接。",
        },
    ]

    auth_modes = [
        {
            "key": "jwt",
            "label": "平台登录令牌",
            "header_name": "Authorization",
            "header_value": "Bearer <平台访问令牌>",
            "summary": "适合控制台联调、用户态调用和浏览器侧受控访问。",
            "recommended": True,
        },
        {
            "key": "service_token",
            "label": "服务令牌",
            "header_name": "X-Gateway-Token",
            "header_value": "<GATEWAY_API_TOKEN>",
            "summary": "适合服务到服务接入、外部 Agent 网关转发；生产环境应替换默认令牌。",
            "recommended": False,
        },
        {
            "key": "runtime_secret",
            "label": "Runtime 长期凭据",
            "header_name": "X-Runtime-Key / X-Runtime-Secret",
            "header_value": "<审批后由客户端自动领取>",
            "summary": "适合已纳管 Agent / Runtime 的长期在线接入；客户端审批通过后自动领证，不需要人工抄写密钥。",
            "recommended": False,
        },
    ]

    access_modes = [
        {
            "key": "model_proxy",
            "label": "模型代理接入",
            "summary": "把原模型请求地址切到平台网关，再路由到当前端点。",
            "detail": "适用于 OpenAI / Azure OpenAI / vLLM / one-api 等模型端点；保留原 model、messages、input 等调用习惯。",
            "routes": [
                {
                    "key": "chat_completions",
                    "label": "Chat Completions",
                    "method": "POST",
                    "path": f"{GATEWAY_BASE_PATH}/chat/completions",
                    "summary": "兼容 OpenAI Chat Completions；支持 stream=true / SSE。",
                },
                {
                    "key": "responses",
                    "label": "Responses",
                    "method": "POST",
                    "path": f"{GATEWAY_BASE_PATH}/responses",
                    "summary": "兼容 OpenAI Responses；适合新式 input / instructions 请求。",
                },
            ],
            "step_items": [
                "把调用方 base_url 改为平台网关地址，并保留原来的模型请求协议。",
                f"显式添加路由头 X-Target-Endpoint: {endpoint_key}，或在请求体写入 target_selector.endpoint_key。",
                "带上平台登录令牌或服务令牌，确保在线请求先经过统一防护链。",
                "如果需要流式返回，继续使用 stream=true，由网关完成上游转发与审计。",
            ],
            "sample_lines": [
                "POST /api/gateway/v1/chat/completions",
                "Authorization: Bearer <平台访问令牌>",
                f"X-Target-Endpoint: {endpoint_key}",
                '{"model":"'
                + item.model_name
                + '","messages":[{"role":"user","content":"ping"}],"stream":true,"target_selector":{"endpoint_key":"'
                + endpoint_key
                + '"}}',
            ],
        },
        {
            "key": "agent_gateway",
            "label": "Agent 网关接入",
            "summary": "把 Agent 调用统一收口到平台网关，再按端点路由到当前模型目标。",
            "detail": "适用于 Dify、Coze、自研 Agent、MCP Agent 等需要同时回传路径、技能、插件元数据的场景。",
            "routes": [
                {
                    "key": "agents_run",
                    "label": "Agents Run",
                    "method": "POST",
                    "path": f"{GATEWAY_BASE_PATH}/agents/run",
                    "summary": "统一承接 Agent 请求；支持 messages / input_text / tools / stream。",
                },
                {
                    "key": "agents_run_ws",
                    "label": "Agents Run WebSocket",
                    "method": "WS",
                    "path": f"{GATEWAY_WS_BASE_PATH}/agents/run",
                    "summary": "需要长连接或持续流式回显时可切到 WebSocket 入口。",
                },
            ],
            "step_items": [
                "把原本直接访问模型的 Agent 调用改为访问 /agents/run。",
                "在请求体里补充 paths、skill_names、plugin_names、requested_scopes 等运行时元数据。",
                f"使用 target_selector.endpoint_key={endpoint_key} 固定命中当前保护目标。",
                "平台会在执行前完成规则判定、AI 复核和运行态审计，再决定拦截、可疑或放行。",
            ],
            "sample_lines": [
                "POST /api/gateway/v1/agents/run",
                "X-Gateway-Token: <GATEWAY_API_TOKEN>",
                '{"runtime_name":"external-agent","input_text":"请总结这个目录","paths":["/srv/project"],"skill_names":["repo-reader"],"target_selector":{"endpoint_key":"'
                + endpoint_key
                + '"}}',
            ],
        },
        {
            "key": "runtime_callback",
            "label": "运行时回调接入",
            "summary": "适用于平台已创建任务、需要外部 Runtime 回传授权、心跳和完成结果的场景。",
            "detail": "更适合样本执行、扫描任务和平台代理执行链；不建议把它当作普通在线模型入口使用。",
            "routes": [
                {
                    "key": "runtime_authorize",
                    "label": "执行前授权",
                    "method": "POST",
                    "path": f"{GATEWAY_BASE_PATH}/runtime/authorize",
                    "summary": "动作执行前回调统一策略面，拿到拦截 / 可疑 / 放行结论。",
                },
                {
                    "key": "runtime_heartbeat",
                    "label": "运行心跳",
                    "method": "POST",
                    "path": f"{GATEWAY_BASE_PATH}/runtime/heartbeat",
                    "summary": "运行中持续回传状态、进度与运行上下文。",
                },
                {
                    "key": "runtime_complete",
                    "label": "完成回传",
                    "method": "POST",
                    "path": f"{GATEWAY_BASE_PATH}/runtime/complete",
                    "summary": "回传原始响应、告警命中和结果摘要，并自动生成安全事件与报告。",
                },
            ],
            "step_items": [
                "先由平台创建任务，或通过 /agents/run 让平台生成 task_id。",
                "外部 Runtime 在执行高风险动作前调用 /runtime/authorize 获取统一判定。",
                "执行过程中定期调用 /runtime/heartbeat 保持任务运行态可见。",
                "结束后调用 /runtime/complete，回传原始响应、事件摘要和命中规则。",
            ],
            "sample_lines": [
                "POST /api/gateway/v1/runtime/authorize",
                "Authorization: Bearer <平台访问令牌>",
                '{"task_id":123,"runtime_name":"openclaw","action_type":"tool_call","input_text":"读取本地文件","paths":["C:/repo/.env"]}',
            ],
        },
    ]

    return {
        "gateway_base_path": GATEWAY_BASE_PATH,
        "gateway_ws_base_path": GATEWAY_WS_BASE_PATH,
        "protection_summary": protection_summary,
        "default_route_summary": default_route_summary,
        "route_selector_items": route_selector_items,
        "auth_modes": auth_modes,
        "access_modes": access_modes,
    }


def build_ai_endpoint_usage_summaries(db: Session) -> dict[int, dict[str, Any]]:
    usage: dict[int, dict[str, Any]] = {}
    online_threshold = utc_now() - timedelta(minutes=10)

    def ensure(endpoint_id: int) -> dict[str, Any]:
        return usage.setdefault(
            endpoint_id,
            {
                "token_count": 0,
                "runtime_count": 0,
                "runtime_pending_count": 0,
                "runtime_active_count": 0,
                "runtime_online_count": 0,
                "task_count": 0,
                "active_task_count": 0,
                "last_runtime_seen_at": "",
            },
        )

    for token in db.query(RuntimeEnrollmentToken).all():
        if token.ai_endpoint_id is None:
            continue
        ensure(token.ai_endpoint_id)["token_count"] += 1

    for runtime in db.query(ManagedRuntime).all():
        if runtime.ai_endpoint_id is None:
            continue
        bucket = ensure(runtime.ai_endpoint_id)
        bucket["runtime_count"] += 1
        if runtime.status in {"pending", "approved"}:
            bucket["runtime_pending_count"] += 1
        if runtime.status == "active":
            bucket["runtime_active_count"] += 1
        if runtime.last_seen_at is not None:
            rendered = format_beijing(runtime.last_seen_at) or ""
            if not bucket["last_runtime_seen_at"] or rendered > bucket["last_runtime_seen_at"]:
                bucket["last_runtime_seen_at"] = rendered
            if runtime.last_seen_at >= online_threshold:
                bucket["runtime_online_count"] += 1

    for task in db.query(AttackTask).all():
        raw_value = task.params.get("ai_endpoint_id")
        endpoint_id: int | None = None
        if isinstance(raw_value, int):
            endpoint_id = raw_value
        elif isinstance(raw_value, str) and raw_value.strip().isdigit():
            endpoint_id = int(raw_value.strip())
        if endpoint_id is None:
            continue
        bucket = ensure(endpoint_id)
        bucket["task_count"] += 1
        if task.status in {"ready", "queued", "scheduled", "running"}:
            bucket["active_task_count"] += 1

    return usage


def is_demo_ai_endpoint(item: AiEndpoint) -> bool:
    endpoint_key = normalize_endpoint_key(item.endpoint_key)
    display_name = item.display_name.strip().lower()
    base_url = item.base_url.strip().lower()
    return (
        endpoint_key.startswith("smoke-")
        or "smoke" in display_name
        or "local null" in display_name
        or base_url.startswith("http://127.0.0.1:9")
        or base_url.startswith("http://localhost:9")
    )


def serialize_ai_endpoint(item: AiEndpoint, *, usage_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    config_view = build_ai_endpoint_config_view(item.config)
    usage = {
        "token_count": 0,
        "runtime_count": 0,
        "runtime_pending_count": 0,
        "runtime_active_count": 0,
        "runtime_online_count": 0,
        "task_count": 0,
        "active_task_count": 0,
        "last_runtime_seen_at": "",
        **(usage_summary or {}),
    }
    is_demo = is_demo_ai_endpoint(item)
    return {
        "id": item.id,
        "endpoint_key": item.endpoint_key,
        "display_name": item.display_name,
        "endpoint_group": normalize_endpoint_group(item.endpoint_group),
        "provider_type": item.provider_type,
        "base_url": item.base_url,
        "model_name": item.model_name,
        "enabled": item.enabled,
        "is_default": item.is_default,
        "protection_enabled": item.protection_enabled,
        "protection_mode": item.protection_mode,
        "description": item.description,
        **config_view,
        "integration_view": build_ai_endpoint_integration_view(item),
        "has_api_key": bool(item.api_key),
        "api_key_hint": mask_api_key(item.api_key),
        "usage_summary": usage,
        "is_demo_endpoint": is_demo,
        "is_cleanup_candidate": is_demo and not usage["active_task_count"] and not usage["runtime_active_count"],
        "created_at": format_beijing(item.created_at) or "",
        "updated_at": format_beijing(item.updated_at) or "",
    }


def build_ai_endpoint_snapshot(item: AiEndpoint) -> dict[str, Any]:
    return {
        "id": item.id,
        "endpoint_key": item.endpoint_key,
        "display_name": item.display_name,
        "endpoint_group": normalize_endpoint_group(item.endpoint_group),
        "provider_type": item.provider_type,
        "base_url": item.base_url,
        "model_name": item.model_name,
        "protection_enabled": item.protection_enabled,
        "protection_mode": item.protection_mode,
        "source": "managed",
    }


def build_env_ai_endpoint_snapshot() -> dict[str, Any]:
    return {
        "id": None,
        "endpoint_key": "env-default",
        "display_name": "Environment Default",
        "endpoint_group": "environment",
        "provider_type": settings.ai_provider,
        "base_url": settings.ai_base_url,
        "model_name": settings.ai_model,
        "protection_enabled": True,
        "protection_mode": "enforce",
        "source": "env",
    }


def provider_endpoint_from_ai_endpoint(item: AiEndpoint) -> ProviderEndpoint:
    return ProviderEndpoint(
        provider=item.provider_type,
        base_url=item.base_url,
        api_key=item.api_key,
        model=item.model_name,
        endpoint_id=item.id,
        endpoint_key=item.endpoint_key,
        endpoint_name=item.display_name,
        enabled=item.enabled,
        protection_enabled=item.protection_enabled,
        protection_mode=item.protection_mode,
        config=item.config,
    )


def provider_endpoint_from_env() -> ProviderEndpoint | None:
    if settings.ai_provider == "disabled":
        return None
    if not settings.ai_base_url or not settings.ai_model:
        return None
    return ProviderEndpoint(
        provider=settings.ai_provider,
        base_url=settings.ai_base_url,
        api_key=settings.ai_api_key,
        model=settings.ai_model,
        endpoint_id=None,
        endpoint_key="env-default",
        endpoint_name="Environment Default",
        enabled=True,
        protection_enabled=True,
        protection_mode="enforce",
        config={},
    )


def get_default_ai_endpoint(db: Session) -> AiEndpoint | None:
    item = (
        db.query(AiEndpoint)
        .filter(AiEndpoint.enabled.is_(True))
        .filter(AiEndpoint.is_default.is_(True))
        .order_by(AiEndpoint.id.asc())
        .first()
    )
    if item is not None:
        return item
    return (
        db.query(AiEndpoint)
        .filter(AiEndpoint.enabled.is_(True))
        .order_by(AiEndpoint.id.asc())
        .first()
    )


def sync_default_ai_endpoint(db: Session, preferred: AiEndpoint | None = None) -> None:
    items = db.query(AiEndpoint).order_by(AiEndpoint.id.asc()).all()
    if not items:
        return

    target_id: int | None = None
    if preferred is not None and preferred.enabled:
        target_id = preferred.id
    else:
        for item in items:
            if item.is_default and item.enabled:
                target_id = item.id
                break
        if target_id is None:
            for item in items:
                if item.enabled:
                    target_id = item.id
                    break

    for item in items:
        item.is_default = item.id == target_id


def attach_ai_endpoint_selection(
    db: Session,
    params_json: dict[str, Any] | None,
    *,
    ai_endpoint_id: int | None = None,
) -> tuple[dict[str, Any], AiEndpoint | None]:
    params = dict(params_json or {})
    resolved_id = ai_endpoint_id

    if resolved_id is None:
        raw_value = params.get("ai_endpoint_id")
        if isinstance(raw_value, int):
            resolved_id = raw_value
        elif isinstance(raw_value, str) and raw_value.strip().isdigit():
            resolved_id = int(raw_value.strip())

    endpoint: AiEndpoint | None = None
    if resolved_id is not None:
        endpoint = db.query(AiEndpoint).get(resolved_id)
        if endpoint is None:
            raise ValueError(f"AI endpoint #{resolved_id} not found")
        if not endpoint.enabled:
            raise ValueError(f"AI endpoint #{resolved_id} is disabled")
    else:
        endpoint = get_default_ai_endpoint(db)

    if endpoint is not None:
        params["ai_endpoint_id"] = endpoint.id
        params["ai_endpoint"] = build_ai_endpoint_snapshot(endpoint)
        params["protection_scope"] = "managed_ai_endpoint"
        return params, endpoint

    env_endpoint = provider_endpoint_from_env()
    if env_endpoint is None:
        params.pop("ai_endpoint_id", None)
        params.pop("ai_endpoint", None)
        params["protection_scope"] = "rule_only"
        return params, None

    params.pop("ai_endpoint_id", None)
    params["ai_endpoint"] = build_env_ai_endpoint_snapshot()
    params["protection_scope"] = "env_ai_provider"
    return params, None


def resolve_task_ai_endpoint(db: Session, task: AttackTask) -> ProviderEndpoint | None:
    params = task.params
    raw_value = params.get("ai_endpoint_id")
    endpoint_id: int | None = None
    if isinstance(raw_value, int):
        endpoint_id = raw_value
    elif isinstance(raw_value, str) and raw_value.strip().isdigit():
        endpoint_id = int(raw_value.strip())

    if endpoint_id is not None:
        endpoint = db.query(AiEndpoint).get(endpoint_id)
        if endpoint is None:
            raise ProviderConfigurationError(f"AI endpoint #{endpoint_id} referenced by task #{task.id} was not found.")
        if not endpoint.enabled:
            raise ProviderConfigurationError(f"AI endpoint #{endpoint_id} is disabled.")
        return provider_endpoint_from_ai_endpoint(endpoint)

    env_endpoint = provider_endpoint_from_env()
    if env_endpoint is not None:
        return env_endpoint

    return None


def task_ai_endpoint_snapshot(task: AttackTask) -> dict[str, Any] | None:
    value = task.params.get("ai_endpoint")
    if isinstance(value, dict) and value:
        return {
            "id": value.get("id"),
            "endpoint_key": str(value.get("endpoint_key") or ""),
            "display_name": str(value.get("display_name") or ""),
            "endpoint_group": normalize_endpoint_group(str(value.get("endpoint_group") or "default")),
            "provider_type": str(value.get("provider_type") or ""),
            "base_url": str(value.get("base_url") or ""),
            "model_name": str(value.get("model_name") or ""),
            "protection_enabled": bool(value.get("protection_enabled", True)),
            "protection_mode": str(value.get("protection_mode") or "enforce"),
            "source": str(value.get("source") or "managed"),
        }

    env_snapshot = build_env_ai_endpoint_snapshot()
    if env_snapshot["provider_type"] != "disabled" and env_snapshot["model_name"]:
        return env_snapshot
    return None


def count_active_tasks_for_endpoint(db: Session, endpoint_id: int) -> int:
    active_statuses = {"ready", "queued", "scheduled", "running"}
    count = 0
    items = db.query(AttackTask).filter(AttackTask.status.in_(tuple(active_statuses))).all()
    for item in items:
        raw_value = item.params.get("ai_endpoint_id")
        if raw_value == endpoint_id or str(raw_value) == str(endpoint_id):
            count += 1
    return count
