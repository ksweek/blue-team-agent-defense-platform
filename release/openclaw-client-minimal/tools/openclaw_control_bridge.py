#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import copy
from contextlib import suppress
import hashlib
import json
import re
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from time import monotonic
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import FastAPI, Request as FastAPIRequest, Response, WebSocket, WebSocketDisconnect
import uvicorn
from websockets.exceptions import ConnectionClosed
from websockets.legacy.client import connect as ws_connect


SCRIPT_DIR = Path(__file__).resolve().parent
AGENT_GATEWAY_DIR = SCRIPT_DIR / "agent_gateway"
BACKEND_DIR = SCRIPT_DIR.parent / "backend"
if str(AGENT_GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_GATEWAY_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from agent_gateway_cli import (  # noqa: E402
    CLIENT_VERSION,
    PlatformClient,
    build_runtime_fingerprint,
    collect_local_ip_addresses,
    default_access_host as default_gateway_access_host,
    ensure_runtime_credentials,
    has_pending_runtime_registration,
    has_runtime_credentials,
    normalize_platform_base_url,
    register_runtime_flow,
    save_config_payload,
    slugify,
)
from app.services.skill_scan import scan_skill_sources  # noqa: E402


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

DEFAULT_READ_ONLY_METHODS = {
    "chat.history",
    "models.list",
    "node.list",
    "device.pair.list",
    "sessions.list",
    "config.get",
    "config.schema",
    "skills.list",
    "plugins.list",
}

OPENCLAW_BOOTSTRAP_METHOD_EXACT_MATCHES = {
    "connect",
    "last-heartbeat",
    "set-heartbeats",
    "sessions.subscribe",
    "sessions.unsubscribe",
    "sessions.messages.subscribe",
    "sessions.messages.unsubscribe",
    "wake",
}

READ_ONLY_METHOD_SUFFIXES = {
    "list",
    "get",
    "history",
    "schema",
    "status",
    "health",
    "ping",
    "preview",
}

FOCUS_METHOD_EXACT_MATCHES = {
    "agent.run",
    "agents.run",
    "assistant.run",
    "browser.request",
    "chat.create",
    "chat.reply",
    "chat.send",
    "chat.stream",
    "chat.submit",
    "completion.create",
    "completions.create",
    "conversation.reply",
    "conversation.send",
    "function.call",
    "functions.call",
    "mcp.call_tool",
    "mcp.invoke",
    "plugin.call",
    "plugin.invoke",
    "response.create",
    "responses.create",
    "skill.call",
    "skill.invoke",
    "tool.call",
    "tool.execute",
    "tool.invoke",
    "tools.call",
    "tools.execute",
    "tools.invoke",
}

OPENCLAW_CHAT_METHOD_EXACT_MATCHES = {
    "chat.send_message",
    "chat.sendmessage",
    "send",
    "sessions.send",
}

OPENCLAW_TOOL_METHOD_EXACT_MATCHES = {
    "browser.request",
    "function.call",
    "functions.call",
    "mcp.call_tool",
    "mcp.calltool",
    "mcp.invoke",
    "plugin.call",
    "plugin.invoke",
    "skill.call",
    "skill.invoke",
    "tool.call",
    "tool.execute",
    "tool.invoke",
    "tools.call",
    "tools.execute",
    "tools.invoke",
}

OPENCLAW_MONITORED_EVENT_EXACT_MATCHES = {
    "session.message",
    "session.tool",
}

OPENCLAW_CHAT_EVENT_EXACT_MATCHES = {
    "session.message",
}

OPENCLAW_TOOL_EVENT_EXACT_MATCHES = {
    "session.tool",
}

CHAT_METHOD_TOKENS = {
    "assistant",
    "chat",
    "completion",
    "completions",
    "conversation",
    "message",
    "messages",
    "prompt",
    "reply",
    "response",
    "responses",
    "session",
    "sessions",
}

TOOL_METHOD_TOKENS = {
    "function",
    "functions",
    "mcp",
    "plugin",
    "plugins",
    "skill",
    "skills",
    "tool",
    "tools",
}

ACTION_METHOD_TOKENS = {
    "call",
    "complete",
    "continue",
    "create",
    "dispatch",
    "execute",
    "invoke",
    "reply",
    "run",
    "send",
    "stream",
    "submit",
}

OPENCLAW_METADATA_FIELDS = (
    "source_plugin",
    "target_plugin",
    "mcp_server",
    "capability_name",
    "session_id",
    "approval_id",
    "handoff_token",
    "agent_id",
    "assistant_agent_id",
    "conversation_id",
    "thread_id",
    "run_id",
    "tool_call_id",
    "session_key",
    "workspace_id",
    "assistant_name",
    "assistant_avatar",
    "server_version",
    "default_agent_id",
    "main_session_key",
    "instance_id",
    "client_mode",
    "client_version",
    "role",
    "locale",
    "user_agent",
    "auth_mode",
    "config_path",
    "state_dir",
    "canvas_host_url",
    "connection_id",
    "protocol",
)

TEXT_KEYS = {
    "prompt",
    "input",
    "query",
    "message",
    "messages",
    "content",
    "text",
    "instruction",
    "instructions",
    "question",
    "input_text",
    "user_input",
    "additional_messages",
    "chat_input",
    "chatinput",
    "input_value",
    "input_message",
    "prompt_text",
    "user_message",
    "assistant_message",
    "draft",
    "draft_message",
    "submission",
    "body",
    "latest_user_message",
    "last_user_message",
}

TURN_KEYS = {
    "messages",
    "history",
    "conversation",
    "conversation_messages",
    "chat_history",
    "turns",
    "additional_messages",
    "message_list",
    "message_history",
    "chat_messages",
    "conversation_items",
    "entries",
    "items",
}

PATH_KEYS = {
    "path",
    "paths",
    "file_path",
    "file_paths",
    "target_path",
    "resource_path",
    "cwd",
    "workspace",
    "workdir",
    "directory",
    "workspace_root",
    "sandbox",
    "sandbox_path",
    "sandbox_root",
    "project_path",
    "project_root",
    "working_directory",
    "current_directory",
    "selected_path",
    "selected_paths",
    "local_media_preview_roots",
}

SCOPE_KEYS = {
    "requested_scopes",
    "scopes",
    "scope",
    "permissions",
    "permission",
    "allowed_scopes",
    "tool_scopes",
    "operator_scopes",
}

SKILL_KEYS = {
    "skill",
    "skills",
    "skill_name",
    "skill_names",
    "tool",
    "tools",
    "tool_name",
    "tool_names",
    "tool_call",
    "tool_calls",
    "tool_call_name",
    "tool_call_names",
    "function_call",
    "function_calls",
    "call_tool",
    "selected_tool",
    "selected_tools",
    "agent_tools",
    "builtin_tools",
}

PLUGIN_KEYS = {
    "plugin",
    "plugins",
    "plugin_name",
    "plugin_names",
    "plugin_id",
    "plugin_ids",
    "extensions",
    "connected_plugins",
}

PROMPT_METHOD_HINTS = (
    "agent",
    "chat",
    "message",
    "prompt",
    "assistant",
    "completion",
    "run",
    "invoke",
    "conversation",
    "reply",
    "session",
)

GENERIC_NAME_FIELDS = (
    "name",
    "tool_name",
    "tool",
    "skill_name",
    "skill",
    "plugin_name",
    "plugin",
    "function_name",
    "server_name",
    "mcp_server",
    "capability_name",
    "label",
    "title",
    "key",
    "value",
    "path",
)
GENERIC_FALLBACK_NAME_FIELDS = ("id",)


def configure_stdio_utf8() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(level: str, message: str, **fields: Any) -> None:
    suffix = ""
    if fields:
        suffix = " | " + " ".join(f"{key}={value}" for key, value in fields.items() if value not in (None, ""))
    print(f"[{now_text()}] [{level}] {message}{suffix}")


def normalize_base_url(value: str) -> str:
    return str(value or "").strip().rstrip("/")


def default_ws_url_from_http(http_url: str) -> str:
    parts = urlsplit(normalize_base_url(http_url))
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, parts.path or "", "", ""))


def default_http_origin(http_url: str) -> str:
    parts = urlsplit(normalize_base_url(http_url))
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def combine_proxy_target(base_url: str, full_path: str, raw_query: str) -> str:
    base_parts = urlsplit(normalize_base_url(base_url))
    request_parts = urlsplit(full_path or "/")
    base_path = base_parts.path.rstrip("/")
    request_path = request_parts.path or "/"
    if base_path:
        merged_path = f"{base_path}{request_path if request_path.startswith('/') else '/' + request_path}"
    else:
        merged_path = request_path
    final_query = raw_query or request_parts.query
    return urlunsplit((base_parts.scheme, base_parts.netloc, merged_path, final_query, ""))


def build_openclaw_upstream_query(raw_query: str, gateway_token: str) -> str:
    token = str(gateway_token or "").strip()
    pairs: list[tuple[str, str]] = []
    token_in_query = False

    for key, value in parse_qsl(raw_query or "", keep_blank_values=True):
        if key == "gatewayUrl":
            continue
        if key == "token":
            if token and not token_in_query:
                pairs.append(("token", token))
                token_in_query = True
            elif not token and not token_in_query:
                pairs.append((key, value))
                token_in_query = True
            continue
        pairs.append((key, value))

    if token and not token_in_query:
        pairs.append(("token", token))

    return urlencode(pairs, doseq=True)


def redact_url_token(url: str) -> str:
    parts = urlsplit(str(url or ""))
    if not parts.query:
        return str(url or "")

    changed = False
    pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key == "token":
            pairs.append((key, "***"))
            changed = True
            continue
        pairs.append((key, value))

    if not changed:
        return str(url or "")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, doseq=True), parts.fragment))


async def probe_openclaw_ws_connectivity(
    *,
    upstream_ws_url: str,
    gateway_token: str,
    upstream_origin: str,
    timeout_seconds: float = 8,
) -> dict[str, Any]:
    token = str(gateway_token or "").strip()
    raw_query = build_openclaw_upstream_query("", token)
    probe_url = combine_proxy_target(upstream_ws_url, "/", raw_query)
    result: dict[str, Any] = {
        "ok": False,
        "probe_url": probe_url,
        "upstream_ws_url": normalize_base_url(upstream_ws_url),
        "origin": upstream_origin,
        "error": "",
    }
    if not token:
        result["error"] = "OpenClaw gateway token 为空"
        return result

    try:
        async with ws_connect(
            probe_url,
            origin=upstream_origin,
            open_timeout=timeout_seconds,
            close_timeout=3,
            max_size=None,
        ) as websocket:
            pong_waiter = await websocket.ping()
            await asyncio.wait_for(pong_waiter, timeout=min(timeout_seconds, 5))
            result["ok"] = True
            return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc) or exc.__class__.__name__
        return result


def probe_openclaw_http_connectivity(
    *,
    upstream_http_url: str,
    timeout_seconds: float = 5,
) -> dict[str, Any]:
    base_url = normalize_base_url(upstream_http_url)
    candidates = [f"{base_url}/health", f"{base_url}/"]
    attempts: list[dict[str, Any]] = []
    for url in candidates:
        attempt: dict[str, Any] = {"url": url, "ok": False, "status": None, "content_type": "", "error": ""}
        try:
            request = Request(url, headers={"Accept": "*/*"}, method="GET")
            with urlopen(request, timeout=timeout_seconds) as response:
                attempt["status"] = int(response.getcode())
                attempt["content_type"] = str(response.headers.get("Content-Type") or "")
                attempt["ok"] = 200 <= int(response.getcode()) < 500
        except Exception as exc:  # noqa: BLE001
            attempt["error"] = str(exc) or exc.__class__.__name__
        attempts.append(attempt)

    return {
        "ok": any(bool(item.get("ok")) for item in attempts),
        "upstream_http_url": base_url,
        "attempts": attempts,
    }


async def probe_openclaw_connectivity(
    *,
    upstream_http_url: str,
    upstream_ws_url: str,
    gateway_token: str,
    upstream_origin: str,
    timeout_seconds: float = 8,
) -> dict[str, Any]:
    http_result = probe_openclaw_http_connectivity(
        upstream_http_url=upstream_http_url,
        timeout_seconds=min(timeout_seconds, 5),
    )
    ws_result = await probe_openclaw_ws_connectivity(
        upstream_ws_url=upstream_ws_url,
        gateway_token=gateway_token,
        upstream_origin=upstream_origin,
        timeout_seconds=timeout_seconds,
    )
    return {
        "ok": bool(ws_result.get("ok")),
        "http": http_result,
        "ws": ws_result,
    }


def sanitize_request_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        cleaned[key] = value
    return cleaned


def sanitize_response_headers(items: list[tuple[str, str]]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in items:
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        cleaned[key] = value
    return cleaned


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def safe_json_dumps(payload: Any, *, max_chars: int) -> str:
    try:
        text = json.dumps(payload, ensure_ascii=False)
    except TypeError:
        text = str(payload)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...(已截断)"


def stable_json_dumps(payload: Any) -> str:
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return str(payload)


def hash_request_args(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    args_source = payload.get("params")
    if args_source in (None, ""):
        args_source = payload
    return hashlib.sha256(stable_json_dumps(args_source).encode("utf-8", errors="replace")).hexdigest()


def normalize_key(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_").lower()


def dedupe_strings(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(normalized)
    return output


def host_and_port_from_url(value: str) -> tuple[str, int]:
    parts = urlsplit(normalize_base_url(value))
    host = str(parts.hostname or "upstream").strip() or "upstream"
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return host, int(port)


def default_profile_name(upstream_http_url: str) -> str:
    host, port = host_and_port_from_url(upstream_http_url)
    return f"openclaw-control-{host}-{port}"


def default_runtime_display_name(upstream_http_url: str) -> str:
    host, port = host_and_port_from_url(upstream_http_url)
    return f"openclaw-control-{host}:{port}"


def default_target_agent_name(upstream_http_url: str) -> str:
    host, port = host_and_port_from_url(upstream_http_url)
    return f"OpenClaw Control UI ({host}:{port})"


def default_runtime_config_path(upstream_http_url: str) -> Path:
    host, port = host_and_port_from_url(upstream_http_url)
    profile_slug = slugify(f"openclaw-control-{host}-{port}")
    return AGENT_GATEWAY_DIR / "generated" / f"{profile_slug}.json"


def load_json_message(text: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def method_is_read_only(method: str, readonly_methods: set[str]) -> bool:
    normalized = str(method or "").strip().lower()
    if not normalized:
        return False
    if normalized in readonly_methods:
        return True
    tail = normalized.rsplit(".", 1)[-1]
    return tail in READ_ONLY_METHOD_SUFFIXES


def split_method_tokens(method: str) -> list[str]:
    normalized = normalize_key(method)
    if not normalized:
        return []
    return [item for item in normalized.split("_") if item]


def is_json_rpc_response(payload: dict[str, Any]) -> bool:
    frame_type = normalize_key(payload.get("type"))
    if frame_type in {"res", "response"}:
        return True
    return payload.get("id") is not None and payload.get("method") in (None, "")


def extract_openclaw_event_name(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict) or is_json_rpc_response(payload):
        return ""

    for key in ("event", "name", "topic"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value

    frame_type = normalize_key(payload.get("type"))
    if frame_type in {"event", "evt", "notification", "notify"}:
        for container in (payload.get("payload"), payload.get("data")):
            if isinstance(container, dict):
                for key in ("event", "name", "topic", "kind"):
                    value = str(container.get(key) or "").strip()
                    if value:
                        return value
        return ""

    if payload.get("id") in (None, "") and payload.get("method") in (None, ""):
        raw_type = str(payload.get("type") or "").strip()
        normalized_type = normalize_key(raw_type)
        if raw_type and normalized_type not in {"req", "request", "res", "response", "error", "ok", "hello", "hello_ok"}:
            return raw_type

    return ""


def upstream_event_method_name(event_name: str) -> str:
    normalized = str(event_name or "").strip()
    if not normalized:
        return "event.unknown"
    if normalized.lower().startswith("event."):
        return normalized
    return f"event.{normalized}"


def context_has_tool_signal(context: dict[str, Any]) -> bool:
    return any(
        [
            context.get("skill_names") or [],
            context.get("plugin_names") or [],
            context.get("requested_scopes") or [],
            str(context.get("source_plugin") or "").strip(),
            str(context.get("target_plugin") or "").strip(),
            str(context.get("mcp_server") or "").strip(),
            str(context.get("capability_name") or "").strip(),
            str(context.get("tool_call_id") or "").strip(),
        ]
    )


def classify_openclaw_operation(method: str, context: dict[str, Any]) -> str:
    normalized = str(method or "").strip().lower()
    token_set = set(split_method_tokens(method))
    has_input_text = bool(str(context.get("input_text") or "").strip())
    has_turns = bool(context.get("turns") or [])
    has_action_token = bool(token_set & ACTION_METHOD_TOKENS)
    if normalized in OPENCLAW_TOOL_METHOD_EXACT_MATCHES:
        return "tool_call"
    if normalized in OPENCLAW_CHAT_METHOD_EXACT_MATCHES:
        return "chat"
    if normalized == "agent" and (has_input_text or has_turns):
        return "chat"
    if (
        token_set & CHAT_METHOD_TOKENS
        or ((has_input_text or has_turns) and has_action_token and any(token in normalized for token in PROMPT_METHOD_HINTS))
    ):
        return "chat"
    if token_set & TOOL_METHOD_TOKENS or context_has_tool_signal(context):
        return "tool_call"
    return "other"


def method_targets_security_platform(
    method: str,
    *,
    readonly_methods: set[str],
    context: dict[str, Any],
) -> bool:
    normalized = str(method or "").strip().lower()
    if not normalized:
        return False
    if normalized in OPENCLAW_BOOTSTRAP_METHOD_EXACT_MATCHES:
        return False

    effective_readonly = set(DEFAULT_READ_ONLY_METHODS) | {item.lower() for item in readonly_methods}
    if method_is_read_only(normalized, effective_readonly):
        return False

    operation_type = classify_openclaw_operation(method, context)
    if operation_type in {"chat", "tool_call"}:
        return True

    if normalized in FOCUS_METHOD_EXACT_MATCHES:
        return True

    token_set = set(split_method_tokens(normalized))
    has_action_token = bool(token_set & ACTION_METHOD_TOKENS)
    has_chat_token = bool(token_set & CHAT_METHOD_TOKENS)
    has_tool_token = bool(token_set & TOOL_METHOD_TOKENS)
    has_input_text = bool(str(context.get("input_text") or "").strip())
    has_turns = bool(context.get("turns") or [])
    has_tool_signal = context_has_tool_signal(context)

    if has_tool_token and (has_action_token or has_tool_signal):
        return True
    if has_chat_token and (has_action_token or has_input_text or has_turns):
        return True
    if has_input_text and has_action_token and any(token in normalized for token in PROMPT_METHOD_HINTS):
        return True
    return False


def classify_openclaw_server_event(event_name: str, context: dict[str, Any]) -> str:
    normalized = str(event_name or "").strip().lower()
    if not normalized:
        return "other"

    token_set = set(split_method_tokens(event_name))
    has_input_text = bool(str(context.get("input_text") or "").strip())
    has_turns = bool(context.get("turns") or [])

    if normalized in OPENCLAW_TOOL_EVENT_EXACT_MATCHES:
        return "tool_call"
    if normalized in OPENCLAW_CHAT_EVENT_EXACT_MATCHES:
        return "chat"
    if token_set & TOOL_METHOD_TOKENS or context_has_tool_signal(context):
        return "tool_call"
    if token_set & CHAT_METHOD_TOKENS and (has_input_text or has_turns):
        return "chat"
    return "other"


def event_targets_security_platform(event_name: str, *, context: dict[str, Any]) -> bool:
    normalized = str(event_name or "").strip().lower()
    if normalized not in OPENCLAW_MONITORED_EVENT_EXACT_MATCHES:
        return False
    return classify_openclaw_server_event(event_name, context) in {"chat", "tool_call"}


def build_json_rpc_error(payload: dict[str, Any], message: str, *, code: int = 403) -> str:
    return json.dumps(
        {
            "id": payload.get("id"),
            "error": {
                "code": code,
                "message": message,
            },
        },
        ensure_ascii=False,
    )


def call_id_key(value: Any) -> str:
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def iter_key_matches(payload: Any, wanted_keys: set[str], *, depth: int = 0, max_depth: int = 8) -> list[Any]:
    if depth > max_depth:
        return []
    matches: list[Any] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if normalize_key(key) in wanted_keys:
                matches.append(value)
            matches.extend(iter_key_matches(value, wanted_keys, depth=depth + 1, max_depth=max_depth))
    elif isinstance(payload, list):
        for item in payload:
            matches.extend(iter_key_matches(item, wanted_keys, depth=depth + 1, max_depth=max_depth))
    return matches


def stringify_message_content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts = [stringify_message_content(item) for item in value]
        return "\n".join(part for part in parts if part)
    if isinstance(value, dict):
        parts: list[str] = []
        for key in ("content", "text", "message", "input", "prompt", "query", "question", "value"):
            text = stringify_message_content(value.get(key))
            if text:
                parts.append(text)
        if parts:
            return "\n".join(dedupe_strings(parts))
        return safe_json_dumps(value, max_chars=1200)
    return str(value)


def flatten_named_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        output: list[str] = []
        for item in value:
            output.extend(flatten_named_values(item))
        return output
    if isinstance(value, dict):
        preferred: list[str] = []
        fallback: list[str] = []
        for key, raw in value.items():
            text = str(raw or "").strip()
            if not text:
                continue
            normalized_key = normalize_key(key)
            if normalized_key in GENERIC_NAME_FIELDS:
                preferred.append(text)
            elif normalized_key in GENERIC_FALLBACK_NAME_FIELDS:
                fallback.append(text)
        if preferred:
            return preferred
        if fallback:
            return fallback
    return []


def extract_message_turns(payload: Any) -> list[dict[str, str]]:
    turns: list[dict[str, str]] = []
    for match in iter_key_matches(payload, TURN_KEYS):
        if isinstance(match, list):
            for item in match:
                text = stringify_message_content(item)
                if text:
                    turns.append({"content": text})
        elif isinstance(match, dict):
            text = stringify_message_content(match)
            if text:
                turns.append({"content": text})
    return turns[:20]


def extract_openclaw_context(payload: dict[str, Any], *, max_capture_chars: int) -> dict[str, Any]:
    source = payload.get("params")
    if source in (None, ""):
        source = payload

    turns = extract_message_turns(source)
    text_fragments = [
        stringify_message_content(item)
        for item in iter_key_matches(source, TEXT_KEYS)
    ]
    text_fragments = dedupe_strings([item for item in text_fragments if item])
    if not text_fragments and turns:
        text_fragments = [str(item.get("content") or "").strip() for item in turns if str(item.get("content") or "").strip()]

    input_text = "\n\n".join(text_fragments[:6]).strip()
    if len(input_text) > max_capture_chars:
        input_text = input_text[:max_capture_chars] + "...(已截断)"

    skill_names = dedupe_strings(
        [item for match in iter_key_matches(source, SKILL_KEYS) for item in flatten_named_values(match)]
    )[:20]
    plugin_names = dedupe_strings(
        [item for match in iter_key_matches(source, PLUGIN_KEYS) for item in flatten_named_values(match)]
    )[:20]
    paths = dedupe_strings(
        [item for match in iter_key_matches(source, PATH_KEYS) for item in flatten_named_values(match)]
    )[:20]
    requested_scopes = dedupe_strings(
        [item for match in iter_key_matches(source, SCOPE_KEYS) for item in flatten_named_values(match)]
    )[:20]

    metadata: dict[str, str] = {}
    for field in OPENCLAW_METADATA_FIELDS:
        values = iter_key_matches(source, {normalize_key(field)})
        metadata[field] = stringify_message_content(values[0]) if values else ""

    session_id = (
        metadata["session_id"]
        or metadata["session_key"]
        or metadata["main_session_key"]
        or metadata["conversation_id"]
        or metadata["thread_id"]
    )

    return {
        "input_text": input_text,
        "turns": turns,
        "paths": paths,
        "skill_names": skill_names,
        "plugin_names": plugin_names,
        "requested_scopes": requested_scopes,
        "source_plugin": metadata["source_plugin"],
        "target_plugin": metadata["target_plugin"],
        "mcp_server": metadata["mcp_server"],
        "capability_name": metadata["capability_name"],
        "session_id": session_id,
        "approval_id": metadata["approval_id"],
        "handoff_token": metadata["handoff_token"],
        "agent_id": metadata["agent_id"],
        "assistant_agent_id": metadata["assistant_agent_id"],
        "conversation_id": metadata["conversation_id"],
        "thread_id": metadata["thread_id"],
        "run_id": metadata["run_id"],
        "tool_call_id": metadata["tool_call_id"],
        "session_key": metadata["session_key"],
        "workspace_id": metadata["workspace_id"],
        "assistant_name": metadata["assistant_name"],
        "assistant_avatar": metadata["assistant_avatar"],
        "server_version": metadata["server_version"],
        "default_agent_id": metadata["default_agent_id"],
        "main_session_key": metadata["main_session_key"],
        "instance_id": metadata["instance_id"],
        "client_mode": metadata["client_mode"],
        "client_version": metadata["client_version"],
        "role": metadata["role"],
        "locale": metadata["locale"],
        "user_agent": metadata["user_agent"],
        "auth_mode": metadata["auth_mode"],
        "config_path": metadata["config_path"],
        "state_dir": metadata["state_dir"],
        "canvas_host_url": metadata["canvas_host_url"],
        "connection_id": metadata["connection_id"],
        "protocol": metadata["protocol"],
    }


def classify_attack_type(method: str, context: dict[str, Any], default_attack_type: str) -> str:
    operation_type = classify_openclaw_operation(method, context)
    if operation_type == "chat":
        return "openclaw_chat"
    if operation_type == "tool_call":
        return "openclaw_tool_call"
    return default_attack_type


def ensure_dir_for_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def build_runtime_bridge_config(
    *,
    profile_name: str,
    platform_base_url: str,
    verify_platform_tls: bool,
    runtime_display_name: str,
    runtime_type: str,
    upstream_http_url: str,
    upstream_ws_url: str,
    listen_host: str,
    listen_port: int,
    access_host: str,
    target_agent_name: str,
    review_action: str,
    attack_type: str,
    readonly_methods: set[str],
    max_capture_chars: int,
) -> dict[str, Any]:
    profile_slug = slugify(profile_name)
    runtime_hostname = socket.gethostname().strip() or "unknown-host"
    runtime_name = f"openclaw-control-bridge/{profile_slug}"
    requested_scopes = [
        "runtime.task.create",
        "runtime.task.authorize",
        "runtime.task.heartbeat",
        "runtime.task.complete",
        "runtime.command.poll",
        "runtime.command.complete",
    ]
    capabilities = [
        "http_proxy",
        "websocket_proxy",
        "openclaw_control_bridge",
        "runtime_event_reporting",
        "runtime_command_execution",
        "remote_skill_scan",
    ]
    runtime_metadata = {
        "profile_name": profile_name,
        "profile_slug": profile_slug,
        "upstream_http_url": upstream_http_url,
        "upstream_ws_url": upstream_ws_url,
        "listen_host": listen_host,
        "listen_port": listen_port,
        "access_host": access_host,
        "target_agent_name": target_agent_name,
    }
    return {
        "profile_name": profile_name,
        "profile_slug": profile_slug,
        "preset": "openclaw_control_bridge",
        "platform": {
            "base_url": normalize_platform_base_url(platform_base_url),
            "verify_tls": verify_platform_tls,
        },
        "runtime": {
            "display_name": runtime_display_name,
            "runtime_type": runtime_type,
            "hostname": runtime_hostname,
            "fingerprint": build_runtime_fingerprint(profile_slug, upstream_http_url, listen_host, listen_port),
            "client_version": CLIENT_VERSION,
            "ip_addresses": collect_local_ip_addresses(),
            "requested_scopes": requested_scopes,
            "capabilities": capabilities,
            "metadata": runtime_metadata,
            "poll_interval_seconds": 5,
            "command_poll_interval_seconds": 2,
            "registration_id": "",
            "poll_secret": "",
            "runtime_key": "",
            "runtime_secret": "",
            "status": "draft",
            "status_summary": "待发起注册",
            "rejection_reason": "",
        },
        "gateway": {
            "listen_host": listen_host,
            "listen_port": listen_port,
            "runtime_name": runtime_name,
            "task_name_prefix": f"openclaw-control-{profile_slug}",
            "attack_type": attack_type,
            "review_action": review_action,
            "request_timeout_seconds": 60,
            "max_capture_chars": max_capture_chars,
        },
        "bridge": {
            "target_agent_name": target_agent_name,
            "readonly_methods": sorted(readonly_methods),
            "upstream_http_url": upstream_http_url,
            "upstream_ws_url": upstream_ws_url,
        },
    }


def merge_runtime_state(base_config: dict[str, Any], existing_config: dict[str, Any]) -> dict[str, Any]:
    existing_runtime = dict(existing_config.get("runtime") or {})
    runtime = dict(base_config.get("runtime") or {})
    for key in (
        "registration_id",
        "poll_secret",
        "runtime_key",
        "runtime_secret",
        "status",
        "status_summary",
        "rejection_reason",
    ):
        value = existing_runtime.get(key)
        if value not in (None, ""):
            runtime[key] = value
    if existing_runtime.get("display_name"):
        runtime["display_name"] = str(existing_runtime["display_name"])
    base_config["runtime"] = runtime
    return base_config


def load_runtime_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class PendingRuntimeAction:
    task_id: int
    request_id: str
    call_id: str
    method: str
    operation_type: str
    ws_path: str
    client_ip: str
    input_text: str
    request_excerpt: str
    request_args_hash: str
    ticket_key: str
    authorization: dict[str, Any]
    context: dict[str, Any]
    created_monotonic: float = field(default_factory=monotonic)


def merge_openclaw_context(primary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    merged = dict(fallback or {})
    for key, value in (primary or {}).items():
        if isinstance(value, list):
            merged[key] = value or list(merged.get(key) or [])
            continue
        if isinstance(value, str):
            merged[key] = value or str(merged.get(key) or "")
            continue
        merged[key] = value if value not in (None, "", []) else merged.get(key)
    return merged


def find_matching_tool_binding(
    active_tool_bindings: list[PendingRuntimeAction],
    *,
    context: dict[str, Any],
) -> PendingRuntimeAction | None:
    best_binding: PendingRuntimeAction | None = None
    best_score = -1
    event_tool_call_id = str(context.get("tool_call_id") or "").strip()
    event_session_id = str(context.get("session_id") or "").strip()
    event_server = str(context.get("mcp_server") or "").strip()
    event_capability = str(context.get("capability_name") or "").strip()
    now_mark = monotonic()

    for binding in active_tool_bindings:
        if binding.operation_type != "tool_call" or not binding.ticket_key:
            continue
        if now_mark - binding.created_monotonic > 600:
            continue

        binding_context = dict(binding.context or {})
        binding_tool_call_id = str(binding_context.get("tool_call_id") or "").strip()
        binding_session_id = str(binding_context.get("session_id") or "").strip()
        binding_server = str(binding_context.get("mcp_server") or "").strip()
        binding_capability = str(binding_context.get("capability_name") or "").strip()

        score = 0
        if event_tool_call_id and binding_tool_call_id:
            if event_tool_call_id != binding_tool_call_id:
                continue
            score += 100
        if event_session_id and binding_session_id:
            if event_session_id != binding_session_id:
                continue
            score += 40
        if event_capability and binding_capability:
            if event_capability != binding_capability:
                continue
            score += 20
        if event_server and binding_server:
            if event_server != binding_server:
                continue
            score += 10
        if not any((event_tool_call_id, event_session_id, event_capability, event_server)):
            score += 1
        if score > best_score:
            best_score = score
            best_binding = binding
    return best_binding


def sanitize_tool_result_payload(payload: dict[str, Any], *, summary: str, decision: str) -> str:
    notice = "工具返回内容已被安全平台隔离，请在平台侧查看审查记录。"
    data = copy.deepcopy(payload)

    def replace_sensitive(node: Any) -> Any:
        if isinstance(node, dict):
            updated: dict[str, Any] = {}
            for key, value in node.items():
                normalized = normalize_key(key)
                if normalized in {
                    "text",
                    "content",
                    "message",
                    "result",
                    "output",
                    "output_text",
                    "response_text",
                    "body",
                    "value",
                    "data",
                }:
                    if isinstance(value, dict):
                        updated[key] = {"notice": notice}
                    elif isinstance(value, list):
                        updated[key] = [{"notice": notice}]
                    else:
                        updated[key] = notice
                    continue
                updated[key] = replace_sensitive(value)
            return updated
        if isinstance(node, list):
            return [replace_sensitive(item) for item in node]
        return node

    sanitized = replace_sensitive(data)
    if isinstance(sanitized, dict):
        sanitized["__blue_team__"] = {
            "decision": decision,
            "summary": summary,
            "quarantined": True,
        }
    return json.dumps(sanitized, ensure_ascii=False)


class RuntimeBridgeClient:
    def __init__(self, config_path: Path, config: dict[str, Any]):
        self.config_path = config_path
        self.config = config
        self.platform = PlatformClient(config)
        runtime = dict(config.get("runtime") or {})
        gateway = dict(config.get("gateway") or {})
        bridge = dict(config.get("bridge") or {})
        self.runtime_name = str(gateway.get("runtime_name") or runtime.get("display_name") or "openclaw-control-bridge").strip()
        self.task_name_prefix = str(gateway.get("task_name_prefix") or "openclaw-control").strip()
        self.default_attack_type = str(gateway.get("attack_type") or "openclaw_control").strip() or "openclaw_control"
        self.review_action = str(gateway.get("review_action") or "block").strip().lower() or "block"
        self.max_capture_chars = int(gateway.get("max_capture_chars") or 16000)
        self.target_agent_name = str(bridge.get("target_agent_name") or "OpenClaw Control UI").strip()
        self.profile_name = str(config.get("profile_name") or config.get("profile_slug") or "openclaw-control").strip()
        self.preset = str(config.get("preset") or "openclaw_control_bridge").strip()
        self.client_id = str(self.platform.client_id or self.runtime_name).strip()
        self.runtime_display_name = str(runtime.get("display_name") or self.runtime_name).strip()
        self.runtime_registration_id = str(runtime.get("registration_id") or "").strip()
        self.command_poll_interval_seconds = max(1.0, float(runtime.get("command_poll_interval_seconds") or 2))

    def validate_session(self) -> dict[str, Any]:
        return self.platform.validate_session()

    def create_task(
        self,
        *,
        request_id: str,
        call_id: str,
        method: str,
        ws_path: str,
        client_ip: str,
        context: dict[str, Any],
        request_excerpt: str,
    ) -> dict[str, Any]:
        attack_type = classify_attack_type(method, context, self.default_attack_type)
        operation_type = classify_openclaw_operation(method, context)
        payload = {
            "task_name": f"{self.task_name_prefix}-{request_id}",
            "attack_type": attack_type,
            "target_agent": self.target_agent_name,
            "params_json": {
                "source_type": "runtime_gateway",
                "source_ref": request_id,
                "content": context["input_text"],
                "turns": context["turns"],
                "skill_names": context["skill_names"],
                "plugin_names": context["plugin_names"],
                "paths": context["paths"],
                "requested_scopes": context["requested_scopes"],
                "source_plugin": context["source_plugin"],
                "target_plugin": context["target_plugin"],
                "mcp_server": context["mcp_server"],
                "capability_name": context["capability_name"],
                "session_id": context["session_id"],
                "approval_id": context["approval_id"],
                "handoff_token": context["handoff_token"],
                "agent_id": context["agent_id"],
                "assistant_agent_id": context["assistant_agent_id"],
                "conversation_id": context["conversation_id"],
                "thread_id": context["thread_id"],
                "run_id": context["run_id"],
                "tool_call_id": context["tool_call_id"],
                "session_key": context["session_key"],
                "workspace_id": context["workspace_id"],
                "assistant_name": context["assistant_name"],
                "assistant_avatar": context["assistant_avatar"],
                "server_version": context["server_version"],
                "default_agent_id": context["default_agent_id"],
                "main_session_key": context["main_session_key"],
                "instance_id": context["instance_id"],
                "client_mode": context["client_mode"],
                "client_version": context["client_version"],
                "role": context["role"],
                "locale": context["locale"],
                "user_agent": context["user_agent"],
                "auth_mode": context["auth_mode"],
                "config_path": context["config_path"],
                "state_dir": context["state_dir"],
                "canvas_host_url": context["canvas_host_url"],
                "connection_id": context["connection_id"],
                "protocol": context["protocol"],
                "gateway_metadata": {
                    "transport": "websocket",
                    "ws_method": method,
                    "ws_call_id": call_id,
                    "ws_path": ws_path,
                    "client_ip": client_ip,
                    "profile_name": self.profile_name,
                    "preset": self.preset,
                    "openclaw_operation_type": operation_type,
                    "openclaw_agent_id": context["agent_id"],
                    "openclaw_assistant_agent_id": context["assistant_agent_id"],
                    "openclaw_conversation_id": context["conversation_id"],
                    "openclaw_thread_id": context["thread_id"],
                    "openclaw_run_id": context["run_id"],
                    "openclaw_tool_call_id": context["tool_call_id"],
                    "openclaw_session_key": context["session_key"],
                    "openclaw_workspace_id": context["workspace_id"],
                    "openclaw_assistant_name": context["assistant_name"],
                    "openclaw_server_version": context["server_version"],
                    "openclaw_default_agent_id": context["default_agent_id"],
                    "openclaw_main_session_key": context["main_session_key"],
                    "openclaw_instance_id": context["instance_id"],
                    "openclaw_client_mode": context["client_mode"],
                    "openclaw_role": context["role"],
                    "openclaw_locale": context["locale"],
                    "openclaw_auth_mode": context["auth_mode"],
                    "openclaw_canvas_host_url": context["canvas_host_url"],
                    "request_excerpt": request_excerpt,
                },
            },
        }
        return self.platform._request("POST", "/gateway/v1/runtime/tasks", payload=payload, with_auth=True)

    def authorize(
        self,
        *,
        task_id: int,
        request_id: str,
        call_id: str,
        method: str,
        ws_path: str,
        context: dict[str, Any],
        request_excerpt: str,
        request_args_hash: str,
        action_type: str = "openclaw_ws_call",
        operation_type: str | None = None,
        event_name: str = "",
        mcp_ticket_key: str = "",
    ) -> dict[str, Any]:
        resolved_operation_type = operation_type or classify_openclaw_operation(method, context)
        payload = {
            "task_id": task_id,
            "runtime_name": self.runtime_name,
            "runtime_task_ref": request_id,
            "action_type": action_type,
            "input_text": context["input_text"],
            "paths": context["paths"],
            "skill_names": context["skill_names"],
            "plugin_names": context["plugin_names"],
            "call_id": call_id,
            "source_plugin": context["source_plugin"],
            "target_plugin": context["target_plugin"],
            "mcp_server": context["mcp_server"],
            "capability_name": context["capability_name"],
            "session_id": context["session_id"],
            "approval_id": context["approval_id"],
            "handoff_token": context["handoff_token"],
            "tool_call_id": context["tool_call_id"],
            "operation_type": resolved_operation_type,
            "event_name": event_name,
            "request_args_hash": request_args_hash,
            "mcp_ticket_key": mcp_ticket_key,
            "requested_scopes": context["requested_scopes"],
            "metadata": {
                "message": context["input_text"],
                "ws_method": method,
                "ws_call_id": call_id,
                "ws_path": ws_path,
                "openclaw_operation_type": resolved_operation_type,
                "openclaw_event_name": event_name,
                "request_args_hash": request_args_hash,
                "mcp_ticket_key": mcp_ticket_key,
                "openclaw_agent_id": context["agent_id"],
                "openclaw_assistant_agent_id": context["assistant_agent_id"],
                "openclaw_conversation_id": context["conversation_id"],
                "openclaw_thread_id": context["thread_id"],
                "openclaw_run_id": context["run_id"],
                "openclaw_tool_call_id": context["tool_call_id"],
                "openclaw_session_key": context["session_key"],
                "openclaw_workspace_id": context["workspace_id"],
                "openclaw_assistant_name": context["assistant_name"],
                "openclaw_server_version": context["server_version"],
                "openclaw_default_agent_id": context["default_agent_id"],
                "openclaw_main_session_key": context["main_session_key"],
                "openclaw_instance_id": context["instance_id"],
                "openclaw_client_mode": context["client_mode"],
                "openclaw_role": context["role"],
                "openclaw_locale": context["locale"],
                "openclaw_auth_mode": context["auth_mode"],
                "openclaw_canvas_host_url": context["canvas_host_url"],
                "request_excerpt": request_excerpt,
            },
        }
        return self.platform._request("POST", "/gateway/v1/runtime/authorize", payload=payload, with_auth=True)

    def heartbeat(self, *, task_id: int, request_id: str, method: str, message: str) -> None:
        payload = {
            "task_id": task_id,
            "runtime_name": self.runtime_name,
            "runtime_task_ref": request_id,
            "status": "running",
            "message": message,
            "progress": 50,
            "metadata": {
                "ws_method": method,
                "stage": "forwarding",
            },
        }
        self.platform._request("POST", "/gateway/v1/runtime/heartbeat", payload=payload, with_auth=True)

    def complete(
        self,
        *,
        task_id: int,
        request_id: str,
        method: str,
        input_text: str,
        status: str,
        summary: str,
        request_excerpt: str,
        raw_response_text: str,
        authorization: dict[str, Any] | None,
        extra_hit_rules: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        completion_metadata = dict(metadata or {})
        decision = str((authorization or {}).get("decision") or "").strip().lower()
        matched_rules = list((authorization or {}).get("matched_rules") or [])
        matched_controls = list((authorization or {}).get("matched_controls") or [])
        hit_rules = dedupe_strings([*matched_rules, *matched_controls, *(extra_hit_rules or [])])

        if decision == "deny" or "local_blocklist" in hit_rules:
            event_status = "intercepted"
            event_level = "high"
        elif status == "failed" or decision == "review":
            event_status = "suspicious"
            event_level = "medium"
        else:
            event_status = "allowed"
            event_level = "low"

        event = {
            "event_type": "openclaw_control",
            "event_level": event_level,
            "event_status": event_status,
            "source": f"runtime/{self.runtime_name}",
            "detail": summary,
            "hit_rules": hit_rules,
            "raw_input": input_text or request_excerpt,
            "result": raw_response_text[: self.max_capture_chars] if raw_response_text else summary,
            "operation_logs": [
                {
                    "operator": self.runtime_name,
                    "action": f"ws:{method}",
                    "time": now_text(),
                },
            ],
        }
        payload = {
            "task_id": task_id,
            "runtime_name": self.runtime_name,
            "runtime_task_ref": request_id,
            "status": status,
            "summary": summary,
            "raw_response_text": raw_response_text[: self.max_capture_chars],
            "report_type": "runtime_execution",
            "call_id": str(completion_metadata.get("call_id") or completion_metadata.get("ws_call_id") or "").strip() or None,
            "tool_call_id": str(completion_metadata.get("tool_call_id") or completion_metadata.get("openclaw_tool_call_id") or "").strip() or None,
            "operation_type": str(completion_metadata.get("operation_type") or completion_metadata.get("openclaw_operation_type") or "").strip() or None,
            "event_name": str(completion_metadata.get("event_name") or completion_metadata.get("openclaw_event_name") or "").strip() or None,
            "request_args_hash": str(completion_metadata.get("request_args_hash") or "").strip() or None,
            "mcp_ticket_key": str(completion_metadata.get("mcp_ticket_key") or "").strip() or None,
            "consume_mcp_ticket": bool(completion_metadata.get("consume_mcp_ticket")),
            "metadata": {
                "ws_method": method,
                "request_excerpt": request_excerpt,
                "authorization": authorization or {},
                **completion_metadata,
            },
            "event": event,
        }
        return self.platform._request("POST", "/gateway/v1/runtime/complete", payload=payload, with_auth=True)

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "config_path": str(self.config_path),
            "runtime_name": self.runtime_name,
            "runtime_display_name": self.runtime_display_name,
            "review_action": self.review_action,
            "target_agent_name": self.target_agent_name,
        }

    def poll_command(self) -> dict[str, Any] | None:
        data = self.platform._request("GET", "/gateway/v1/runtime/commands/next", with_auth=True)
        command = data.get("command")
        return dict(command) if isinstance(command, dict) and command else None

    def complete_command(
        self,
        command_id: int,
        *,
        status: str,
        summary: str,
        response_text: str | None,
        response_json: dict[str, Any] | list[Any] | None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.platform._request(
            "POST",
            f"/gateway/v1/runtime/commands/{command_id}/complete",
            payload={
                "status": status,
                "summary": summary,
                "response_text": response_text,
                "response_json": response_json,
                "error": error,
                "metadata": dict(metadata or {}),
            },
            with_auth=True,
        )


@dataclass
class BridgeConfig:
    upstream_http_url: str
    upstream_ws_url: str
    listen_host: str
    listen_port: int
    access_host: str
    gateway_token: str
    request_timeout_seconds: float
    connect_timeout_seconds: float
    log_jsonl_path: Path | None
    block_methods: set[str]
    readonly_methods: set[str]
    upstream_origin: str
    max_capture_chars: int
    runtime_client: RuntimeBridgeClient | None = None
    platform_state: dict[str, Any] = field(default_factory=dict)

    @property
    def launch_http_url(self) -> str:
        gateway_url = f"ws://{self.access_host}:{self.listen_port}"
        encoded_gateway_url = quote(gateway_url, safe=":/")
        encoded_token = quote(self.gateway_token, safe="")
        return f"http://{self.access_host}:{self.listen_port}/?gatewayUrl={encoded_gateway_url}&token={encoded_token}"


def resolve_runtime_client(args: argparse.Namespace, bridge_config: BridgeConfig) -> tuple[RuntimeBridgeClient | None, dict[str, Any]]:
    runtime_config_arg = str(getattr(args, "runtime_config", "") or "").strip()
    platform_base_url_arg = str(getattr(args, "platform_base_url", "") or "").strip()
    enrollment_token = str(getattr(args, "enrollment_token", "") or "").strip()

    if not runtime_config_arg and not platform_base_url_arg and not enrollment_token:
        return None, {"mode": "local_only", "summary": "未启用 Runtime 联动，仅做代理和日志记录。"}

    config_path = Path(runtime_config_arg).expanduser().resolve() if runtime_config_arg else default_runtime_config_path(bridge_config.upstream_http_url).resolve()
    ensure_dir_for_file(config_path)
    existing_config = load_runtime_config(config_path) if config_path.exists() else {}

    platform_base_url = platform_base_url_arg or str((existing_config.get("platform") or {}).get("base_url") or "").strip()
    if not platform_base_url:
        raise RuntimeError("启用 Runtime 联动时必须提供 --platform-base-url，或使用已生成的 --runtime-config。")

    verify_platform_tls = not bool(getattr(args, "insecure_platform", False))
    profile_name = str(getattr(args, "profile_name", "") or existing_config.get("profile_name") or default_profile_name(bridge_config.upstream_http_url)).strip()
    runtime_display_name = str(getattr(args, "runtime_display_name", "") or (existing_config.get("runtime") or {}).get("display_name") or default_runtime_display_name(bridge_config.upstream_http_url)).strip()
    runtime_type = str(getattr(args, "runtime_type", "") or (existing_config.get("runtime") or {}).get("runtime_type") or "openclaw_control_bridge").strip()
    target_agent_name = str(getattr(args, "target_agent_name", "") or (existing_config.get("bridge") or {}).get("target_agent_name") or default_target_agent_name(bridge_config.upstream_http_url)).strip()
    review_action = str(getattr(args, "review_action", "") or (existing_config.get("gateway") or {}).get("review_action") or "block").strip().lower()
    attack_type = str(getattr(args, "attack_type", "") or (existing_config.get("gateway") or {}).get("attack_type") or "openclaw_control").strip()

    base_config = build_runtime_bridge_config(
        profile_name=profile_name,
        platform_base_url=platform_base_url,
        verify_platform_tls=verify_platform_tls,
        runtime_display_name=runtime_display_name,
        runtime_type=runtime_type,
        upstream_http_url=bridge_config.upstream_http_url,
        upstream_ws_url=bridge_config.upstream_ws_url,
        listen_host=bridge_config.listen_host,
        listen_port=bridge_config.listen_port,
        access_host=bridge_config.access_host,
        target_agent_name=target_agent_name,
        review_action=review_action,
        attack_type=attack_type,
        readonly_methods=bridge_config.readonly_methods,
        max_capture_chars=bridge_config.max_capture_chars,
    )
    config = merge_runtime_state(base_config, existing_config)
    save_config_payload(config_path, config)

    if has_runtime_credentials(config):
        client = RuntimeBridgeClient(config_path, config)
        session = client.validate_session()
        return client, {
            "mode": "runtime_active",
            "summary": "已使用现有 Runtime 凭据接入保护平台。",
            "config_path": str(config_path),
            "session": session,
            **client.summary(),
        }

    if has_pending_runtime_registration(config):
        config = ensure_runtime_credentials(
            config_path,
            config,
            wait_for_approval=not bool(getattr(args, "skip_approval_wait", False)),
        )
    elif enrollment_token:
        config = register_runtime_flow(
            config_path,
            config,
            enrollment_token=enrollment_token,
            wait_for_approval=not bool(getattr(args, "skip_approval_wait", False)),
        )
    else:
        raise RuntimeError(
            "当前 Runtime 配置没有可用凭据。请提供 --enrollment-token 完成注册审批，或传入已有凭据的 --runtime-config。"
        )

    if not has_runtime_credentials(config):
        return None, {
            "mode": "pending_approval",
            "summary": "Runtime 注册已提交，但尚未审批通过；桥接器将以本地模式启动。",
            "config_path": str(config_path),
            "runtime_status": dict(config.get("runtime") or {}),
        }

    save_config_payload(config_path, config)
    client = RuntimeBridgeClient(config_path, config)
    session = client.validate_session()
    return client, {
        "mode": "runtime_active",
        "summary": "Runtime 注册和审批已完成，桥接器将接入任务授权与事件回传链。",
        "config_path": str(config_path),
        "session": session,
        **client.summary(),
    }


async def report_local_block(
    config: BridgeConfig,
    *,
    payload: dict[str, Any],
    method: str,
    ws_path: str,
    client_ip: str,
    request_excerpt: str,
    reason: str,
    context: dict[str, Any] | None = None,
) -> None:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return

    request_id = f"ocws-{uuid4().hex[:12]}"
    context = context or extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
    try:
        task = await asyncio.to_thread(
            runtime_client.create_task,
            request_id=request_id,
            call_id=call_id_key(payload.get("id")),
            method=method,
            ws_path=ws_path,
            client_ip=client_ip,
            context=context,
            request_excerpt=request_excerpt,
        )
        await asyncio.to_thread(
            runtime_client.complete,
            task_id=int(task["id"]),
            request_id=request_id,
            method=method,
            input_text=str(context.get("input_text") or ""),
            status="failed",
            summary=reason,
            request_excerpt=request_excerpt,
            raw_response_text=safe_json_dumps(payload, max_chars=config.max_capture_chars),
            authorization={"decision": "deny", "matched_rules": ["local_blocklist"], "matched_controls": ["local_bridge"]},
            extra_hit_rules=["local_blocklist"],
            metadata={"local_block": True},
        )
    except Exception as exc:  # noqa: BLE001
        log("WARN", "本地阻断结果未能回传平台", method=method, error=str(exc))


async def report_upstream_event(
    config: BridgeConfig,
    *,
    payload: dict[str, Any],
    event_name: str,
    ws_path: str,
    client_ip: str,
    request_excerpt: str,
    context: dict[str, Any] | None = None,
) -> None:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return

    request_id = f"ocws-evt-{uuid4().hex[:12]}"
    method = upstream_event_method_name(event_name)
    context = context or extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
    try:
        task = await asyncio.to_thread(
            runtime_client.create_task,
            request_id=request_id,
            call_id="",
            method=method,
            ws_path=ws_path,
            client_ip=client_ip,
            context=context,
            request_excerpt=request_excerpt,
        )
        await asyncio.to_thread(
            runtime_client.complete,
            task_id=int(task["id"]),
            request_id=request_id,
            method=method,
            input_text=str(context.get("input_text") or ""),
            status="done",
            summary=f"OpenClaw 事件 {event_name} 已观察并回传平台。",
            request_excerpt=request_excerpt,
            raw_response_text=request_excerpt,
            authorization={"decision": "allow", "matched_rules": [], "matched_controls": []},
            metadata={
                "phase": "upstream_event",
                "ws_direction": "upstream_to_client",
                "openclaw_event_name": event_name,
                "openclaw_event_type": classify_openclaw_server_event(event_name, context),
            },
        )
    except Exception as exc:  # noqa: BLE001
        log("WARN", "OpenClaw 上游事件未能回传平台", event_name=event_name, error=str(exc))


async def review_upstream_tool_event(
    config: BridgeConfig,
    *,
    payload: dict[str, Any],
    event_name: str,
    ws_path: str,
    client_ip: str,
    request_excerpt: str,
    context: dict[str, Any] | None = None,
    active_tool_bindings: list[PendingRuntimeAction],
) -> str:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return json.dumps(payload, ensure_ascii=False)

    context = context or extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
    method = upstream_event_method_name(event_name)
    binding = find_matching_tool_binding(active_tool_bindings, context=context)
    merged_context = merge_openclaw_context(context, binding.context if binding is not None else {})
    request_id = f"ocws-evt-{uuid4().hex[:12]}"
    call_id = binding.call_id if binding is not None else ""
    request_args_hash = binding.request_args_hash if binding is not None else hash_request_args(payload)
    ticket_key = binding.ticket_key if binding is not None else ""
    task_id: int | None = None
    original_text = json.dumps(payload, ensure_ascii=False)

    try:
        task = await asyncio.to_thread(
            runtime_client.create_task,
            request_id=request_id,
            call_id=call_id,
            method=method,
            ws_path=ws_path,
            client_ip=client_ip,
            context=merged_context,
            request_excerpt=request_excerpt,
        )
        task_id = int(task["id"])
        auth_result = await asyncio.to_thread(
            runtime_client.authorize,
            task_id=task_id,
            request_id=request_id,
            call_id=call_id,
            method=method,
            ws_path=ws_path,
            context=merged_context,
            request_excerpt=request_excerpt,
            request_args_hash=request_args_hash,
            action_type="openclaw_ws_tool_result",
            operation_type="tool_result",
            event_name=event_name,
            mcp_ticket_key=ticket_key,
        )
        authorization = dict(auth_result.get("authorization") or {})
        decision = str(authorization.get("decision") or "").strip().lower()
        blocked = decision == "deny" or (decision == "review" and runtime_client.review_action == "block")
        summary = str(
            authorization.get("summary")
            or (f"OpenClaw 工具结果 {event_name} 已通过平台审查。" if not blocked else f"OpenClaw 工具结果 {event_name} 已被平台隔离。")
        ).strip()
        outbound_text = sanitize_tool_result_payload(payload, summary=summary, decision=decision or "deny") if blocked else original_text
        await asyncio.to_thread(
            runtime_client.complete,
            task_id=task_id,
            request_id=request_id,
            method=method,
            input_text=str(merged_context.get("input_text") or ""),
            status="failed" if blocked else "done",
            summary=summary,
            request_excerpt=request_excerpt,
            raw_response_text=original_text,
            authorization=authorization,
            metadata={
                "phase": "upstream_event_review",
                "ws_direction": "upstream_to_client",
                "call_id": call_id,
                "tool_call_id": str(merged_context.get("tool_call_id") or ""),
                "operation_type": "tool_result",
                "event_name": event_name,
                "request_args_hash": request_args_hash,
                "session_id": str(merged_context.get("session_id") or ""),
                "approval_id": str(merged_context.get("approval_id") or ""),
                "mcp_server": str(merged_context.get("mcp_server") or ""),
                "capability_name": str(merged_context.get("capability_name") or ""),
                "source_plugin": str(merged_context.get("source_plugin") or ""),
                "target_plugin": str(merged_context.get("target_plugin") or ""),
                "handoff_token": str(merged_context.get("handoff_token") or ""),
                "requested_scopes": list(merged_context.get("requested_scopes") or []),
                "mcp_ticket_key": ticket_key,
                "consume_mcp_ticket": bool(ticket_key),
                "openclaw_event_name": event_name,
                "openclaw_event_type": classify_openclaw_server_event(event_name, merged_context),
            },
        )
        if binding is not None:
            with suppress(ValueError):
                active_tool_bindings.remove(binding)
        return outbound_text
    except Exception as exc:  # noqa: BLE001
        failure_summary = f"OpenClaw 工具结果审查失败，已隔离：{exc}"
        if task_id is not None:
            try:
                await asyncio.to_thread(
                    runtime_client.complete,
                    task_id=task_id,
                    request_id=request_id,
                    method=method,
                    input_text=str(merged_context.get("input_text") or ""),
                    status="failed",
                    summary=failure_summary,
                    request_excerpt=request_excerpt,
                    raw_response_text=original_text,
                    authorization={"decision": "deny", "matched_rules": ["platform_authorization_failure"], "matched_controls": []},
                    extra_hit_rules=["platform_authorization_failure"],
                    metadata={
                        "phase": "upstream_event_review",
                        "error": str(exc),
                        "mcp_ticket_key": ticket_key,
                        "call_id": call_id,
                        "tool_call_id": str(merged_context.get("tool_call_id") or ""),
                        "operation_type": "tool_result",
                        "event_name": event_name,
                        "request_args_hash": request_args_hash,
                    },
                )
            except Exception as complete_exc:  # noqa: BLE001
                log("WARN", "OpenClaw 工具结果补偿回传失败", event_name=event_name, error=str(complete_exc))
        return sanitize_tool_result_payload(payload, summary=failure_summary, decision="deny")


async def evaluate_runtime_action(
    config: BridgeConfig,
    *,
    payload: dict[str, Any],
    method: str,
    ws_path: str,
    client_ip: str,
    request_excerpt: str,
    context: dict[str, Any] | None = None,
) -> tuple[bool, str, PendingRuntimeAction | None]:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return True, "", None

    context = context or extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
    request_id = f"ocws-{uuid4().hex[:12]}"
    call_id = call_id_key(payload.get("id"))
    operation_type = classify_openclaw_operation(method, context)
    request_args_hash = hash_request_args(payload)
    task_id: int | None = None

    try:
        task = await asyncio.to_thread(
            runtime_client.create_task,
            request_id=request_id,
            call_id=call_id,
            method=method,
            ws_path=ws_path,
            client_ip=client_ip,
            context=context,
            request_excerpt=request_excerpt,
        )
        task_id = int(task["id"])
        auth_result = await asyncio.to_thread(
            runtime_client.authorize,
            task_id=task_id,
            request_id=request_id,
            call_id=call_id,
            method=method,
            ws_path=ws_path,
            context=context,
            request_excerpt=request_excerpt,
            request_args_hash=request_args_hash,
            operation_type=operation_type,
        )
        authorization = dict(auth_result.get("authorization") or {})
        decision = str(authorization.get("decision") or "").strip().lower()
        ticket_key = str((authorization.get("mcp_execution_ticket") or {}).get("ticket_key") or "").strip()

        if decision == "deny":
            message = str(authorization.get("summary") or f"OpenClaw 方法 {method} 被策略阻断。").strip()
            await asyncio.to_thread(
                runtime_client.complete,
                task_id=task_id,
                request_id=request_id,
                method=method,
                input_text=str(context.get("input_text") or ""),
                status="failed",
                summary=message,
                request_excerpt=request_excerpt,
                raw_response_text=safe_json_dumps(payload, max_chars=config.max_capture_chars),
                authorization=authorization,
                metadata={
                    "phase": "authorize",
                    "blocked_by": "policy",
                    "call_id": call_id,
                    "tool_call_id": context["tool_call_id"],
                    "operation_type": operation_type,
                    "request_args_hash": request_args_hash,
                    "session_id": context["session_id"],
                    "mcp_server": context["mcp_server"],
                    "capability_name": context["capability_name"],
                    "requested_scopes": context["requested_scopes"],
                },
            )
            return False, message, None

        if decision == "review" and runtime_client.review_action == "block":
            message = str(authorization.get("summary") or f"OpenClaw 方法 {method} 被标记为可疑，当前按 review_action=block 阻断。").strip()
            await asyncio.to_thread(
                runtime_client.complete,
                task_id=task_id,
                request_id=request_id,
                method=method,
                input_text=str(context.get("input_text") or ""),
                status="failed",
                summary=message,
                request_excerpt=request_excerpt,
                raw_response_text=safe_json_dumps(payload, max_chars=config.max_capture_chars),
                authorization=authorization,
                metadata={
                    "phase": "authorize",
                    "blocked_by": "review_action",
                    "call_id": call_id,
                    "tool_call_id": context["tool_call_id"],
                    "operation_type": operation_type,
                    "request_args_hash": request_args_hash,
                    "session_id": context["session_id"],
                    "mcp_server": context["mcp_server"],
                    "capability_name": context["capability_name"],
                    "requested_scopes": context["requested_scopes"],
                },
            )
            return False, message, None

        await asyncio.to_thread(
            runtime_client.heartbeat,
            task_id=task_id,
            request_id=request_id,
            method=method,
            message=f"OpenClaw 方法 {method} 已放行并转发上游。",
        )
        pending = PendingRuntimeAction(
            task_id=task_id,
            request_id=request_id,
            call_id=call_id,
            method=method,
            operation_type=operation_type,
            ws_path=ws_path,
            client_ip=client_ip,
            input_text=str(context.get("input_text") or ""),
            request_excerpt=request_excerpt,
            request_args_hash=request_args_hash,
            ticket_key=ticket_key,
            authorization=authorization,
            context=context,
        )
        return True, "", pending
    except Exception as exc:  # noqa: BLE001
        if task_id is not None:
            try:
                await asyncio.to_thread(
                    runtime_client.complete,
                    task_id=task_id,
                    request_id=request_id,
                    method=method,
                    input_text=str(context.get("input_text") or ""),
                    status="failed",
                    summary=f"平台授权链执行失败：{exc}",
                    request_excerpt=request_excerpt,
                    raw_response_text=str(exc),
                    authorization={"decision": "review", "matched_rules": ["platform_authorization_failure"], "matched_controls": []},
                    extra_hit_rules=["platform_authorization_failure"],
                    metadata={"phase": "authorize", "error": str(exc)},
                )
            except Exception as complete_exc:  # noqa: BLE001
                log("WARN", "平台失败补偿回传失败", method=method, error=str(complete_exc))
        return False, f"平台授权链不可用，已拒绝放行该 OpenClaw 动作：{exc}", None


async def complete_pending_action(
    config: BridgeConfig,
    pending: PendingRuntimeAction,
    *,
    status: str,
    summary: str,
    raw_response_text: str,
    extra_hit_rules: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return
    await asyncio.to_thread(
        runtime_client.complete,
        task_id=pending.task_id,
        request_id=pending.request_id,
        method=pending.method,
        input_text=pending.input_text,
        status=status,
        summary=summary,
        request_excerpt=pending.request_excerpt,
        raw_response_text=raw_response_text,
        authorization=pending.authorization,
        extra_hit_rules=extra_hit_rules,
        metadata={
            "call_id": pending.call_id,
            "tool_call_id": str(pending.context.get("tool_call_id") or ""),
            "operation_type": pending.operation_type,
            "request_args_hash": pending.request_args_hash,
            "session_id": str(pending.context.get("session_id") or ""),
            "approval_id": str(pending.context.get("approval_id") or ""),
            "mcp_server": str(pending.context.get("mcp_server") or ""),
            "capability_name": str(pending.context.get("capability_name") or ""),
            "source_plugin": str(pending.context.get("source_plugin") or ""),
            "target_plugin": str(pending.context.get("target_plugin") or ""),
            "handoff_token": str(pending.context.get("handoff_token") or ""),
            "requested_scopes": list(pending.context.get("requested_scopes") or []),
            "mcp_ticket_key": pending.ticket_key,
            **dict(metadata or {}),
        },
    )


async def fail_pending_actions(config: BridgeConfig, pending_actions: dict[str, PendingRuntimeAction], reason: str) -> None:
    if not pending_actions:
        return
    for key, pending in list(pending_actions.items()):
        try:
            await complete_pending_action(
                config,
                pending,
                status="failed",
                summary=reason,
                raw_response_text=reason,
                extra_hit_rules=["bridge_connection_failure"],
                metadata={"phase": "proxy", "error": reason},
            )
        except Exception as exc:  # noqa: BLE001
            log("WARN", "挂起任务回传失败", method=pending.method, task_id=pending.task_id, error=str(exc))
        pending_actions.pop(key, None)


def _execute_remote_skill_scan_command(config: BridgeConfig, command: dict[str, Any]) -> dict[str, Any]:
    command_id = int(command.get("id") or 0)
    payload = dict(command.get("payload") or {})
    skill_sources = payload.get("skill_sources")
    if not isinstance(skill_sources, list) or not skill_sources:
        return {
            "status": "failed",
            "summary": "Runtime remote skill scan command does not contain any skill sources.",
            "response_text": "",
            "response_json": None,
            "error": "missing skill_sources",
            "metadata": {
                "command_id": command_id,
                "command_type": "remote_skill_scan",
            },
        }

    scan_options = dict(payload.get("scan_options") or {})
    max_files = scan_options.get("max_files")
    max_file_bytes = scan_options.get("max_file_bytes")
    try:
        result = scan_skill_sources(
            [dict(item) for item in skill_sources if isinstance(item, dict)],
            engine_label="remote",
            include_external_scan=False,
            max_files=int(max_files) if max_files is not None else None,
            max_file_bytes=int(max_file_bytes) if max_file_bytes is not None else None,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "summary": f"Remote skill scan execution failed: {exc}",
            "response_text": "",
            "response_json": None,
            "error": str(exc),
            "metadata": {
                "command_id": command_id,
                "command_type": "remote_skill_scan",
                "skill_count": len(skill_sources),
            },
        }

    result_payload = result.to_payload()
    return {
        "status": "completed",
        "summary": result.summary,
        "response_text": safe_json_dumps(result_payload, max_chars=config.max_capture_chars),
        "response_json": result_payload,
        "error": "",
        "metadata": {
            "command_id": command_id,
            "command_type": "remote_skill_scan",
            "skill_count": len(skill_sources),
            "verdict": result.verdict,
            "finding_count": result.finding_count,
        },
    }


async def execute_openclaw_runtime_command(config: BridgeConfig, command: dict[str, Any]) -> dict[str, Any]:
    command_id = int(command.get("id") or 0)
    command_type = str(command.get("command_type") or "").strip()
    payload = dict(command.get("payload") or {})
    if command_type == "remote_skill_scan":
        return await asyncio.to_thread(_execute_remote_skill_scan_command, config, command)

    if command_type != "openclaw_ws_attack":
        return {
            "status": "failed",
            "summary": f"Unsupported runtime command type: {command_type or '-'}",
            "response_text": "",
            "response_json": None,
            "error": f"unsupported runtime command type: {command_type or '-'}",
            "metadata": {
                "command_id": command_id,
                "command_type": command_type,
            },
        }

    request_frame = dict(payload.get("request_frame") or {})
    if not request_frame:
        return {
            "status": "failed",
            "summary": "Runtime command does not contain an OpenClaw request frame.",
            "response_text": "",
            "response_json": None,
            "error": "missing request_frame",
            "metadata": {"command_id": command_id},
        }

    ws_path = str(payload.get("ws_path") or "/").strip() or "/"
    timeout_seconds = max(5.0, float(payload.get("timeout_seconds") or config.request_timeout_seconds))
    request_id = call_id_key(request_frame.get("id"))
    request_text = json.dumps(request_frame, ensure_ascii=False)
    raw_query = build_openclaw_upstream_query("", config.gateway_token)
    upstream_url = combine_proxy_target(config.upstream_ws_url, ws_path, raw_query)
    upstream_url_safe = redact_url_token(upstream_url)

    try:
        async with ws_connect(
            upstream_url,
            origin=config.upstream_origin,
            open_timeout=config.connect_timeout_seconds,
            close_timeout=5,
            max_size=None,
        ) as websocket:
            await websocket.send(request_text)
            response_text = ""
            response_json: dict[str, Any] | None = None
            deadline = monotonic() + timeout_seconds
            while True:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"OpenClaw runtime command timed out after {int(timeout_seconds)}s")
                raw = await asyncio.wait_for(websocket.recv(), timeout=remaining)
                if isinstance(raw, bytes):
                    response_text = f"{len(raw)} bytes"
                    response_json = None
                    if not request_id:
                        break
                    continue
                response_text = str(raw)
                response_json = load_json_message(response_text)
                if not request_id:
                    break
                if response_json is not None and call_id_key(response_json.get("id")) == request_id:
                    break

        if response_json is not None and response_json.get("error") is not None:
            error_message = safe_json_dumps(response_json.get("error"), max_chars=config.max_capture_chars)
            return {
                "status": "failed",
                "summary": f"OpenClaw upstream returned an error for {request_frame.get('method')}.",
                "response_text": response_text[: config.max_capture_chars],
                "response_json": response_json,
                "error": error_message,
                "metadata": {
                    "command_id": command_id,
                    "command_type": command_type,
                    "ws_path": ws_path,
                    "upstream_url": upstream_url_safe,
                    "request_method": str(request_frame.get("method") or ""),
                },
            }

        return {
            "status": "completed",
            "summary": f"OpenClaw upstream completed {request_frame.get('method')}.",
            "response_text": response_text[: config.max_capture_chars],
            "response_json": response_json,
            "error": "",
            "metadata": {
                "command_id": command_id,
                "command_type": command_type,
                "ws_path": ws_path,
                "upstream_url": upstream_url_safe,
                "request_method": str(request_frame.get("method") or ""),
            },
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "summary": f"OpenClaw runtime command failed: {exc}",
            "response_text": "",
            "response_json": None,
            "error": str(exc),
            "metadata": {
                "command_id": command_id,
                "command_type": command_type,
                "ws_path": ws_path,
                "upstream_url": upstream_url_safe,
                "request_method": str(request_frame.get("method") or ""),
            },
        }


async def runtime_command_worker(config: BridgeConfig, stop_event: asyncio.Event) -> None:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return

    log("INFO", "OpenClaw Runtime 命令轮询已启动", runtime=runtime_client.runtime_display_name)
    try:
        while not stop_event.is_set():
            try:
                command = await asyncio.to_thread(runtime_client.poll_command)
                if not command:
                    await asyncio.sleep(runtime_client.command_poll_interval_seconds)
                    continue

                command_id = int(command.get("id") or 0)
                result = await execute_openclaw_runtime_command(config, command)
                await asyncio.to_thread(
                    runtime_client.complete_command,
                    command_id,
                    status=str(result.get("status") or "failed"),
                    summary=str(result.get("summary") or ""),
                    response_text=str(result.get("response_text") or ""),
                    response_json=result.get("response_json"),
                    error=str(result.get("error") or ""),
                    metadata=dict(result.get("metadata") or {}),
                )
                log(
                    "INFO",
                    "OpenClaw Runtime 命令已完成",
                    command_id=command_id,
                    status=result.get("status"),
                    method=(result.get("metadata") or {}).get("request_method"),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log("WARN", "OpenClaw Runtime 命令轮询失败", error=str(exc))
                await asyncio.sleep(max(2.0, runtime_client.command_poll_interval_seconds))
    finally:
        log("INFO", "OpenClaw Runtime 命令轮询已停止", runtime=runtime_client.runtime_display_name)


async def run_bridge(config: BridgeConfig) -> int:
    app = FastAPI()

    if config.log_jsonl_path is not None:
        config.log_jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    log("INFO", "正在测试 OpenClaw 上游连通性", upstream_http=config.upstream_http_url, upstream_ws=config.upstream_ws_url)
    connectivity = await probe_openclaw_connectivity(
        upstream_http_url=config.upstream_http_url,
        upstream_ws_url=config.upstream_ws_url,
        gateway_token=config.gateway_token,
        upstream_origin=config.upstream_origin,
        timeout_seconds=min(config.connect_timeout_seconds, 10),
    )
    for attempt in connectivity.get("http", {}).get("attempts", []):
        if attempt.get("ok"):
            log("INFO", "OpenClaw HTTP 探测可达", url=attempt.get("url"), status=attempt.get("status"))
            break
    else:
        first_error = ""
        attempts = connectivity.get("http", {}).get("attempts", [])
        if attempts:
            first_error = str(attempts[0].get("error") or attempts[0].get("status") or "")
        log("WARN", "OpenClaw HTTP 探测未命中可用页面，将继续以 WebSocket 握手为准", error=first_error)

    if not bool(connectivity.get("ws", {}).get("ok")):
        ws_error = str(connectivity.get("ws", {}).get("error") or "unknown")
        raise RuntimeError(
            f"OpenClaw WebSocket 连通性测试失败: {ws_error}. "
            f"请确认 OpenClaw 地址、gateway token、虚拟机网络和防火墙。上游 WS: {config.upstream_ws_url}"
        )
    log("INFO", "OpenClaw WebSocket 握手测试通过", upstream_ws=config.upstream_ws_url)

    def write_frame_log(direction: str, frame_type: str, payload: str) -> None:
        if config.log_jsonl_path is None:
            return
        line = json.dumps(
            {
                "time": now_text(),
                "direction": direction,
                "frame_type": frame_type,
                "payload": payload,
            },
            ensure_ascii=False,
        )
        with config.log_jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    runtime_command_stop_event = asyncio.Event()
    runtime_command_task: asyncio.Task[Any] | None = None

    @app.on_event("startup")
    async def startup_runtime_command_worker() -> None:
        nonlocal runtime_command_task
        if config.runtime_client is None:
            return
        if str(config.platform_state.get("mode") or "") != "runtime_active":
            return
        runtime_command_stop_event.clear()
        runtime_command_task = asyncio.create_task(runtime_command_worker(config, runtime_command_stop_event))

    @app.on_event("shutdown")
    async def shutdown_runtime_command_worker() -> None:
        nonlocal runtime_command_task
        runtime_command_stop_event.set()
        if runtime_command_task is None:
            return
        runtime_command_task.cancel()
        with suppress(asyncio.CancelledError):
            await runtime_command_task
        runtime_command_task = None

    @app.get("/__bridge__/health")
    async def bridge_health() -> dict[str, Any]:
        return {
            "ok": True,
            "upstream_http_url": config.upstream_http_url,
            "upstream_ws_url": config.upstream_ws_url,
            "launch_url": config.launch_http_url,
            "platform_focus": "chat_and_tool_calls_only",
            "monitored_upstream_events": sorted(OPENCLAW_MONITORED_EVENT_EXACT_MATCHES),
            "block_methods": sorted(config.block_methods),
            "readonly_methods": sorted(config.readonly_methods),
            "platform_state": config.platform_state,
        }

    @app.websocket("/{full_path:path}")
    async def websocket_proxy(websocket: WebSocket, full_path: str) -> None:
        query_string = websocket.scope.get("query_string", b"").decode("utf-8", errors="ignore")
        upstream_query = build_openclaw_upstream_query(query_string, config.gateway_token)
        upstream_url = combine_proxy_target(config.upstream_ws_url, f"/{full_path}", upstream_query)
        upstream_url_safe = redact_url_token(upstream_url)
        protocol_header = websocket.headers.get("sec-websocket-protocol") or ""
        subprotocols = [item.strip() for item in protocol_header.split(",") if item.strip()]
        client_ip = websocket.client.host if websocket.client else "-"
        pending_actions: dict[str, PendingRuntimeAction] = {}
        active_tool_bindings: list[PendingRuntimeAction] = []

        await websocket.accept(subprotocol=subprotocols[0] if subprotocols else None)
        log("INFO", "WebSocket 客户端已连接", path=f"/{full_path}", upstream=upstream_url_safe, client_ip=client_ip)

        try:
            async with ws_connect(
                upstream_url,
                origin=config.upstream_origin,
                subprotocols=subprotocols or None,
                open_timeout=config.connect_timeout_seconds,
                close_timeout=5,
                max_size=None,
            ) as upstream:
                async def client_to_upstream() -> None:
                    while True:
                        message = await websocket.receive()
                        if "text" in message and message["text"] is not None:
                            text = str(message["text"])
                            write_frame_log("client_to_upstream", "text", text)
                            payload = load_json_message(text)
                            if payload is not None:
                                method = str(payload.get("method") or "").strip()
                                if method:
                                    log("INFO", "OpenClaw 请求", method=method, request_id=payload.get("id"))
                                    request_excerpt = safe_json_dumps(payload, max_chars=config.max_capture_chars)
                                    context = extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
                                    monitor_this_method = method_targets_security_platform(
                                        method,
                                        readonly_methods=config.readonly_methods,
                                        context=context,
                                    )
                                    if method in config.block_methods:
                                        reason = f"OpenClaw 方法 {method} 已被本地桥接器显式阻断。"
                                        if monitor_this_method:
                                            await report_local_block(
                                                config,
                                                payload=payload,
                                                method=method,
                                                ws_path=f"/{full_path}",
                                                client_ip=client_ip,
                                                request_excerpt=request_excerpt,
                                                reason=reason,
                                                context=context,
                                            )
                                        if payload.get("id") is not None:
                                            await websocket.send_text(build_json_rpc_error(payload, reason))
                                            continue
                                        await websocket.close(code=4403, reason=reason)
                                        return

                                    if monitor_this_method:
                                        should_forward, deny_message, pending = await evaluate_runtime_action(
                                            config,
                                            payload=payload,
                                            method=method,
                                            ws_path=f"/{full_path}",
                                            client_ip=client_ip,
                                            request_excerpt=request_excerpt,
                                            context=context,
                                        )
                                        if not should_forward:
                                            if payload.get("id") is not None:
                                                await websocket.send_text(build_json_rpc_error(payload, deny_message))
                                                continue
                                            await websocket.close(code=4403, reason=deny_message)
                                            return
                                        await upstream.send(text)
                                        if pending is not None:
                                            if pending.operation_type == "tool_call" and pending.ticket_key:
                                                active_tool_bindings.append(pending)
                                            if pending.call_id:
                                                pending_actions[pending.call_id] = pending
                                            else:
                                                await complete_pending_action(
                                                    config,
                                                    pending,
                                                    status="done",
                                                    summary=f"OpenClaw 方法 {method} 已无编号转发。",
                                                    raw_response_text=request_excerpt,
                                                    metadata={"phase": "proxy", "notification": True},
                                                )
                                        continue

                            await upstream.send(text)
                        elif "bytes" in message and message["bytes"] is not None:
                            data = bytes(message["bytes"])
                            write_frame_log("client_to_upstream", "bytes", f"{len(data)} bytes")
                            await upstream.send(data)
                        elif message.get("type") == "websocket.disconnect":
                            await upstream.close()
                            return

                async def upstream_to_client() -> None:
                    while True:
                        response = await upstream.recv()
                        if isinstance(response, bytes):
                            write_frame_log("upstream_to_client", "bytes", f"{len(response)} bytes")
                            await websocket.send_bytes(response)
                            continue

                        text = str(response)
                        write_frame_log("upstream_to_client", "text", text)
                        payload = load_json_message(text)
                        if payload is not None and payload.get("error") is not None:
                            log(
                                "WARN",
                                "OpenClaw 上游返回错误",
                                request_id=payload.get("id"),
                                error=payload.get("error"),
                            )
                        if payload is not None:
                            pending = pending_actions.pop(call_id_key(payload.get("id")), None)
                            if pending is not None:
                                if payload.get("error") is not None:
                                    with suppress(ValueError):
                                        active_tool_bindings.remove(pending)
                                    await complete_pending_action(
                                        config,
                                        pending,
                                        status="failed",
                                        summary=f"OpenClaw 方法 {pending.method} 上游返回错误。",
                                        raw_response_text=text,
                                        extra_hit_rules=["upstream_error"],
                                        metadata={"phase": "upstream_response", "has_error": True},
                                    )
                                else:
                                    await complete_pending_action(
                                        config,
                                        pending,
                                        status="done",
                                        summary=f"OpenClaw 方法 {pending.method} 已完成。",
                                        raw_response_text=text,
                                        metadata={"phase": "upstream_response", "has_error": False},
                                    )
                        if payload is not None:
                            event_name = extract_openclaw_event_name(payload)
                            if event_name:
                                context = extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
                                if event_targets_security_platform(event_name, context=context):
                                    log("INFO", "OpenClaw 事件", event_name=event_name)
                                    event_type = classify_openclaw_server_event(event_name, context)
                                    if event_type == "tool_call":
                                        reviewed_text = await review_upstream_tool_event(
                                            config,
                                            payload=payload,
                                            event_name=event_name,
                                            ws_path=f"/{full_path}",
                                            client_ip=client_ip,
                                            request_excerpt=text[: config.max_capture_chars],
                                            context=context,
                                            active_tool_bindings=active_tool_bindings,
                                        )
                                        await websocket.send_text(reviewed_text)
                                        continue
                                    await report_upstream_event(
                                        config,
                                        payload=payload,
                                        event_name=event_name,
                                        ws_path=f"/{full_path}",
                                        client_ip=client_ip,
                                        request_excerpt=text[: config.max_capture_chars],
                                        context=context,
                                    )
                        await websocket.send_text(text)

                tasks = [
                    asyncio.create_task(client_to_upstream()),
                    asyncio.create_task(upstream_to_client()),
                ]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    exc = task.exception()
                    if exc is not None and not isinstance(exc, (WebSocketDisconnect, ConnectionClosed)):
                        raise exc
                active_tool_bindings.clear()
                await fail_pending_actions(config, pending_actions, "OpenClaw 会话已结束，挂起动作已回传为失败。")
        except Exception as exc:  # noqa: BLE001
            await fail_pending_actions(config, pending_actions, f"OpenClaw 桥接链路异常中断：{exc}")
            active_tool_bindings.clear()
            log("ERROR", "WebSocket 代理失败", path=f"/{full_path}", error=str(exc))
            if websocket.application_state.name != "DISCONNECTED":
                await websocket.close(code=1011, reason="bridge failure")
            return

        log("INFO", "WebSocket 客户端已断开", path=f"/{full_path}")

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def http_proxy(full_path: str, request: FastAPIRequest) -> Response:
        raw_query = request.scope.get("query_string", b"").decode("utf-8", errors="ignore")
        upstream_url = combine_proxy_target(config.upstream_http_url, f"/{full_path}", raw_query)
        body = await request.body()
        headers = sanitize_request_headers(dict(request.headers))
        req = Request(
            upstream_url,
            data=body if request.method != "HEAD" else None,
            headers=headers,
            method=request.method,
        )
        try:
            with urlopen(req, timeout=config.request_timeout_seconds) as upstream_response:
                content = upstream_response.read() if request.method != "HEAD" else b""
                response_headers = sanitize_response_headers(list(upstream_response.headers.items()))
                return Response(
                    content=content,
                    status_code=int(upstream_response.getcode()),
                    headers=response_headers,
                )
        except Exception as exc:  # noqa: BLE001
            log("ERROR", "HTTP 代理失败", path=f"/{full_path}", upstream=upstream_url, error=str(exc))
            return Response(
                content=json.dumps(
                    {
                        "error": "openclaw_http_proxy_failed",
                        "detail": str(exc),
                        "upstream_url": upstream_url,
                    },
                    ensure_ascii=False,
                ).encode("utf-8"),
                status_code=502,
                media_type="application/json",
            )

    print("=" * 72)
    print("OpenClaw 控制台桥接器")
    print("本地代理 OpenClaw Control UI 的 HTTP/WS 流量，并可接入 Runtime 注册、审批、授权与事件回传链。")
    print("=" * 72)
    print(f"上游 HTTP : {config.upstream_http_url}")
    print(f"上游 WS   : {config.upstream_ws_url}")
    print(f"本地监听  : http://{config.listen_host}:{config.listen_port}")
    print(f"浏览器地址: {config.launch_http_url}")
    print(f"只读方法数: {len(config.readonly_methods)}")
    print("平台关注  : 仅 AI 聊天与工具调用类 WS 方法")
    print(f"上游事件  : {', '.join(sorted(OPENCLAW_MONITORED_EVENT_EXACT_MATCHES))}")
    if config.block_methods:
        print(f"本地阻断  : {', '.join(sorted(config.block_methods))}")
    if config.log_jsonl_path is not None:
        print(f"日志文件  : {config.log_jsonl_path}")
    print()
    platform_mode = str(config.platform_state.get("mode") or "local_only")
    if platform_mode == "runtime_active":
        print("平台联动  : 已启用")
        print(f"配置文件  : {config.platform_state.get('config_path')}")
        print(f"Runtime   : {config.platform_state.get('runtime_display_name') or config.platform_state.get('runtime_name')}")
        print(f"目标资产  : {config.platform_state.get('target_agent_name')}")
        print(f"复核策略  : review_action={config.platform_state.get('review_action')}")
    elif platform_mode == "pending_approval":
        print("平台联动  : 待审批")
        print(f"配置文件  : {config.platform_state.get('config_path')}")
        print("说明      : Runtime 已提交注册，但尚未审批；当前仅运行本地代理能力。")
    else:
        print("平台联动  : 未启用")
        print("说明      : 当前只做代理和帧日志，不会创建任务、执行授权或回传安全事件。")
    print()
    print("使用说明")
    print("1. 浏览器请打开上面的本地地址，不要再直接打开远端 OpenClaw。")
    print("2. 控制台的 WebSocket 会先经过本桥接器，再决定是否放行到上游 OpenClaw。")
    print("3. 非只读方法在启用 Runtime 联动后，会进入：建任务 -> 授权 -> 心跳 -> 完成回传。")
    print()

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=config.listen_host,
            port=config.listen_port,
            log_level="warning",
            access_log=False,
        )
    )
    await server.serve()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="本地桥接 OpenClaw Control UI，并可接入保护平台的 Runtime 注册、审批、授权与事件回传链。",
    )
    parser.add_argument("--upstream-http-url", required=True, help="远端 OpenClaw 控制台地址，例如 http://192.168.137.140:18789")
    parser.add_argument("--upstream-ws-url", help="远端 OpenClaw WebSocket 地址；默认从 HTTP 地址自动推导")
    parser.add_argument("--gateway-token", required=True, help="OpenClaw Control UI 使用的 gateway token")
    parser.add_argument("--listen-host", default="127.0.0.1", help="本地监听地址，默认 127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=19090, help="本地监听端口，默认 19090")
    parser.add_argument("--access-host", help="浏览器访问本桥接器时使用的地址/IP；默认自动推导")
    parser.add_argument("--request-timeout-seconds", type=float, default=30, help="HTTP 代理超时秒数")
    parser.add_argument("--connect-timeout-seconds", type=float, default=20, help="WS 上游连接超时秒数")
    parser.add_argument("--log-jsonl", help="将 WS 文本/二进制帧记录到 jsonl 文件")
    parser.add_argument("--block-methods", default="", help="可选，逗号分隔的 WS 方法名阻断列表，例如 config.set,chat.send")
    parser.add_argument(
        "--readonly-methods",
        default=",".join(sorted(DEFAULT_READ_ONLY_METHODS)),
        help="逗号分隔的只读 WS 方法列表；这些方法默认直接放行",
    )
    parser.add_argument("--max-capture-chars", type=int, default=16000, help="请求/响应截取上限，默认 16000")

    parser.add_argument("--platform-base-url", help="保护平台地址，例如 http://127.0.0.1:8000")
    parser.add_argument("--enrollment-token", help="一次性 Runtime 注册码；首次接入时使用")
    parser.add_argument("--runtime-config", help="Runtime 本地配置文件路径；默认写入 tools/agent_gateway/generated")
    parser.add_argument("--profile-name", help="桥接配置名称；默认按 OpenClaw 地址自动生成")
    parser.add_argument("--runtime-display-name", help="Runtime 显示名称；默认按 OpenClaw 地址自动生成")
    parser.add_argument("--runtime-type", default="openclaw_control_bridge", help="Runtime 类型，默认 openclaw_control_bridge")
    parser.add_argument("--target-agent-name", help="平台中显示的受保护目标名称")
    parser.add_argument("--review-action", choices=["block", "allow"], default="block", help="授权结果为 review 时是否阻断")
    parser.add_argument("--attack-type", default="openclaw_control", help="默认攻击类型；聊天和工具调用会自动归类为 openclaw_chat/openclaw_tool_call")
    parser.add_argument("--skip-approval-wait", action="store_true", help="只发起注册，不等待审批；未审批前以本地模式启动")
    parser.add_argument("--insecure-platform", action="store_true", help="不校验保护平台 HTTPS 证书")
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdio_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    upstream_http_url = normalize_base_url(args.upstream_http_url)
    upstream_ws_url = normalize_base_url(args.upstream_ws_url) if args.upstream_ws_url else default_ws_url_from_http(upstream_http_url)
    listen_host = str(args.listen_host).strip()
    access_host = str(args.access_host).strip() if str(args.access_host or "").strip() else default_gateway_access_host(listen_host)
    log_jsonl_path = Path(args.log_jsonl).expanduser().resolve() if args.log_jsonl else None

    config = BridgeConfig(
        upstream_http_url=upstream_http_url,
        upstream_ws_url=upstream_ws_url,
        listen_host=listen_host,
        listen_port=int(args.listen_port),
        access_host=access_host,
        gateway_token=str(args.gateway_token).strip(),
        request_timeout_seconds=float(args.request_timeout_seconds),
        connect_timeout_seconds=float(args.connect_timeout_seconds),
        log_jsonl_path=log_jsonl_path,
        block_methods={item.lower() for item in split_csv(args.block_methods)},
        readonly_methods={item.lower() for item in split_csv(args.readonly_methods)} or set(DEFAULT_READ_ONLY_METHODS),
        upstream_origin=default_http_origin(upstream_http_url),
        max_capture_chars=max(2000, int(args.max_capture_chars)),
    )

    try:
        runtime_client, platform_state = resolve_runtime_client(args, config)
        config.runtime_client = runtime_client
        config.platform_state = platform_state
        return asyncio.run(run_bridge(config))
    except KeyboardInterrupt:
        print("\n已停止 OpenClaw 控制台桥接器。")
        return 130
    except Exception as exc:  # noqa: BLE001
        log("ERROR", "OpenClaw 控制台桥接器启动失败", error=str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
