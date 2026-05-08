#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import re
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import FastAPI, Request as FastAPIRequest, Response, WebSocket, WebSocketDisconnect
import uvicorn
from websockets.exceptions import ConnectionClosed
from websockets.legacy.client import connect as ws_connect


SCRIPT_DIR = Path(__file__).resolve().parent
AGENT_GATEWAY_DIR = SCRIPT_DIR / "agent_gateway"
if str(AGENT_GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_GATEWAY_DIR))

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
}

TURN_KEYS = {
    "messages",
    "history",
    "conversation",
    "conversation_messages",
    "chat_history",
    "turns",
    "additional_messages",
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
}

SCOPE_KEYS = {
    "requested_scopes",
    "scopes",
    "scope",
    "permissions",
    "permission",
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
}

PLUGIN_KEYS = {
    "plugin",
    "plugins",
    "plugin_name",
    "plugin_names",
}

PROMPT_METHOD_HINTS = (
    "chat",
    "message",
    "prompt",
    "assistant",
    "completion",
    "run",
    "invoke",
    "conversation",
    "reply",
)

GENERIC_NAME_FIELDS = ("name", "id", "key", "value", "path")


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


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


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
        output: list[str] = []
        for field in GENERIC_NAME_FIELDS:
            text = str(value.get(field) or "").strip()
            if text:
                output.append(text)
        if output:
            return output
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
    for field in ("source_plugin", "target_plugin", "mcp_server", "capability_name", "session_id", "approval_id", "handoff_token"):
        values = iter_key_matches(source, {normalize_key(field)})
        metadata[field] = stringify_message_content(values[0]) if values else ""

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
        "session_id": metadata["session_id"],
        "approval_id": metadata["approval_id"],
        "handoff_token": metadata["handoff_token"],
    }


def classify_attack_type(method: str, context: dict[str, Any], default_attack_type: str) -> str:
    normalized_method = str(method or "").strip().lower()
    if str(context.get("input_text") or "").strip():
        return "prompt_injection"
    if any(token in normalized_method for token in PROMPT_METHOD_HINTS):
        return "prompt_injection"
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
    ]
    capabilities = [
        "http_proxy",
        "websocket_proxy",
        "openclaw_control_bridge",
        "runtime_event_reporting",
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
    ws_path: str
    client_ip: str
    input_text: str
    request_excerpt: str
    authorization: dict[str, Any]
    context: dict[str, Any]


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
                "gateway_metadata": {
                    "transport": "websocket",
                    "ws_method": method,
                    "ws_call_id": call_id,
                    "ws_path": ws_path,
                    "client_ip": client_ip,
                    "profile_name": self.profile_name,
                    "preset": self.preset,
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
    ) -> dict[str, Any]:
        payload = {
            "task_id": task_id,
            "runtime_name": self.runtime_name,
            "runtime_task_ref": request_id,
            "action_type": "openclaw_ws_call",
            "input_text": context["input_text"],
            "paths": context["paths"],
            "skill_names": context["skill_names"],
            "plugin_names": context["plugin_names"],
            "source_plugin": context["source_plugin"],
            "target_plugin": context["target_plugin"],
            "mcp_server": context["mcp_server"],
            "capability_name": context["capability_name"],
            "session_id": context["session_id"],
            "approval_id": context["approval_id"],
            "handoff_token": context["handoff_token"],
            "requested_scopes": context["requested_scopes"],
            "metadata": {
                "message": context["input_text"],
                "ws_method": method,
                "ws_call_id": call_id,
                "ws_path": ws_path,
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
            "metadata": {
                "ws_method": method,
                "request_excerpt": request_excerpt,
                "authorization": authorization or {},
                **dict(metadata or {}),
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
) -> None:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return

    request_id = f"ocws-{uuid4().hex[:12]}"
    context = extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
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


async def evaluate_runtime_action(
    config: BridgeConfig,
    *,
    payload: dict[str, Any],
    method: str,
    ws_path: str,
    client_ip: str,
    request_excerpt: str,
) -> tuple[bool, str, PendingRuntimeAction | None]:
    runtime_client = config.runtime_client
    if runtime_client is None:
        return True, "", None

    context = extract_openclaw_context(payload, max_capture_chars=config.max_capture_chars)
    request_id = f"ocws-{uuid4().hex[:12]}"
    call_id = call_id_key(payload.get("id"))
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
        )
        authorization = dict(auth_result.get("authorization") or {})
        decision = str(authorization.get("decision") or "").strip().lower()

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
                metadata={"phase": "authorize", "blocked_by": "policy"},
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
                metadata={"phase": "authorize", "blocked_by": "review_action"},
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
            ws_path=ws_path,
            client_ip=client_ip,
            input_text=str(context.get("input_text") or ""),
            request_excerpt=request_excerpt,
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
        metadata=metadata,
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


async def run_bridge(config: BridgeConfig) -> int:
    app = FastAPI()

    if config.log_jsonl_path is not None:
        config.log_jsonl_path.parent.mkdir(parents=True, exist_ok=True)

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

    @app.get("/__bridge__/health")
    async def bridge_health() -> dict[str, Any]:
        return {
            "ok": True,
            "upstream_http_url": config.upstream_http_url,
            "upstream_ws_url": config.upstream_ws_url,
            "launch_url": config.launch_http_url,
            "block_methods": sorted(config.block_methods),
            "readonly_methods": sorted(config.readonly_methods),
            "platform_state": config.platform_state,
        }

    @app.websocket("/{full_path:path}")
    async def websocket_proxy(websocket: WebSocket, full_path: str) -> None:
        query_string = websocket.scope.get("query_string", b"").decode("utf-8", errors="ignore")
        upstream_url = combine_proxy_target(config.upstream_ws_url, f"/{full_path}", query_string)
        protocol_header = websocket.headers.get("sec-websocket-protocol") or ""
        subprotocols = [item.strip() for item in protocol_header.split(",") if item.strip()]
        client_ip = websocket.client.host if websocket.client else "-"
        pending_actions: dict[str, PendingRuntimeAction] = {}

        await websocket.accept(subprotocol=subprotocols[0] if subprotocols else None)
        log("INFO", "WebSocket 客户端已连接", path=f"/{full_path}", upstream=upstream_url, client_ip=client_ip)

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
                                    if method in config.block_methods:
                                        reason = f"OpenClaw 方法 {method} 已被本地桥接器显式阻断。"
                                        await report_local_block(
                                            config,
                                            payload=payload,
                                            method=method,
                                            ws_path=f"/{full_path}",
                                            client_ip=client_ip,
                                            request_excerpt=request_excerpt,
                                            reason=reason,
                                        )
                                        if payload.get("id") is not None:
                                            await websocket.send_text(build_json_rpc_error(payload, reason))
                                            continue
                                        await websocket.close(code=4403, reason=reason)
                                        return

                                    if not method_is_read_only(method, config.readonly_methods):
                                        should_forward, deny_message, pending = await evaluate_runtime_action(
                                            config,
                                            payload=payload,
                                            method=method,
                                            ws_path=f"/{full_path}",
                                            client_ip=client_ip,
                                            request_excerpt=request_excerpt,
                                        )
                                        if not should_forward:
                                            if payload.get("id") is not None:
                                                await websocket.send_text(build_json_rpc_error(payload, deny_message))
                                                continue
                                            await websocket.close(code=4403, reason=deny_message)
                                            return
                                        await upstream.send(text)
                                        if pending is not None:
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
                await fail_pending_actions(config, pending_actions, "OpenClaw 会话已结束，挂起动作已回传为失败。")
        except Exception as exc:  # noqa: BLE001
            await fail_pending_actions(config, pending_actions, f"OpenClaw 桥接链路异常中断：{exc}")
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
    parser.add_argument("--upstream-http-url", required=True, help="远端 OpenClaw 控制台地址，例如 http://OPENCLAW_HOST:18789")
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
    parser.add_argument("--attack-type", default="openclaw_control", help="默认攻击类型；带输入文本的动作会自动提升为 prompt_injection")
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
