from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any
from urllib.parse import urlencode, urlsplit

try:
    import boto3
except Exception:  # pragma: no cover - optional dependency
    boto3 = None

from ..core.config import settings

logger = logging.getLogger("app.provider")


class ProviderConfigurationError(RuntimeError):
    pass


class ProviderExecutionError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        status_code: int | None = None,
        failure_type: str = "provider_execution",
    ):
        super().__init__(message)
        self.retryable = bool(retryable)
        self.status_code = status_code
        self.failure_type = failure_type


@dataclass
class ProviderEndpoint:
    provider: str
    base_url: str
    api_key: str
    model: str
    endpoint_id: int | None = None
    endpoint_key: str = "env-default"
    endpoint_name: str = "Environment Default"
    enabled: bool = True
    protection_enabled: bool = True
    protection_mode: str = "enforce"
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResult:
    provider: str
    model: str
    output_text: str
    raw_response: str
    usage: dict[str, Any]
    endpoint_id: int | None = None
    endpoint_key: str = ""
    endpoint_name: str = ""


def _is_retryable_http_status(status_code: int) -> bool:
    return status_code in {408, 425, 429} or 500 <= status_code < 600


def _provider_http_error(status_code: int, detail: str) -> ProviderExecutionError:
    return ProviderExecutionError(
        f"Provider HTTP {status_code}: {detail}",
        retryable=_is_retryable_http_status(status_code),
        status_code=status_code,
        failure_type="http_error",
    )


def _provider_connection_error(reason: Any) -> ProviderExecutionError:
    return ProviderExecutionError(
        f"Provider connection failed: {reason}",
        retryable=True,
        failure_type="connection_failed",
    )


def _provider_timeout_error() -> ProviderExecutionError:
    return ProviderExecutionError(
        "Provider request timed out.",
        retryable=True,
        failure_type="timeout",
    )


def _provider_invalid_json_error(body: str) -> ProviderExecutionError:
    return ProviderExecutionError(
        f"Provider returned non-JSON content: {body[:200]}",
        retryable=False,
        failure_type="invalid_json",
    )


class ProviderStreamSession:
    def __init__(self, endpoint: ProviderEndpoint):
        self.endpoint = endpoint
        self.provider = endpoint.provider
        self.model = endpoint.model
        self.endpoint_id = endpoint.endpoint_id
        self.endpoint_key = endpoint.endpoint_key
        self.endpoint_name = endpoint.endpoint_name
        self.usage: dict[str, Any] = {}
        self.error: str | None = None
        self._fragments: list[str] = []
        self._raw_events: list[Any] = []
        self._iterator = iter(())

    def set_iterator(self, iterator) -> None:
        self._iterator = iterator

    def iter_deltas(self):
        yield from self._iterator

    def append_text(self, text: str) -> None:
        if text:
            self._fragments.append(text)

    def append_event(self, payload: Any) -> None:
        self._raw_events.append(payload)

    def update_usage(self, payload: dict[str, Any] | None) -> None:
        if not isinstance(payload, dict):
            return
        for key, value in payload.items():
            if value is not None:
                self.usage[key] = value

    def build_result(self) -> ProviderResult:
        return ProviderResult(
            provider=self.provider,
            model=self.model,
            output_text="".join(self._fragments),
            raw_response=json.dumps(self._raw_events, ensure_ascii=False),
            usage=dict(self.usage),
            endpoint_id=self.endpoint_id,
            endpoint_key=self.endpoint_key,
            endpoint_name=self.endpoint_name,
        )


def provider_status(endpoint: ProviderEndpoint | None = None) -> dict[str, Any]:
    resolved = endpoint or _default_env_endpoint()
    return {
        "provider": resolved.provider,
        "configured": resolved.provider != "disabled" and bool(resolved.base_url and resolved.model),
        "base_url": resolved.base_url,
        "model": resolved.model,
        "endpoint_key": resolved.endpoint_key,
        "endpoint_name": resolved.endpoint_name,
    }


def invoke_chat_completion(
    messages: list[dict[str, str]],
    *,
    endpoint: ProviderEndpoint | None = None,
) -> ProviderResult:
    resolved_endpoint = endpoint or _default_env_endpoint()
    _validate_endpoint(resolved_endpoint)

    if resolved_endpoint.provider == "openai_compatible":
        return _invoke_openai_compatible(messages, resolved_endpoint)
    if resolved_endpoint.provider == "anthropic":
        return _invoke_anthropic(messages, resolved_endpoint)
    if resolved_endpoint.provider == "azure_openai":
        return _invoke_azure_openai(messages, resolved_endpoint)
    if resolved_endpoint.provider == "gemini":
        return _invoke_gemini(messages, resolved_endpoint)
    if resolved_endpoint.provider == "ollama":
        return _invoke_ollama(messages, resolved_endpoint)
    if resolved_endpoint.provider == "bedrock":
        return _invoke_bedrock(messages, resolved_endpoint)

    logger.error(
        "provider request rejected | reason=unsupported_provider provider=%s endpoint_key=%s",
        resolved_endpoint.provider,
        resolved_endpoint.endpoint_key,
    )
    raise ProviderConfigurationError(f"Unsupported provider: {resolved_endpoint.provider}")


def provider_supports_streaming(endpoint: ProviderEndpoint | None) -> bool:
    resolved_endpoint = endpoint or _default_env_endpoint()
    return resolved_endpoint.provider in {"openai_compatible", "azure_openai", "anthropic", "ollama"}


def invoke_chat_completion_stream(
    messages: list[dict[str, str]],
    *,
    endpoint: ProviderEndpoint | None = None,
) -> ProviderStreamSession:
    resolved_endpoint = endpoint or _default_env_endpoint()
    _validate_endpoint(resolved_endpoint)

    if resolved_endpoint.provider == "openai_compatible":
        return _stream_openai_compatible(messages, resolved_endpoint)
    if resolved_endpoint.provider == "azure_openai":
        return _stream_azure_openai(messages, resolved_endpoint)
    if resolved_endpoint.provider == "anthropic":
        return _stream_anthropic(messages, resolved_endpoint)
    if resolved_endpoint.provider == "ollama":
        return _stream_ollama(messages, resolved_endpoint)

    raise ProviderConfigurationError(f"Streaming is not supported for provider: {resolved_endpoint.provider}")


def _default_env_endpoint() -> ProviderEndpoint:
    return ProviderEndpoint(
        provider=settings.ai_provider,
        base_url=settings.ai_base_url,
        api_key=settings.ai_api_key,
        model=settings.ai_model,
        endpoint_key="env-default",
        endpoint_name="Environment Default",
        config={},
    )


def _validate_endpoint(endpoint: ProviderEndpoint) -> None:
    if not endpoint.enabled:
        logger.warning("provider request rejected | reason=endpoint_disabled endpoint_key=%s", endpoint.endpoint_key)
        raise ProviderConfigurationError(f"AI endpoint {endpoint.endpoint_name} is disabled.")
    if endpoint.provider == "disabled":
        logger.warning("provider request rejected | reason=provider_disabled endpoint_key=%s", endpoint.endpoint_key)
        raise ProviderConfigurationError(
            "AI provider is disabled. Configure an AI endpoint or legacy AI_PROVIDER settings before running tasks."
        )
    if endpoint.provider != "bedrock" and not endpoint.base_url:
        logger.error("provider request rejected | reason=missing_base_url endpoint_key=%s", endpoint.endpoint_key)
        raise ProviderConfigurationError(f"AI endpoint {endpoint.endpoint_name} is missing base_url.")
    if endpoint.provider == "bedrock" and not (endpoint.base_url or str(endpoint.config.get("aws_region") or "").strip()):
        logger.error("provider request rejected | reason=missing_region endpoint_key=%s", endpoint.endpoint_key)
        raise ProviderConfigurationError(
            f"AI endpoint {endpoint.endpoint_name} is missing AWS region. Use base_url or config.aws_region."
        )
    if not endpoint.model:
        logger.error("provider request rejected | reason=missing_model endpoint_key=%s", endpoint.endpoint_key)
        raise ProviderConfigurationError(f"AI endpoint {endpoint.endpoint_name} is missing model_name.")


def _invoke_openai_compatible(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderResult:
    payload: dict[str, Any] = {
        "model": endpoint.model,
        "messages": messages,
        "temperature": _temperature(endpoint),
    }
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"

    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _openai_chat_completion_url(endpoint.base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    body = _execute_request(request, endpoint)
    payload_json = _load_response_json(body, endpoint)
    output_text = _extract_openai_message_text(payload_json)
    usage = dict(payload_json.get("usage") or {})
    return _build_result(endpoint, payload_json, output_text, usage)


def _stream_openai_compatible(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderStreamSession:
    payload: dict[str, Any] = {
        "model": endpoint.model,
        "messages": messages,
        "temperature": _temperature(endpoint),
        "stream": True,
    }
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"

    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _openai_chat_completion_url(endpoint.base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    session = ProviderStreamSession(endpoint)
    session.set_iterator(_iter_openai_like_stream(request, endpoint, session))
    return session


def _invoke_anthropic(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderResult:
    system_segments: list[str] = []
    request_messages: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "")
        if role == "system":
            if content:
                system_segments.append(content)
            continue
        normalized_role = "assistant" if role == "assistant" else "user"
        request_messages.append({"role": normalized_role, "content": content})

    payload: dict[str, Any] = {
        "model": endpoint.model,
        "messages": request_messages,
        "temperature": _temperature(endpoint),
        "max_tokens": _max_tokens(endpoint) or 1024,
    }
    if system_segments:
        payload["system"] = "\n\n".join(system_segments)

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "anthropic-version": str(endpoint.config.get("anthropic_version") or "2023-06-01"),
    }
    if endpoint.api_key:
        headers["x-api-key"] = endpoint.api_key

    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _anthropic_messages_url(endpoint.base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    body = _execute_request(request, endpoint)
    payload_json = _load_response_json(body, endpoint)
    output_text = _extract_anthropic_message_text(payload_json)
    usage = dict(payload_json.get("usage") or {})
    return _build_result(endpoint, payload_json, output_text, usage)


def _stream_anthropic(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderStreamSession:
    system_segments: list[str] = []
    request_messages: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "")
        if role == "system":
            if content:
                system_segments.append(content)
            continue
        normalized_role = "assistant" if role == "assistant" else "user"
        request_messages.append({"role": normalized_role, "content": content})

    payload: dict[str, Any] = {
        "model": endpoint.model,
        "messages": request_messages,
        "temperature": _temperature(endpoint),
        "max_tokens": _max_tokens(endpoint) or 1024,
        "stream": True,
    }
    if system_segments:
        payload["system"] = "\n\n".join(system_segments)

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "anthropic-version": str(endpoint.config.get("anthropic_version") or "2023-06-01"),
    }
    if endpoint.api_key:
        headers["x-api-key"] = endpoint.api_key

    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _anthropic_messages_url(endpoint.base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    session = ProviderStreamSession(endpoint)
    session.set_iterator(_iter_anthropic_stream(request, endpoint, session))
    return session


def _invoke_azure_openai(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderResult:
    payload: dict[str, Any] = {
        "messages": messages,
        "temperature": _temperature(endpoint),
    }
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if endpoint.api_key:
        headers["api-key"] = endpoint.api_key

    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _azure_openai_chat_completion_url(endpoint.base_url, endpoint.model, endpoint.config),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    body = _execute_request(request, endpoint)
    payload_json = _load_response_json(body, endpoint)
    output_text = _extract_openai_message_text(payload_json)
    usage = dict(payload_json.get("usage") or {})
    return _build_result(endpoint, payload_json, output_text, usage)


def _stream_azure_openai(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderStreamSession:
    payload: dict[str, Any] = {
        "messages": messages,
        "temperature": _temperature(endpoint),
        "stream": True,
    }
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0:
        payload["max_tokens"] = max_tokens

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if endpoint.api_key:
        headers["api-key"] = endpoint.api_key

    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _azure_openai_chat_completion_url(endpoint.base_url, endpoint.model, endpoint.config),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    session = ProviderStreamSession(endpoint)
    session.set_iterator(_iter_openai_like_stream(request, endpoint, session))
    return session


def _invoke_gemini(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderResult:
    system_segments: list[str] = []
    contents: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "")
        if role == "system":
            if content:
                system_segments.append(content)
            continue
        contents.append(
            {
                "role": "model" if role == "assistant" else "user",
                "parts": [{"text": content}],
            }
        )

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {
            "temperature": _temperature(endpoint),
        },
    }
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0:
        payload["generationConfig"]["maxOutputTokens"] = max_tokens
    if system_segments:
        payload["systemInstruction"] = {
            "parts": [{"text": "\n\n".join(system_segments)}],
        }

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    extra_headers = endpoint.config.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)

    request = urllib.request.Request(
        _gemini_generate_content_url(endpoint.base_url, endpoint.model, endpoint.api_key),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    body = _execute_request(request, endpoint)
    payload_json = _load_response_json(body, endpoint)
    output_text = _extract_gemini_message_text(payload_json)
    usage = dict(payload_json.get("usageMetadata") or {})
    return _build_result(endpoint, payload_json, output_text, usage)


def _invoke_ollama(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderResult:
    payload: dict[str, Any] = {
        "model": endpoint.model,
        "messages": messages,
        "stream": False,
    }
    options = dict(endpoint.config.get("options") or {})
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0 and "num_predict" not in options:
        options["num_predict"] = max_tokens
    temperature = _temperature(endpoint)
    if "temperature" not in options:
        options["temperature"] = temperature
    if options:
        payload["options"] = options

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    request = urllib.request.Request(
        _ollama_chat_url(endpoint.base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    body = _execute_request(request, endpoint)
    payload_json = _load_response_json(body, endpoint)
    output_text = _extract_ollama_message_text(payload_json)
    usage = {
        "prompt_eval_count": payload_json.get("prompt_eval_count"),
        "eval_count": payload_json.get("eval_count"),
    }
    return _build_result(endpoint, payload_json, output_text, usage)


def _stream_ollama(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderStreamSession:
    payload: dict[str, Any] = {
        "model": endpoint.model,
        "messages": messages,
        "stream": True,
    }
    options = dict(endpoint.config.get("options") or {})
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0 and "num_predict" not in options:
        options["num_predict"] = max_tokens
    temperature = _temperature(endpoint)
    if "temperature" not in options:
        options["temperature"] = temperature
    if options:
        payload["options"] = options

    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/x-ndjson",
    }
    request = urllib.request.Request(
        _ollama_chat_url(endpoint.base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    session = ProviderStreamSession(endpoint)
    session.set_iterator(_iter_ollama_stream(request, endpoint, session))
    return session


def _invoke_bedrock(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> ProviderResult:
    if boto3 is None:
        raise ProviderConfigurationError(
            "Bedrock support requires boto3. Install backend dependencies with boto3 available."
        )

    region = str(endpoint.config.get("aws_region") or endpoint.base_url or "").strip()
    if not region:
        raise ProviderConfigurationError("Bedrock requires an AWS region.")

    client = boto3.client(
        "bedrock-runtime",
        region_name=region,
        aws_access_key_id=str(endpoint.config.get("aws_access_key_id") or "") or None,
        aws_secret_access_key=str(endpoint.config.get("aws_secret_access_key") or "") or None,
        aws_session_token=str(endpoint.config.get("aws_session_token") or "") or None,
    )

    bedrock_format = str(endpoint.config.get("bedrock_format") or "").strip().lower()
    if not bedrock_format:
        bedrock_format = "anthropic_messages" if endpoint.model.startswith("anthropic.") else "simple_text"

    if bedrock_format == "anthropic_messages":
        body_payload = _build_bedrock_anthropic_payload(messages, endpoint)
    elif bedrock_format == "simple_text":
        body_payload = _build_bedrock_simple_text_payload(messages, endpoint)
    else:
        raise ProviderConfigurationError(f"Unsupported bedrock_format: {bedrock_format}")

    logger.info(
        "provider request | provider=%s endpoint_key=%s model=%s region=%s format=%s",
        endpoint.provider,
        endpoint.endpoint_key,
        endpoint.model,
        region,
        bedrock_format,
    )
    try:
        response = client.invoke_model(
            modelId=endpoint.model,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body_payload).encode("utf-8"),
        )
        body = response["body"].read().decode("utf-8")
    except Exception as exc:  # pragma: no cover - depends on AWS runtime
        logger.exception(
            "provider response | provider=%s endpoint_key=%s model=%s status=bedrock_error",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
        )
        raise ProviderExecutionError(f"Bedrock invocation failed: {exc}") from exc

    payload_json = _load_response_json(body, endpoint)
    if bedrock_format == "anthropic_messages":
        output_text = _extract_anthropic_message_text(payload_json)
        usage = dict(payload_json.get("usage") or {})
    else:
        output_text = _extract_bedrock_simple_text(payload_json)
        usage = dict(payload_json.get("usage") or {})
    return _build_result(endpoint, payload_json, output_text, usage)


def _execute_request(request: urllib.request.Request, endpoint: ProviderEndpoint) -> str:
    started_at = perf_counter()
    timeout_seconds = _timeout_seconds(endpoint)
    target = _safe_endpoint(request.full_url)
    logger.info(
        "provider request | provider=%s endpoint_key=%s model=%s messages=%s endpoint=%s timeout=%.1fs",
        endpoint.provider,
        endpoint.endpoint_key,
        endpoint.model,
        _message_count(request.data),
        target,
        timeout_seconds,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        duration_ms = int((perf_counter() - started_at) * 1000)
        logger.error(
            "provider response | provider=%s endpoint_key=%s model=%s status=http_error code=%s duration_ms=%s detail=%s",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
            exc.code,
            duration_ms,
            _truncate(detail),
        )
        raise _provider_http_error(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        duration_ms = int((perf_counter() - started_at) * 1000)
        logger.error(
            "provider response | provider=%s endpoint_key=%s model=%s status=connection_failed duration_ms=%s detail=%s",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
            duration_ms,
            exc.reason,
        )
        raise _provider_connection_error(exc.reason) from exc
    except TimeoutError as exc:
        duration_ms = int((perf_counter() - started_at) * 1000)
        logger.error(
            "provider response | provider=%s endpoint_key=%s model=%s status=timeout duration_ms=%s",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
            duration_ms,
        )
        raise _provider_timeout_error() from exc

    duration_ms = int((perf_counter() - started_at) * 1000)
    logger.info(
        "provider response | provider=%s endpoint_key=%s model=%s status=received duration_ms=%s body_chars=%s",
        endpoint.provider,
        endpoint.endpoint_key,
        endpoint.model,
        duration_ms,
        len(body),
    )
    return body


def _iter_openai_like_stream(
    request: urllib.request.Request,
    endpoint: ProviderEndpoint,
    session: ProviderStreamSession,
):
    started_at = perf_counter()
    timeout_seconds = _timeout_seconds(endpoint)
    target = _safe_endpoint(request.full_url)
    logger.info(
        "provider stream request | provider=%s endpoint_key=%s model=%s endpoint=%s timeout=%.1fs",
        endpoint.provider,
        endpoint.endpoint_key,
        endpoint.model,
        target,
        timeout_seconds,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            for event_data in _iter_sse_data(response):
                if event_data == "[DONE]":
                    break
                payload_json = json.loads(event_data)
                session.append_event(payload_json)
                session.model = str(payload_json.get("model") or session.model)
                session.update_usage(dict(payload_json.get("usage") or {}))
                text_delta = _extract_openai_stream_delta_text(payload_json)
                if text_delta:
                    session.append_text(text_delta)
                    yield text_delta
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        session.error = f"Provider HTTP {exc.code}: {detail}"
        logger.error(
            "provider stream response | provider=%s endpoint_key=%s model=%s status=http_error code=%s detail=%s",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
            exc.code,
            _truncate(detail),
        )
        raise _provider_http_error(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        session.error = f"Provider connection failed: {exc.reason}"
        logger.error(
            "provider stream response | provider=%s endpoint_key=%s model=%s status=connection_failed detail=%s",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
            exc.reason,
        )
        raise _provider_connection_error(exc.reason) from exc
    except TimeoutError as exc:
        session.error = "Provider request timed out."
        logger.error(
            "provider stream response | provider=%s endpoint_key=%s model=%s status=timeout",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
        )
        raise _provider_timeout_error() from exc
    except json.JSONDecodeError as exc:
        session.error = "Provider stream returned invalid JSON."
        logger.error(
            "provider stream response | provider=%s endpoint_key=%s model=%s status=invalid_json",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
        )
        raise ProviderExecutionError(session.error, failure_type="invalid_json") from exc

    duration_ms = int((perf_counter() - started_at) * 1000)
    logger.info(
        "provider stream response | provider=%s endpoint_key=%s model=%s status=completed duration_ms=%s output_chars=%s",
        endpoint.provider,
        endpoint.endpoint_key,
        session.model,
        duration_ms,
        len("".join(session._fragments)),
    )


def _iter_anthropic_stream(
    request: urllib.request.Request,
    endpoint: ProviderEndpoint,
    session: ProviderStreamSession,
):
    started_at = perf_counter()
    timeout_seconds = _timeout_seconds(endpoint)
    target = _safe_endpoint(request.full_url)
    logger.info(
        "provider stream request | provider=%s endpoint_key=%s model=%s endpoint=%s timeout=%.1fs",
        endpoint.provider,
        endpoint.endpoint_key,
        endpoint.model,
        target,
        timeout_seconds,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            for event_name, event_data in _iter_sse_events(response):
                if not event_data:
                    continue
                payload_json = json.loads(event_data)
                session.append_event({"event": event_name, "data": payload_json})
                if event_name == "message_start":
                    message_payload = payload_json.get("message") or {}
                    session.model = str(message_payload.get("model") or session.model)
                    session.update_usage(dict(message_payload.get("usage") or {}))
                    continue
                if event_name == "message_delta":
                    session.update_usage(dict(payload_json.get("usage") or {}))
                    continue
                if event_name == "content_block_delta":
                    delta = payload_json.get("delta") or {}
                    text_delta = str(delta.get("text") or "")
                    if text_delta:
                        session.append_text(text_delta)
                        yield text_delta
                    continue
                if event_name == "message_stop":
                    break
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        session.error = f"Provider HTTP {exc.code}: {detail}"
        raise _provider_http_error(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        session.error = f"Provider connection failed: {exc.reason}"
        raise _provider_connection_error(exc.reason) from exc
    except TimeoutError as exc:
        session.error = "Provider request timed out."
        raise _provider_timeout_error() from exc
    except json.JSONDecodeError as exc:
        session.error = "Provider stream returned invalid JSON."
        raise ProviderExecutionError(session.error, failure_type="invalid_json") from exc

    duration_ms = int((perf_counter() - started_at) * 1000)
    logger.info(
        "provider stream response | provider=%s endpoint_key=%s model=%s status=completed duration_ms=%s output_chars=%s",
        endpoint.provider,
        endpoint.endpoint_key,
        session.model,
        duration_ms,
        len("".join(session._fragments)),
    )


def _iter_ollama_stream(
    request: urllib.request.Request,
    endpoint: ProviderEndpoint,
    session: ProviderStreamSession,
):
    started_at = perf_counter()
    timeout_seconds = _timeout_seconds(endpoint)
    target = _safe_endpoint(request.full_url)
    logger.info(
        "provider stream request | provider=%s endpoint_key=%s model=%s endpoint=%s timeout=%.1fs",
        endpoint.provider,
        endpoint.endpoint_key,
        endpoint.model,
        target,
        timeout_seconds,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                payload_json = json.loads(line)
                session.append_event(payload_json)
                session.model = str(payload_json.get("model") or session.model)
                session.update_usage(
                    {
                        "prompt_eval_count": payload_json.get("prompt_eval_count"),
                        "eval_count": payload_json.get("eval_count"),
                    }
                )
                text_delta = _extract_ollama_stream_delta_text(payload_json)
                if text_delta:
                    session.append_text(text_delta)
                    yield text_delta
                if payload_json.get("done") is True:
                    break
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        session.error = f"Provider HTTP {exc.code}: {detail}"
        raise _provider_http_error(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        session.error = f"Provider connection failed: {exc.reason}"
        raise _provider_connection_error(exc.reason) from exc
    except TimeoutError as exc:
        session.error = "Provider request timed out."
        raise _provider_timeout_error() from exc
    except json.JSONDecodeError as exc:
        session.error = "Provider stream returned invalid JSON."
        raise ProviderExecutionError(session.error, failure_type="invalid_json") from exc

    duration_ms = int((perf_counter() - started_at) * 1000)
    logger.info(
        "provider stream response | provider=%s endpoint_key=%s model=%s status=completed duration_ms=%s output_chars=%s",
        endpoint.provider,
        endpoint.endpoint_key,
        session.model,
        duration_ms,
        len("".join(session._fragments)),
    )


def _load_response_json(body: str, endpoint: ProviderEndpoint) -> dict[str, Any]:
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error(
            "provider response | provider=%s endpoint_key=%s model=%s status=invalid_json body=%s",
            endpoint.provider,
            endpoint.endpoint_key,
            endpoint.model,
            _truncate(body),
        )
        raise _provider_invalid_json_error(body) from exc


def _build_result(
    endpoint: ProviderEndpoint,
    payload_json: dict[str, Any],
    output_text: str,
    usage: dict[str, Any],
) -> ProviderResult:
    logger.info(
        "provider response | provider=%s endpoint_key=%s model=%s status=ok output_chars=%s total_tokens=%s",
        endpoint.provider,
        endpoint.endpoint_key,
        str(payload_json.get("model") or endpoint.model),
        len(output_text),
        usage.get("total_tokens", usage.get("output_tokens", "-")),
    )
    return ProviderResult(
        provider=endpoint.provider,
        model=str(payload_json.get("model") or endpoint.model),
        output_text=output_text,
        raw_response=json.dumps(payload_json, ensure_ascii=False),
        usage=usage,
        endpoint_id=endpoint.endpoint_id,
        endpoint_key=endpoint.endpoint_key,
        endpoint_name=endpoint.endpoint_name,
    )


def _openai_chat_completion_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def _anthropic_messages_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/messages"):
        return normalized
    return f"{normalized}/messages"


def _azure_openai_chat_completion_url(base_url: str, deployment_name: str, config: dict[str, Any]) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        api_version = str(config.get("api_version") or "2024-10-21")
        separator = "&" if "?" in normalized else "?"
        if "api-version=" in normalized:
            return normalized
        return f"{normalized}{separator}api-version={api_version}"
    api_version = str(config.get("api_version") or "2024-10-21")
    return (
        f"{normalized}/openai/deployments/{deployment_name}/chat/completions"
        f"?api-version={api_version}"
    )


def _gemini_generate_content_url(base_url: str, model: str, api_key: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith(":generateContent"):
        if "key=" in normalized or not api_key:
            return normalized
        separator = "&" if "?" in normalized else "?"
        return f"{normalized}{separator}{urlencode({'key': api_key})}"
    url = f"{normalized}/models/{model}:generateContent"
    if api_key:
        url = f"{url}?{urlencode({'key': api_key})}"
    return url


def _ollama_chat_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api/chat"):
        return normalized
    return f"{normalized}/api/chat"


def _extract_openai_message_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not choices:
        raise ProviderExecutionError("Provider response does not include choices.")

    message = choices[0].get("message") or {}
    content = message.get("content")
    if content in (None, "") and isinstance(message.get("tool_calls"), list) and message.get("tool_calls"):
        return json.dumps({"tool_calls": message.get("tool_calls")}, ensure_ascii=False)
    return _normalize_message_content(content)


def _extract_openai_stream_delta_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    delta = choices[0].get("delta") or {}
    content = delta.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        fragments = [str(item.get("text")) for item in content if isinstance(item, dict) and item.get("text")]
        return "".join(fragments)
    return ""


def _extract_anthropic_message_text(payload: dict[str, Any]) -> str:
    content = payload.get("content")
    if not isinstance(content, list) or not content:
        raise ProviderExecutionError("Anthropic response does not include content blocks.")

    fragments: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text" and item.get("text"):
            fragments.append(str(item.get("text")))
    if not fragments:
        raise ProviderExecutionError("Anthropic response does not include readable text content.")
    return "\n".join(fragments)


def _extract_gemini_message_text(payload: dict[str, Any]) -> str:
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ProviderExecutionError("Gemini response does not include candidates.")
    content = candidates[0].get("content") or {}
    parts = content.get("parts")
    if not isinstance(parts, list) or not parts:
        raise ProviderExecutionError("Gemini response does not include content parts.")
    fragments = [str(item.get("text")) for item in parts if isinstance(item, dict) and item.get("text")]
    if not fragments:
        raise ProviderExecutionError("Gemini response does not include readable text content.")
    return "\n".join(fragments)


def _extract_ollama_message_text(payload: dict[str, Any]) -> str:
    message = payload.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str) and content:
            return content
    response = payload.get("response")
    if isinstance(response, str) and response:
        return response
    raise ProviderExecutionError("Ollama response does not include readable message content.")


def _extract_ollama_stream_delta_text(payload: dict[str, Any]) -> str:
    message = payload.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            return content
    response = payload.get("response")
    if isinstance(response, str):
        return response
    return ""


def _extract_bedrock_simple_text(payload: dict[str, Any]) -> str:
    results = payload.get("results")
    if isinstance(results, list) and results:
        output_text = results[0].get("outputText")
        if output_text:
            return str(output_text)
    output_text = payload.get("outputText")
    if output_text:
        return str(output_text)
    raise ProviderExecutionError("Bedrock response does not include readable text content.")


def _normalize_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        fragments: list[str] = []
        for item in content:
            if isinstance(item, str):
                fragments.append(item)
                continue
            if not isinstance(item, dict):
                continue
            text_value = item.get("text") or item.get("input_text")
            if text_value:
                fragments.append(str(text_value))
        if fragments:
            return "\n".join(fragments)
    raise ProviderExecutionError("Provider response does not include readable message content.")


def _build_bedrock_anthropic_payload(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> dict[str, Any]:
    system_segments: list[str] = []
    request_messages: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "")
        if role == "system":
            if content:
                system_segments.append(content)
            continue
        request_messages.append(
            {
                "role": "assistant" if role == "assistant" else "user",
                "content": [{"type": "text", "text": content}],
            }
        )

    payload: dict[str, Any] = {
        "anthropic_version": str(endpoint.config.get("anthropic_version") or "bedrock-2023-05-31"),
        "messages": request_messages,
        "temperature": _temperature(endpoint),
        "max_tokens": _max_tokens(endpoint) or 1024,
    }
    if system_segments:
        payload["system"] = "\n\n".join(system_segments)
    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)
    return payload


def _build_bedrock_simple_text_payload(messages: list[dict[str, str]], endpoint: ProviderEndpoint) -> dict[str, Any]:
    prompt = "\n".join(
        f"{str(item.get('role') or 'user').upper()}: {str(item.get('content') or '')}"
        for item in messages
    )
    payload: dict[str, Any] = {
        "inputText": prompt,
        "textGenerationConfig": {
            "temperature": _temperature(endpoint),
        },
    }
    max_tokens = _max_tokens(endpoint)
    if max_tokens > 0:
        payload["textGenerationConfig"]["maxTokenCount"] = max_tokens
    extra_body = endpoint.config.get("extra_body")
    if isinstance(extra_body, dict):
        payload.update(extra_body)
    return payload


def _timeout_seconds(endpoint: ProviderEndpoint) -> float:
    value = endpoint.config.get("timeout_seconds")
    try:
        return float(value) if value is not None else settings.ai_timeout_seconds
    except (TypeError, ValueError):
        return settings.ai_timeout_seconds


def _temperature(endpoint: ProviderEndpoint) -> float:
    value = endpoint.config.get("temperature")
    try:
        return float(value) if value is not None else settings.ai_temperature
    except (TypeError, ValueError):
        return settings.ai_temperature


def _max_tokens(endpoint: ProviderEndpoint) -> int:
    value = endpoint.config.get("max_tokens")
    try:
        return int(value) if value is not None else settings.ai_max_tokens
    except (TypeError, ValueError):
        return settings.ai_max_tokens


def _message_count(payload_bytes: bytes | None) -> int:
    if not payload_bytes:
        return 0
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 0
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return 0
    return len(messages)


def _iter_sse_data(response) -> Any:
    for _event_name, event_data in _iter_sse_events(response):
        if event_data:
            yield event_data


def _iter_sse_events(response):
    event_name = ""
    data_lines: list[str] = []
    for raw_line in response:
        line = raw_line.decode("utf-8", errors="ignore").rstrip("\r\n")
        if not line:
            if data_lines:
                yield event_name, "\n".join(data_lines)
            event_name = ""
            data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip()
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
    if data_lines:
        yield event_name, "\n".join(data_lines)


def _safe_endpoint(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _truncate(value: str, limit: int = 240) -> str:
    text = value.replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."
