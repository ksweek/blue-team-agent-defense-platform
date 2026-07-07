from __future__ import annotations

import json
import logging
from collections import OrderedDict
from hashlib import sha1
from threading import Lock
from time import monotonic
from typing import Any, Callable

from ..core.config import settings

logger = logging.getLogger("app.cache")


class MemoryCacheBackend:
    def __init__(self, max_items: int) -> None:
        self._max_items = max(64, max_items)
        self._values: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._counters: dict[str, int] = {}
        self._lock = Lock()

    def get(self, key: str) -> str | None:
        now = monotonic()
        with self._lock:
            payload = self._values.get(key)
            if payload is None:
                return None
            expires_at, value = payload
            if expires_at <= now:
                self._values.pop(key, None)
                return None
            self._values.move_to_end(key)
            return value

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        expires_at = monotonic() + ttl_seconds
        with self._lock:
            self._values[key] = (expires_at, value)
            self._values.move_to_end(key)
            self._prune_locked()

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)

    def get_counter(self, key: str) -> int:
        with self._lock:
            return int(self._counters.get(key, 0))

    def increment(self, key: str) -> int:
        with self._lock:
            value = int(self._counters.get(key, 0)) + 1
            self._counters[key] = value
            return value

    def _prune_locked(self) -> None:
        now = monotonic()
        expired_keys = [key for key, (expires_at, _value) in self._values.items() if expires_at <= now]
        for key in expired_keys:
            self._values.pop(key, None)
        while len(self._values) > self._max_items:
            self._values.popitem(last=False)


class RedisCacheBackend:
    def __init__(self, url: str) -> None:
        from redis import Redis

        self._client = Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
            retry_on_timeout=False,
        )

    def get(self, key: str) -> str | None:
        return self._client.get(key)

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        self._client.setex(key, ttl_seconds, value)

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def get_counter(self, key: str) -> int:
        value = self._client.get(key)
        if value is None:
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def increment(self, key: str) -> int:
        return int(self._client.incr(key))


class CacheService:
    def __init__(self) -> None:
        requested_backend = (settings.cache_backend or "memory").strip().lower()
        if requested_backend not in {"disabled", "memory", "redis"}:
            logger.warning("unknown cache backend %s; using memory", requested_backend)
            requested_backend = "memory"
        self._configured_backend = requested_backend
        self._prefix = settings.cache_namespace.strip() or "guardian-agent"
        self._default_ttl = max(1, settings.cache_default_ttl_seconds)
        self._memory = MemoryCacheBackend(settings.cache_memory_max_items)
        self._fallback_active = False
        self._fallback_reason = ""
        self._backend = self._build_primary_backend()
        self._lock = Lock()

    def get_json(self, namespace: str, key_parts: dict[str, Any], ttl_seconds: int | None = None) -> Any | None:
        key = self._build_key(namespace, key_parts)
        raw_value = self._call_backend("get", key)
        if raw_value is None:
            return None
        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            self._call_backend("delete", key)
            logger.warning("cache payload decode failed | namespace=%s key=%s", namespace, key)
            return None

    def set_json(self, namespace: str, key_parts: dict[str, Any], value: Any, ttl_seconds: int | None = None) -> None:
        ttl = self._normalize_ttl(ttl_seconds)
        if ttl <= 0 or self._configured_backend == "disabled":
            return
        key = self._build_key(namespace, key_parts)
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        self._call_backend("set", key, payload, ttl)

    def get_or_set_json(
        self,
        namespace: str,
        key_parts: dict[str, Any],
        loader: Callable[[], Any],
        ttl_seconds: int | None = None,
    ) -> Any:
        if self._configured_backend == "disabled":
            return loader()
        cached = self.get_json(namespace, key_parts, ttl_seconds=ttl_seconds)
        if cached is not None:
            return cached
        value = loader()
        self.set_json(namespace, key_parts, value, ttl_seconds=ttl_seconds)
        return value

    def invalidate_namespace(self, *namespaces: str) -> None:
        if not namespaces:
            return
        for namespace in namespaces:
            normalized = namespace.strip()
            if not normalized:
                continue
            self._call_backend("increment", self._namespace_version_key(normalized))

    def snapshot(self) -> dict[str, Any]:
        return {
            "configured_backend": self._configured_backend,
            "effective_backend": self.effective_backend,
            "fallback_active": self._fallback_active,
            "fallback_reason": self._fallback_reason,
        }

    @property
    def effective_backend(self) -> str:
        if self._configured_backend == "disabled":
            return "disabled"
        if self._backend is None or self._fallback_active:
            return "memory"
        return "redis"

    def _build_primary_backend(self) -> RedisCacheBackend | None:
        if self._configured_backend != "redis":
            return None
        try:
            return RedisCacheBackend(settings.redis_url)
        except Exception as exc:
            self._fallback_active = True
            self._fallback_reason = str(exc)
            logger.warning("redis cache init failed; using in-memory fallback | error=%s", exc)
            return None

    def _build_key(self, namespace: str, key_parts: dict[str, Any]) -> str:
        version = self._namespace_version(namespace)
        encoded_parts = json.dumps(key_parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
        digest = sha1(encoded_parts.encode("utf-8")).hexdigest()
        return f"{self._prefix}:cache:{namespace}:v{version}:{digest}"

    def _namespace_version_key(self, namespace: str) -> str:
        return f"{self._prefix}:cache-version:{namespace}"

    def _namespace_version(self, namespace: str) -> int:
        return int(self._call_backend("get_counter", self._namespace_version_key(namespace)))

    def _normalize_ttl(self, ttl_seconds: int | None) -> int:
        if ttl_seconds is None:
            return self._default_ttl
        return max(0, int(ttl_seconds))

    def _call_backend(self, method: str, *args: Any) -> Any:
        if self._configured_backend == "disabled":
            if method == "increment":
                return 0
            if method == "get_counter":
                return 0
            return None

        backend = self._backend
        if backend is None or self._fallback_active:
            return getattr(self._memory, method)(*args)

        try:
            return getattr(backend, method)(*args)
        except Exception as exc:
            self._activate_fallback(exc)
            return getattr(self._memory, method)(*args)

    def _activate_fallback(self, exc: Exception) -> None:
        with self._lock:
            if self._fallback_active:
                return
            self._fallback_active = True
            self._fallback_reason = str(exc)
        logger.warning("redis cache unavailable; switched to in-memory fallback | error=%s", exc)


cache_service = CacheService()


def cached_payload(
    namespace: str,
    *,
    key_parts: dict[str, Any],
    loader: Callable[[], Any],
    ttl_seconds: int | None = None,
) -> Any:
    return cache_service.get_or_set_json(namespace, key_parts, loader, ttl_seconds=ttl_seconds)


def invalidate_cache_namespaces(*namespaces: str) -> None:
    cache_service.invalidate_namespace(*namespaces)
