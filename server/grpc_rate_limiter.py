"""gRPC per-agent rate limiter using token bucket algorithm.

Limits RPC calls per agent_id to prevent abuse. Each agent gets
independent rate limits per RPC method. Unauthenticated calls
(no agent_id in request) use a shared "anonymous" bucket.

Configuration via environment variables:
  DLP_GRPC_RATE_HEARTBEAT=60      # max heartbeats/minute per agent
  DLP_GRPC_RATE_DETECT=120        # max DetectContent/minute per agent
  DLP_GRPC_RATE_INCIDENT=60       # max ReportIncident/minute per agent
  DLP_GRPC_RATE_DEFAULT=120       # default for other RPCs
"""

from __future__ import annotations

import logging
import os
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field

import grpc

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token bucket
# ---------------------------------------------------------------------------

@dataclass
class TokenBucket:
    """Thread-safe token bucket rate limiter."""
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self):
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def consume(self, n: float = 1.0) -> bool:
        """Try to consume n tokens. Returns True if allowed."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now

            if self.tokens >= n:
                self.tokens -= n
                return True
            return False


# ---------------------------------------------------------------------------
# Per-agent rate limit registry
# ---------------------------------------------------------------------------

# Method-specific limits (requests per minute)
_METHOD_LIMITS: dict[str, int] = {
    "/akesodlp.AkesoDLPService/Heartbeat": int(os.getenv("DLP_GRPC_RATE_HEARTBEAT", "60")),
    "/akesodlp.AkesoDLPService/DetectContent": int(os.getenv("DLP_GRPC_RATE_DETECT", "120")),
    "/akesodlp.AkesoDLPService/ReportIncident": int(os.getenv("DLP_GRPC_RATE_INCIDENT", "60")),
    "/akesodlp.AkesoDLPService/ReportDiscoverResults": int(os.getenv("DLP_GRPC_RATE_INCIDENT", "60")),
}
_DEFAULT_LIMIT = int(os.getenv("DLP_GRPC_RATE_DEFAULT", "120"))


class RateLimitRegistry:
    """Maintains per-agent, per-method token buckets."""

    def __init__(self):
        self._lock = threading.Lock()
        # {(agent_id, method): TokenBucket}
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._last_cleanup = time.monotonic()
        self._cleanup_interval = 300  # 5 minutes

    def allow(self, agent_id: str, method: str) -> bool:
        key = (agent_id, method)
        bucket = self._get_or_create(key, method)
        allowed = bucket.consume()

        # Periodic cleanup of stale buckets
        if time.monotonic() - self._last_cleanup > self._cleanup_interval:
            self._cleanup()

        return allowed

    def _get_or_create(self, key: tuple[str, str], method: str) -> TokenBucket:
        with self._lock:
            if key not in self._buckets:
                rpm = _METHOD_LIMITS.get(method, _DEFAULT_LIMIT)
                # capacity = rpm (burst), refill = rpm/60 per second
                self._buckets[key] = TokenBucket(
                    capacity=float(rpm),
                    refill_rate=rpm / 60.0,
                )
            return self._buckets[key]

    def _cleanup(self):
        """Remove buckets that are full (idle agents)."""
        with self._lock:
            self._last_cleanup = time.monotonic()
            stale = [
                k for k, b in self._buckets.items()
                if b.tokens >= b.capacity - 0.1
            ]
            for k in stale:
                del self._buckets[k]
            if stale:
                logger.debug("RateLimiter: cleaned up %d idle buckets", len(stale))


# Singleton
_registry = RateLimitRegistry()


# ---------------------------------------------------------------------------
# gRPC server interceptor
# ---------------------------------------------------------------------------

def _extract_agent_id(request_or_message) -> str:
    """Best-effort extraction of agent_id from the request proto."""
    try:
        return getattr(request_or_message, "agent_id", "") or "anonymous"
    except Exception:
        return "anonymous"


class RateLimitInterceptor(grpc.aio.ServerInterceptor):
    """Async gRPC server interceptor that enforces per-agent rate limits."""

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        handler = await continuation(handler_call_details)

        if handler is None:
            return None

        # Skip rate limiting for Register (agents need to be able to register)
        if method.endswith("/Register"):
            return handler

        # Wrap the handler to inspect the request
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                self._make_rate_limited_unary(handler.unary_unary, method),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        elif handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                self._make_rate_limited_stream(handler.unary_stream, method),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler

    def _make_rate_limited_unary(self, original_handler, method):
        async def wrapper(request, context):
            agent_id = _extract_agent_id(request)
            if not _registry.allow(agent_id, method):
                logger.warning(
                    "Rate limit exceeded: agent=%s method=%s", agent_id, method,
                )
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    f"Rate limit exceeded for {method.split('/')[-1]}. "
                    f"Try again shortly.",
                )
            return await original_handler(request, context)
        return wrapper

    def _make_rate_limited_stream(self, original_handler, method):
        async def wrapper(request, context):
            agent_id = _extract_agent_id(request)
            if not _registry.allow(agent_id, method):
                logger.warning(
                    "Rate limit exceeded: agent=%s method=%s", agent_id, method,
                )
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    f"Rate limit exceeded for {method.split('/')[-1]}. "
                    f"Try again shortly.",
                )
            async for response in original_handler(request, context):
                yield response
        return wrapper
