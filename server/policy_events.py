"""Policy event bus for real-time policy update streaming.

Architecture:
  - PolicyEventBus: In-process fanout via asyncio.Queue per subscriber.
    Always available, used directly in tests.
  - RedisEventBridge: Optional cross-process bridge using Redis pub/sub.
    Publishes events to a Redis channel and relays incoming messages
    into the in-process bus.

Module-level API:
  - get_bus() → PolicyEventBus singleton
  - publish_policy_event(update_type, policy_id) → publish + version bump
  - init_redis_bridge() → connect Redis, start listener task
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event types (match proto PolicyUpdateType enum names)
# ---------------------------------------------------------------------------

POLICY_ADD = "POLICY_ADD"
POLICY_MODIFY = "POLICY_MODIFY"
POLICY_REMOVE = "POLICY_REMOVE"
POLICY_FULL_SYNC = "POLICY_FULL_SYNC"


# ---------------------------------------------------------------------------
# In-process event bus
# ---------------------------------------------------------------------------


class PolicyEventBus:
    """Fan-out event bus backed by per-subscriber asyncio.Queue."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        self._version: int = 0

    async def subscribe(self) -> asyncio.Queue:
        """Register a new listener and return its queue."""
        queue: asyncio.Queue = asyncio.Queue()
        async with self._lock:
            self._subscribers.append(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Remove a listener queue."""
        async with self._lock:
            try:
                self._subscribers.remove(queue)
            except ValueError:
                pass

    async def publish(self, event: dict[str, Any]) -> None:
        """Push *event* to every subscriber queue."""
        async with self._lock:
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning(
                        "PolicyEventBus: subscriber queue full, dropping event"
                    )

    def get_version(self) -> int:
        return self._version

    def increment_version(self) -> int:
        self._version += 1
        return self._version


# ---------------------------------------------------------------------------
# Redis event bridge (optional, production)
# ---------------------------------------------------------------------------

_REDIS_CHANNEL = "akeso:policy_updates"
_REDIS_VERSION_KEY = "akeso:policy_version"


class RedisEventBridge:
    """Bridges policy events through Redis pub/sub."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._redis = None
        self._listener_task: asyncio.Task | None = None

    async def connect(self) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
        await self._redis.ping()
        logger.info("RedisEventBridge: connected to %s", self._redis_url)

    async def close(self) -> None:
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        if self._redis:
            await self._redis.aclose()

    async def publish_event(self, event: dict[str, Any]) -> None:
        """Publish event to Redis channel and bump version key."""
        if not self._redis:
            return
        new_ver = await self._redis.incr(_REDIS_VERSION_KEY)
        event["new_version"] = new_ver
        await self._redis.publish(_REDIS_CHANNEL, json.dumps(event))

    async def get_version(self) -> int:
        """Read current version from Redis."""
        if not self._redis:
            return 0
        val = await self._redis.get(_REDIS_VERSION_KEY)
        return int(val) if val else 0

    async def start_listener(self, bus: PolicyEventBus) -> None:
        """Subscribe to Redis channel and relay messages into the bus."""
        if not self._redis:
            return

        async def _listen():
            pubsub = self._redis.pubsub()
            await pubsub.subscribe(_REDIS_CHANNEL)
            try:
                async for message in pubsub.listen():
                    if message["type"] != "message":
                        continue
                    try:
                        event = json.loads(message["data"])
                        # Sync in-memory version
                        ver = event.get("new_version", 0)
                        while bus.get_version() < ver:
                            bus.increment_version()
                        await bus.publish(event)
                    except Exception:
                        logger.exception("RedisEventBridge: failed to process message")
            except asyncio.CancelledError:
                await pubsub.unsubscribe(_REDIS_CHANNEL)
                raise

        self._listener_task = asyncio.create_task(_listen())
        logger.info("RedisEventBridge: listener started on channel %s", _REDIS_CHANNEL)


# ---------------------------------------------------------------------------
# Module-level singleton API
# ---------------------------------------------------------------------------

_bus = PolicyEventBus()
_redis_bridge: RedisEventBridge | None = None


def get_bus() -> PolicyEventBus:
    """Return the global policy event bus."""
    return _bus


async def init_redis_bridge() -> None:
    """Initialize Redis bridge (call once at startup)."""
    global _redis_bridge
    from server.config import settings

    bridge = RedisEventBridge(settings.redis_url)
    await bridge.connect()

    # Sync in-memory version with Redis
    redis_ver = await bridge.get_version()
    while _bus.get_version() < redis_ver:
        _bus.increment_version()

    await bridge.start_listener(_bus)
    _redis_bridge = bridge
    logger.info("PolicyEventBus: Redis bridge initialized (version=%d)", redis_ver)


async def shutdown_redis_bridge() -> None:
    """Shut down Redis bridge (call at shutdown)."""
    global _redis_bridge
    if _redis_bridge:
        await _redis_bridge.close()
        _redis_bridge = None


async def publish_policy_event(update_type: str, policy_id: str) -> None:
    """Publish a policy change event.

    Called from REST API mutation endpoints after db.commit().
    """
    event = {
        "update_type": update_type,
        "policy_id": policy_id,
    }

    if _redis_bridge:
        # Redis bridge handles version bump and pub/sub
        await _redis_bridge.publish_event(event)
    else:
        # In-process only (tests, single-process deployment)
        new_ver = _bus.increment_version()
        event["new_version"] = new_ver
        await _bus.publish(event)
