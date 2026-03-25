"""Graceful shutdown coordinator (P11-T1).

Orchestrates clean drain-and-flush on SIGTERM for all server components:
  1. FastAPI completes in-flight API requests (30s timeout)
  2. gRPC server completes in-flight RPCs
  3. Redis consumer drains current batch
  4. SIEM emitter flushes pending events
  5. Database connections closed cleanly

Usage in main.py lifespan:
    from server.shutdown import ShutdownCoordinator
    coordinator = ShutdownCoordinator()
    coordinator.register("grpc", grpc_server.stop, grace=5)
    coordinator.register("redis", shutdown_redis_bridge)
    await coordinator.shutdown_all(timeout=30)
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


@dataclass
class ShutdownTask:
    """A registered shutdown task."""
    name: str
    handler: Callable[..., Coroutine[Any, Any, None]]
    kwargs: dict[str, Any] = field(default_factory=dict)
    priority: int = 0  # Lower = runs first


class ShutdownCoordinator:
    """Coordinates graceful shutdown of all server components.

    Components are shut down in priority order (lower first):
      0: Accept no new connections (gRPC stop accepting)
      1: Drain in-flight work (complete active RPCs, API requests)
      2: Flush buffers (SIEM emitter, Redis consumer)
      3: Close connections (database, Redis)
    """

    def __init__(self) -> None:
        self._tasks: list[ShutdownTask] = []
        self._shutting_down = False
        self._shutdown_event = asyncio.Event()

    @property
    def is_shutting_down(self) -> bool:
        return self._shutting_down

    def register(
        self,
        name: str,
        handler: Callable[..., Coroutine[Any, Any, None]],
        priority: int = 1,
        **kwargs: Any,
    ) -> None:
        """Register a component for coordinated shutdown."""
        self._tasks.append(ShutdownTask(
            name=name,
            handler=handler,
            kwargs=kwargs,
            priority=priority,
        ))
        logger.debug("Shutdown: registered %s (priority=%d)", name, priority)

    def install_signal_handlers(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Install SIGTERM/SIGINT handlers that trigger coordinated shutdown."""
        loop = loop or asyncio.get_event_loop()

        def _signal_handler(signame: str) -> None:
            logger.info("Shutdown: received %s — initiating graceful shutdown", signame)
            self._shutting_down = True
            self._shutdown_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, _signal_handler, sig.name)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler for all signals
                signal.signal(sig, lambda s, f: _signal_handler(signal.Signals(s).name))

    async def wait_for_shutdown(self) -> None:
        """Block until shutdown signal received."""
        await self._shutdown_event.wait()

    async def shutdown_all(self, timeout: float = 30.0) -> None:
        """Execute all registered shutdown tasks within timeout.

        Tasks run in priority order. Tasks with the same priority
        run concurrently. If total time exceeds timeout, remaining
        tasks are cancelled.
        """
        self._shutting_down = True
        start = time.monotonic()

        # Group by priority
        by_priority: dict[int, list[ShutdownTask]] = {}
        for task in self._tasks:
            by_priority.setdefault(task.priority, []).append(task)

        for priority in sorted(by_priority.keys()):
            elapsed = time.monotonic() - start
            remaining = max(0.1, timeout - elapsed)

            if elapsed >= timeout:
                logger.warning(
                    "Shutdown: timeout reached (%.1fs) — skipping priority %d tasks",
                    timeout, priority,
                )
                break

            tasks = by_priority[priority]
            logger.info(
                "Shutdown: running priority %d — %s (%.1fs remaining)",
                priority, [t.name for t in tasks], remaining,
            )

            # Run same-priority tasks concurrently
            coros = []
            for task in tasks:
                coros.append(self._run_task(task))

            try:
                await asyncio.wait_for(
                    asyncio.gather(*coros, return_exceptions=True),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Shutdown: priority %d tasks timed out after %.1fs",
                    priority, remaining,
                )

        total = time.monotonic() - start
        logger.info("Shutdown: complete in %.1fs", total)

    async def _run_task(self, task: ShutdownTask) -> None:
        """Run a single shutdown task with error handling."""
        try:
            logger.info("Shutdown: stopping %s...", task.name)
            await task.handler(**task.kwargs)
            logger.info("Shutdown: %s stopped", task.name)
        except Exception as exc:
            logger.error("Shutdown: %s failed: %s", task.name, exc)
