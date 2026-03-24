"""In-memory command queue for delivering commands to agents via heartbeat.

Commands are queued by REST endpoints and delivered on the next agent
heartbeat. Each command is delivered once and then removed.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class AgentCommand:
    command_type: str
    parameters: dict[str, str] = field(default_factory=dict)


class CommandQueue:
    """Thread-safe per-agent command queue."""

    def __init__(self):
        self._lock = threading.Lock()
        self._queues: dict[str, list[AgentCommand]] = defaultdict(list)

    def enqueue(self, agent_id: str | None, command: AgentCommand):
        """Queue a command. If agent_id is None, broadcast to all agents."""
        with self._lock:
            if agent_id:
                self._queues[agent_id].append(command)
            else:
                # Broadcast: store under special key
                self._queues["__broadcast__"].append(command)

    def drain(self, agent_id: str) -> list[AgentCommand]:
        """Return and remove all pending commands for the given agent."""
        with self._lock:
            cmds = self._queues.pop(agent_id, [])
            # Also include broadcast commands
            broadcast = self._queues.pop("__broadcast__", [])
            return cmds + broadcast


# Singleton
_queue = CommandQueue()


def get_command_queue() -> CommandQueue:
    return _queue
