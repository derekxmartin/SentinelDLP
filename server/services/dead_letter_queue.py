"""Dead letter queue service (P11-T4).

Handles failed operations:
  - Store failures with original payload and error details
  - Automatic retry with exponential backoff (max 3 attempts)
  - Manual retry/dismiss from console
  - Query for DLQ entries by type, status

Usage:
    from server.services.dead_letter_queue import dlq_service

    # Enqueue a failed detection
    await dlq_service.enqueue(
        db=db,
        operation_type="detection",
        source="api",
        request_payload={"text": "..."},
        error=exc,
    )

    # Retry an entry
    await dlq_service.retry(db, entry_id)

    # Dismiss an entry
    await dlq_service.dismiss(db, entry_id)
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.dead_letter import DeadLetterEntry

logger = logging.getLogger(__name__)

# Exponential backoff: 30s, 120s, 480s
BACKOFF_BASE = 30
BACKOFF_MULTIPLIER = 4


class DeadLetterQueueService:
    """Manages the dead letter queue for failed operations."""

    async def enqueue(
        self,
        db: AsyncSession,
        operation_type: str,
        source: str,
        request_payload: dict,
        error: Exception | str,
        max_retries: int = 3,
    ) -> DeadLetterEntry:
        """Add a failed operation to the DLQ."""
        error_message = str(error)
        error_type = type(error).__name__ if isinstance(error, Exception) else "str"

        # Truncate payload if too large (> 1MB)
        import json
        payload_str = json.dumps(request_payload, default=str)
        if len(payload_str) > 1_000_000:
            request_payload = {
                "_truncated": True,
                "_original_size": len(payload_str),
                "_preview": payload_str[:10_000],
            }

        entry = DeadLetterEntry(
            operation_type=operation_type,
            source=source,
            request_payload=request_payload,
            error_message=error_message[:5000],  # Cap error message
            error_type=error_type[:200],
            max_retries=max_retries,
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)

        logger.warning(
            "DLQ: enqueued %s from %s — %s: %s (id=%s)",
            operation_type, source, error_type, error_message[:200], entry.id,
        )
        return entry

    async def list_entries(
        self,
        db: AsyncSession,
        operation_type: str | None = None,
        include_dismissed: bool = False,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[DeadLetterEntry], int]:
        """List DLQ entries with optional filters."""
        stmt = select(DeadLetterEntry)

        if operation_type:
            stmt = stmt.where(DeadLetterEntry.operation_type == operation_type)
        if not include_dismissed:
            stmt = stmt.where(DeadLetterEntry.is_dismissed == False)  # noqa: E712

        # Count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await db.execute(count_stmt)).scalar() or 0

        # Paginate
        stmt = stmt.order_by(DeadLetterEntry.created_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(stmt)
        entries = list(result.scalars().all())

        return entries, total

    async def get_entry(self, db: AsyncSession, entry_id: UUID) -> DeadLetterEntry | None:
        """Get a single DLQ entry."""
        result = await db.execute(
            select(DeadLetterEntry).where(DeadLetterEntry.id == entry_id)
        )
        return result.scalar_one_or_none()

    async def retry(self, db: AsyncSession, entry_id: UUID) -> DeadLetterEntry | None:
        """Mark an entry for retry (increment counter, update timestamp).

        Returns the updated entry, or None if not found / already permanent.
        The actual retry execution is handled by the caller.
        """
        entry = await self.get_entry(db, entry_id)
        if not entry or entry.is_permanent or entry.is_dismissed:
            return None

        entry.retry_count += 1
        entry.last_retry_at = datetime.now(timezone.utc)

        if entry.retry_count >= entry.max_retries:
            entry.is_permanent = True
            logger.warning(
                "DLQ: entry %s exhausted retries (%d/%d) — marked permanent",
                entry_id, entry.retry_count, entry.max_retries,
            )

        await db.commit()
        await db.refresh(entry)
        return entry

    async def dismiss(self, db: AsyncSession, entry_id: UUID) -> DeadLetterEntry | None:
        """Dismiss a DLQ entry (operator acknowledgment)."""
        entry = await self.get_entry(db, entry_id)
        if not entry:
            return None

        entry.is_dismissed = True
        await db.commit()
        await db.refresh(entry)

        logger.info("DLQ: entry %s dismissed", entry_id)
        return entry

    async def get_stats(self, db: AsyncSession) -> dict:
        """Get DLQ statistics for the console dashboard."""
        total_stmt = select(func.count()).where(
            DeadLetterEntry.is_dismissed == False  # noqa: E712
        )
        total = (await db.execute(total_stmt)).scalar() or 0

        pending_stmt = select(func.count()).where(
            DeadLetterEntry.is_dismissed == False,  # noqa: E712
            DeadLetterEntry.is_permanent == False,  # noqa: E712
        )
        pending = (await db.execute(pending_stmt)).scalar() or 0

        permanent_stmt = select(func.count()).where(
            DeadLetterEntry.is_permanent == True,  # noqa: E712
            DeadLetterEntry.is_dismissed == False,  # noqa: E712
        )
        permanent = (await db.execute(permanent_stmt)).scalar() or 0

        return {
            "total": total,
            "pending_retry": pending,
            "permanent_failure": permanent,
        }


# Singleton
dlq_service = DeadLetterQueueService()
