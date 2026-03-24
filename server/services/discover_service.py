"""Discover scan service layer (P7-T5).

Async SQLAlchemy queries for managing discover scans.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.discover import DiscoverScan, DiscoverStatus


async def list_discovers(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 25,
    status_filter: str | None = None,
    agent_id: str | None = None,
    search: str | None = None,
) -> tuple[list[DiscoverScan], int]:
    """List discover scans with pagination and optional filters."""
    base = select(DiscoverScan)

    if status_filter:
        base = base.where(DiscoverScan.status == status_filter)
    if agent_id:
        base = base.where(DiscoverScan.agent_id == agent_id)
    if search:
        base = base.where(DiscoverScan.name.ilike(f"%{search}%"))

    # Count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    stmt = base.order_by(DiscoverScan.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return items, total


async def get_discover(db: AsyncSession, discover_id) -> DiscoverScan | None:
    """Get a single discover scan by ID."""
    result = await db.execute(
        select(DiscoverScan).where(DiscoverScan.id == discover_id)
    )
    return result.scalar_one_or_none()


async def create_discover(db: AsyncSession, data: dict) -> DiscoverScan:
    """Create a new discover scan definition."""
    scan = DiscoverScan(
        name=data["name"],
        agent_id=data.get("agent_id"),
        scan_path=data["scan_path"],
        recursive=data.get("recursive", True),
        file_extensions=data.get("file_extensions"),
        path_exclusions=data.get("path_exclusions"),
        status=DiscoverStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    return scan


async def update_discover(db: AsyncSession, scan: DiscoverScan, data: dict) -> DiscoverScan:
    """Update discover scan fields."""
    for key, value in data.items():
        if hasattr(scan, key):
            setattr(scan, key, value)
    await db.flush()
    return scan


async def trigger_discover(db: AsyncSession, scan: DiscoverScan) -> DiscoverScan:
    """Mark a discover scan as running."""
    scan.status = DiscoverStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    await db.flush()
    return scan


async def complete_discover(
    db: AsyncSession,
    scan: DiscoverScan,
    data: dict,
) -> DiscoverScan:
    """Mark a discover scan as completed with results."""
    scan.status = DiscoverStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    scan.files_examined = data.get("files_examined", 0)
    scan.files_scanned = data.get("files_scanned", 0)
    scan.violations_found = data.get("violations_found", 0)
    scan.files_quarantined = data.get("files_quarantined", 0)
    scan.duration_ms = data.get("duration_ms")
    scan.findings = data.get("findings")
    await db.flush()
    return scan
