"""Scheduled archival job (P11-T5).

Runs database maintenance tasks on a schedule:
  - Ensure monthly partitions exist
  - Archive old incidents (> retention period)
  - Reindex high-churn indexes

Can be run standalone or integrated with APScheduler.

Usage:
    # Standalone
    python -m server.tasks.archive_job

    # With custom retention
    python -m server.tasks.archive_job --retention-days 180
"""

from __future__ import annotations

import argparse
import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def run_maintenance(retention_days: int = 365) -> None:
    """Execute all database maintenance tasks."""
    from server.database import async_session_factory
    from server.services.db_maintenance import db_maintenance

    async with async_session_factory() as db:
        summary = await db_maintenance.run_all(db, retention_days=retention_days)

    logger.info("Maintenance complete:")
    logger.info("  Partitions created: %s", summary["partitions_created"])
    logger.info("  Incidents archived: %d", summary["incidents_archived"])
    logger.info("  Indexes reindexed: %s", summary["indexes_reindexed"])
    logger.info("  Active incidents: %d", summary["stats"]["incidents_row_count"])
    logger.info("  Archived incidents: %d", summary["stats"]["archive_row_count"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Run database maintenance")
    parser.add_argument(
        "--retention-days", type=int, default=365,
        help="Archive incidents older than this many days (default: 365)",
    )
    args = parser.parse_args()

    asyncio.run(run_maintenance(args.retention_days))


if __name__ == "__main__":
    main()
