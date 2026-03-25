"""Database maintenance service (P11-T5).

Handles:
  - Monthly partition creation for incidents table
  - Incident archival (move old incidents to incidents_archive)
  - Index maintenance (REINDEX CONCURRENTLY)
  - Stats reporting for console

Designed to run as a scheduled task via APScheduler or cron.

Usage:
    from server.services.db_maintenance import db_maintenance

    # Run all maintenance tasks
    await db_maintenance.run_all(db)

    # Individual tasks
    await db_maintenance.ensure_partitions(db, months_ahead=3)
    await db_maintenance.archive_old_incidents(db, retention_days=365)
    await db_maintenance.reindex(db)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 365
MONTHS_AHEAD = 3  # Pre-create partitions this many months ahead


class DatabaseMaintenanceService:
    """Manages database partitioning, archival, and index maintenance."""

    async def ensure_partitions(
        self, db: AsyncSession, months_ahead: int = MONTHS_AHEAD
    ) -> list[str]:
        """Ensure monthly partitions exist for the incidents table.

        Creates partitions for the current month plus `months_ahead`
        future months. Skips if partition already exists.

        Returns list of partition names created.
        """
        created = []
        now = datetime.now(timezone.utc)

        for offset in range(-1, months_ahead + 1):
            year = now.year + (now.month + offset - 1) // 12
            month = (now.month + offset - 1) % 12 + 1
            partition_name = f"incidents_{year}_{month:02d}"

            start_date = datetime(year, month, 1)
            if month == 12:
                end_date = datetime(year + 1, 1, 1)
            else:
                end_date = datetime(year, month + 1, 1)

            # Check if partition exists
            check_sql = text(
                "SELECT 1 FROM pg_class WHERE relname = :name"
            )
            result = await db.execute(check_sql, {"name": partition_name})
            if result.scalar():
                continue

            # Create partition
            try:
                create_sql = text(f"""
                    CREATE TABLE IF NOT EXISTS {partition_name}
                    PARTITION OF incidents
                    FOR VALUES FROM ('{start_date.strftime('%Y-%m-%d')}')
                    TO ('{end_date.strftime('%Y-%m-%d')}')
                """)
                await db.execute(create_sql)
                await db.commit()
                created.append(partition_name)
                logger.info("DB maintenance: created partition %s", partition_name)
            except Exception as exc:
                await db.rollback()
                # Partition may already exist or table is not partitioned
                logger.debug(
                    "DB maintenance: partition %s skipped — %s",
                    partition_name, exc,
                )

        return created

    async def archive_old_incidents(
        self, db: AsyncSession, retention_days: int = DEFAULT_RETENTION_DAYS
    ) -> int:
        """Move incidents older than retention period to archive table.

        Returns number of incidents archived.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Ensure archive table exists
        try:
            await db.execute(text("""
                CREATE TABLE IF NOT EXISTS incidents_archive (
                    LIKE incidents INCLUDING ALL
                )
            """))
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.debug("DB maintenance: archive table creation skipped — %s", exc)

        # Move old incidents
        try:
            # Insert into archive
            insert_sql = text("""
                INSERT INTO incidents_archive
                SELECT * FROM incidents
                WHERE created_at < :cutoff
                AND id NOT IN (SELECT id FROM incidents_archive)
            """)
            await db.execute(insert_sql, {"cutoff": cutoff})

            # Count archived
            count_sql = text("""
                SELECT count(*) FROM incidents
                WHERE created_at < :cutoff
            """)
            result = await db.execute(count_sql, {"cutoff": cutoff})
            count = result.scalar() or 0

            # Delete from main table
            if count > 0:
                delete_sql = text("""
                    DELETE FROM incidents
                    WHERE created_at < :cutoff
                """)
                await db.execute(delete_sql, {"cutoff": cutoff})

            await db.commit()
            logger.info(
                "DB maintenance: archived %d incidents older than %d days",
                count, retention_days,
            )
            return count

        except Exception as exc:
            await db.rollback()
            logger.error("DB maintenance: archival failed — %s", exc)
            return 0

    async def reindex(self, db: AsyncSession) -> list[str]:
        """Reindex high-churn indexes on the incidents table.

        Uses REINDEX CONCURRENTLY to avoid locking.
        Returns list of indexes reindexed.
        """
        indexes = [
            "ix_incidents_status",
            "ix_incidents_severity",
            "ix_incidents_created_at",
            "ix_incidents_channel",
            "ix_incidents_policy_name",
        ]
        reindexed = []

        for index_name in indexes:
            try:
                # Check if index exists
                check = text(
                    "SELECT 1 FROM pg_indexes WHERE indexname = :name"
                )
                result = await db.execute(check, {"name": index_name})
                if not result.scalar():
                    continue

                # REINDEX CONCURRENTLY must run outside a transaction
                # In async SQLAlchemy, we execute it directly
                await db.execute(text(f"REINDEX INDEX CONCURRENTLY {index_name}"))
                await db.commit()
                reindexed.append(index_name)
                logger.info("DB maintenance: reindexed %s", index_name)
            except Exception as exc:
                await db.rollback()
                logger.debug(
                    "DB maintenance: reindex %s skipped — %s",
                    index_name, exc,
                )

        return reindexed

    async def get_stats(self, db: AsyncSession) -> dict:
        """Get database maintenance stats for the console."""
        stats: dict = {
            "partitions": [],
            "partition_count": 0,
            "archive_row_count": 0,
            "incidents_row_count": 0,
            "last_maintenance": None,
        }

        try:
            # Count partitions
            result = await db.execute(text("""
                SELECT relname FROM pg_class
                WHERE relname LIKE 'incidents_%'
                AND relkind = 'r'
                ORDER BY relname
            """))
            partitions = [row[0] for row in result.fetchall()]
            stats["partitions"] = partitions
            stats["partition_count"] = len(partitions)
        except Exception:
            pass

        try:
            # Count archive rows
            result = await db.execute(text(
                "SELECT count(*) FROM incidents_archive"
            ))
            stats["archive_row_count"] = result.scalar() or 0
        except Exception:
            pass  # Table may not exist

        try:
            # Count active incidents
            result = await db.execute(text(
                "SELECT count(*) FROM incidents"
            ))
            stats["incidents_row_count"] = result.scalar() or 0
        except Exception:
            pass

        return stats

    async def run_all(
        self,
        db: AsyncSession,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        months_ahead: int = MONTHS_AHEAD,
    ) -> dict:
        """Run all maintenance tasks and return summary."""
        logger.info("DB maintenance: starting full maintenance run")

        partitions = await self.ensure_partitions(db, months_ahead)
        archived = await self.archive_old_incidents(db, retention_days)
        reindexed = await self.reindex(db)
        stats = await self.get_stats(db)

        summary = {
            "partitions_created": partitions,
            "incidents_archived": archived,
            "indexes_reindexed": reindexed,
            "stats": stats,
        }
        logger.info("DB maintenance: complete — %s", summary)
        return summary


# Singleton
db_maintenance = DatabaseMaintenanceService()
