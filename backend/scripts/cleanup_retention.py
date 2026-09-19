#!/usr/bin/env python3
"""Preview or apply local NetSecureAI data-retention cleanup.

The command is dry-run by default. Set --apply to delete records and matching
raw uploads older than NETSECURE_RETENTION_DAYS (default: 365).
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
LOCAL_DB = DATA_DIR / "netsecureai.sqlite3"
UPLOADS_DIR = DATA_DIR / "uploads"


def retention_cutoff(days: int, now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
    return (current - timedelta(days=days)).isoformat()


def existing_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def cleanup_local_data(
    database: Path = LOCAL_DB,
    uploads: Path = UPLOADS_DIR,
    days: int = 365,
    apply: bool = False,
) -> dict[str, int | bool]:
    if days < 1:
        raise ValueError("Retention days must be at least 1")
    if not database.exists():
        return {"dry_run": not apply, "analyses": 0, "mappings": 0, "audit_events": 0, "uploads": 0}

    cutoff = retention_cutoff(days)
    counts: dict[str, int | bool] = {"dry_run": not apply, "analyses": 0, "mappings": 0, "audit_events": 0, "uploads": 0}

    with sqlite3.connect(database) as connection:
        tables = existing_tables(connection)
        analysis_ids: list[str] = []
        if "analyses" in tables:
            analysis_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT id FROM analyses WHERE created_at < ?", (cutoff,)
                )
            ]
            counts["analyses"] = len(analysis_ids)
        if "mappings" in tables:
            counts["mappings"] = connection.execute(
                "SELECT count(*) FROM mappings WHERE created_at < ?", (cutoff,)
            ).fetchone()[0]
        if "audit_events" in tables:
            counts["audit_events"] = connection.execute(
                "SELECT count(*) FROM audit_events WHERE timestamp < ?", (cutoff,)
            ).fetchone()[0]

        if apply:
            if "analyses" in tables:
                connection.execute("DELETE FROM analyses WHERE created_at < ?", (cutoff,))
            if "mappings" in tables:
                connection.execute("DELETE FROM mappings WHERE created_at < ?", (cutoff,))
            if "audit_events" in tables:
                connection.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
            connection.commit()

        if apply and uploads.exists():
            for analysis_id in analysis_ids:
                for path in uploads.glob(f"{analysis_id}_*"):
                    path.unlink()
                    counts["uploads"] += 1

    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Apply deletion; otherwise preview only")
    parser.add_argument(
        "--days",
        type=int,
        default=int(os.getenv("NETSECURE_RETENTION_DAYS", "365")),
        help="Retain this many days of data",
    )
    args = parser.parse_args()
    print(cleanup_local_data(days=args.days, apply=args.apply))


if __name__ == "__main__":
    main()
