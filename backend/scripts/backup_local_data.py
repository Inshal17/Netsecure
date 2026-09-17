#!/usr/bin/env python3
"""Create or restore a local NetSecureAI backup archive.

Backups contain a consistent SQLite snapshot, raw uploads, and a manifest.
Restore refuses to overwrite existing targets unless --force is supplied.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
LOCAL_DB = DATA_DIR / "netsecureai.sqlite3"
UPLOADS_DIR = DATA_DIR / "uploads"


def backup_local_data(
    archive: Path,
    database: Path = LOCAL_DB,
    uploads: Path = UPLOADS_DIR,
) -> dict[str, str | int]:
    if not database.exists():
        raise FileNotFoundError(f"Database not found: {database}")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        snapshot = staging / "netsecureai.sqlite3"
        with sqlite3.connect(database) as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database": "netsecureai.sqlite3",
            "uploads": "uploads",
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        if uploads.exists():
            shutil.copytree(uploads, staging / "uploads")
        else:
            (staging / "uploads").mkdir()
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(snapshot, arcname="netsecureai.sqlite3")
            bundle.add(staging / "manifest.json", arcname="manifest.json")
            bundle.add(staging / "uploads", arcname="uploads")
    return {"archive": str(archive), "uploads": sum(1 for _ in uploads.iterdir()) if uploads.exists() else 0}


def restore_local_data(
    archive: Path,
    database: Path = LOCAL_DB,
    uploads: Path = UPLOADS_DIR,
    force: bool = False,
) -> dict[str, str | int]:
    if not archive.exists():
        raise FileNotFoundError(f"Backup archive not found: {archive}")
    if not force and (database.exists() or uploads.exists()):
        raise FileExistsError("Restore targets exist; use --force to overwrite them")
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(staging, filter="data")
        manifest = json.loads((staging / "manifest.json").read_text())
        if manifest.get("database") != "netsecureai.sqlite3" or manifest.get("uploads") != "uploads":
            raise ValueError("Unsupported backup manifest")
        database.parent.mkdir(parents=True, exist_ok=True)
        uploads.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staging / "netsecureai.sqlite3", database)
        if uploads.exists():
            shutil.rmtree(uploads)
        shutil.copytree(staging / "uploads", uploads)
    return {"database": str(database), "uploads": sum(1 for _ in uploads.iterdir())}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    backup = subcommands.add_parser("backup")
    backup.add_argument("archive", type=Path)
    restore = subcommands.add_parser("restore")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.command == "backup":
        print(backup_local_data(args.archive))
    else:
        print(restore_local_data(args.archive, force=args.force))


if __name__ == "__main__":
    main()
