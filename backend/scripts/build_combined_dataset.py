#!/usr/bin/env python3
"""Build a combined training dataset from local config samples and optional external CSV files.

This consolidates the project's real config corpus with benchmark-derived instruction/response
training examples into a single JSONL-ready dataset for LLM fine-tuning or evaluation.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT = ROOT / "data" / "datasets" / "vendor_configs"
DEFAULT_OUTPUT = ROOT / "data" / "datasets" / "combined_training_dataset.jsonl"


def build_local_dataset(dataset_root: Path | str = DEFAULT_DATASET_ROOT) -> list[dict[str, Any]]:
    root = Path(dataset_root)
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        return []

    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError, TypeError):
        return []

    records: list[dict[str, Any]] = []
    for item in manifest:
        config_file = root / item.get("filename", "")
        if not config_file.exists():
            continue

        snippet = config_file.read_text(errors="replace")
        preview = snippet[:1200].strip().replace("\r", "")
        if not preview:
            preview = "No content was captured for this config sample."

        vendor = str(item.get("vendor") or "Unknown")
        frameworks = item.get("frameworks") or ["CIS Benchmarks"]
        instruction = (
            f"Audit the following {vendor} device configuration for the framework(s) "
            f"{', '.join(frameworks)}. Identify any insecure settings, explain why they matter, "
            "and provide a concise remediation recommendation."
        )
        response = (
            f"This {vendor} configuration sample was evaluated against {', '.join(frameworks)}. "
            "The sample should be checked for insecure management settings, weak SSH policy, missing "
            "logging or NTP controls, and vendor-specific exposure indicators. Use the exact evidence in "
            "the config snippet to justify each finding and propose a safe remediation."
        )

        records.append(
            {
                "source": "local-config",
                "vendor": vendor,
                "product": item.get("vendor") or "Network device",
                "frameworks": frameworks,
                "state": item.get("state") or "unknown",
                "source_hint": item.get("source_hint") or "",
                "filename": item.get("filename"),
                "config_snippet": preview,
                "instruction": instruction,
                "response": response,
            }
        )

    return records


def merge_external_csv(records: list[dict[str, Any]], csv_path: Path | str) -> list[dict[str, Any]]:
    path = Path(csv_path)
    if not path.exists():
        return records

    with path.open("r", newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            instruction = (row.get("instruction") or "").strip()
            response = (row.get("response") or "").strip()
            vendor = (row.get("vendor") or "Unknown").strip()
            if not instruction or not response:
                continue
            records.append(
                {
                    "source": "external-csv",
                    "vendor": vendor,
                    "product": (row.get("product") or vendor).strip(),
                    "frameworks": [row.get("benchmark_version") or "CIS Benchmarks"],
                    "control_id": row.get("control_id") or "",
                    "control_title": row.get("control_title") or "",
                    "assessment_status": row.get("assessment_status") or "",
                    "instruction": instruction,
                    "response": response,
                    "source_url": row.get("source_url") or "",
                    "source_file": row.get("source_file") or "",
                    "cve": row.get("cve") or "",
                    "vulnerability_name": row.get("vulnerability_name") or "",
                }
            )

    return records


def write_jsonl(records: list[dict[str, Any]], output_path: Path | str) -> Path:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a combined vendor-training dataset for NetSecureAI.")
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=DEFAULT_DATASET_ROOT,
        help="Path to the local vendor-config dataset directory.",
    )
    parser.add_argument(
        "--external-csv",
        type=Path,
        default=None,
        help="Optional external CSV file to merge into the training set.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Destination JSONL file for the combined dataset.",
    )
    args = parser.parse_args()

    records = build_local_dataset(args.dataset_root)
    if args.external_csv is not None:
        records = merge_external_csv(records, args.external_csv)

    output_path = write_jsonl(records, args.output)
    print(f"records={len(records)}")
    print(f"output={output_path}")


if __name__ == "__main__":
    main()
