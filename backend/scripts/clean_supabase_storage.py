#!/usr/bin/env python3
"""Normalize Supabase rows so JSON data is stored as structured values.

This script updates existing analyses/mappings records that were previously
stored as stringified JSON so the project stores proper values going forward.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from supabase import create_client


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SECRET_KEY")

if not url or not key:
    raise SystemExit("Missing SUPABASE_URL or SUPABASE_SECRET_KEY in backend/.env")

client = create_client(url, key)


def parse_jsonish(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, (dict, list)) else value
        except Exception:
            return value
    return value


updated_analyses = 0
for row in client.table("analyses").select("*").execute().data or []:
    cleaned = parse_jsonish(row.get("result_json"))
    if cleaned != row.get("result_json"):
        client.table("analyses").update({"result_json": cleaned}).eq("id", row["id"]).execute()
        updated_analyses += 1

updated_mappings = 0
for row in client.table("mappings").select("*").execute().data or []:
    cleaned = parse_jsonish(row.get("observed_value"))
    if cleaned != row.get("observed_value"):
        client.table("mappings").update({"observed_value": cleaned}).eq("id", row["id"]).execute()
        updated_mappings += 1

print({
    "analyses_normalized": updated_analyses,
    "mappings_normalized": updated_mappings,
    "bucket": os.getenv("SUPABASE_BUCKET", "configurations"),
})
