-- Initial schema for NetSecureAI
-- Run against Postgres: psql $DATABASE_URL -f 0001_initial.sql
-- Or run against SQLite: sqlite3 data/netsecureai.sqlite3 < 0001_initial.sql

CREATE TABLE IF NOT EXISTS mappings (
  id TEXT PRIMARY KEY,
  raw_command TEXT NOT NULL,
  vendor TEXT NOT NULL,
  field_name TEXT NOT NULL,
  observed_value TEXT NOT NULL,
  meaning TEXT NOT NULL,
  confidence REAL NOT NULL,
  analysis_id TEXT,
  review_status TEXT NOT NULL DEFAULT 'Approved',
  reviewed_by TEXT,
  reviewed_at TEXT,
  review_reason TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  vendor TEXT NOT NULL,
  framework TEXT NOT NULL,
  created_at TEXT NOT NULL,
  result_json TEXT NOT NULL,
  upload_url TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  "user" TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  device TEXT NOT NULL,
  result TEXT NOT NULL,
  ip_address TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  asset TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  evidence_json TEXT NOT NULL,
  external_id TEXT,
  related_analysis_id TEXT,
  correlations_json TEXT NOT NULL DEFAULT '[]'
);
