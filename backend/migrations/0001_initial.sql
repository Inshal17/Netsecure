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
