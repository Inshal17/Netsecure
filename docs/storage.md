# Storage and Production Configuration

This document describes how to configure production storage for NetSecureAI
including Postgres for the primary database and S3-compatible object storage
for uploaded configuration archives.

Environment variables

- `DATABASE_URL` — SQLAlchemy/psycopg2 style URL, e.g. `postgresql://user:pass@db.example.com:5432/netsecure`
- `S3_BUCKET` — name of the S3 bucket to use for uploaded raw files
- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` — credentials for S3-compatible storage
- `S3_ENDPOINT` — optional custom endpoint for MinIO or other S3-compatible providers

Local developer defaults

- By default the app uses SQLite at `backend/data/netsecureai.sqlite3` and local
  uploads in `backend/data/uploads/`.

Installing production deps

Install optional production packages in your Python environment:

```bash
pip install psycopg2-binary boto3 alembic
```

Running migrations

If you have Alembic available and configured, run:

```bash
alembic upgrade head
```

Otherwise you can use the built-in fallback which creates the schema safely:

```bash
python3 backend/scripts/run_alembic.py
```

Testing connectivity

Use the included helper to validate DB and S3 settings (non-destructive):

```bash
python3 backend/scripts/test_storage.py
```

Security notes

- Avoid embedding credentials in version control. Use environment variables or a
  secrets manager in CI/CD.
- For S3 consider enabling server-side encryption and restricted IAM policies.
# Storage Design (Postgres + S3)

This repo ships with a local SQLite database for development and a `data/uploads/` folder for raw configuration files.

Recommended production setup:

- Use Postgres for relational data (analyses, mappings).
  - Run migrations using Alembic (recommended). Create an `alembic` directory and an initial revision that creates the `mappings` and `analyses` tables.
  - Set `DATABASE_URL=postgresql://user:password@db-host:5432/netsecure` in your environment.
- Use an S3-compatible object store for raw uploaded configuration files.
  - Configure `S3_BUCKET` and optional `S3_ENDPOINT` environment variables.
  - Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the environment or use an IAM role.

How this repo supports both:

- `backend/main.py` will use SQLite by default. If `DATABASE_URL` points to Postgres and `psycopg2` is installed, Postgres will be used.
- Uploaded files are written to S3 when `S3_BUCKET` is set and `boto3` is available; otherwise they are stored under `data/uploads/`.

Migration notes:

- The code includes a small migration helper that will add an `upload_url` column to the existing `analyses` table if it is missing.
- For production, use Alembic migrations instead of relying on runtime ALTER statements.
- The code includes a small migration helper that will add an `upload_url` column to the existing `analyses` table if it is missing.

Applying migrations without Alembic
----------------------------------

If you prefer not to install Alembic in a quick environment, an equivalent SQL migration is provided at `backend/migrations/0001_initial.sql`.

Apply to Postgres:

```bash
export DATABASE_URL=postgresql://user:pass@host:5432/netsecure
psql "$DATABASE_URL" -f backend/migrations/0001_initial.sql
```

Apply to SQLite (local dev):

```bash
sqlite3 data/netsecureai.sqlite3 < backend/migrations/0001_initial.sql
```

Example `.env` entries can be found in `.env.example`.
