# NetSecureAI backend

Run locally from the repository root:

```bash
uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` to exercise the upload, training, and PDF-report endpoints. Supabase is used when configured; local development falls back to `backend/data/netsecureai.sqlite3` and `backend/data/uploads/`.

Deployment authentication:

```bash
export NETSECURE_API_TOKEN='replace-with-a-secret-token'
```

For user sessions, configure the backend before deployment:

```bash
export NETSECURE_AUTH_SECRET='replace-with-a-long-random-secret'
export NETSECURE_ADMIN_USERNAME='admin'
export NETSECURE_ADMIN_PASSWORD='replace-with-a-strong-password'
export NETSECURE_VIEWER_USERNAME='viewer'
export NETSECURE_VIEWER_PASSWORD='replace-with-a-viewer-password'
export NETSECURE_AUDITOR_USERNAME='auditor'
export NETSECURE_AUDITOR_PASSWORD='replace-with-an-auditor-password'
export NETSECURE_LOGIN_MAX_ATTEMPTS='5'
export NETSECURE_LOGIN_WINDOW_SECONDS='60'
export NETSECURE_CORS_ORIGINS='https://netsecure.example.com'
export NETSECURE_API_RATE_LIMIT='120'
export NETSECURE_API_RATE_WINDOW_SECONDS='60'
```

The frontend login obtains a signed session from `/api/auth/login`. Training mutations require the `admin` role. Keep all values in the deployment secret store rather than committing them.

Set `NETSECURE_CORS_ORIGINS` to a comma-separated allowlist for production. Every API response includes an `X-Request-ID`; clients may provide one to correlate application and server logs.
Set `NETSECURE_API_RATE_LIMIT` to the maximum requests per client IP in the configured window. Leave it unset or `0` for unrestricted local development.
Unhandled API failures are logged as structured JSON with the request ID and return a generic 500 response without exposing exception details.

Local retention cleanup is preview-only by default:

```bash
NETSECURE_RETENTION_DAYS=365 python3 backend/scripts/cleanup_retention.py
NETSECURE_RETENTION_DAYS=365 python3 backend/scripts/cleanup_retention.py --apply
```

The command removes expired analyses, training mappings, audit events, and matching raw uploads only when `--apply` is supplied.

Create and restore local backups:

```bash
python3 backend/scripts/backup_local_data.py backup /secure/backups/netsecureai.tar.gz
python3 backend/scripts/backup_local_data.py restore /secure/backups/netsecureai.tar.gz --force
```
