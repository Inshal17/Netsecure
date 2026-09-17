# Usage & Quickstart

Run the backend in development:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python3 backend/scripts/run_alembic.py
uvicorn backend.main:app --reload --port 8000
```

Run the frontend:

```bash
npm ci
npm run dev
```

Uploading and scanning

- Open the UI at http://localhost:5175/configuration and drag/drop a config file.
- Multiple configuration files can be selected and analyzed as one batch.
- The analyzer detects Cisco, Arista, Fortinet, Juniper, and SONiC syntax, records line-level evidence, and marks unknown lines for training.
- You can download raw uploads from the Uploaded Files table and re-run analyses.
- Training mappings are persisted and can be applied by re-analyzing stored local uploads or Supabase objects.

For deployment, set `NETSECURE_AUTH_SECRET`, `NETSECURE_ADMIN_USERNAME`, and `NETSECURE_ADMIN_PASSWORD` for signed user sessions. Training mutations require an administrator role. `NETSECURE_API_TOKEN` with matching `VITE_API_TOKEN` is also supported for service-to-service requests, while `/api/health` remains available for service probes.

Optional `NETSECURE_VIEWER_USERNAME`/`NETSECURE_VIEWER_PASSWORD` and `NETSECURE_AUDITOR_USERNAME`/`NETSECURE_AUDITOR_PASSWORD` variables provision read-only role accounts.

Login brute-force protection defaults to five attempts per 60-second window. Tune it with `NETSECURE_LOGIN_MAX_ATTEMPTS` and `NETSECURE_LOGIN_WINDOW_SECONDS` when needed.

For production CORS, set `NETSECURE_CORS_ORIGINS` to a comma-separated list of trusted frontend origins. API responses include `X-Request-ID` for request tracing.

General API rate limiting is disabled by default. Configure `NETSECURE_API_RATE_LIMIT` and `NETSECURE_API_RATE_WINDOW_SECONDS` for deployment protection.

Unhandled API errors return a generic response containing the request ID. Use that ID to correlate the client error with the structured backend log.
