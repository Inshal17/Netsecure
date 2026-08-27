# NetSecureAI backend

Run locally from the repository root:

```bash
uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` to exercise the upload, training, and PDF-report endpoints. Supabase is used when configured; local development falls back to `backend/data/netsecureai.sqlite3` and `backend/data/uploads/`.
