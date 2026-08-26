# NetSecureAI backend

Run locally from the repository root:

```bash
uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` to exercise the upload, training, and PDF-report endpoints. Data is persisted in `backend/data/netsecureai.sqlite3`, which is intentionally excluded from version control.
