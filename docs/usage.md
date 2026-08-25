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
- You can download raw uploads from the Uploaded Files table and re-run analyses.
