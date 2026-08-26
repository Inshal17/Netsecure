# Demo Notes

Checklist for a demo:

- Start backend: `uvicorn backend.main:app --reload --port 8000`
- Start frontend: `npm run dev`
- Upload a sample Cisco config file via Configuration → Uploaded Files
- Show Reports page: select a report, the preview shows findings and remediation suggestions
- Show Training: teach NetSecureAI a new mapping and demonstrate it applying to stored analyses

Talking points:
- Default developer setup uses SQLite + local uploads for simplicity.
- Production deployments should use Postgres + S3 (see docs/storage.md).
- The system preserves original uploads for auditability and re-processing.
