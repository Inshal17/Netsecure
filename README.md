# NetSecureAI — Multi-Vendor Network Security Compliance Auditor

NetSecureAI ingests network device configuration exports, converts them to a vendor-neutral Security Baseline Model, evaluates selected compliance controls, and produces actionable remediation and PDF evidence.

## Implemented workflow

```text
Config upload → vendor detection → line-level parsing
                              ├─ known syntax → normalized baseline
                              └─ unknown syntax → training mapping store → normalized baseline
Normalized baseline → CIS/NIST/STIG/ISO control evaluation → findings + confidence → PDF report
```

The initial deterministic parsers support Cisco IOS-style, Arista EOS, Fortinet, Juniper, and SONiC configuration syntax. Unknown syntax can be mapped to one of the Security Baseline Model fields in the Training screen; that mapping is stored in SQLite and used on subsequent analyses without a backend change.

## Local setup

Requirements: Python 3.11+ and Node.js 20+.

```bash
# Terminal 1 — API
python3 -m uvicorn backend.main:app --reload --port 8000

# Terminal 2 — dashboard
npm install
npm run dev
```

Open `http://localhost:5173`. The API documentation is at `http://localhost:8000/docs`.

For a deployed API, set `NETSECURE_AUTH_SECRET`, `NETSECURE_ADMIN_USERNAME`, and `NETSECURE_ADMIN_PASSWORD` in the backend environment. The frontend login obtains a signed session from the backend; API requests then use that session as a bearer token. `NETSECURE_API_TOKEN` and matching `VITE_API_TOKEN` remain available for service-to-service access. Keep both auth modes disabled only for local demo mode.

## Demo

1. Upload [sample insecure Cisco config](data/configs/cisco-insecure.cfg) in **Configurations**.
2. Select **CIS Benchmarks** and start analysis.
3. Review actual normalized findings and the per-control confidence source.
4. Open the Training page and map an unfamiliar line to an SBM field.
5. Re-upload the same syntax and observe it being classified as `trained_mapping`.
6. Download the PDF through `GET /api/analyses/{analysis_id}/report.pdf` (the API docs expose this immediately; dashboard report wiring is the next UI increment).

## Security Baseline Model fields

`telnet_disabled`, `http_disabled`, `ssh_version`, `logging_enabled`, `ntp_configured`, `aaa_enabled`, `snmp_secure`, and `idle_timeout`.

Controls are intentionally declarative in the backend catalogue and cross-mapped into CIS, NIST SP 800-53, DISA STIG, and ISO/IEC 27001 result IDs. Expand each framework with reviewed, versioned source controls before describing the product as certified compliance coverage.

## Safety note

Use sanitized configuration exports only. The ingestion path redacts common password, secret, community, and key values before analysis persistence, but this is a demo safeguard—not a replacement for production secrets management, encryption, RBAC, and retention policy.
