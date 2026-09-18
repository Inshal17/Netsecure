# NetSecureAI — Multi-Vendor Network Security Compliance Auditor

NetSecureAI is a full-stack prototype for auditing network device configuration exports against security baselines. It ingests vendor-specific configuration files, normalizes them into a common Security Baseline Model, evaluates them against multiple frameworks, and produces evidence-based findings, risk scoring, remediation guidance, and report exports.

This project is designed around the NTRO-style requirement for an AI-assisted, multi-vendor network security compliance auditor and includes a working prototype with backend automation, frontend dashboarding, security controls mapping, and a training pipeline for unknown device syntax.

## Project scope

The current implementation covers:

- Vendor and device-family detection for major network operating systems
- Configuration parsing and normalization into a baseline model
- Crosswalk mapping to CIS Benchmarks, NIST SP 800-53, DISA STIG, and ISO/IEC 27001
- Security findings with severity, evidence, and remediation suggestions
- Dashboard and report views for compliance results
- Training mappings for unknown or vendor-specific commands
- Audit and health endpoints for API validation and operational monitoring
- Local and Supabase-backed storage support
- PDF report generation and export flows

## Current implemented workflow

```text
Upload config file
  → vendor detection
  → syntax parsing
  → security baseline normalization
  → applicable control evaluation
  → findings + severity + remediation
  → dashboard/report export
```

## Supported vendors and parsing coverage

The parser currently recognizes and evaluates these vendor syntaxes with deterministic rules and evidence:

- Cisco IOS-style configuration
- Juniper Junos-like configuration
- Arista EOS configuration
- Fortinet configuration
- SONiC configuration
- Palo Alto configuration
- HPE Aruba configuration
- Huawei configuration
- Check Point configuration

The `/api/vendors` endpoint and Frameworks page expose the support matrix. Planned vendor and cloud-platform families are explicitly marked as AI-assisted mapping rather than being presented as fully supported.

## Framework coverage

The project includes control mappings for:

- CIS Benchmarks
- NIST SP 800-53
- DISA STIG
- ISO/IEC 27001

The framework metadata is exposed through the backend API and surfaced in the frontend as visible control families and source references.

## Security baseline model

The normalization layer maps device commands into a common security model with fields such as:

- telnet_disabled
- http_disabled
- ssh_version
- logging_enabled
- ntp_configured
- aaa_enabled
- snmp_secure
- idle_timeout
- plus additional vendor-specific fields where applicable

These control fields are evaluated with evidence and mapped to compliance frameworks.

## Key features implemented

### Backend

- FastAPI REST service
- configuration upload and analysis endpoints
- local SQLite persistence and optional Supabase integration
- training mapping API
- compliance evaluation engine
- evidence hashing and reproducible output
- health, dashboard, findings, reports, and frameworks APIs
- vendor support matrix and explainable mapping suggestion APIs
- unknown-command training queue sourced from saved analyses
- PDF report generation
- authentication and authorization support
- rate limiting and request identity tracking

### Frontend

- dashboard with summary cards
- configuration upload workflow
- analysis selection and result inspection
- findings view with filtering
- remediation view
- framework overview
- report export actions
- training page for unknown command mapping
- vendor support matrix for implementation and review status

### Data and mapping logic

The project includes:

- evidence-based compliance findings
- deterministic rule evaluation
- heuristic suggestions for unknown vendor commands
- explainable mapping suggestions that require reviewer approval
- approval-triggered re-analysis for previously saved configurations
- stored training mappings that can be reused across re-analysis
- per-control mapping provenance and confidence values

## Project structure

```text
Netsecure/
├── backend/
│   ├── main.py
│   ├── tests/
│   ├── scripts/
│   ├── alembic/
│   ├── data/
│   └── README.md
├── frontend/
│   └── src/
├── data/
│   └── configs/
├── docs/
├── README.md
├── package.json
├── vite.config.ts
├── index.html
└── test-config.cfg
```

## Local setup

Requirements:

- Python 3.11+
- Node.js 20+
- npm

### Backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
PYTHONPATH=. pytest -q backend/tests
python3 -m uvicorn backend.main:app --reload --port 8000
```

### Frontend

```bash
npm install
npm run dev
```

Access the app at:

- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs

## Environment variables

Key configuration values used by the app include:

- NETSECURE_AUTH_SECRET
- NETSECURE_ADMIN_USERNAME
- NETSECURE_ADMIN_PASSWORD
- NETSECURE_VIEWER_USERNAME / PASSWORD
- NETSECURE_AUDITOR_USERNAME / PASSWORD
- NETSECURE_API_TOKEN
- NETSECURE_CORS_ORIGINS
- NETSECURE_API_RATE_LIMIT
- NETSECURE_API_RATE_WINDOW_SECONDS
- SUPABASE_URL
- SUPABASE_SECRET_KEY
- SUPABASE_BUCKET

## Verification status

The project was validated with real checks:

- Backend test suite passed with:
  `PYTHONPATH=. pytest -q backend/tests`
  Result: 32 passed

- Frontend production build passed with:
  `npm run build -- --emptyOutDir`
  Result: successful Vite build completed

This confirms the current prototype is functionally working and stable enough for demo and local validation.

## Blockchain extension plan

The current implementation is already a working compliance prototype. The next major enhancement is to add blockchain-based integrity and auditability for compliance evidence.

Recommended direction:

- permissioned blockchain network such as Hyperledger Fabric or Quorum
- store only hashes and metadata on-chain, not raw config data
- anchor analysis records, findings, reports, and training mappings
- enable tamper detection and immutable audit validation
- expose verification status in the UI and report exports

This blockchain layer should complement the compliance engine rather than replace it.

## NTRO-grade prototype maturity

The project currently satisfies the core problem statement as a strong prototype and demo system:

- device configuration audit workflow exists
- multi-vendor scanner exists
- framework mapping exists
- evidence and findings exist
- dashboard and reporting exist
- training and learning pipeline exists

However, for a fully NTRO-grade production-level solution, the next major workstreams are:

1. stronger authoritative framework validation and control review
2. broader vendor coverage and richer parsing rules
3. AI-assisted mapping confidence and explainability improvements
4. blockchain-backed evidence integrity
5. hardened enterprise security and governance controls
6. final deployment-grade documentation and operational readiness

## Safety and governance note

Use sanitized configuration exports only. The ingestion path includes some redaction and strict handling for common secret patterns, but it should not be treated as a complete production secret-management or compliance platform without additional governance controls, retention policies, and deployment hardening.

## Summary

NetSecureAI is an operational proof-of-concept for AI-assisted network compliance auditing. It demonstrates the full cycle from configuration upload through parsing, normalization, framework evaluation, findings, remediation, and export. It is already suitable as a prototype and can be advanced further into an NTRO-grade compliance and evidence-integrity platform with the planned blockchain and governance enhancements.
