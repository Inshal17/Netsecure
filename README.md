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

## Local dataset and AI support workflow

The project also ships with a reusable training-data workflow for AI-assisted interpretation and benchmark preparation:

- `backend/scripts/build_combined_dataset.py` merges local vendor config samples with optional external CSV examples into a single JSONL dataset
- the generated output is stored under `data/datasets/combined_training_dataset.jsonl`
- this dataset is intended for local LLM benchmarking, explanation generation, and model evaluation support rather than as the sole source of compliance truth

This keeps the rule-based compliance engine authoritative while still producing a useful AI training corpus.

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
- vendor-aware platform version detection with applicability warnings
- deterministic quality benchmark API for vendor, control, evidence, and version metrics
- normalized Wazuh, Suricata, and Zeek security-event ingestion APIs
- persisted telemetry events with explainable asset/control correlation
- unified telemetry-backed findings with transparent correlation confidence scores
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
- grounded mapping context with framework references and source URLs
- offline RAG retrieval over curated framework and vendor-security knowledge
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

Note: the active Vite app root is `frontend/`; the root-level `src/`, `public/`, and `index.html` files are legacy leftovers and are not used by the active build. This is intentional for the current project layout but should be cleaned up in a future repository refactor.

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
- NETSECURE_LLM_PROVIDER (defaults to `offline`; supports `gemini` and `openai-compatible`)
- NETSECURE_LLM_ENDPOINT (optional provider endpoint)
- NETSECURE_LLM_API_KEY (optional; never exposed to the frontend)
- NETSECURE_LLM_MODEL (optional model label for audit metadata)

The mapping assistant is offline-safe by default. Remote LLM use is opt-in, accepts only validated structured JSON, and falls back to the local heuristic provider when credentials are absent or the response is unavailable or invalid. Configuration commands and retrieved knowledge are sent to a remote endpoint only when `NETSECURE_LLM_PROVIDER` is explicitly set to `gemini`, `remote`, or `openai-compatible`.

## Verification status

The project was validated with fresh checks on the current working tree:

- Backend tests passed with:
  `PYTHONPATH=. pytest -q backend/tests`
  Result: 52 passed

- Frontend production build passed with:
  `npm run build -- --emptyOutDir`
  Result: successful Vite production build completed

- Frontend lint check completed with warnings only, no blocking errors:
  `npm run lint`

This confirms the current prototype is functionally working and stable enough for demo, validation, and local deployment testing.

## Prototype readiness controls

The current implementation is intentionally designed as a validated prototype with explicit production boundaries. It is not presented as a full enterprise deployment but as a working compliance auditor that includes:

- local-first production storage defaults with optional remote storage integration
- blockchain-backed evidence attestation as an integrity extension rather than a full ledger deployment
- offline-safe mapping logic with remote LLM fallback only when configured
- a curated multi-vendor dataset that is sufficient for benchmarking and demo work without claiming enterprise-scale corpus maturity

These controls are surfaced through the API in `/api/architecture/status`, `/api/dataset/summary`, and `/api/ai/status` to make the solution’s maturity posture transparent.

## Team B completion status

The Team B scope is complete for the prototype phase and covers the key governance, compliance, telemetry, and operational hardening workstreams:

- secure default configuration and governance exposure
- retention cleanup and local backup workflows
- admin-only governance actions and audit logging
- telemetry/event normalization and correlation
- training queue, explainable mapping suggestions, and mapping provenance
- benchmark and quality checks for readiness validation
- frontend settings and governance visibility
- local SQLite fallback behavior for audit/security operations

At this point, the remaining work is primarily production-hardening and scale-up rather than missing core functionality.

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

NetSecureAI is an operational proof-of-concept for AI-assisted network compliance auditing. It demonstrates the full cycle from configuration upload through parsing, normalization, framework evaluation, findings, remediation, and export. The current repository includes a rule-driven engine, vendor-aware detection and parsing, explainable AI-assisted mapping, security telemetry correlation, dataset generation, and a blockchain-integrity extension.

The project is suitable as a prototype and aligns with the original NTRO-style objective while staying honest about its current maturity: the deterministic engine is the production-grade core, and the AI and blockchain components are best understood as prototype support layers that add explainability and evidence integrity rather than replacing the compliance logic itself.
