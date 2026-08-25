"""NetSecureAI local API.

This is intentionally upload-first: it accepts sanitized configuration exports,
normalizes them into a vendor-neutral baseline, evaluates declarative controls,
and persists administrator training mappings without requiring a redeploy.
"""
from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "netsecureai.sqlite3"
UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Environment-driven configuration
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite://{DB_PATH}")
S3_BUCKET = os.getenv("S3_BUCKET")
S3_ENDPOINT = os.getenv("S3_ENDPOINT")

# Optional dependencies
_psycopg2 = None
_boto3 = None
try:
    import psycopg2
    import psycopg2.extras
    _psycopg2 = psycopg2
except Exception:
    _psycopg2 = None

try:
    import boto3
    _boto3 = boto3
except Exception:
    _boto3 = None

app = FastAPI(title="NetSecureAI API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    # Allow common local dev origins (Vite may run on 5173/5174/5175)
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174", "http://localhost:5175", "http://127.0.0.1:5175"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DBConnection:
    """Light wrapper to provide a sqlite-like API backed by sqlite3 or psycopg2."""
    def __init__(self, conn, cursor=None, postgres=False):
        self._conn = conn
        self._cursor = cursor
        self.postgres = postgres

    def execute(self, sql, params=None):
        if self.postgres and _psycopg2:
            cur = self._conn.cursor(cursor_factory=_psycopg2.extras.RealDictCursor)
        else:
            cur = self._conn.cursor()
        if params:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        return cur

    def executescript(self, script: str):
        if self.postgres:
            # split naive script into statements
            for stmt in script.split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                self._conn.cursor().execute(stmt)
            self._conn.commit()
        else:
            # sqlite connection supports executescript directly
            self._conn.executescript(script)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.postgres:
                self._conn.commit()
            else:
                self._conn.commit()
        finally:
            try:
                self._conn.close()
            except Exception:
                pass


def db():
    """Return a DBConnection. Uses SQLite by default; if DATABASE_URL indicates Postgres and psycopg2 is available, uses that."""
    if DATABASE_URL.startswith("postgres") or DATABASE_URL.startswith("postgresql"):
        if not _psycopg2:
            raise RuntimeError("psycopg2 is required for Postgres DATABASE_URL but it's not installed")
        conn = _psycopg2.connect(DATABASE_URL)
        return DBConnection(conn, postgres=True)
    # default sqlite
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return DBConnection(conn, postgres=False)


def init_db() -> None:
        # Create tables in a way compatible with both SQLite and Postgres
        ddl = (
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    id TEXT PRIMARY KEY, raw_command TEXT NOT NULL, vendor TEXT NOT NULL,
                    field_name TEXT NOT NULL, observed_value TEXT NOT NULL,
                    meaning TEXT NOT NULL, confidence REAL NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY, filename TEXT NOT NULL, vendor TEXT NOT NULL,
                    framework TEXT NOT NULL, created_at TEXT NOT NULL, result_json TEXT NOT NULL, upload_url TEXT
                );
                """
        )
        with db() as connection:
                connection.executescript(ddl)
                # Ensure `upload_url` column exists in case the DB was created before this change
                try:
                        if getattr(connection, 'postgres', False):
                                cur = connection.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'analyses' AND table_schema = 'public'")
                                cols = [r['column_name'] for r in cur.fetchall()]
                                if 'upload_url' not in cols:
                                        connection.execute('ALTER TABLE analyses ADD COLUMN upload_url TEXT')
                        else:
                                cur = connection.execute("PRAGMA table_info(analyses)")
                                cols = [r['name'] for r in cur.fetchall()]
                                if 'upload_url' not in cols:
                                        connection.execute("ALTER TABLE analyses ADD COLUMN upload_url TEXT")
                except Exception:
                        # non-fatal migration helper
                        pass


@app.on_event("startup")
def startup() -> None:
    init_db()
    # If using Postgres, check connectivity and warn if driver missing
    if DATABASE_URL.startswith('postgres') or DATABASE_URL.startswith('postgresql'):
        if not _psycopg2:
            print('WARNING: DATABASE_URL points to Postgres but psycopg2 is not installed. Install psycopg2 to enable Postgres support.')
        else:
            try:
                conn = _psycopg2.connect(DATABASE_URL)
                conn.close()
                print('Postgres connectivity OK')
            except Exception as e:
                print('WARNING: Could not connect to Postgres:', str(e))


class TrainingMapping(BaseModel):
    raw_command: str = Field(min_length=1, max_length=2000)
    vendor: str = "Unknown"
    field_name: str = Field(min_length=1, max_length=80)
    observed_value: Any
    meaning: str = Field(min_length=1, max_length=500)
    confidence: float = Field(default=92, ge=0, le=100)


CONTROL_CATALOG = [
    ("telnet_disabled", "Disable insecure Telnet management", True, "Critical", "Management Access"),
    ("http_disabled", "Disable unencrypted HTTP management", True, "High", "Management Access"),
    ("ssh_version", "Enforce SSH version 2", "2", "High", "Management Access"),
    ("logging_enabled", "Forward audit logs to a central collector", True, "Medium", "Audit Logging"),
    ("ntp_configured", "Configure a trusted NTP source", True, "Medium", "Time Synchronization"),
    ("aaa_enabled", "Enable centralized authentication and authorization", True, "High", "Authentication"),
    ("snmp_secure", "Use secure SNMP configuration", True, "High", "Monitoring"),
    ("idle_timeout", "Configure an administrative idle timeout", True, "Medium", "Session Security"),
]

FRAMEWORK_IDS = {
    "CIS Benchmarks": "CIS",
    "NIST SP 800-53": "NIST",
    "DISA STIG": "STIG",
    "ISO/IEC 27001": "ISO",
}

REMEDIATIONS = {
    "Cisco": {
        "telnet_disabled": "line vty 0 15\n transport input ssh",
        "http_disabled": "no ip http server",
        "ssh_version": "ip ssh version 2",
        "logging_enabled": "logging host <SIEM_IP>",
        "ntp_configured": "ntp server <NTP_IP>",
        "aaa_enabled": "aaa new-model",
        "snmp_secure": "no snmp-server community public\nsnmp-server group SEC v3 priv",
        "idle_timeout": "line vty 0 15\n exec-timeout 10 0",
    },
    "Fortinet": {
        "telnet_disabled": "config system interface\n edit <mgmt-interface>\n  set allowaccess https ssh\n next\nend",
        "http_disabled": "config system global\n set admin-https-redirect enable\nend",
        "logging_enabled": "config log syslogd setting\n set status enable\n set server <SIEM_IP>\nend",
        "ntp_configured": "config system ntp\n set ntpsync enable\nend",
        "idle_timeout": "config system global\n set admintimeout 10\nend",
    },
    "Juniper": {
        "telnet_disabled": "delete system services telnet",
        "http_disabled": "delete system services web-management http",
        "logging_enabled": "set system syslog host <SIEM_IP> any any",
        "ntp_configured": "set system ntp server <NTP_IP>",
        "idle_timeout": "set system login class <class> idle-timeout 10",
    },
}


def redact(text: str) -> str:
    # Preserve syntax but avoid persisting common credential forms in analysis evidence.
    return re.sub(r"(?im)(password|secret|community|key)\s+(?:\d\s+)?\S+", r"\1 <REDACTED>", text)


def detect_vendor(config: str, requested: str | None = None) -> str:
    if requested and requested.lower() not in {"auto", "unknown"}:
        return requested
    lower = config.lower()
    if "config system global" in lower or "fortigate" in lower:
        return "Fortinet"
    if "set system" in lower or "junos:" in lower:
        return "Juniper"
    if "sonic" in lower:
        return "SONiC"
    if "hostname " in lower or "ip ssh version" in lower or "line vty" in lower:
        return "Cisco"
    return "Unknown"


def empty_baseline() -> dict[str, Any]:
    return {field: {"value": None, "confidence": 0, "source": "unobserved", "evidence": []} for field, *_ in CONTROL_CATALOG}


def set_field(baseline: dict[str, Any], field: str, value: Any, line: str, confidence: float, source: str) -> None:
    if field not in baseline:
        return
    baseline[field] = {"value": value, "confidence": confidence, "source": source, "evidence": [line.strip()]}


def parse_known(config: str, vendor: str, baseline: dict[str, Any]) -> set[str]:
    recognized: set[str] = set()
    lines = config.splitlines()
    for line in lines:
        text = line.strip()
        lower = text.lower()
        if vendor == "Cisco":
            if match := re.search(r"^ip ssh version\s+(\d+)", lower):
                set_field(baseline, "ssh_version", match.group(1), text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("transport input"):
                # IOS `all` includes Telnet; only an explicit SSH-only transport is compliant.
                allowed = set(lower.removeprefix("transport input").split())
                set_field(baseline, "telnet_disabled", "all" not in allowed and "telnet" not in allowed, text, 100, "deterministic"); recognized.add(text)
            elif lower == "no ip http server":
                set_field(baseline, "http_disabled", True, text, 100, "deterministic"); recognized.add(text)
            elif lower == "ip http server":
                set_field(baseline, "http_disabled", False, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("logging host "):
                set_field(baseline, "logging_enabled", True, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith(("ntp server ", "sntp server ")):
                set_field(baseline, "ntp_configured", True, text, 100, "deterministic"); recognized.add(text)
            elif lower == "aaa new-model":
                set_field(baseline, "aaa_enabled", True, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("snmp-server community"):
                # Community strings mean SNMPv1/v2c even when an ACL restricts them.
                set_field(baseline, "snmp_secure", False, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("snmp-server group") and " v3 " in f" {lower} ":
                set_field(baseline, "snmp_secure", True, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("exec-timeout "):
                set_field(baseline, "idle_timeout", True, text, 100, "deterministic"); recognized.add(text)
        elif vendor == "Fortinet":
            if lower.startswith("set admin-telnet "):
                set_field(baseline, "telnet_disabled", lower.endswith("disable"), text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("set admin-http "):
                set_field(baseline, "http_disabled", lower.endswith("disable"), text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("set admintimeout "):
                set_field(baseline, "idle_timeout", True, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("set server "):
                set_field(baseline, "logging_enabled", True, text, 90, "deterministic"); recognized.add(text)
            elif lower.startswith("set ntpsync enable"):
                set_field(baseline, "ntp_configured", True, text, 100, "deterministic"); recognized.add(text)
        elif vendor == "Juniper":
            if lower.startswith("set system services telnet"):
                set_field(baseline, "telnet_disabled", False, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("delete system services telnet"):
                set_field(baseline, "telnet_disabled", True, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("set system services ssh"):
                set_field(baseline, "ssh_version", "2", text, 95, "deterministic"); recognized.add(text)
            elif lower.startswith("set system syslog host "):
                set_field(baseline, "logging_enabled", True, text, 100, "deterministic"); recognized.add(text)
            elif lower.startswith("set system ntp server "):
                set_field(baseline, "ntp_configured", True, text, 100, "deterministic"); recognized.add(text)
            elif "idle-timeout" in lower:
                set_field(baseline, "idle_timeout", True, text, 100, "deterministic"); recognized.add(text)
    return recognized


def apply_training_mappings(lines: list[str], vendor: str, baseline: dict[str, Any]) -> set[str]:
    matched: set[str] = set()
    with db() as connection:
        rows = connection.execute("SELECT * FROM mappings WHERE vendor IN (?, 'Unknown')", (vendor,)).fetchall()
    for line in lines:
        canonical = " ".join(line.strip().lower().split())
        for row in rows:
            stored = " ".join(row["raw_command"].strip().lower().split())
            if canonical == stored:
                try:
                    value = json.loads(row["observed_value"])
                except json.JSONDecodeError:
                    value = row["observed_value"]
                set_field(baseline, row["field_name"], value, line, row["confidence"], "trained_mapping")
                matched.add(line.strip())
    return matched


def remediation(vendor: str, field: str) -> str:
    return REMEDIATIONS.get(vendor, {}).get(field, "AI-suggested remediation: verify vendor syntax before applying.")


def evaluate(baseline: dict[str, Any], vendor: str, framework: str) -> tuple[list[dict[str, Any]], int]:
    framework_id = FRAMEWORK_IDS.get(framework, framework)
    controls: list[dict[str, Any]] = []
    passed = 0
    for index, (field, requirement, expected, severity, category) in enumerate(CONTROL_CATALOG, start=1):
        item = baseline[field]
        value = item["value"]
        result = "Pass" if value == expected else "Warning" if value is None else "Fail"
        if result == "Pass":
            passed += 1
        control_id = f"{framework_id}-{index:02d}"
        controls.append({
            "id": control_id, "framework": framework, "field": field, "requirement": requirement,
            "result": result, "severity": severity, "category": category,
            "evidence": item["evidence"][0] if item["evidence"] else "No matching configuration evidence found",
            "confidence": item["confidence"], "confidence_source": item["source"],
            "remediation": remediation(vendor, field),
        })
    return controls, round(passed / len(CONTROL_CATALOG) * 100)


def analyze(filename: str, config: str, framework: str, requested_vendor: str | None) -> dict[str, Any]:
    vendor = detect_vendor(config, requested_vendor)
    baseline = empty_baseline()
    recognized = parse_known(config, vendor, baseline)
    mapped = apply_training_mappings(config.splitlines(), vendor, baseline)
    unknown = [line.strip() for line in config.splitlines() if line.strip() and line.strip() not in recognized and line.strip() not in mapped and not line.strip().startswith(("!", "#", "end", "exit"))]
    controls, score = evaluate(baseline, vendor, framework)
    counts = {result: sum(control["result"] == result for control in controls) for result in ("Pass", "Fail", "Warning")}
    risk = "Low" if score >= 85 else "Moderate" if score >= 65 else "High" if score >= 40 else "Critical"
    hostname = next((line.split(maxsplit=1)[1] for line in config.splitlines() if line.strip().lower().startswith("hostname ")), Path(filename).stem)
    firmware = next((line.split(maxsplit=1)[1] for line in config.splitlines() if line.strip().lower().startswith("version ")), "Not detected")
    return {
        "id": f"analysis-{uuid.uuid4().hex[:12]}", "fileName": filename, "vendor": vendor,
        "framework": framework, "createdAt": now(), "device": {"name": hostname, "model": "Not detected", "firmware": firmware, "serialNumber": "Not available in configuration"}, "overallScore": score, "riskLevel": risk,
        "controlsChecked": len(controls), "passed": counts["Pass"], "failed": counts["Fail"], "warnings": counts["Warning"],
        "baseline": baseline, "controls": controls, "unknownLines": unknown[:100],
        "summary": f"{vendor} configuration normalized into the Security Baseline Model and evaluated against {framework}."
    }


def normalize_device(analysis: dict[str, Any]) -> dict[str, Any]:
    """Return a device dict for an analysis, providing sensible defaults when missing.

    Older analysis records may not include a `device` object; prefer `fileName` as a fallback.
    """
    device = analysis.get("device")
    if isinstance(device, dict) and device.get("name"):
        return {
            "name": device.get("name"),
            "model": device.get("model", "Not detected"),
            "firmware": device.get("firmware", "Not detected"),
            "serialNumber": device.get("serialNumber", "Not available"),
        }
    # fallback to filename-derived name
    name = analysis.get("fileName") or analysis.get("id") or "Unknown"
    return {"name": Path(name).stem, "model": "Not detected", "firmware": "Not detected", "serialNumber": "Not available"}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "operational"}


@app.get("/api/storage-info")
def storage_info() -> dict[str, Any]:
    return {"s3_configured": bool(S3_BUCKET and _boto3), "s3_bucket": S3_BUCKET}


@app.post("/api/analyses/upload")
async def upload_analysis(
    file: UploadFile = File(...), framework: str = Form("CIS Benchmarks"), vendor: str = Form("Auto")
) -> dict[str, Any]:
    if Path(file.filename or "config.txt").suffix.lower() not in {".txt", ".cfg", ".conf", ".log"}:
        raise HTTPException(400, "Only .txt, .cfg, .conf, and .log configuration exports are accepted.")
    raw = (await file.read()).decode("utf-8", errors="replace")
    result = analyze(file.filename or "config.txt", redact(raw), framework, vendor)
    # persist the original uploaded file for later inspection (local or S3)
    stored_name = None
    try:
        stored_name = f"{result['id']}_{Path(file.filename or 'config.txt').name}"
        # Try to upload to S3-compatible storage when configured, otherwise store locally
        def store_upload(content: str, name: str) -> None:
            if S3_BUCKET and _boto3:
                try:
                    s3 = _boto3.client('s3', endpoint_url=S3_ENDPOINT) if S3_ENDPOINT else _boto3.client('s3')
                    s3.put_object(Bucket=S3_BUCKET, Key=name, Body=content.encode('utf-8'))
                    return
                except Exception:
                    pass
            # fallback to local storage
            (UPLOADS_DIR / name).write_text(content, encoding='utf-8')

        store_upload(raw, stored_name)
    except Exception:
        # non-fatal: continue even if storing the raw file fails
        stored_name = None
    upload_url = f"/api/analyses/{result['id']}/raw" if stored_name else None
    with db() as connection:
        connection.execute("INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?)", (
            result["id"], result["fileName"], result["vendor"], result["framework"], result["createdAt"], json.dumps(result), upload_url
        ))
    return result


@app.get("/api/analyses/{analysis_id}/raw")
def download_raw_analysis(analysis_id: str):
    # Look for a stored uploaded file that starts with the analysis id
    # Check S3 first when configured
    prefix = f"{analysis_id}_"
    if S3_BUCKET and _boto3:
        try:
            s3 = _boto3.client('s3', endpoint_url=S3_ENDPOINT) if S3_ENDPOINT else _boto3.client('s3')
            objs = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
            for item in objs.get('Contents', []):
                key = item['Key']
                body = s3.get_object(Bucket=S3_BUCKET, Key=key)['Body'].read()
                return StreamingResponse(io.BytesIO(body), media_type='text/plain', headers={"Content-Disposition": f"attachment; filename={key}"})
        except Exception:
            pass

    for path in UPLOADS_DIR.iterdir():
        if path.name.startswith(prefix):
            return StreamingResponse(path.open("rb"), media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={path.name}"})
    raise HTTPException(404, "Raw uploaded file not found")


@app.get("/api/analyses")
def list_analyses() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT id, result_json, upload_url FROM analyses ORDER BY created_at DESC").fetchall()
        out = []
        for row in rows:
            obj = json.loads(row["result_json"]) if isinstance(row["result_json"], (str, bytes)) else row["result_json"]
            # ensure upload_url is available on the returned object
            if isinstance(row, dict) and 'upload_url' in row:
                obj['upload_url'] = row.get('upload_url')
            else:
                try:
                    obj['upload_url'] = row['upload_url'] if 'upload_url' in row.keys() else None
                except Exception:
                    obj['upload_url'] = None
            out.append(obj)
        return out


def all_analyses() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT id, result_json, upload_url FROM analyses ORDER BY created_at DESC").fetchall()
        out = []
        for row in rows:
            obj = json.loads(row["result_json"]) if isinstance(row["result_json"], (str, bytes)) else row["result_json"]
            try:
                obj['upload_url'] = row['upload_url'] if 'upload_url' in row.keys() else None
            except Exception:
                obj['upload_url'] = None
            out.append(obj)
        return out


@app.get("/api/dashboard")
def dashboard() -> dict[str, Any]:
    analyses = all_analyses()
    latest_by_device: dict[str, dict[str, Any]] = {}
    for analysis in analyses:
        dev = normalize_device(analysis)
        latest_by_device.setdefault(dev["name"], analysis)
    current = list(latest_by_device.values())
    findings = [control for analysis in current for control in analysis["controls"] if control["result"] != "Pass"]
    average = round(sum(item["overallScore"] for item in current) / len(current)) if current else 0
    severity = {level: sum(item["severity"] == level for item in findings) for level in ("Critical", "High", "Medium", "Low")}
    vendor_groups: dict[str, list[int]] = {}
    framework_groups: dict[str, list[int]] = {}
    for item in current:
        vendor_groups.setdefault(item["vendor"], []).append(item["overallScore"])
        framework_groups.setdefault(item["framework"], []).append(item["overallScore"])
    return {
        "totalDevices": len(current), "configurationsAnalyzed": len(analyses), "overallScore": average,
        "openFindings": len(findings), "severityBreakdown": [{"name": level, "value": severity[level]} for level in severity],
        "recentActivity": [{"id": item["id"], "device": normalize_device(item)["name"], "vendor": item["vendor"], "framework": item["framework"], "score": item["overallScore"], "status": "Compliant" if item["overallScore"] >= 85 else "Warning" if item["overallScore"] >= 65 else "Non-Compliant", "date": item["createdAt"]} for item in analyses[:8]],
        "vendorCompliance": [{"name": name, "score": round(sum(scores) / len(scores))} for name, scores in vendor_groups.items()],
        "frameworkComparison": [{"name": name, "score": round(sum(scores) / len(scores))} for name, scores in framework_groups.items()],
    }


@app.get("/api/devices")
def devices() -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for analysis in all_analyses():
        latest.setdefault(normalize_device(analysis)["name"], analysis)
    return [{
        "id": item["id"], "name": normalize_device(item)["name"], "vendor": item["vendor"], "model": normalize_device(item)["model"],
        "serialNumber": normalize_device(item)["serialNumber"], "firmware": normalize_device(item)["firmware"], "ipAddress": "Not collected", "deviceType": "Network device",
        "complianceScore": item["overallScore"], "risk": item["riskLevel"], "lastScan": item["createdAt"],
        "status": "Compliant" if item["overallScore"] >= 85 else "Warning" if item["overallScore"] >= 65 else "Non-Compliant", "location": "Not collected"
    } for item in latest.values()]


@app.get("/api/findings")
def findings() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for analysis in all_analyses():
        for control in analysis["controls"]:
            if control["result"] == "Pass":
                continue
            output.append({
                "id": f"{analysis['id']}:{control['id']}", "analysisId": analysis["id"], "title": control["requirement"], "device": normalize_device(analysis)["name"],
                "vendor": analysis["vendor"], "framework": control["framework"], "severity": control["severity"], "category": control["category"],
                "status": "Open", "detected": analysis["createdAt"], "action": control["remediation"], "riskScore": 100 - analysis["overallScore"],
                "controlId": control["id"], "description": control["requirement"], "whyItMatters": "The observed configuration does not meet the selected baseline.",
                "evidence": control["evidence"], "currentConfig": control["evidence"], "recommendedConfig": control["remediation"],
                "remediationCommand": control["remediation"], "references": [control["framework"]], "confidence": control["confidence"], "confidenceSource": control["confidence_source"]
            })
    return output


@app.get("/api/reports")
def reports() -> list[dict[str, Any]]:
    return [{"id": item["id"], "name": f"{normalize_device(item)['name']} compliance report", "device": normalize_device(item)["name"], "vendor": item["vendor"], "framework": item["framework"], "complianceScore": item["overallScore"], "generatedDate": item["createdAt"], "status": "Ready"} for item in all_analyses()]


@app.get("/api/frameworks")
def list_frameworks() -> list[dict[str, Any]]:
    # Provide a simple list of supported frameworks and a small summary for the UI.
    frameworks = []
    for name, fid in FRAMEWORK_IDS.items():
        controls = sum(1 for field, *_ in CONTROL_CATALOG)
        frameworks.append({"id": fid, "name": name, "controls": controls, "description": f"{name} controls", "status": "Healthy"})
    return frameworks


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Analysis not found")
    return json.loads(row["result_json"])


@app.get("/api/training-mappings")
def list_mappings() -> list[dict[str, Any]]:
    with db() as connection:
        return [dict(row) | {"observed_value": json.loads(row["observed_value"])} for row in connection.execute("SELECT * FROM mappings ORDER BY created_at DESC")]


@app.post("/api/training-mappings", status_code=201)
def create_mapping(payload: TrainingMapping) -> dict[str, Any]:
    if payload.field_name not in {item[0] for item in CONTROL_CATALOG}:
        raise HTTPException(400, "field_name must be a Security Baseline Model field")
    record = {
        "id": f"mapping-{uuid.uuid4().hex[:12]}", "raw_command": payload.raw_command.strip(), "vendor": payload.vendor.strip() or "Unknown",
        "field_name": payload.field_name, "observed_value": payload.observed_value, "meaning": payload.meaning.strip(),
        "confidence": payload.confidence, "created_at": now(),
    }
    with db() as connection:
        connection.execute("INSERT INTO mappings VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
            record["id"], record["raw_command"], record["vendor"], record["field_name"], json.dumps(record["observed_value"]),
            record["meaning"], record["confidence"], record["created_at"]
        ))
    return record


@app.post("/api/training-mappings/apply")
def apply_mappings_endpoint() -> dict[str, Any]:
    """Re-apply training mappings to existing analyses that have preserved raw uploads.

    This iterates analyses with stored uploads, re-runs `analyze` using the original raw
    configuration (so newly saved mappings are applied), and updates the stored `result_json`.
    """
    updated = 0
    with db() as connection:
        rows = connection.execute("SELECT id, result_json, upload_url FROM analyses").fetchall()
        for row in rows:
            # sqlite3.Row supports mapping but not .get; handle both tuple-like and mapping-like rows
            try:
                aid = row["id"]
                result_json_field = row["result_json"]
                upload_url = row["upload_url"]
            except Exception:
                # fallback to sequence access
                aid = row[0]
                result_json_field = row[1]
                upload_url = row[2] if len(row) > 2 else None
            # only attempt re-analyze if an upload was stored
            if not upload_url:
                continue
            # try to read raw content from local uploads dir or S3
            prefix = f"{aid}_"
            raw_text = None
            # S3 first
            if S3_BUCKET and _boto3:
                try:
                    s3 = _boto3.client('s3', endpoint_url=S3_ENDPOINT) if S3_ENDPOINT else _boto3.client('s3')
                    objs = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
                    for item in objs.get('Contents', []):
                        key = item['Key']
                        body = s3.get_object(Bucket=S3_BUCKET, Key=key)['Body'].read()
                        raw_text = body.decode('utf-8', errors='replace')
                        break
                except Exception:
                    raw_text = None
            # local fallback
            if raw_text is None:
                for path in UPLOADS_DIR.iterdir():
                    if path.name.startswith(prefix):
                        raw_text = path.read_text(encoding='utf-8')
                        break
            if raw_text is None:
                continue
            # preserve framework and vendor from stored result_json when re-running
            try:
                stored = json.loads(result_json_field) if isinstance(result_json_field, (str, bytes)) else result_json_field
                framework = stored.get('framework', 'CIS Benchmarks')
                vendor = stored.get('vendor')
            except Exception:
                framework = 'CIS Benchmarks'
                vendor = None
            try:
                new_result = analyze(stored.get('fileName', f'{aid}.cfg'), redact(raw_text), framework, vendor)
                connection.execute("UPDATE analyses SET result_json = ? WHERE id = ?", (json.dumps(new_result), aid))
                updated += 1
            except Exception:
                continue
    return {"updated": updated}


@app.get("/api/analyses/{analysis_id}/report.pdf")
def report(analysis_id: str) -> StreamingResponse:
    result = get_analysis(analysis_id)
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    story = [Paragraph("NetSecureAI Compliance Report", styles["Title"]), Spacer(1, 12)]
    story.append(Paragraph(f"<b>Device/configuration:</b> {result['fileName']}<br/><b>Vendor:</b> {result['vendor']}<br/><b>Framework:</b> {result['framework']}<br/><b>Compliance score:</b> {result['overallScore']}%", styles["BodyText"]))
    story.append(Spacer(1, 12))
    rows = [["Control", "Result", "Severity", "Confidence", "Evidence"]]
    for control in result["controls"]:
        rows.append([control["id"], control["result"], control["severity"], f"{control['confidence']}% ({control['confidence_source']})", control["evidence"][:55]])
    table = Table(rows, repeatRows=1, colWidths=[60, 45, 55, 110, 250])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123047")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 7), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fa")])]))
    story.extend([Paragraph("Findings and evidence", styles["Heading2"]), table, Spacer(1, 12), Paragraph("Remediation paths", styles["Heading2"])])
    for control in result["controls"]:
        if control["result"] != "Pass":
            story.append(Paragraph(f"<b>{control['id']} — {control['requirement']}</b><br/>{control['remediation'].replace(chr(10), '<br/>')}", styles["BodyText"]))
            story.append(Spacer(1, 6))
    SimpleDocTemplate(output, pagesize=A4, rightMargin=28, leftMargin=28, topMargin=32, bottomMargin=32).build(story)
    output.seek(0)
    return StreamingResponse(output, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{analysis_id}.pdf"'})
