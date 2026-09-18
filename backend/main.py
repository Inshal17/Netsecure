"""
NetSecureAI API

FastAPI backend for the NetSecureAI network configuration
compliance and security posture platform.

Storage:
    - Supabase PostgreSQL -> analyses + training mappings
    - Supabase Storage    -> original configuration files

The local SQLite database is no longer used for application data.
"""

from __future__ import annotations

import io
import base64
import hashlib
import hmac
import importlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

try:
    create_client = importlib.import_module("supabase").create_client
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    create_client = None


# ============================================================
# ENVIRONMENT / SUPABASE
# ============================================================

ROOT = Path(__file__).resolve().parent
logger = logging.getLogger("netsecureai.api")

# Load backend/.env
load_dotenv(ROOT / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")
SUPABASE_BUCKET = os.getenv(
    "SUPABASE_BUCKET",
    "configurations",
)
AUTH_SECRET = os.getenv("NETSECURE_AUTH_SECRET", "")
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
API_REQUESTS: dict[str, list[float]] = {}

supabase = None

if create_client is not None and SUPABASE_URL and SUPABASE_SECRET_KEY:
    supabase = create_client(
        SUPABASE_URL,
        SUPABASE_SECRET_KEY,
    )


# ============================================================
# LOCAL DIRECTORIES
# ============================================================

DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)
LOCAL_DB = DATA_DIR / "netsecureai.sqlite3"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="NetSecureAI API",
    version="1.0.0",
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:16])
    logger.exception(
        json.dumps(
            {
                "event": "unhandled_exception",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "error_type": type(exc).__name__,
            }
        )
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "NETSECURE_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:5175,http://127.0.0.1:5175",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_token_guard(request: Request, call_next):
    """Require a static API token or signed user session when configured."""

    configured_token = os.getenv("NETSECURE_API_TOKEN")
    auth_secret = os.getenv("NETSECURE_AUTH_SECRET", "")
    is_api_request = request.url.path.startswith("/api/")
    is_public_request = request.url.path in {"/api/health", "/api/auth/login"} or request.method == "OPTIONS"
    request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:16])

    if is_api_request and not is_public_request:
        rate_limit = int(os.getenv("NETSECURE_API_RATE_LIMIT", "0"))
        rate_window = int(os.getenv("NETSECURE_API_RATE_WINDOW_SECONDS", "60"))
        client_id = request.client.host if request.client else "unknown"
        now_timestamp = time.time()
        recent_requests = [
            timestamp
            for timestamp in API_REQUESTS.get(client_id, [])
            if now_timestamp - timestamp < rate_window
        ]
        if rate_limit > 0 and len(recent_requests) >= rate_limit:
            logger.info(json.dumps({
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": 429,
            }))
            return JSONResponse(
                status_code=429,
                content={"detail": "API rate limit exceeded; try again later"},
                headers={"Retry-After": str(rate_window), "X-Request-ID": request_id},
            )
        if rate_limit > 0:
            recent_requests.append(now_timestamp)
            API_REQUESTS[client_id] = recent_requests

    if (configured_token or auth_secret) and is_api_request and not is_public_request:
        authorization = request.headers.get("Authorization", "")
        bearer = authorization.removeprefix("Bearer ").strip()
        valid_static = bool(configured_token and hmac.compare_digest(bearer, configured_token))
        session = verify_session_token(bearer, auth_secret) if auth_secret else None
        valid_session = bool(session)
        if not (valid_static or valid_session):
            logger.info(json.dumps({
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": 401,
            }))
            return JSONResponse(
                status_code=401,
                content={"detail": "Valid API bearer token required"},
                headers={"WWW-Authenticate": "Bearer", "X-Request-ID": request_id},
            )
        if session:
            request.state.user = session

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        json.dumps(
            {
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
            }
        )
    )
    return response


# ============================================================
# HELPERS
# ============================================================

def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_hash(result: dict[str, Any]) -> str:
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_session_token(username: str, role: str, secret: str) -> str:
    payload = f"{username}|{role}|{int(time.time()) + 28800}"
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def verify_session_token(token: str, secret: str) -> dict[str, str] | None:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = base64.urlsafe_b64decode(f"{encoded}===").decode()
        username, role, expires = payload.split("|", 2)
        if int(expires) <= int(time.time()):
            return None
        return {"username": username, "role": role}
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        return None


def require_supabase():
    if supabase is None or create_client is None:
        raise HTTPException(
            status_code=500,
            detail=(
                "Supabase is not configured or the optional "
                "Supabase dependency is unavailable. "
                "Check backend/.env and install the project requirements."
            ),
        )

    return supabase


def local_rows(query: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    if not LOCAL_DB.exists():
        return []

    with sqlite3.connect(LOCAL_DB) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query, parameters)]


def ensure_local_audit_table() -> None:
    if not LOCAL_DB.exists():
        return

    with sqlite3.connect(LOCAL_DB) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                device TEXT NOT NULL,
                result TEXT NOT NULL,
                ip_address TEXT NOT NULL
            )
            """
        )


def record_local_audit(
    action: str,
    resource: str,
    result: str = "Success",
    device: str = "Unknown",
) -> None:
    if not LOCAL_DB.exists():
        return

    ensure_local_audit_table()
    with sqlite3.connect(LOCAL_DB) as connection:
        connection.execute(
            """
            INSERT INTO audit_events
            (id, timestamp, user, action, resource, device, result, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"audit-{uuid.uuid4().hex[:12]}",
                now(),
                "Admin",
                action,
                resource,
                device,
                result,
                "127.0.0.1",
            ),
        )
        connection.commit()


def record_audit_event(
    action: str,
    resource: str,
    result: str = "Success",
    device: str = "Unknown",
) -> None:
    if supabase is None:
        record_local_audit(action, resource, result, device)
        return

    try:
        supabase.table("audit_events").insert(
            {
                "id": f"audit-{uuid.uuid4().hex[:12]}",
                "timestamp": now(),
                "user": "Admin",
                "action": action,
                "resource": resource,
                "device": device,
                "result": result,
                "ip_address": "127.0.0.1",
            }
        ).execute()
    except Exception as exc:
        print("Audit event could not be persisted:", exc)


# ============================================================
# TRAINING MODEL
# ============================================================

class TrainingMapping(BaseModel):
    raw_command: str = Field(
        min_length=1,
        max_length=2000,
    )

    vendor: str = "Unknown"

    field_name: str = Field(
        min_length=1,
        max_length=80,
    )

    observed_value: Any

    meaning: str = Field(
        min_length=1,
        max_length=500,
    )

    confidence: float = Field(
        default=92,
        ge=0,
        le=100,
    )


class MappingSuggestionRequest(BaseModel):
    raw_command: str = Field(min_length=1, max_length=2000)
    vendor: str = Field(default="Unknown", max_length=100)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


# ============================================================
# SECURITY CONTROL CATALOG
# ============================================================

CONTROL_CATALOG = [
    (
        "telnet_disabled",
        "Disable insecure Telnet management",
        True,
        "Critical",
        "Management Access",
    ),
    (
        "http_disabled",
        "Disable unencrypted HTTP management",
        True,
        "High",
        "Management Access",
    ),
    (
        "ssh_version",
        "Enforce SSH version 2",
        "2",
        "High",
        "Management Access",
    ),
    (
        "logging_enabled",
        "Forward audit logs to a central collector",
        True,
        "Medium",
        "Audit Logging",
    ),
    (
        "ntp_configured",
        "Configure a trusted NTP source",
        True,
        "Medium",
        "Time Synchronization",
    ),
    (
        "aaa_enabled",
        "Enable centralized authentication and authorization",
        True,
        "High",
        "Authentication",
    ),
    (
        "snmp_secure",
        "Use secure SNMP configuration",
        True,
        "High",
        "Monitoring",
    ),
    (
        "idle_timeout",
        "Configure an administrative idle timeout",
        True,
        "Medium",
        "Session Security",
    ),
    (
        "source_routing_disabled",
        "Disable IP source routing",
        True,
        "High",
        "Routing Security",
    ),
    (
        "proxy_arp_disabled",
        "Disable proxy ARP on interfaces",
        True,
        "Medium",
        "Interface Security",
    ),
    (
        "tcp_keepalives_enabled",
        "Enable TCP keepalives",
        True,
        "Low",
        "Transport Security",
    ),
    (
        "pad_disabled",
        "Disable PAD service",
        True,
        "Medium",
        "Legacy Services",
    ),
    (
        "ntp_authenticated",
        "Authenticate NTP synchronization",
        True,
        "Medium",
        "Time Synchronization",
    ),
    (
        "ssh_rate_limit",
        "Limit SSH connection attempts",
        4,
        "Medium",
        "Management Access",
    ),
    (
        "login_attempts",
        "Limit failed login attempts",
        3,
        "High",
        "Authentication",
    ),
    (
        "reverse_telnet_disabled",
        "Disable reverse Telnet",
        True,
        "High",
        "Legacy Services",
    ),
    (
        "ftp_disabled",
        "Disable insecure FTP service",
        True,
        "High",
        "Legacy Services",
    ),
]

COMMON_CONTROL_FIELDS = {
    "telnet_disabled",
    "http_disabled",
    "ssh_version",
    "logging_enabled",
    "ntp_configured",
    "aaa_enabled",
    "snmp_secure",
    "idle_timeout",
}

CONTROL_VENDOR_APPLICABILITY = {
    "Cisco": {field for field, *_ in CONTROL_CATALOG},
    "Juniper": COMMON_CONTROL_FIELDS | {
        "ssh_rate_limit",
        "login_attempts",
        "reverse_telnet_disabled",
        "ftp_disabled",
    },
    "Arista": COMMON_CONTROL_FIELDS,
    "SONiC": COMMON_CONTROL_FIELDS,
    "Fortinet": COMMON_CONTROL_FIELDS,
    "Palo Alto": COMMON_CONTROL_FIELDS | {
        "source_routing_disabled",
        "proxy_arp_disabled",
        "ssh_rate_limit",
        "login_attempts",
    },
    "HPE Aruba": COMMON_CONTROL_FIELDS | {
        "source_routing_disabled",
        "proxy_arp_disabled",
        "ssh_rate_limit",
        "login_attempts",
    },
    "Huawei": COMMON_CONTROL_FIELDS | {
        "source_routing_disabled",
        "proxy_arp_disabled",
        "ssh_rate_limit",
        "login_attempts",
    },
    "Check Point": COMMON_CONTROL_FIELDS | {
        "source_routing_disabled",
        "proxy_arp_disabled",
        "ssh_rate_limit",
        "login_attempts",
    },
}

CONTROL_REFERENCES = {
    "telnet_disabled": {"CIS": "CIS 1.1.1", "NIST": "AC-17(2)", "STIG": "NET-01", "ISO": "A.5.15"},
    "http_disabled": {"CIS": "CIS 1.1.2", "NIST": "CM-7", "STIG": "NET-02", "ISO": "A.8.2"},
    "ssh_version": {"CIS": "CIS 1.1.3", "NIST": "AC-17(2)", "STIG": "NET-03", "ISO": "A.8.2"},
    "logging_enabled": {"CIS": "CIS 2.1.1", "NIST": "AU-2", "STIG": "LOG-01", "ISO": "A.8.2"},
    "ntp_configured": {"CIS": "CIS 3.3.1", "NIST": "AU-8", "STIG": "TIM-01", "ISO": "A.8.4"},
    "aaa_enabled": {"CIS": "CIS 4.1.1", "NIST": "IA-2", "STIG": "AUTH-01", "ISO": "A.5.2"},
    "snmp_secure": {"CIS": "CIS 5.2.1", "NIST": "CM-6", "STIG": "MON-01", "ISO": "A.8.2"},
    "idle_timeout": {"CIS": "CIS 6.3.1", "NIST": "AC-2(5)", "STIG": "SESS-01", "ISO": "A.5.17"},
    "source_routing_disabled": {"CIS": "CIS 7.1.1", "NIST": "CM-7", "STIG": "NET-04", "ISO": "A.8.2"},
    "proxy_arp_disabled": {"CIS": "CIS 7.2.1", "NIST": "SC-7", "STIG": "INT-01", "ISO": "A.8.2"},
    "tcp_keepalives_enabled": {"CIS": "CIS 8.1.1", "NIST": "SC-7", "STIG": "TRN-01", "ISO": "A.8.2"},
    "pad_disabled": {"CIS": "CIS 8.2.1", "NIST": "CM-7", "STIG": "LEG-01", "ISO": "A.8.2"},
    "ntp_authenticated": {"CIS": "CIS 3.3.2", "NIST": "AU-8", "STIG": "TIM-02", "ISO": "A.8.4"},
    "ssh_rate_limit": {"CIS": "CIS 1.1.4", "NIST": "AC-7", "STIG": "NET-05", "ISO": "A.5.2"},
    "login_attempts": {"CIS": "CIS 4.1.2", "NIST": "AC-7", "STIG": "AUTH-02", "ISO": "A.5.2"},
    "reverse_telnet_disabled": {"CIS": "CIS 8.3.1", "NIST": "CM-7", "STIG": "LEG-02", "ISO": "A.8.2"},
    "ftp_disabled": {"CIS": "CIS 8.3.2", "NIST": "CM-7", "STIG": "LEG-03", "ISO": "A.8.2"},
}


# ============================================================
# FRAMEWORKS
# ============================================================

FRAMEWORK_IDS = {
    "CIS Benchmarks": "CIS",
    "NIST SP 800-53": "NIST",
    "DISA STIG": "STIG",
    "ISO/IEC 27001": "ISO",
}

FRAMEWORK_METADATA = {
    "CIS": {
        "source": "CIS Controls and vendor benchmark crosswalk",
        "version": "v8-aligned",
        "authorityUrl": "https://www.cisecurity.org/controls",
        "reviewStatus": "Crosswalk review required",
        "scope": "Network security baseline indicators",
    },
    "NIST": {
        "source": "NIST SP 800-53 Rev. 5 control families",
        "version": "Rev. 5",
        "authorityUrl": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        "reviewStatus": "Reference aligned",
        "scope": "Access, audit, configuration, and system protection controls",
    },
    "STIG": {
        "source": "DISA network device STIG-style requirements",
        "version": "2024 baseline",
        "authorityUrl": "https://public.cyber.mil/stigs/",
        "reviewStatus": "STIG applicability review required",
        "scope": "Network device hardening indicators",
    },
    "ISO": {
        "source": "ISO/IEC 27001:2022 Annex A crosswalk",
        "version": "2022",
        "authorityUrl": "https://www.iso.org/standard/27001.html",
        "reviewStatus": "Annex A mapping review required",
        "scope": "Information security control themes",
    },
}

VENDOR_SUPPORT = [
    {
        "name": name,
        "category": category,
        "supportLevel": "Deterministic parser",
        "mappingMode": "Rules and evidence",
        "status": "Available",
    }
    for name, category in (
        ("Cisco", "Router, switch, firewall"),
        ("Juniper", "Router, switch, firewall"),
        ("Arista", "Switch, router"),
        ("SONiC", "White-box switch"),
        ("Fortinet", "Firewall"),
        ("Palo Alto", "Firewall"),
        ("HPE Aruba", "Switch, wireless"),
        ("Huawei", "Router, switch"),
        ("Check Point", "Firewall"),
    )
] + [
    {
        "name": name,
        "category": category,
        "supportLevel": "AI-assisted mapping",
        "mappingMode": "Heuristic suggestion and review",
        "status": "Planned",
    }
    for name, category in (
        ("Sophos", "Firewall"),
        ("SonicWall", "Firewall"),
        ("WatchGuard", "Firewall"),
        ("Barracuda", "Firewall, SASE"),
        ("Zscaler", "SASE"),
        ("AWS Network Firewall", "Cloud firewall"),
        ("Azure Firewall", "Cloud firewall"),
        ("Google Cloud Firewall", "Cloud firewall"),
        ("MikroTik", "Router, switch"),
        ("Ubiquiti", "Router, switch, wireless"),
        ("Extreme", "Switch, wireless"),
        ("NVIDIA Cumulus", "Disaggregated networking"),
        ("Dell SONiC", "White-box switch"),
        ("Nokia", "Router, switch"),
    )
]


# ============================================================
# REMEDIATION COMMANDS
# ============================================================

REMEDIATIONS = {
    "Cisco": {
        "telnet_disabled":
            "line vty 0 15\n transport input ssh",

        "http_disabled":
            "no ip http server",

        "ssh_version":
            "ip ssh version 2",

        "logging_enabled":
            "logging host <SIEM_IP>",

        "ntp_configured":
            "ntp server <NTP_IP>",

        "aaa_enabled":
            "aaa new-model",

        "snmp_secure":
            "no snmp-server community public\n"
            "snmp-server group SEC v3 priv",

        "idle_timeout":
            "line vty 0 15\n exec-timeout 10 0",

        "source_routing_disabled":
            "no ip source-route",

        "proxy_arp_disabled":
            "interface <interface>\n no ip proxy-arp",

        "tcp_keepalives_enabled":
            "service tcp-keepalives-in\nservice tcp-keepalives-out",

        "pad_disabled":
            "no service pad",

        "ntp_authenticated":
            "ntp authenticate",
    },

    "Arista": {
        "telnet_disabled":
            "no management telnet",

        "http_disabled":
            "no management api http-commands",

        "ssh_version":
            "management ssh",

        "logging_enabled":
            "logging host <SIEM_IP>",

        "ntp_configured":
            "ntp server <NTP_IP>",

        "aaa_enabled":
            "aaa authorization exec default local",

        "idle_timeout":
            "exec-timeout 10",
    },

    "SONiC": {
        "http_disabled":
            "sudo config http disable",

        "ntp_configured":
            "sudo config ntp add <NTP_IP>",

        "logging_enabled":
            "sudo config syslog add <SIEM_IP>",

        "aaa_enabled":
            "sudo config aaa enable",

        "idle_timeout":
            "set mgmt timeout 10",
    },

    "Fortinet": {
        "telnet_disabled":
            "config system interface\n"
            " edit <mgmt-interface>\n"
            "  set allowaccess httpsssh\n"
            " next\n"
            "end",

        "http_disabled":
            "config system global\n"
            " set admin-https-redirect enable\n"
            "end",

        "logging_enabled":
            "config log syslogd setting\n"
            " set status enable\n"
            " set server <SIEM_IP>\n"
            "end",

        "ntp_configured":
            "config system ntp\n"
            " set ntpsync enable\n"
            "end",

        "idle_timeout":
            "config system global\n"
            " set admintimeout 10\n"
            "end",
    },

    "Juniper": {
        "telnet_disabled":
            "delete system services telnet",

        "http_disabled":
            "delete system services web-management http",

        "logging_enabled":
            "set system syslog host <SIEM_IP> any any",

        "ntp_configured":
            "set system ntp server <NTP_IP>",

        "idle_timeout":
            "set system login class <class> idle-timeout 10",

        "ssh_rate_limit":
            "set system services ssh rate-limit 4",

        "login_attempts":
            "set system login retry-options tries-before-disconnect 3",

        "reverse_telnet_disabled":
            "delete system services reverse-telnet",

        "ftp_disabled":
            "delete system services ftp",
    },
}


# ============================================================
# REDACTION
# ============================================================

def redact(text: str) -> str:
    """
    Redact common credential-like values before they are
    persisted into analysis evidence.
    """

    return re.sub(
        r"(?im)"
        r"(password|secret|community|key)"
        r"\s+(?:\d\s+)?\S+",
        r"\1 <REDACTED>",
        text,
    )


# ============================================================
# VENDOR DETECTION
# ============================================================

def detect_vendor(
    config: str,
    requested: str | None = None,
) -> str:

    if requested and requested.lower() not in {
        "auto",
        "unknown",
    }:
        return requested

    lower = config.lower()

    if (
        "config system global" in lower
        or "fortigate" in lower
    ):
        return "Fortinet"

    if (
        "set deviceconfig system" in lower
        or "deviceconfig system" in lower
        or "set network virtual-router" in lower
        or "set zone" in lower
    ):
        return "Palo Alto"

    if (
        "no telnet-server" in lower
        or "aaa authentication-server" in lower
        or "ip ssh version" in lower and "hostname sw-" in lower
        or "ip http server" in lower and "hostname" in lower
    ):
        return "HPE Aruba"

    if (
        "sysname" in lower
        or "undo telnet server enable" in lower
        or "undo http server enable" in lower
        or "ntp-service enable" in lower
    ):
        return "Huawei"

    if (
        "set hostname" in lower
        or "set admin telnet" in lower
        or "set ssh version" in lower
        or "cp-" in lower
    ):
        return "Check Point"

    if (
        "set system" in lower
        or "junos:" in lower
        or "protocol-version v" in lower
        or "tries-before-disconnect" in lower
    ):
        return "Juniper"

    if "sonic" in lower:
        return "SONiC"

    if (
        "arista" in lower
        or "management ssh" in lower
        or "management api http-commands" in lower
    ):
        return "Arista"

    if (
        "hostname " in lower
        or "ip ssh version" in lower
        or "line vty" in lower
    ):
        return "Cisco"

    return "Unknown"


# ============================================================
# BASELINE
# ============================================================

def empty_baseline() -> dict[str, Any]:

    return {
        field: {
            "value": None,
            "confidence": 0,
            "source": "unobserved",
            "evidence": [],
        }
        for field, *_ in CONTROL_CATALOG
    }


def set_field(
    baseline: dict[str, Any],
    field: str,
    value: Any,
    line: str,
    confidence: float,
    source: str,
) -> None:

    if field not in baseline:
        return

    baseline[field] = {
        "value": value,
        "confidence": confidence,
        "source": source,
        "evidence": [
            line.strip()
        ],
    }


# ============================================================
# CONFIGURATION PARSER
# ============================================================

def parse_known(
    config: str,
    vendor: str,
    baseline: dict[str, Any],
) -> set[str]:

    recognized: set[str] = set()

    lines = config.splitlines()

    for line in lines:

        text = line.strip()
        lower = text.lower()

        # ----------------------------------------------------
        # CISCO
        # ----------------------------------------------------

        if vendor == "Cisco":

            if match := re.search(
                r"^ip ssh version\s+(\d+)",
                lower,
            ):
                set_field(
                    baseline,
                    "ssh_version",
                    match.group(1),
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith("transport input"):

                allowed = set(
                    lower
                    .removeprefix(
                        "transport input"
                    )
                    .split()
                )

                set_field(
                    baseline,
                    "telnet_disabled",
                    (
                        "all" not in allowed
                        and "telnet" not in allowed
                    ),
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower == "no ip http server":

                set_field(
                    baseline,
                    "http_disabled",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower == "ip http server":

                set_field(
                    baseline,
                    "http_disabled",
                    False,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "logging host "
            ):

                set_field(
                    baseline,
                    "logging_enabled",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower == "no logging enable":
                set_field(baseline, "logging_enabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith(
                (
                    "ntp server ",
                    "sntp server ",
                )
            ):

                set_field(
                    baseline,
                    "ntp_configured",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower == "aaa new-model":

                set_field(
                    baseline,
                    "aaa_enabled",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "snmp-server community"
            ):

                set_field(
                    baseline,
                    "snmp_secure",
                    False,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif (
                lower.startswith(
                    "snmp-server group"
                )
                and " v3 " in f" {lower} "
            ):

                set_field(
                    baseline,
                    "snmp_secure",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "exec-timeout "
            ):

                set_field(
                    baseline,
                    "idle_timeout",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower == "no ip source-route":
                set_field(baseline, "source_routing_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "ip source-route":
                set_field(baseline, "source_routing_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "no ip proxy-arp":
                set_field(baseline, "proxy_arp_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "ip proxy-arp":
                set_field(baseline, "proxy_arp_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower in {"service tcp-keepalives-in", "service tcp-keepalives-out"}:
                set_field(baseline, "tcp_keepalives_enabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower in {"no service tcp-keepalives-in", "no service tcp-keepalives-out"}:
                set_field(baseline, "tcp_keepalives_enabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "no service pad":
                set_field(baseline, "pad_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "service pad":
                set_field(baseline, "pad_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "ntp authenticate":
                set_field(baseline, "ntp_authenticated", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "no ntp authenticate":
                set_field(baseline, "ntp_authenticated", False, text, 100, "deterministic")
                recognized.add(text)

        # ----------------------------------------------------
        # SONIC

        elif vendor == "SONiC":

            if lower.startswith("set mgmt timeout "):
                set_field(baseline, "idle_timeout", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower in {"set mgmt http disable", "sudo config http disable"}:
                set_field(baseline, "http_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower in {"set mgmt http enable", "sudo config http enable"}:
                set_field(baseline, "http_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith(("set system ntp server ", "sudo config ntp add ")):
                set_field(baseline, "ntp_configured", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith(("set system syslog server ", "sudo config syslog add ")):
                set_field(baseline, "logging_enabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith(("set aaa authentication ", "sudo config aaa enable")):
                set_field(baseline, "aaa_enabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "set mgmt telnet enable":
                set_field(baseline, "telnet_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "set mgmt telnet disable":
                set_field(baseline, "telnet_disabled", True, text, 100, "deterministic")
                recognized.add(text)

        # FORTINET
        # ----------------------------------------------------

        elif vendor == "Arista":

            if lower == "no management telnet":
                set_field(baseline, "telnet_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "management telnet":
                set_field(baseline, "telnet_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "no management api http-commands":
                set_field(baseline, "http_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "management api http-commands":
                set_field(baseline, "http_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower == "management ssh":
                set_field(baseline, "ssh_version", "2", text, 90, "deterministic")
                recognized.add(text)

            elif lower.startswith("logging host "):
                set_field(baseline, "logging_enabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("ntp server "):
                set_field(baseline, "ntp_configured", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("aaa authorization exec"):
                set_field(baseline, "aaa_enabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("exec-timeout "):
                set_field(baseline, "idle_timeout", True, text, 100, "deterministic")
                recognized.add(text)

        # ----------------------------------------------------
        # FORTINET
        # ----------------------------------------------------

        elif vendor == "Fortinet":

            if lower.startswith(
                "set admin-telnet "
            ):

                set_field(
                    baseline,
                    "telnet_disabled",
                    lower.endswith("disable"),
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "set admin-http "
            ):

                set_field(
                    baseline,
                    "http_disabled",
                    lower.endswith("disable"),
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower in {
                "set admin-https-redirect enable",
                "set admin-http disable",
            }:
                set_field(baseline, "http_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower in {"set ssh-v1 disable", "set ssh-version 2"}:
                set_field(baseline, "ssh_version", "2", text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("set auth-server ") or lower.startswith("set auth-"):
                set_field(baseline, "aaa_enabled", True, text, 90, "deterministic")
                recognized.add(text)

            elif lower in {"set snmp-community disable", "set snmp-v3 enable"}:
                set_field(baseline, "snmp_secure", True, text, 90, "deterministic")
                recognized.add(text)

            elif lower.startswith(
                "set admintimeout "
            ):

                set_field(
                    baseline,
                    "idle_timeout",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "set server "
            ):

                set_field(
                    baseline,
                    "logging_enabled",
                    True,
                    text,
                    90,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "set ntpsync enable"
            ):

                set_field(
                    baseline,
                    "ntp_configured",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

        elif vendor == "Palo Alto":
            if "ssh version" in lower and "deviceconfig system" in lower:
                if re.search(r"ssh version\s+(\d+)", lower):
                    set_field(baseline, "ssh_version", re.search(r"ssh version\s+(\d+)", lower).group(1), text, 95, "deterministic")
                    recognized.add(text)

            elif "service disable telnet" in lower or "service disable webserver" in lower:
                if "telnet" in lower:
                    set_field(baseline, "telnet_disabled", True, text, 95, "deterministic")
                if "webserver" in lower:
                    set_field(baseline, "http_disabled", True, text, 95, "deterministic")
                recognized.add(text)

            elif "ntp servers" in lower and "deviceconfig system" in lower:
                set_field(baseline, "ntp_configured", True, text, 90, "deterministic")
                recognized.add(text)

            elif "logging" in lower and "deviceconfig system" in lower:
                set_field(baseline, "logging_enabled", True, text, 90, "deterministic")
                recognized.add(text)

        elif vendor == "HPE Aruba":
            if re.search(r"^ip ssh version\s+(\d+)", lower):
                set_field(baseline, "ssh_version", re.search(r"^ip ssh version\s+(\d+)", lower).group(1), text, 95, "deterministic")
                recognized.add(text)

            elif lower == "no telnet-server":
                set_field(baseline, "telnet_disabled", True, text, 95, "deterministic")
                recognized.add(text)

            elif lower == "no ip http server":
                set_field(baseline, "http_disabled", True, text, 95, "deterministic")
                recognized.add(text)

            elif "aaa authentication-server" in lower:
                set_field(baseline, "aaa_enabled", True, text, 92, "deterministic")
                recognized.add(text)

            elif lower.startswith("logging "):
                set_field(baseline, "logging_enabled", True, text, 90, "deterministic")
                recognized.add(text)

            elif lower.startswith("sntp server ") or lower.startswith("ntp server "):
                set_field(baseline, "ntp_configured", True, text, 90, "deterministic")
                recognized.add(text)

        elif vendor == "Huawei":
            if lower.startswith("undo telnet server enable"):
                set_field(baseline, "telnet_disabled", True, text, 95, "deterministic")
                recognized.add(text)
            elif lower.startswith("undo http server enable"):
                set_field(baseline, "http_disabled", True, text, 95, "deterministic")
                recognized.add(text)
            elif lower.startswith("ssh server version "):
                match = re.search(r"ssh server version\s+(\d+)", lower)
                if match:
                    set_field(baseline, "ssh_version", match.group(1), text, 95, "deterministic")
                    recognized.add(text)
            elif lower.startswith("ntp-service enable"):
                set_field(baseline, "ntp_configured", True, text, 90, "deterministic")
                recognized.add(text)
            elif lower.startswith("logging "):
                set_field(baseline, "logging_enabled", True, text, 90, "deterministic")
                recognized.add(text)

        elif vendor == "Check Point":
            if lower.startswith("set ssh version "):
                match = re.search(r"set ssh version\s+(\d+)", lower)
                if match:
                    set_field(baseline, "ssh_version", match.group(1), text, 95, "deterministic")
                    recognized.add(text)
            elif "set admin telnet disable" in lower:
                set_field(baseline, "telnet_disabled", True, text, 95, "deterministic")
                recognized.add(text)
            elif "set admin http disable" in lower or "set web ssl disable" in lower:
                set_field(baseline, "http_disabled", True, text, 90, "deterministic")
                recognized.add(text)
            elif "set ntp server" in lower:
                set_field(baseline, "ntp_configured", True, text, 90, "deterministic")
                recognized.add(text)
            elif "set snmp" in lower:
                set_field(baseline, "snmp_secure", True, text, 90, "deterministic")
                recognized.add(text)

        # ----------------------------------------------------
        # JUNIPER
        # ----------------------------------------------------

        elif vendor == "Juniper":

            if lower.startswith(
                "set system services telnet"
            ):

                set_field(
                    baseline,
                    "telnet_disabled",
                    False,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "delete system services telnet"
            ):

                set_field(
                    baseline,
                    "telnet_disabled",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "set system services ssh"
            ):

                set_field(
                    baseline,
                    "ssh_version",
                    "2",
                    text,
                    95,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "set system syslog host "
            ):

                set_field(
                    baseline,
                    "logging_enabled",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith(
                "set system ntp server "
            ):

                set_field(
                    baseline,
                    "ntp_configured",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif "idle-timeout" in lower:

                set_field(
                    baseline,
                    "idle_timeout",
                    True,
                    text,
                    100,
                    "deterministic",
                )

                recognized.add(text)

            elif lower.startswith("set system services ssh") and "rate-limit" in lower:
                match = re.search(r"rate-limit\s+(\d+)", lower)
                if match:
                    set_field(baseline, "ssh_rate_limit", int(match.group(1)), text, 100, "deterministic")
                    recognized.add(text)

            elif lower.startswith("set system login retry-options"):
                match = re.search(r"tries-before-disconnect\s+(\d+)", lower)
                if match:
                    set_field(baseline, "login_attempts", int(match.group(1)), text, 100, "deterministic")
                    recognized.add(text)

            elif lower.startswith("set system services reverse-telnet"):
                set_field(baseline, "reverse_telnet_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("delete system services reverse-telnet"):
                set_field(baseline, "reverse_telnet_disabled", True, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("set system services ftp"):
                set_field(baseline, "ftp_disabled", False, text, 100, "deterministic")
                recognized.add(text)

            elif lower.startswith("delete system services ftp"):
                set_field(baseline, "ftp_disabled", True, text, 100, "deterministic")
                recognized.add(text)

    if vendor == "Juniper":
        protocol = re.search(r"protocol-version\s+(v[12])\s*;", config.lower())
        if protocol:
            set_field(
                baseline,
                "ssh_version",
                protocol.group(1)[1:],
                protocol.group(0),
                100,
                "deterministic",
            )
            recognized.add(protocol.group(0))

        rate_limit = re.search(r"rate-limit\s+(\d+)\s*;", config.lower())
        if rate_limit:
            set_field(baseline, "ssh_rate_limit", int(rate_limit.group(1)), rate_limit.group(0), 100, "deterministic")
            recognized.add(rate_limit.group(0))

        attempts = re.search(r"tries-before-disconnect\s+(\d+)\s*;", config.lower())
        if attempts:
            set_field(baseline, "login_attempts", int(attempts.group(1)), attempts.group(0), 100, "deterministic")
            recognized.add(attempts.group(0))

        telnet = re.search(r"(?m)^\s*telnet\s*;", config.lower())
        set_field(
            baseline,
            "telnet_disabled",
            not bool(telnet),
            "telnet service absent" if not telnet else telnet.group(0).strip(),
            100,
            "deterministic",
        )

        reverse_telnet = "reverse-telnet" in config.lower()
        ftp = re.search(r"(?m)^\s*ftp\s*;", config.lower())
        set_field(
            baseline,
            "reverse_telnet_disabled",
            not reverse_telnet,
            "reverse-telnet service absent" if not reverse_telnet else "reverse-telnet;",
            100,
            "deterministic",
        )
        set_field(
            baseline,
            "ftp_disabled",
            not bool(ftp),
            "ftp service absent" if not ftp else ftp.group(0).strip(),
            100,
            "deterministic",
        )

    return recognized


# ============================================================
# SUPABASE TRAINING MAPPINGS
# ============================================================

def get_training_mappings(
    vendor: str,
) -> list[dict[str, Any]]:

    if supabase is not None:
        response = (
            supabase
            .table("mappings")
            .select("*")
            .execute()
        )
        mappings = response.data or []
    else:
        mappings = local_rows("SELECT * FROM mappings")

    return [
        row
        for row in mappings
        if row.get("vendor") in {
            vendor,
            "Unknown",
        }
    ]


def apply_training_mappings(
    lines: list[str],
    vendor: str,
    baseline: dict[str, Any],
) -> set[str]:

    matched: set[str] = set()

    mappings = get_training_mappings(vendor)

    for line in lines:

        canonical = " ".join(
            line.strip().lower().split()
        )

        for row in mappings:

            stored_command = " ".join(
                str(
                    row.get(
                        "raw_command",
                        "",
                    )
                )
                .strip()
                .lower()
                .split()
            )

            if canonical != stored_command:
                continue

            value = row.get(
                "observed_value"
            )

            if isinstance(value, str):

                try:
                    value = json.loads(value)
                except Exception:
                    pass

            set_field(
                baseline,
                row["field_name"],
                value,
                line,
                float(
                    row.get(
                        "confidence",
                        92,
                    )
                ),
                "trained_mapping",
            )

            matched.add(
                line.strip()
            )

    return matched


# ============================================================
# REMEDIATION
# ============================================================

def remediation(
    vendor: str,
    field: str,
) -> str:

    return (
        REMEDIATIONS
        .get(vendor, {})
        .get(
            field,
            "AI-suggested remediation: "
            "verify vendor syntax before applying.",
        )
    )


# ============================================================
# CONTROL EVALUATION
# ============================================================

def evaluate(
    baseline: dict[str, Any],
    vendor: str,
    framework: str,
) -> tuple[list[dict[str, Any]], int]:

    framework_id = FRAMEWORK_IDS.get(
        framework,
        framework,
    )

    controls: list[dict[str, Any]] = []

    passed = 0

    for index, (
        field,
        requirement,
        expected,
        severity,
        category,
    ) in enumerate(
        CONTROL_CATALOG,
        start=1,
    ):

        item = baseline[field]

        applicable = field in CONTROL_VENDOR_APPLICABILITY.get(
            vendor,
            {catalog_field for catalog_field, *_ in CONTROL_CATALOG},
        )

        value = item["value"]

        if not applicable:
            result = "Not Applicable"
        elif value == expected:
            result = "Pass"

        elif value is None:
            result = "Warning"

        else:
            result = "Fail"

        if result == "Pass":
            passed += 1

        control_id = (
            f"{framework_id}-{index:02d}"
        )

        references = CONTROL_REFERENCES.get(field, {})
        framework_reference = references.get(framework_id, references.get("CIS", "Reference N/A"))
        mapping_status = "Mapped" if framework_id in references else "Unmapped"

        controls.append(
            {
                "id": control_id,
            "controlKey": field,
                "framework": framework,
            "frameworkId": framework_id,
                "field": field,
                "requirement": requirement,
                "result": result,
                "severity": severity,
                "category": category,
                "reference": framework_reference,
                "references": [framework_reference],
                "mappingStatus": mapping_status,
                "applicability": "Applicable" if applicable else "Not Applicable",
                "evidence": (
                    item["evidence"][0]
                    if item["evidence"]
                    else "No matching configuration evidence found"
                ),
                "confidence": item[
                    "confidence"
                ],
                "confidence_source": item[
                    "source"
                ],
                "evidenceSource": item["source"],
                "trainingApplied": item["source"] == "trained_mapping",
                "remediationSource": "vendor-specific" if vendor in REMEDIATIONS and field in REMEDIATIONS[vendor] else "generic guidance",
                "remediation": remediation(
                    vendor,
                    field,
                ),
            }
        )

    applicable_count = sum(
        field in CONTROL_VENDOR_APPLICABILITY.get(
            vendor,
            {catalog_field for catalog_field, *_ in CONTROL_CATALOG},
        )
        for field, *_ in CONTROL_CATALOG
    )
    score = round(passed / applicable_count * 100) if applicable_count else 0

    return controls, score


# ============================================================
# ANALYSIS ENGINE
# ============================================================

def infer_unknown_mapping(line: str, vendor: str | None = None) -> str | None:
    text = line.strip().lower()
    if not text or text.startswith(("!", "#", "end", "exit")):
        return None

    if "ssh" in text and ("version" in text or "protocol-version" in text):
        return "ssh_version"
    if "telnet" in text:
        return "telnet_disabled"
    if "http" in text or "web-management" in text or "admin-http" in text:
        return "http_disabled"
    if "logging" in text or "syslog" in text:
        return "logging_enabled"
    if "ntp" in text:
        return "ntp_configured"
    if "aaa" in text or "radius" in text or "tacacs" in text:
        return "aaa_enabled"
    if "idle-timeout" in text or "admintimeout" in text or "exec-timeout" in text:
        return "idle_timeout"
    if "source-route" in text or "source route" in text:
        return "source_routing_disabled"
    if "proxy-arp" in text:
        return "proxy_arp_disabled"
    if "retry-options" in text or "login attempts" in text or "tries-before-disconnect" in text:
        return "login_attempts"
    if "rate-limit" in text:
        return "ssh_rate_limit"
    if "reverse-telnet" in text:
        return "reverse_telnet_disabled"
    if "ftp" in text:
        return "ftp_disabled"
    if "community" in text or "snmp" in text:
        return "snmp_secure"
    return None


@app.post("/api/training-mappings/suggest")
def suggest_training_mapping(
    payload: MappingSuggestionRequest,
) -> dict[str, Any]:
    command = payload.raw_command.strip()
    field_name = infer_unknown_mapping(command, payload.vendor)

    if field_name is None:
        raise HTTPException(
            status_code=422,
            detail="No explainable baseline mapping could be suggested for this command",
        )

    lowered = command.lower()
    if field_name == "ssh_version":
        version_match = re.search(r"(?:version|protocol-version)\s+([\w.-]+)", lowered)
        observed_value: Any = version_match.group(1) if version_match else "unknown"
    elif field_name.endswith("_disabled"):
        observed_value = any(token in lowered for token in ("disable", "disabled", "no ", "undo "))
    else:
        observed_value = True

    return {
        "raw_command": command,
        "vendor": payload.vendor.strip() or "Unknown",
        "field_name": field_name,
        "observed_value": observed_value,
        "meaning": f"Explainable heuristic suggests this command controls {field_name}.",
        "confidence": 72,
        "confidence_source": "keyword_heuristic",
        "reason": "Matched a known security keyword; reviewer approval is required before persistence.",
        "status": "Pending Approval",
    }


def analyze(
    filename: str,
    config: str,
    framework: str,
    requested_vendor: str | None,
) -> dict[str, Any]:

    vendor = detect_vendor(
        config,
        requested_vendor,
    )

    baseline = empty_baseline()

    recognized = parse_known(
        config,
        vendor,
        baseline,
    )

    mapped = apply_training_mappings(
        config.splitlines(),
        vendor,
        baseline,
    )

    unknown = [
        line.strip()
        for line in config.splitlines()
        if (
            line.strip()
            and line.strip() not in recognized
            and line.strip() not in mapped
            and not line.strip().startswith(
                (
                    "!",
                    "#",
                    "end",
                    "exit",
                )
            )
        )
    ]

    heuristic_suggestions = []
    for line in config.splitlines():
        command = line.strip()
        if not command:
            continue
        field_name = infer_unknown_mapping(command, vendor)
        if field_name and command not in recognized and command not in mapped:
            heuristic_suggestions.append(
                {
                    "raw_command": command,
                    "suggested_field": field_name,
                    "confidence": 72,
                    "reason": "Keyword match from vendor-agnostic security heuristic",
                }
            )

    controls, score = evaluate(
        baseline,
        vendor,
        framework,
    )

    counts = {
        result: sum(
            control["result"] == result
            for control in controls
        )
        for result in (
            "Pass",
            "Fail",
            "Warning",
        )
    }

    evidence_summary = {
        "controlsWithEvidence": sum(
            control["evidence"] != "No matching configuration evidence found"
            for control in controls
        ),
        "controlsWithoutEvidence": sum(
            control["evidence"] == "No matching configuration evidence found"
            for control in controls
        ),
        "deterministicControls": sum(
            control["evidenceSource"] == "deterministic"
            for control in controls
        ),
        "trainedMappingControls": sum(
            control["evidenceSource"] == "trained_mapping"
            for control in controls
        ),
        "averageConfidence": round(
            sum(control["confidence"] for control in controls) / len(controls)
        ) if controls else 0,
    }

    if score >= 85:
        risk = "Low"
    elif score >= 65:
        risk = "Moderate"
    elif score >= 40:
        risk = "High"
    else:
        risk = "Critical"

    hostname = next(
        (
            line.split(
                maxsplit=1
            )[1]
            for line in config.splitlines()
            if line.strip()
            .lower()
            .startswith("hostname ")
        ),
        Path(filename).stem,
    )

    ip_address = next(
        (
            match.group(1)
            for line in config.splitlines()
            if (match := re.search(r"(?:\bip address\s+|\baddress\s+)(\d{1,3}(?:\.\d{1,3}){3})\b", line, re.I))
        ),
        "Not detected",
    )

    serial_number = next(
        (
            match.group(1)
            for line in config.splitlines()
            if (match := re.search(r"\b(?:serial(?:-number)?|chassis\s+serial)\s+[:=]?\s*([\w.-]+)", line, re.I))
        ),
        "Not detected",
    )

    model = next(
        (
            match.group(1).strip()
            for line in config.splitlines()
            if (match := re.search(r"^\s*model\s+(.+)$", line, re.I))
        ),
        "Not detected",
    )

    firmware = next(
        (
            line.split(
                maxsplit=1
            )[1]
            for line in config.splitlines()
            if line.strip()
            .lower()
            .startswith("version ")
        ),
        "Not detected",
    )

    result = {
        "id": (
            f"analysis-"
            f"{uuid.uuid4().hex[:12]}"
        ),

        "fileName": filename,

        "vendor": vendor,

        "framework": framework,

        "createdAt": now(),

        "device": {
            "name": hostname,
            "model": model,
            "firmware": firmware,
            "serialNumber": serial_number,
            "ipAddress": ip_address,
            "deviceType": "Router" if vendor in {"Cisco", "Juniper"} else "Network device",
        },

        "overallScore": score,

        "riskLevel": risk,

        "controlsChecked":
            len(controls),

        "passed":
            counts["Pass"],

        "failed":
            counts["Fail"],

        "warnings":
            counts["Warning"],

        "evidenceSummary":
            evidence_summary,

        "baseline":
            baseline,

        "controls":
            controls,

        "unknownLines":
            unknown[:100],

        "heuristicSuggestions":
            heuristic_suggestions[:20],

        "summary":
            (
                f"{vendor} configuration "
                f"normalized into the Security "
                f"Baseline Model and evaluated "
                f"against {framework}."
            ),
    }
    result["evidenceHash"] = evidence_hash(result)
    result["hashAlgorithm"] = "SHA-256"
    return result


# ============================================================
# DEVICE NORMALIZATION
# ============================================================

def normalize_device(
    analysis: dict[str, Any],
) -> dict[str, Any]:

    device = analysis.get("device")

    if (
        isinstance(device, dict)
        and device.get("name")
    ):

        return {
            "name":
                device.get("name"),

            "model":
                device.get(
                    "model",
                    "Not detected",
                ),

            "firmware":
                device.get(
                    "firmware",
                    "Not detected",
                ),

            "serialNumber":
                device.get(
                    "serialNumber",
                    "Not available",
                ),

            "ipAddress": device.get("ipAddress", "Not detected"),

            "deviceType": device.get("deviceType", "Network device"),
        }

    name = (
        analysis.get("fileName")
        or analysis.get("id")
        or "Unknown"
    )

    return {
        "name":
            Path(name).stem,

        "model":
            "Not detected",

        "firmware":
            "Not detected",

        "serialNumber":
            "Not available",

        "ipAddress": "Not detected",

        "deviceType": "Network device",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health() -> dict[str, Any]:

    return {
        "status": "operational",
    }


@app.post("/api/auth/login")
def login(request: Request, payload: LoginRequest) -> dict[str, Any]:
    client_id = request.client.host if request.client else "unknown"
    now_timestamp = time.time()
    window_seconds = int(os.getenv("NETSECURE_LOGIN_WINDOW_SECONDS", "60"))
    max_attempts = int(os.getenv("NETSECURE_LOGIN_MAX_ATTEMPTS", "5"))
    recent_attempts = [
        timestamp
        for timestamp in LOGIN_ATTEMPTS.get(client_id, [])
        if now_timestamp - timestamp < window_seconds
    ]
    if len(recent_attempts) >= max_attempts:
        raise HTTPException(status_code=429, detail="Too many login attempts; try again later")

    secret = os.getenv("NETSECURE_AUTH_SECRET", "local-development-secret")

    accounts = [
        (
            os.getenv("NETSECURE_ADMIN_USERNAME", "admin"),
            os.getenv("NETSECURE_ADMIN_PASSWORD", "admin@123"),
            os.getenv("NETSECURE_ADMIN_ROLE", "admin"),
        ),
        (
            os.getenv("NETSECURE_VIEWER_USERNAME", ""),
            os.getenv("NETSECURE_VIEWER_PASSWORD", ""),
            "viewer",
        ),
        (
            os.getenv("NETSECURE_AUDITOR_USERNAME", ""),
            os.getenv("NETSECURE_AUDITOR_PASSWORD", ""),
            "auditor",
        ),
    ]
    matched_account = next(
        (
            account
            for account in accounts
            if account[0]
            and hmac.compare_digest(payload.username, account[0])
            and hmac.compare_digest(payload.password, account[1])
        ),
        None,
    )

    if matched_account is None:
        recent_attempts.append(now_timestamp)
        LOGIN_ATTEMPTS[client_id] = recent_attempts
        raise HTTPException(status_code=401, detail="Incorrect ID or password")

    LOGIN_ATTEMPTS.pop(client_id, None)
    role = matched_account[2]
    return {
        "access_token": create_session_token(payload.username, role, secret),
        "token_type": "bearer",
        "user": payload.username,
        "role": role,
    }


# ============================================================
# STORAGE INFO
# ============================================================

@app.get("/api/storage-info")
def storage_info() -> dict[str, Any]:

    audit_events_configured = None
    if supabase is not None:
        try:
            supabase.table("audit_events").select("id").limit(1).execute()
            audit_events_configured = True
        except Exception:
            audit_events_configured = False

    return {
        "storage_provider":
            "Supabase Storage",

        "supabase_configured":
            supabase is not None,

        "supabase_bucket":
            SUPABASE_BUCKET,

        "audit_events_configured":
            audit_events_configured,
    }


# ============================================================
# UPLOAD + ANALYZE
# ============================================================

@app.post("/api/analyses/upload")
async def upload_analysis(
    file: UploadFile = File(...),
    framework: str = Form(
        "CIS Benchmarks"
    ),
    vendor: str = Form(
        "Auto"
    ),
    device_model: str = Form(""),
    device_serial: str = Form(""),
    device_ip: str = Form(""),
) -> dict[str, Any]:

    client = supabase

    filename = (
        file.filename
        or "config.txt"
    )

    allowed_extensions = {
        ".txt",
        ".cfg",
        ".conf",
        ".log",
    }

    if (
        Path(filename)
        .suffix
        .lower()
        not in allowed_extensions
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Only .txt, .cfg, "
                ".conf, and .log "
                "configuration exports "
                "are accepted."
            ),
        )

    raw = (
        await file.read()
    ).decode(
        "utf-8",
        errors="replace",
    )

    # Analyze sanitized configuration
    result = analyze(
        filename,
        redact(raw),
        framework,
        vendor,
    )

    if device_model.strip():
        result["device"]["model"] = device_model.strip()
    if device_serial.strip():
        result["device"]["serialNumber"] = device_serial.strip()
    if device_ip.strip():
        result["device"]["ipAddress"] = device_ip.strip()

    analysis_id = result["id"]

    # Storage filename
    stored_name = (
        f"{analysis_id}_"
        f"{Path(filename).name}"
    )

    upload_url = (
        f"/api/analyses/"
        f"{analysis_id}/raw"
    )

    if client is None:
        try:
            (UPLOADS_DIR / stored_name).write_bytes(raw.encode("utf-8"))
            with sqlite3.connect(LOCAL_DB) as connection:
                connection.execute(
                    """
                    INSERT INTO analyses
                    (id, filename, vendor, framework, created_at, result_json, upload_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result["id"],
                        result["fileName"],
                        result["vendor"],
                        result["framework"],
                        result["createdAt"],
                        json.dumps(result),
                        upload_url,
                    ),
                )
                connection.commit()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not save local analysis: {exc}")

        result["upload_url"] = upload_url
        record_audit_event(
            "Analysis completed",
            result["fileName"],
            device=result["device"].get("name", "Unknown"),
        )
        return result

    # --------------------------------------------------------
    # SUPABASE STORAGE
    # --------------------------------------------------------

    try:

        client.storage \
            .from_(SUPABASE_BUCKET) \
            .upload(
                stored_name,
                raw.encode("utf-8"),
                {
                    "content-type":
                        "text/plain",
                    "upsert":
                        "true",
                },
            )

        print(
            "Supabase Storage upload successful:",
            stored_name,
        )

    except Exception as exc:

        print(
            "Supabase Storage upload failed:",
            exc,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Supabase Storage upload failed: "
                f"{exc}"
            ),
        )

    # --------------------------------------------------------
    # SUPABASE DATABASE
    # --------------------------------------------------------

    record = {
        "id":
            result["id"],

        "filename":
            result["fileName"],

        "vendor":
            result["vendor"],

        "framework":
            result["framework"],

        "created_at":
            result["createdAt"],

        "result_json":
            result,

        "upload_url":
            upload_url,
    }

    try:

        client \
            .table("analyses") \
            .upsert(record) \
            .execute()

        print(
            "Analysis saved to Supabase:",
            analysis_id,
        )

    except Exception as exc:

        print(
            "Supabase database insert failed:",
            exc,
        )

        # Try to remove the orphaned file
        try:

            client.storage \
                .from_(SUPABASE_BUCKET) \
                .remove(
                    [stored_name]
                )

        except Exception:
            pass

        raise HTTPException(
            status_code=500,
            detail=(
                "Could not save analysis "
                f"to Supabase: {exc}"
            ),
        )

    result["upload_url"] = upload_url

    return result


@app.get("/api/audit-logs")
def list_audit_logs() -> list[dict[str, Any]]:
    if supabase is not None:
        try:
            response = supabase.table("audit_events").select("*").order("timestamp", desc=True).execute()
        except Exception as exc:
            logger.warning("Supabase audit_events table unavailable: %s", type(exc).__name__)
            return []
        rows = response.data or []
        return [
            {
                **row,
                "ipAddress": row.get("ip_address", "Unknown"),
            }
            for row in rows
        ]

    ensure_local_audit_table()
    return [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "user": row["user"],
            "action": row["action"],
            "resource": row["resource"],
            "device": row["device"],
            "result": row["result"],
            "ipAddress": row["ip_address"],
        }
        for row in local_rows(
            "SELECT * FROM audit_events ORDER BY timestamp DESC"
        )
    ]


# ============================================================
# FRONTEND COMPATIBILITY ALIAS
# ============================================================

@app.post("/api/configurations/upload")
async def upload_configuration(
    file: UploadFile = File(...),
    framework: str = Form(
        "CIS Benchmarks"
    ),
    vendor: str = Form(
        "Auto"
    ),
) -> dict[str, Any]:

    return await upload_analysis(
        file=file,
        framework=framework,
        vendor=vendor,
    )


@app.post("/api/analyses/upload-batch")
async def upload_analysis_batch(
    files: list[UploadFile] = File(...),
    framework: str = Form("CIS Benchmarks"),
    vendor: str = Form("Auto"),
    device_model: str = Form(""),
    device_serial: str = Form(""),
    device_ip: str = Form(""),
) -> list[dict[str, Any]]:
    if not files:
        raise HTTPException(status_code=400, detail="At least one configuration file is required.")

    return [
        await upload_analysis(
            file=file,
            framework=framework,
            vendor=vendor,
            device_model=device_model,
            device_serial=device_serial,
            device_ip=device_ip,
        )
        for file in files
    ]


# ============================================================
# DOWNLOAD ORIGINAL CONFIGURATION
# ============================================================

@app.get(
    "/api/analyses/{analysis_id}/raw"
)
def download_raw_analysis(
    analysis_id: str,
):

    if supabase is None:
        analyses = local_rows(
            "SELECT filename FROM analyses WHERE id = ? LIMIT 1",
            (analysis_id,),
        )
        if not analyses:
            raise HTTPException(status_code=404, detail="Analysis not found")

        filename = Path(analyses[0].get("filename") or "configuration.txt").name
        local_path = UPLOADS_DIR / f"{analysis_id}_{filename}"
        if not local_path.exists():
            raise HTTPException(status_code=404, detail="Raw configuration not found")

        return StreamingResponse(
            io.BytesIO(local_path.read_bytes()),
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    client = require_supabase()

    response = (
        client
        .table("analyses")
        .select(
            "filename"
        )
        .eq(
            "id",
            analysis_id,
        )
        .limit(1)
        .execute()
    )

    if not response.data:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found",
        )

    filename = (
        response.data[0]
        .get("filename")
        or "configuration.txt"
    )

    storage_path = (
        f"{analysis_id}_"
        f"{Path(filename).name}"
    )

    try:

        file_bytes = (
            client
            .storage
            .from_(SUPABASE_BUCKET)
            .download(storage_path)
        )

        return StreamingResponse(
            io.BytesIO(file_bytes),
            media_type="text/plain",
            headers={
                "Content-Disposition":
                    (
                        f'attachment; '
                        f'filename="{Path(filename).name}"'
                    )
            },
        )

    except Exception as exc:

        print(
            "Supabase download failed:",
            exc,
        )

        raise HTTPException(
            status_code=404,
            detail=(
                "Raw configuration not found "
                f"in Supabase Storage: {exc}"
            ),
        )


# ============================================================
# GET ALL ANALYSES FROM SUPABASE
# ============================================================

def all_analyses() -> list[dict[str, Any]]:

    if supabase is not None:
        response = (
            supabase
            .table("analyses")
            .select(
                """
                id,
                filename,
                vendor,
                framework,
                created_at,
                result_json,
                upload_url
                """
            )
            .order(
                "created_at",
                desc=True,
            )
            .execute()
        )
        rows = response.data or []
    else:
        rows = local_rows(
            """
            SELECT id, filename, vendor, framework, created_at,
                   result_json, upload_url
            FROM analyses
            ORDER BY created_at DESC
            """
        )

    output: list[
        dict[str, Any]
    ] = []

    for row in rows:

        result = row.get(
            "result_json"
        )

        if isinstance(
            result,
            str,
        ):

            try:
                result = json.loads(
                    result
                )
            except Exception:
                result = {}

        if not isinstance(
            result,
            dict,
        ):
            result = {}

        # Ensure metadata exists
        result["id"] = row["id"]

        result["fileName"] = (
            row["filename"]
        )

        result["vendor"] = (
            row["vendor"]
        )

        result["framework"] = (
            row["framework"]
        )

        result["createdAt"] = (
            row["created_at"]
        )

        result["upload_url"] = (
            row.get("upload_url")
        )

        output.append(result)

    return output


# ============================================================
# GET ALL ANALYSES
# ============================================================

@app.get("/api/analyses")
def list_analyses() -> list[
    dict[str, Any]
]:

    return all_analyses()


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/api/dashboard")
def dashboard() -> dict[str, Any]:

    analyses = all_analyses()

    latest_by_device: dict[
        str,
        dict[str, Any],
    ] = {}

    for analysis in analyses:

        device = normalize_device(
            analysis
        )

        latest_by_device.setdefault(
            device["name"],
            analysis,
        )

    current = list(
        latest_by_device.values()
    )

    findings = [
        control
        for analysis in current
        for control in analysis.get(
            "controls",
            [],
        )
        if control.get("result") in {"Fail", "Warning"}
    ]

    if current:

        average = round(
            sum(
                item.get(
                    "overallScore",
                    0,
                )
                for item in current
            )
            / len(current)
        )

    else:
        average = 0

    severity = {
        level: sum(
            control.get(
                "severity"
            ) == level
            for control in findings
        )
        for level in (
            "Critical",
            "High",
            "Medium",
            "Low",
        )
    }

    vendor_groups: dict[
        str,
        list[int],
    ] = {}

    framework_groups: dict[
        str,
        list[int],
    ] = {}

    for item in current:

        vendor_groups.setdefault(
            item.get(
                "vendor",
                "Unknown",
            ),
            [],
        ).append(
            item.get(
                "overallScore",
                0,
            )
        )

        framework_groups.setdefault(
            item.get(
                "framework",
                "Unknown",
            ),
            [],
        ).append(
            item.get(
                "overallScore",
                0,
            )
        )

    return {
        "totalDevices":
            len(current),

        "configurationsAnalyzed":
            len(analyses),

        "overallScore":
            average,

        "openFindings":
            len(findings),

        "severityBreakdown": [
            {
                "name": level,
                "value": severity[level],
            }
            for level in severity
        ],

        "recentActivity": [
            {
                "id":
                    item["id"],

                "device":
                    normalize_device(
                        item
                    )["name"],

                "vendor":
                    item["vendor"],

                "framework":
                    item["framework"],

                "score":
                    item["overallScore"],

                "status":
                    (
                        "Compliant"
                        if item["overallScore"] >= 85
                        else
                        "Warning"
                        if item["overallScore"] >= 65
                        else
                        "Non-Compliant"
                    ),

                "date":
                    item["createdAt"],
            }
            for item in analyses[:8]
        ],

        "vendorCompliance": [
            {
                "name":
                    name,

                "score":
                    round(
                        sum(scores)
                        / len(scores)
                    ),
            }
            for name, scores
            in vendor_groups.items()
        ],

        "frameworkComparison": [
            {
                "name":
                    name,

                "score":
                    round(
                        sum(scores)
                        / len(scores)
                    ),
            }
            for name, scores
            in framework_groups.items()
        ],
    }


# ============================================================
# DEVICES
# ============================================================

@app.get("/api/devices")
def devices() -> list[
    dict[str, Any]
]:

    latest: dict[
        str,
        dict[str, Any],
    ] = {}

    for analysis in all_analyses():

        device = normalize_device(
            analysis
        )

        latest.setdefault(
            device["name"],
            analysis,
        )

    output = []

    for item in latest.values():

        device = normalize_device(
            item
        )

        score = item.get(
            "overallScore",
            0,
        )

        if score >= 85:
            status = "Compliant"
        elif score >= 65:
            status = "Warning"
        else:
            status = "Non-Compliant"

        output.append(
            {
                "id":
                    item["id"],

                "name":
                    device["name"],

                "vendor":
                    item["vendor"],

                "model":
                    device["model"],

                "serialNumber":
                    device["serialNumber"],

                "firmware":
                    device["firmware"],

                "ipAddress":
                    device.get("ipAddress", "Not detected"),

                "deviceType":
                    device.get("deviceType", "Network device"),

                "complianceScore":
                    score,

                "risk":
                    item.get(
                        "riskLevel",
                        "Unknown",
                    ),

                "lastScan":
                    item["createdAt"],

                "status":
                    status,

                "location":
                    "Not detected",
            }
        )

    return output


# ============================================================
# FINDINGS
# ============================================================

@app.get("/api/findings")
def findings() -> list[
    dict[str, Any]
]:

    output: list[
        dict[str, Any]
    ] = []

    for analysis in all_analyses():

        device = normalize_device(
            analysis
        )

        for control in analysis.get(
            "controls",
            [],
        ):

            if control.get("result") in {"Pass", "Not Applicable"}:

                continue

            output.append(
                {
                    "id":
                        (
                            f"{analysis['id']}:"
                            f"{control['id']}"
                        ),

                    "analysisId":
                        analysis["id"],

                    "title":
                        control["requirement"],

                    "device":
                        device["name"],

                    "vendor":
                        analysis["vendor"],

                    "framework":
                        control["framework"],

                    "severity":
                        control["severity"],

                    "category":
                        control["category"],

                    "status":
                        "Open",

                    "detected":
                        analysis["createdAt"],

                    "action":
                        control["remediation"],

                    "riskScore":
                        100
                        - analysis[
                            "overallScore"
                        ],

                    "controlId":
                        control["id"],

                    "description":
                        control["requirement"],

                    "whyItMatters":
                        (
                            "The observed "
                            "configuration does "
                            "not meet the selected "
                            "baseline."
                        ),

                    "evidence":
                        control["evidence"],

                    "currentConfig":
                        control["evidence"],

                    "recommendedConfig":
                        control["remediation"],

                    "remediationCommand":
                        control["remediation"],

                    "references":
                        [
                            control["framework"]
                        ],

                    "confidence":
                        control["confidence"],

                    "confidenceSource":
                        control[
                            "confidence_source"
                        ],
                }
            )

    return output


# ============================================================
# REPORTS
# ============================================================

@app.get("/api/reports")
def reports() -> list[
    dict[str, Any]
]:

    output = []

    for item in all_analyses():

        device = normalize_device(
            item
        )

        output.append(
            {
                "id":
                    item["id"],

                "name":
                    (
                        f"{device['name']} "
                        f"compliance report"
                    ),

                "device":
                    device["name"],

                "vendor":
                    item["vendor"],

                "framework":
                    item["framework"],

                "complianceScore":
                    item["overallScore"],

                "generatedDate":
                    item["createdAt"],

                "status":
                    "Ready",
            }
        )

    return output


# ============================================================
# FRAMEWORKS
# ============================================================

@app.get("/api/vendors")
def list_vendors() -> list[dict[str, Any]]:
    return VENDOR_SUPPORT

@app.get("/api/frameworks")
def list_frameworks() -> list[
    dict[str, Any]
]:

    frameworks = []

    for name, framework_id in (
        FRAMEWORK_IDS.items()
    ):

        mapped_controls = [
            field
            for field, references in CONTROL_REFERENCES.items()
            if framework_id in references
        ]
        metadata = FRAMEWORK_METADATA.get(framework_id, {})

        frameworks.append(
            {
                "id":
                    framework_id,

                "name":
                    name,

                "controls":
                    len(mapped_controls),

                "activeRules":
                    len(mapped_controls),

                "description":
                    metadata.get("source", f"{name} controls"),

                "version":
                    metadata.get("version", "Not specified"),

                "authorityUrl":
                    metadata.get("authorityUrl", ""),

                "reviewStatus":
                    metadata.get("reviewStatus", "Review required"),

                "scope":
                    metadata.get("scope", "Not specified"),

                "mappedControls":
                    mapped_controls,

                "status":
                    "Healthy",

                "lastUpdated":
                    now(),
            }
        )

    return frameworks


# ============================================================
# GET SINGLE ANALYSIS
# ============================================================

@app.get(
    "/api/analyses/{analysis_id}"
)
def get_analysis(
    analysis_id: str,
) -> dict[str, Any]:

    if supabase is None:
        analysis = next(
            (item for item in all_analyses() if item.get("id") == analysis_id),
            None,
        )
        if analysis is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return analysis

    client = require_supabase()

    response = (
        client
        .table("analyses")
        .select("result_json")
        .eq(
            "id",
            analysis_id,
        )
        .limit(1)
        .execute()
    )

    if not response.data:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found",
        )

    result = response.data[0].get(
        "result_json"
    )

    if isinstance(
        result,
        str,
    ):

        try:
            result = json.loads(
                result
            )
        except Exception:
            result = {}

    if not isinstance(
        result,
        dict,
    ):

        raise HTTPException(
            status_code=500,
            detail="Invalid analysis data",
        )

    return result


# ============================================================
# TRAINING MAPPINGS - LIST
# ============================================================

@app.get(
    "/api/training-mappings"
)
def list_mappings() -> list[
    dict[str, Any]
]:

    if supabase is None:
        return local_rows("SELECT * FROM mappings ORDER BY created_at DESC")

    client = require_supabase()

    response = (
        client
        .table("mappings")
        .select("*")
        .order(
            "created_at",
            desc=True,
        )
        .execute()
    )

    output = []

    for row in (
        response.data or []
    ):

        value = row.get(
            "observed_value"
        )

        if isinstance(
            value,
            str,
        ):

            try:
                value = json.loads(
                    value
                )
            except Exception:
                pass

        row["observed_value"] = value

        output.append(row)

    return output


# ============================================================
# TRAINING MAPPINGS - CREATE
# ============================================================

@app.post(
    "/api/training-mappings",
    status_code=201,
)
def create_mapping(
    request: Request,
    payload: TrainingMapping,
) -> dict[str, Any]:

    authenticated_user = getattr(request.state, "user", None)
    if authenticated_user and authenticated_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")

    valid_fields = {
        item[0]
        for item in CONTROL_CATALOG
    }

    if (
        payload.field_name
        not in valid_fields
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "field_name must be "
                "a Security Baseline "
                "Model field"
            ),
        )

    record = {
        "id":
            f"mapping-"
            f"{uuid.uuid4().hex[:12]}",

        "raw_command":
            payload.raw_command.strip(),

        "vendor":
            payload.vendor.strip()
            or "Unknown",

        "field_name":
            payload.field_name,

        "observed_value":
            payload.observed_value,

        "meaning":
            payload.meaning.strip(),

        "confidence":
            payload.confidence,

        "created_at":
            now(),
    }

    if supabase is None:
        with sqlite3.connect(LOCAL_DB) as connection:
            connection.execute(
                """
                INSERT INTO mappings
                (id, raw_command, vendor, field_name, observed_value, meaning, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["raw_command"],
                    record["vendor"],
                    record["field_name"],
                    json.dumps(record["observed_value"]),
                    record["meaning"],
                    record["confidence"],
                    record["created_at"],
                ),
            )
            connection.commit()
        record_audit_event(
            "AI mapping created",
            record["raw_command"],
        )
        return record

    client = require_supabase()

    try:

        client \
            .table("mappings") \
            .insert(record) \
            .execute()

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Could not save training "
                f"mapping: {exc}"
            ),
        )

    return record


# ============================================================
# APPLY TRAINING MAPPINGS
# ============================================================

@app.post(
    "/api/training-mappings/apply"
)
def apply_mappings_endpoint(request: Request) -> dict[str, Any]:
    authenticated_user = getattr(request.state, "user", None)
    if authenticated_user and authenticated_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")

    if supabase is None:
        updated = 0
        for stored in all_analyses():
            analysis_id = stored.get("id")
            filename = stored.get("fileName", f"{analysis_id}.cfg")
            local_path = UPLOADS_DIR / f"{analysis_id}_{Path(filename).name}"
            if not analysis_id or not local_path.exists():
                continue

            try:
                new_result = analyze(
                    filename,
                    redact(local_path.read_text(encoding="utf-8", errors="replace")),
                    stored.get("framework", "CIS Benchmarks"),
                    stored.get("vendor", "Auto"),
                )
                new_result["id"] = analysis_id
                new_result["upload_url"] = stored.get("upload_url")
                with sqlite3.connect(LOCAL_DB) as connection:
                    connection.execute(
                        """
                        UPDATE analyses
                        SET vendor = ?, framework = ?, created_at = ?, result_json = ?
                        WHERE id = ?
                        """,
                        (
                            new_result["vendor"],
                            new_result["framework"],
                            new_result["createdAt"],
                            json.dumps(new_result),
                            analysis_id,
                        ),
                    )
                    connection.commit()
                updated += 1
            except Exception as exc:
                print(f"Could not re-analyze {analysis_id}: {exc}")

        return {"updated": updated}

    client = require_supabase()

    analyses = all_analyses()

    updated = 0

    for stored in analyses:

        analysis_id = stored.get(
            "id"
        )

        upload_url = stored.get(
            "upload_url"
        )

        if not upload_url:
            continue

        filename = stored.get(
            "fileName",
            f"{analysis_id}.cfg",
        )

        storage_path = (
            f"{analysis_id}_"
            f"{Path(filename).name}"
        )

        # ----------------------------------------------------
        # Download original configuration
        # ----------------------------------------------------

        try:

            raw_bytes = (
                client
                .storage
                .from_(SUPABASE_BUCKET)
                .download(storage_path)
            )

            raw_text = raw_bytes.decode(
                "utf-8",
                errors="replace",
            )

        except Exception as exc:

            print(
                "Could not read stored "
                f"configuration {analysis_id}: "
                f"{exc}"
            )

            continue

        # ----------------------------------------------------
        # Re-run analysis
        # ----------------------------------------------------

        try:

            framework = stored.get(
                "framework",
                "CIS Benchmarks",
            )

            vendor = stored.get(
                "vendor"
            )

            new_result = analyze(
                filename,
                redact(raw_text),
                framework,
                vendor,
            )

            new_result["upload_url"] = (
                upload_url
            )

            # ------------------------------------------------
            # Update Supabase
            # ------------------------------------------------

            client \
                .table("analyses") \
                .update(
                    {
                        "vendor":
                            new_result["vendor"],

                        "framework":
                            new_result["framework"],

                        "created_at":
                            new_result["createdAt"],

                        "result_json":
                            new_result,
                    }
                ) \
                .eq(
                    "id",
                    analysis_id,
                ) \
                .execute()

            updated += 1

        except Exception as exc:

            print(
                "Could not re-analyze "
                f"{analysis_id}: {exc}"
            )

            continue

    return {
        "updated":
            updated
    }


# ============================================================
# PDF REPORT
# ============================================================

@app.get(
    "/api/analyses/{analysis_id}/report.pdf"
)
def report(
    analysis_id: str,
) -> StreamingResponse:

    result = get_analysis(
        analysis_id
    )

    output = io.BytesIO()

    styles = (
        getSampleStyleSheet()
    )

    story = [
        Paragraph(
            "NetSecureAI Compliance Report",
            styles["Title"],
        ),
        Spacer(1, 12),
    ]

    story.append(
        Paragraph(
            (
                f"<b>Device/configuration:</b> "
                f"{escape(str(result['fileName']))}"
                f"<br/>"
                f"<b>Vendor:</b> "
                f"{escape(str(result['vendor']))}"
                f"<br/>"
                f"<b>Framework:</b> "
                f"{escape(str(result['framework']))}"
                f"<br/>"
                f"<b>Compliance score:</b> "
                f"{result['overallScore']}%"
                f"<br/>"
                f"<b>Evidence hash (SHA-256):</b> "
                f"{escape(str(result.get('evidenceHash', 'Not available')))}"
            ),
            styles["BodyText"],
        )
    )

    story.append(
        Spacer(1, 12)
    )

    rows = [
        [
            "Control",
            "Result",
            "Severity",
            "Confidence",
            "Evidence",
        ]
    ]

    for control in result.get(
        "controls",
        [],
    ):

        evidence = str(
            control.get(
                "evidence",
                "",
            )
        )

        rows.append(
            [
                control.get(
                    "id",
                    "",
                ),

                control.get(
                    "result",
                    "",
                ),

                control.get(
                    "severity",
                    "",
                ),

                (
                    f"{control.get('confidence', 0)}%"
                    f" ({control.get('confidence_source', '')})"
                ),

                evidence[:55],
            ]
        )

    table = Table(
        rows,
        repeatRows=1,
        colWidths=[
            60,
            45,
            55,
            110,
            250,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#123047"
                    ),
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.25,
                    colors.grey,
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7,
                ),

                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor(
                            "#f4f7fa"
                        ),
                    ],
                ),
            ]
        )
    )

    story.extend(
        [
            Paragraph(
                "Findings and evidence",
                styles["Heading2"],
            ),

            table,

            Spacer(1, 12),

            Paragraph(
                "Remediation paths",
                styles["Heading2"],
            ),
        ]
    )

    for control in result.get(
        "controls",
        [],
    ):

        if (
            control.get("result")
            == "Pass"
        ):
            continue

        requirement = escape(
            str(
                control.get(
                    "requirement",
                    "",
                )
            )
        )

        remediation_text = escape(
            str(
                control.get(
                    "remediation",
                    "",
                )
            )
        ).replace(
            "\n",
            "<br/>",
        )

        story.append(
            Paragraph(
                (
                    f"<b>"
                    f"{escape(str(control.get('id', '')))} "
                    f"— {requirement}"
                    f"</b>"
                    f"<br/>"
                    f"{remediation_text}"
                ),
                styles["BodyText"],
            )
        )

        story.append(
            Spacer(1, 6)
        )

    SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=28,
        leftMargin=28,
        topMargin=32,
        bottomMargin=32,
    ).build(
        story
    )

    output.seek(0)

    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                (
                    f'attachment; '
                    f'filename="{analysis_id}.pdf"'
                )
        },
    )