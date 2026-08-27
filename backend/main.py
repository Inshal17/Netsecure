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
import importlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
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

# Load backend/.env
load_dotenv(ROOT / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")
SUPABASE_BUCKET = os.getenv(
    "SUPABASE_BUCKET",
    "configurations",
)

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


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HELPERS
# ============================================================

def now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


# ============================================================
# FRAMEWORKS
# ============================================================

FRAMEWORK_IDS = {
    "CIS Benchmarks": "CIS",
    "NIST SP 800-53": "NIST",
    "DISA STIG": "STIG",
    "ISO/IEC 27001": "ISO",
}


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
        "set system" in lower
        or "junos:" in lower
        or "protocol-version v" in lower
        or "tries-before-disconnect" in lower
    ):
        return "Juniper"

    if "sonic" in lower:
        return "SONiC"

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

        value = item["value"]

        if value == expected:
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

        controls.append(
            {
                "id": control_id,
                "framework": framework,
                "field": field,
                "requirement": requirement,
                "result": result,
                "severity": severity,
                "category": category,
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
                "remediation": remediation(
                    vendor,
                    field,
                ),
            }
        )

    score = round(
        passed
        / len(CONTROL_CATALOG)
        * 100
    )

    return controls, score


# ============================================================
# ANALYSIS ENGINE
# ============================================================

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

    return {
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

        "baseline":
            baseline,

        "controls":
            controls,

        "unknownLines":
            unknown[:100],

        "summary":
            (
                f"{vendor} configuration "
                f"normalized into the Security "
                f"Baseline Model and evaluated "
                f"against {framework}."
            ),
    }


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


# ============================================================
# STORAGE INFO
# ============================================================

@app.get("/api/storage-info")
def storage_info() -> dict[str, Any]:

    return {
        "storage_provider":
            "Supabase Storage",

        "supabase_configured":
            supabase is not None,

        "supabase_bucket":
            SUPABASE_BUCKET,
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
        if control.get(
            "result"
        ) != "Pass"
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

            if control.get(
                "result"
            ) == "Pass":

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

@app.get("/api/frameworks")
def list_frameworks() -> list[
    dict[str, Any]
]:

    frameworks = []

    controls_count = len(
        CONTROL_CATALOG
    )

    for name, framework_id in (
        FRAMEWORK_IDS.items()
    ):

        frameworks.append(
            {
                "id":
                    framework_id,

                "name":
                    name,

                "controls":
                    controls_count,

                "activeRules":
                    controls_count,

                "description":
                    f"{name} controls",

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
    payload: TrainingMapping,
) -> dict[str, Any]:

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
def apply_mappings_endpoint() -> dict[str, Any]:

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