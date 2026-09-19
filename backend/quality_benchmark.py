"""Deterministic quality benchmark for the compliance engine."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


BENCHMARK_CASES = (
    {
        "id": "cisco-secure-baseline",
        "vendor": "Cisco",
        "config": "hostname EDGE\nversion 17.9\nip ssh version 2\nlogging enable\nlogging host 192.0.2.10\nntp authenticate\n",
        "expected_pass": ("ssh_version", "logging_enabled", "ntp_authenticated"),
    },
    {
        "id": "juniper-insecure-services",
        "vendor": "Juniper",
        "config": "version 23.4R1\nsystem {\n services {\n  ssh { protocol-version v1; }\n  telnet;\n  ftp;\n }\n}\n",
        "expected_fail": ("ssh_version", "telnet_disabled", "ftp_disabled"),
    },
    {
        "id": "arista-management-controls",
        "vendor": "Arista",
        "config": "! device: Arista EOS\n! software image version: 4.31.2F\nhostname EDGE\nno management telnet\nmanagement ssh\n",
        "expected_pass": ("telnet_disabled", "ssh_version"),
    },
    {
        "id": "sonic-management-controls",
        "vendor": "SONiC",
        "config": "SONiC-OS 202411\nset mgmt timeout 10\nset mgmt telnet disable\nset mgmt http disable\n",
        "expected_pass": ("telnet_disabled", "http_disabled", "idle_timeout"),
    },
)


def run_benchmark(analyze: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    case_results: list[dict[str, Any]] = []
    vendor_hits = 0
    control_checks = 0
    control_hits = 0
    evidence_checks = 0
    evidence_hits = 0
    version_checks = 0
    version_hits = 0

    for case in BENCHMARK_CASES:
        result = analyze(
            f"{case['id']}.cfg",
            case["config"],
            "CIS Benchmarks",
            "Auto",
        )
        controls = {item["field"]: item for item in result["controls"]}
        expected_statuses = {
            **{field: "Pass" for field in case.get("expected_pass", ())},
            **{field: "Fail" for field in case.get("expected_fail", ())},
        }
        assertions = []
        for field, expected_status in expected_statuses.items():
            control = controls.get(field)
            status_match = control is not None and control["result"] == expected_status
            evidence_match = status_match and control["evidence"] != "No matching configuration evidence found"
            control_checks += 1
            control_hits += status_match
            evidence_checks += 1
            evidence_hits += evidence_match
            assertions.append({
                "field": field,
                "expected": expected_status,
                "actual": control["result"] if control else "Missing",
                "passed": status_match,
                "hasEvidence": evidence_match,
            })

        expected_vendor = case["vendor"]
        vendor_match = result["vendor"] == expected_vendor
        vendor_hits += vendor_match
        expected_version = True
        version_match = result["device"]["versionConfidence"] > 0
        version_checks += expected_version
        version_hits += version_match if expected_version else 0
        case_results.append({
            "id": case["id"],
            "vendorExpected": expected_vendor,
            "vendorActual": result["vendor"],
            "vendorDetected": vendor_match,
            "version": result["device"]["firmware"],
            "versionConfidence": result["device"]["versionConfidence"],
            "versionExpected": expected_version,
            "versionDetected": version_match,
            "assertions": assertions,
        })

    percentage = lambda hits, total: round(hits / total * 100, 1) if total else 0
    return {
        "cases": len(BENCHMARK_CASES),
        "metrics": {
            "vendorDetectionAccuracy": percentage(vendor_hits, len(BENCHMARK_CASES)),
            "controlAssertionAccuracy": percentage(control_hits, control_checks),
            "evidenceCoverage": percentage(evidence_hits, evidence_checks),
            "versionDetectionRate": percentage(version_hits, version_checks),
        },
        "assertions": {
            "vendors": vendor_hits,
            "controls": control_hits,
            "controlChecks": control_checks,
            "evidenceChecks": evidence_checks,
            "versions": version_hits,
            "versionChecks": version_checks,
        },
        "casesDetail": case_results,
    }
