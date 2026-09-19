#!/usr/bin/env python3
"""Generate a multi-vendor network device config dataset for benchmarking.

This script creates a synthetic-but-realistic dataset that mirrors the major
vendors supported by NetSecureAI and covers both secure and insecure variants.
It is intentionally offline-safe and deterministic so it can run in CI or local
checkouts without external network access.

Optional behavior:
- It can also annotate each generated file with public-source placeholders for
  manual collection of vendor examples when a real external dataset is added later.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "data" / "datasets" / "vendor_configs"
FRAMEWORKS = [
    "CIS Benchmarks",
    "NIST SP 800-53",
    "DISA STIG",
    "ISO/IEC 27001",
]

VENDOR_VARIANTS: dict[str, dict[str, list[str]]] = {
    "Cisco": {
        "secure": [
            "hostname {hostname}\nip ssh version 2\nlogging enable\nlogging host {ip1}\nntp authenticate\nntp server {ip2} key 1\nno ip source-route\ninterface GigabitEthernet0/0\n no ip proxy-arp\nend\n",
            "hostname {hostname}\nip domain-name example.com\nip ssh version 2\nservice tcp-keepalives-in\nlogging buffered 4096\nlogging host {ip1}\nntp server {ip2}\nno ip source-route\nend\n",
        ],
        "insecure": [
            "hostname {hostname}\nip ssh version 1\nno logging enable\nntp server {ip2}\nip source-route\ninterface GigabitEthernet0/0\n ip proxy-arp\nend\n",
            "hostname {hostname}\nno ip ssh server algorithm encryption aes128-ctr\nservice password-encryption\nno logging on\nntp server {ip2}\ninterface GigabitEthernet0/1\n ip proxy-arp\nend\n",
        ],
        "mixed": [
            "hostname {hostname}\nip ssh version 2\nno logging enable\nntp server {ip2}\nno ip source-route\ninterface GigabitEthernet0/0\n ip proxy-arp\nend\n",
            "hostname {hostname}\nip ssh version 1\nlogging enable\nntp authenticate\nno ip source-route\nend\n",
        ],
    },
    "Juniper": {
        "secure": [
            "system {\n    services {\n        ssh {\n            protocol-version v2;\n            rate-limit 4;\n        }\n    }\n    login {\n        retry-options {\n            tries-before-disconnect 3;\n        }\n    }\n}\n",
            "system {\n    services {\n        ssh {\n            protocol-version v2;\n            rate-limit 4;\n        }\n        telnet;\n    }\n    login {\n        retry-options {\n            tries-before-disconnect 3;\n        }\n    }\n}\n",
        ],
        "insecure": [
            "system {\n    services {\n        ssh {\n            protocol-version v1;\n            rate-limit 20;\n        }\n        telnet;\n        reverse-telnet;\n        ftp;\n    }\n    login {\n        retry-options {\n            tries-before-disconnect 10;\n        }\n    }\n}\n",
            "system {\n    services {\n        ssh {\n            protocol-version v1;\n        }\n        telnet;\n    }\n}\n",
        ],
        "mixed": [
            "system {\n    services {\n        ssh {\n            protocol-version v2;\n            rate-limit 20;\n        }\n        telnet;\n    }\n}\n",
            "system {\n    services {\n        ssh {\n            protocol-version v1;\n            rate-limit 4;\n        }\n    }\n}\n",
        ],
    },
    "Fortinet": {
        "secure": [
            "config system global\n set admin-scp enable\n set admin-telnet disable\n set admin-https-redirect enable\n set ssh-v1 disable\n set auth-server radius-main\n set snmp-v3 enable\nend\n",
            "config system global\n set admin-telnet disable\n set admin-https-redirect enable\n set ssh-v1 disable\n set sslvpn status enable\n set snmp-v3 enable\nend\n",
        ],
        "insecure": [
            "config system global\n set admin-telnet enable\n set admin-scp disable\n set ssh-v1 enable\n set admin-https-redirect disable\n set snmp-v2-status enable\nend\n",
            "config system global\n set admin-telnet enable\n set ssh-v1 enable\n set snmp-v2-status enable\nend\n",
        ],
        "mixed": [
            "config system global\n set admin-telnet disable\n set ssh-v1 enable\n set snmp-v2-status enable\nend\n",
            "config system global\n set admin-telnet disable\n set admin-https-redirect enable\n set ssh-v1 disable\n set snmp-v2-status enable\nend\n",
        ],
    },
    "Palo Alto": {
        "secure": [
            "set deviceconfig system ssh version 2\nset deviceconfig system service disable telnet\nset deviceconfig system service disable webserver\nset deviceconfig system ntp servers primary {ip1}\nset deviceconfig system hostname {hostname}\n",
            "set deviceconfig system ssh version 2\nset deviceconfig system service disable telnet\nset deviceconfig system service disable webserver\nset deviceconfig system logging server {ip1}\nset deviceconfig system ntp servers primary {ip2}\n",
        ],
        "insecure": [
            "set deviceconfig system ssh version 1\nset deviceconfig system service disable webserver\nset deviceconfig system service enable telnet\nset deviceconfig system ntp servers primary {ip2}\n",
            "set deviceconfig system ssh version 1\nset deviceconfig system service enable telnet\nset deviceconfig system service disable webserver\n",
        ],
        "mixed": [
            "set deviceconfig system ssh version 2\nset deviceconfig system service enable telnet\nset deviceconfig system service disable webserver\nset deviceconfig system ntp servers primary {ip2}\n",
            "set deviceconfig system ssh version 1\nset deviceconfig system service disable telnet\nset deviceconfig system ntp servers primary {ip1}\n",
        ],
    },
    "Arista": {
        "secure": [
            "! device: Arista EOS\nhostname {hostname}\nno management telnet\nmanagement ssh\nno management api http-commands\nlogging host {ip1}\nntp server {ip2}\naaa authorization exec default local\nexec-timeout 10\n",
            "! device: Arista EOS\nhostname {hostname}\nmanagement ssh\nlogging host {ip1}\nntp server {ip2}\nno management telnet\n",
        ],
        "insecure": [
            "! device: Arista EOS\nhostname {hostname}\nmanagement telnet\nmanagement api http-commands\nlogging host {ip1}\nntp server {ip2}\n",
            "! device: Arista EOS\nhostname {hostname}\nmanagement telnet\nno management ssh\nlogging host {ip1}\n",
        ],
        "mixed": [
            "! device: Arista EOS\nhostname {hostname}\nmanagement ssh\nmanagement telnet\nlogging host {ip1}\nntp server {ip2}\n",
            "! device: Arista EOS\nhostname {hostname}\nno management telnet\nmanagement api http-commands\nntp server {ip2}\n",
        ],
    },
    "HPE Aruba": {
        "secure": [
            "hostname {hostname}\nip ssh version 2\nno telnet-server\nno ip http server\nlogging {ip1}\naaa authentication-server radius\n",
            "hostname {hostname}\nip ssh version 2\nno telnet-server\nno ip http server\nlogging {ip1}\n",
        ],
        "insecure": [
            "hostname {hostname}\nip ssh version 1\ntelnet-server\nip http server\nlogging {ip1}\n",
            "hostname {hostname}\ntelnet-server\nip http server\n",
        ],
        "mixed": [
            "hostname {hostname}\nip ssh version 2\ntelnet-server\nno ip http server\nlogging {ip1}\n",
            "hostname {hostname}\nip ssh version 1\nno telnet-server\nip http server\n",
        ],
    },
    "Huawei": {
        "secure": [
            "sysname {hostname}\nundo telnet server enable\nundo http server enable\nssh server version 2\nntp-service enable\n",
            "sysname {hostname}\nundo telnet server enable\nundo http server enable\nssh server version 2\nssh authentication-type default password\n",
        ],
        "insecure": [
            "sysname {hostname}\ntelnet server enable\nhttp server enable\nssh server version 1\n",
            "sysname {hostname}\ntelnet server enable\nhttp server enable\nnat enable\n",
        ],
        "mixed": [
            "sysname {hostname}\nundo telnet server enable\nhttp server enable\nssh server version 2\nntp-service enable\n",
            "sysname {hostname}\ntelnet server enable\nundo http server enable\nssh server version 1\n",
        ],
    },
    "Check Point": {
        "secure": [
            "set hostname {hostname}\nset ssh version 2\nset admin telnet disable\nset ntp server {ip2}\nset snmp community public\n",
            "set hostname {hostname}\nset ssh version 2\nset admin telnet disable\nset ntp server {ip1}\n",
        ],
        "insecure": [
            "set hostname {hostname}\nset ssh version 1\nset admin telnet enable\nset ntp server {ip2}\nset snmp community public\n",
            "set hostname {hostname}\nset ssh version 1\nset admin telnet enable\n",
        ],
        "mixed": [
            "set hostname {hostname}\nset ssh version 2\nset admin telnet enable\nset ntp server {ip2}\n",
            "set hostname {hostname}\nset ssh version 1\nset admin telnet disable\nset ntp server {ip1}\n",
        ],
    },
    "SONiC": {
        "secure": [
            "SONiC-OS {version}\nset mgmt timeout 10\nset mgmt telnet disable\nset mgmt http disable\nsudo config ntp add {ip2}\nsudo config syslog add {ip1}\nsudo config aaa enable\n",
            "SONiC-OS {version}\nset mgmt timeout 15\nset mgmt telnet disable\nset mgmt http disable\nsudo configaaa enable\n",
        ],
        "insecure": [
            "SONiC-OS {version}\nset mgmt timeout 0\nset mgmt telnet enable\nset mgmt http enable\n",
            "SONiC-OS {version}\nset mgmt timeout 0\nset mgmt telnet enable\nset mgmt http enable\nsudo config ntp add {ip2}\n",
        ],
        "mixed": [
            "SONiC-OS {version}\nset mgmt timeout 10\nset mgmt telnet enable\nset mgmt http disable\n",
            "SONiC-OS {version}\nset mgmt timeout 0\nset mgmt telnet disable\nset mgmt http enable\n",
        ],
    },
}

PUBLIC_SOURCE_HINTS: dict[str, str] = {
    "Cisco": "https://developer.cisco.com/",
    "Juniper": "https://www.juniper.net/documentation/",
    "Fortinet": "https://docs.fortinet.com/",
    "Palo Alto": "https://docs.paloaltonetworks.com/",
    "Arista": "https://www.arista.com/en/support/docs",
    "HPE Aruba": "https://www.arubanetworks.com/techdocs/",
    "Huawei": "https://support.huawei.com/",
    "Check Point": "https://community.checkpoint.com/",
    "SONiC": "https://github.com/sonic-net/sonic-buildimage",
}


def build_config(vendor: str, state: str, index: int) -> str:
    base_ip1 = f"192.0.2.{(index % 254) + 1}"
    base_ip2 = f"10.0.0.{(index % 254) + 1}"
    hostname = f"{vendor.lower().replace(' ', '-')}-{state}-{index:03d}"
    version = f"2024{index % 12 + 1}"
    choices = VENDOR_VARIANTS[vendor][state]
    template = choices[index % len(choices)]
    for key, value in {
        "hostname": hostname,
        "ip1": base_ip1,
        "ip2": base_ip2,
        "version": version,
    }.items():
        template = template.replace(f"{{{key}}}", str(value))
    return template


def build_manifest(output_dir: Path, vendor: str, generated: list[dict[str, Any]]) -> None:
    manifest_path = output_dir / "manifest.json"
    existing: list[dict[str, Any]] = []
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text())
    existing.extend(generated)
    manifest_path.write_text(json.dumps(existing, indent=2))


def generate_dataset(output_dir: Path, count_per_vendor: int) -> list[dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    for vendor in VENDOR_VARIANTS:
        for index in range(count_per_vendor):
            state = ["secure", "insecure", "mixed"][index % 3]
            config_text = build_config(vendor, state, index)
            file_name = f"{vendor.lower().replace(' ', '-')}_{state}_{index:03d}.cfg"
            if vendor == "Juniper":
                file_name = file_name.replace(".cfg", ".conf")
            elif vendor == "SONiC":
                file_name = file_name.replace(".cfg", ".conf")
            target = output_dir / file_name
            target.write_text(config_text)
            entry = {
                "vendor": vendor,
                "filename": file_name,
                "state": state,
                "frameworks": FRAMEWORKS,
                "source_hint": PUBLIC_SOURCE_HINTS[vendor],
                "file_path": str(target.relative_to(ROOT)),
            }
            manifest.append(entry)
    build_manifest(output_dir, "all", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a multi-vendor config benchmark dataset.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Directory to store the generated vendor configuration files.",
    )
    parser.add_argument(
        "--count-per-vendor",
        type=int,
        default=40,
        help="Number of synthetic config files to generate for each vendor.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = generate_dataset(args.output_dir, args.count_per_vendor)
    print(f"Generated {len(manifest)} config files in {args.output_dir}")
    print(f"Vendors covered: {', '.join(VENDOR_VARIANTS.keys())}")


if __name__ == "__main__":
    main()
