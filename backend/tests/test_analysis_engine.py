import sqlite3

from fastapi.testclient import TestClient

import backend.main as main
from backend.main import analyze


CISCO_INSECURE = """
hostname INSECURE-ROUTER
ip ssh version 1
no logging enable
ntp server 10.0.0.20
ip source-route
interface GigabitEthernet0/0
 ip proxy-arp
end
"""

CISCO_SECURE = """
hostname SECURE-ROUTER
ip ssh version 2
logging enable
logging host 10.0.0.10
ntp authenticate
ntp server 10.0.0.20 key 1
no ip source-route
interface GigabitEthernet0/0
 no ip proxy-arp
end
"""

JUNIPER_INSECURE = """
system {
    services {
        ssh {
            protocol-version v1;
            rate-limit 20;
        }
        telnet;
        reverse-telnet;
        ftp;
    }
    login {
        retry-options {
            tries-before-disconnect 10;
        }
    }
}
"""

JUNIPER_SECURE = """
system {
    services {
        ssh {
            protocol-version v2;
            rate-limit 4;
        }
    }
    login {
        retry-options {
            tries-before-disconnect 3;
        }
    }
}
"""

ARISTA_INSECURE = """
! device: Arista EOS
hostname ARISTA-INSECURE
management telnet
management api http-commands
logging host 192.0.2.20
ntp server 192.0.2.30
"""

ARISTA_SECURE = """
! device: Arista EOS
hostname ARISTA-SECURE
no management telnet
no management api http-commands
management ssh
logging host 192.0.2.20
ntp server 192.0.2.30
aaa authorization exec default local
exec-timeout 10
"""

SONIC_INSECURE = """
SONiC-OS 202411
set mgmt timeout 0
set mgmt telnet enable
set mgmt http enable
"""

SONIC_SECURE = """
SONiC-OS 202411
set mgmt timeout 10
set mgmt telnet disable
set mgmt http disable
sudo config ntp add 192.0.2.30
sudo config syslog add 192.0.2.20
sudo config aaa enable
"""


def fields(result, status):
    return {control["field"] for control in result["controls"] if control["result"] == status}


def test_cisco_pair_produces_evidence_based_findings():
    insecure = analyze("cisco_insecure.cfg", CISCO_INSECURE, "CIS Benchmarks", "Auto")
    secure = analyze("cisco_secure.cfg", CISCO_SECURE, "CIS Benchmarks", "Auto")

    assert insecure["vendor"] == "Cisco"
    assert {"ssh_version", "logging_enabled", "source_routing_disabled", "proxy_arp_disabled"} <= fields(insecure, "Fail")
    assert {"ssh_version", "logging_enabled", "ntp_authenticated", "source_routing_disabled", "proxy_arp_disabled"} <= fields(secure, "Pass")


def test_juniper_pair_produces_evidence_based_findings():
    insecure = analyze("juniper_insecure.conf", JUNIPER_INSECURE, "CIS Benchmarks", "Auto")
    secure = analyze("juniper_secure.conf", JUNIPER_SECURE, "CIS Benchmarks", "Auto")

    assert insecure["vendor"] == "Juniper"
    assert {"ssh_version", "ssh_rate_limit", "login_attempts", "telnet_disabled", "reverse_telnet_disabled", "ftp_disabled"} <= fields(insecure, "Fail")
    assert {"ssh_version", "ssh_rate_limit", "login_attempts", "telnet_disabled", "reverse_telnet_disabled", "ftp_disabled"} <= fields(secure, "Pass")
    source_routing = next(control for control in secure["controls"] if control["field"] == "source_routing_disabled")
    assert source_routing["result"] == "Not Applicable"
    assert source_routing["applicability"] == "Not Applicable"


def test_arista_pair_is_detected_and_parsed():
    insecure = analyze("arista_insecure.cfg", ARISTA_INSECURE, "CIS Benchmarks", "Auto")
    secure = analyze("arista_secure.cfg", ARISTA_SECURE, "CIS Benchmarks", "Auto")

    assert insecure["vendor"] == "Arista"
    assert {"telnet_disabled", "http_disabled"} <= fields(insecure, "Fail")
    assert {"telnet_disabled", "http_disabled", "ssh_version", "aaa_enabled", "idle_timeout"} <= fields(secure, "Pass")
    assert secure["device"]["name"] == "ARISTA-SECURE"


def test_sonic_pair_is_detected_and_parsed():
    insecure = analyze("sonic_insecure.cfg", SONIC_INSECURE, "CIS Benchmarks", "Auto")
    secure = analyze("sonic_secure.cfg", SONIC_SECURE, "CIS Benchmarks", "Auto")

    assert insecure["vendor"] == "SONiC"
    assert {"telnet_disabled", "http_disabled"} <= fields(insecure, "Fail")
    assert {"telnet_disabled", "http_disabled", "idle_timeout", "ntp_configured", "logging_enabled", "aaa_enabled"} <= fields(secure, "Pass")


def test_fortinet_security_controls_are_extracted():
    result = analyze(
        "fortinet.cfg",
        "config system global\n"
        " set admin-telnet disable\n"
        " set admin-https-redirect enable\n"
        " set ssh-v1 disable\n"
        " set auth-server radius-main\n"
        " set snmp-v3 enable\n"
        "end\n",
        "CIS Benchmarks",
        "Auto",
    )

    assert result["vendor"] == "Fortinet"
    assert {"telnet_disabled", "http_disabled", "ssh_version", "aaa_enabled", "snmp_secure"} <= fields(result, "Pass")


def test_palo_alto_and_aruba_vendor_variants_are_detected_and_parsed():
    palo = analyze(
        "paloalto.cfg",
        "set deviceconfig system ssh version 2\n"
        "set deviceconfig system service disable telnet\n"
        "set deviceconfig system service disable webserver\n"
        "set deviceconfig system ntp servers primary 10.0.0.10\n",
        "CIS Benchmarks",
        "Auto",
    )
    aruba = analyze(
        "aruba.cfg",
        "hostname sw-01\n"
        "ip ssh version 2\n"
        "no telnet-server\n"
        "no ip http server\n"
        "aaa authentication-server radius\n"
        "logging 10.0.0.20\n",
        "CIS Benchmarks",
        "Auto",
    )

    assert palo["vendor"] == "Palo Alto"
    assert {"ssh_version", "telnet_disabled", "http_disabled", "ntp_configured"} <= fields(palo, "Pass")
    assert aruba["vendor"] == "HPE Aruba"
    assert {"ssh_version", "telnet_disabled", "http_disabled", "aaa_enabled", "logging_enabled"} <= fields(aruba, "Pass")


def test_malformed_and_large_configurations_do_not_crash():
    malformed = analyze("malformed.cfg", "\x00\xff\nconfig system { ???\n", "CIS Benchmarks", "Auto")
    large = analyze("large.cfg", ("set unknown syntax enabled\n" * 5000), "CIS Benchmarks", "Auto")

    assert malformed["controls"]
    assert len(large["unknownLines"]) == 100


def test_unknown_lines_are_exposed_for_training():
    result = analyze("unknown.cfg", "hostname EDGE\nset vendor-specific-feature enabled\n", "CIS Benchmarks", "Auto")
    assert "set vendor-specific-feature enabled" in result["unknownLines"]


def test_framework_mapping_metadata_is_explicit():
    result = analyze("mapped.cfg", CISCO_SECURE, "NIST SP 800-53", "Auto")
    ssh_control = next(control for control in result["controls"] if control["field"] == "ssh_version")

    assert ssh_control["frameworkId"] == "NIST"
    assert ssh_control["reference"] == "AC-17(2)"
    assert ssh_control["mappingStatus"] == "Mapped"
    assert ssh_control["controlKey"] == "ssh_version"


def test_analysis_has_reproducible_evidence_hash():
    result = analyze("hash.cfg", CISCO_SECURE, "CIS Benchmarks", "Auto")

    assert len(result["evidenceHash"]) == 64
    assert result["hashAlgorithm"] == "SHA-256"


def test_training_mapping_provenance_is_exposed(monkeypatch):
    monkeypatch.setattr(
        main,
        "get_training_mappings",
        lambda vendor: [{
            "raw_command": "set secure-admin enabled",
            "vendor": vendor,
            "field_name": "aaa_enabled",
            "observed_value": True,
            "meaning": "Enables centralized administration",
            "confidence": 96,
        }],
    )

    result = analyze(
        "trained.cfg",
        "hostname EDGE\nset secure-admin enabled\n",
        "CIS Benchmarks",
        "Auto",
    )
    aaa_control = next(control for control in result["controls"] if control["field"] == "aaa_enabled")

    assert aaa_control["result"] == "Pass"
    assert aaa_control["trainingApplied"] is True
    assert aaa_control["evidenceSource"] == "trained_mapping"


def test_inventory_values_are_extracted_from_configuration():
    result = analyze(
        "inventory.cfg",
        "hostname EDGE\nip address 192.0.2.10 255.255.255.0\nserial-number ABC123\nmodel ISR\n",
        "CIS Benchmarks",
        "Auto",
    )
    assert result["device"] == {
        "name": "EDGE",
        "model": "ISR",
        "firmware": "Not detected",
        "serialNumber": "ABC123",
        "ipAddress": "192.0.2.10",
        "deviceType": "Router",
    }


def test_batch_upload_persists_each_file(tmp_path, monkeypatch):
    database = tmp_path / "analyses.sqlite3"
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE analyses (
                id TEXT PRIMARY KEY, filename TEXT, vendor TEXT, framework TEXT,
                created_at TEXT, result_json TEXT, upload_url TEXT
            );
            CREATE TABLE mappings (
                id TEXT PRIMARY KEY, raw_command TEXT, vendor TEXT, field_name TEXT,
                observed_value TEXT, meaning TEXT, confidence REAL, created_at TEXT
            );
            """
        )
    monkeypatch.setattr(main, "LOCAL_DB", database)
    monkeypatch.setattr(main, "UPLOADS_DIR", uploads)
    monkeypatch.setattr(main, "supabase", None)

    client = TestClient(main.app)
    response = client.post(
        "/api/analyses/upload-batch",
        files=[
            ("files", ("one.cfg", b"hostname ONE\nip ssh version 2\n", "text/plain")),
            ("files", ("two.conf", b"system { services { ssh { protocol-version v2; } } }", "text/plain")),
        ],
        data={"vendor": "Auto", "framework": "CIS Benchmarks"},
    )
    assert response.status_code == 200
    assert [item["vendor"] for item in response.json()] == ["Cisco", "Juniper"]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM analyses").fetchone()[0] == 2
