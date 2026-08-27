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


def test_unknown_lines_are_exposed_for_training():
    result = analyze("unknown.cfg", "hostname EDGE\nset vendor-specific-feature enabled\n", "CIS Benchmarks", "Auto")
    assert "set vendor-specific-feature enabled" in result["unknownLines"]


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
