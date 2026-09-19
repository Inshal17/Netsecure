import sqlite3
import json

import pytest
from requests import RequestException

import backend.main as main
import backend.llm_provider as llm_provider
from backend.scripts.cleanup_retention import cleanup_local_data
from backend.scripts.backup_local_data import backup_local_data, restore_local_data
from fastapi.testclient import TestClient
from backend.main import app


def test_health_endpoint():
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "operational"}
    assert r.headers.get("X-Request-ID")


def test_architecture_status_reports_prototype_readiness():
    client = TestClient(app)
    response = client.get("/api/architecture/status")

    assert response.status_code == 200
    body = response.json()
    assert body["storage"]["mode"] == "local-first"
    assert body["storage"]["remoteSupport"] in {True, False}
    assert body["blockchain"]["mode"] == "integrity-extension"
    assert body["blockchain"]["fallbackMode"] == "local-only-attestation"
    assert body["ai"]["provider"] in {"offline", "gemini", "openai-compatible", "remote"}
    assert body["dataset"]["readiness"] == "prototype-curated"
    assert body["dataset"]["vendorCount"] >= 9


def test_runtime_configuration_validation_rejects_invalid_security_settings(monkeypatch):
    monkeypatch.setenv("NETSECURE_API_RATE_LIMIT", "-1")
    monkeypatch.setenv("NETSECURE_API_RATE_WINDOW_SECONDS", "0")
    monkeypatch.setenv("NETSECURE_MAX_UPLOAD_BYTES", "0")
    monkeypatch.setenv("NETSECURE_AUTH_SECRET", "")
    monkeypatch.setenv("NETSECURE_ADMIN_PASSWORD", "")

    with pytest.raises(ValueError, match="NETSECURE_API_RATE_LIMIT|NETSECURE_MAX_UPLOAD_BYTES|NETSECURE_AUTH_SECRET"):
        main.validate_runtime_configuration()


def test_request_id_is_preserved():
    client = TestClient(app)
    response = client.get("/api/health", headers={"X-Request-ID": "qa-request-1"})
    assert response.headers["X-Request-ID"] == "qa-request-1"


def test_unhandled_errors_return_traceable_json(monkeypatch):
    def broken_all_analyses():
        raise RuntimeError("test-only failure")

    monkeypatch.setattr(main, "all_analyses", broken_all_analyses)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/dashboard", headers={"X-Request-ID": "error-request-1"})

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal server error",
        "request_id": "error-request-1",
    }
    assert response.headers["X-Request-ID"] == "error-request-1"


def test_frameworks_expose_source_and_review_metadata():
    client = TestClient(app)
    frameworks = client.get("/api/frameworks").json()
    nist = next(item for item in frameworks if item["id"] == "NIST")

    assert nist["authorityUrl"].startswith("https://")
    assert nist["version"] == "Rev. 5"
    assert nist["reviewStatus"] == "Reference aligned"
    assert nist["scope"]


def test_governance_reports_secure_defaults(monkeypatch):
    monkeypatch.setenv("NETSECURE_API_RATE_LIMIT", "120")
    monkeypatch.setenv("NETSECURE_API_RATE_WINDOW_SECONDS", "60")
    monkeypatch.setenv("NETSECURE_RETENTION_DAYS", "180")
    monkeypatch.setenv("NETSECURE_MAX_UPLOAD_BYTES", "2097152")

    response = TestClient(app).get("/api/governance")
    assert response.status_code == 200
    body = response.json()
    assert body["rateLimitPerWindow"] == 120
    assert body["rateLimitWindowSeconds"] == 60
    assert body["retentionDays"] == 180
    assert body["maxUploadBytes"] == 2097152
    assert body["redactionEnabled"] is True
    assert body["backupAvailable"] is True


def test_upload_rejects_oversized_configuration(monkeypatch):
    monkeypatch.setenv("NETSECURE_MAX_UPLOAD_BYTES", "10")
    client = TestClient(app)
    response = client.post(
        "/api/analyses/upload",
        files={"file": ("overflow.cfg", b"hostname BIG\n" + b"x" * 100, "text/plain")},
        data={"framework": "CIS Benchmarks", "vendor": "Auto"},
    )

    assert response.status_code == 413
    assert "exceeds the allowed size" in response.json()["detail"]


def test_quality_benchmark_reports_deterministic_metrics():
    response = TestClient(app).get("/api/quality/benchmark")
    assert response.status_code == 200
    body = response.json()
    assert body["cases"] == 4
    assert body["metrics"]["vendorDetectionAccuracy"] == 100.0
    assert body["metrics"]["controlAssertionAccuracy"] == 100.0
    assert body["metrics"]["evidenceCoverage"] == 100.0
    assert body["metrics"]["versionDetectionRate"] == 100.0


def test_security_events_normalize_wazuh_suricata_and_zeek_payloads():
    client = TestClient(app)
    wazuh = client.post(
        "/api/security-events/wazuh",
        json={"payload": {"id": "w-1", "timestamp": "2026-01-01T00:00:00Z", "agent": {"name": "edge-1"}, "rule": {"level": 12, "description": "Multiple failed SSH logins"}}},
    )
    suricata = client.post(
        "/api/security-events/suricata",
        json={"payload": {"flow_id": 22, "timestamp": "2026-01-01T00:00:01Z", "src_ip": "192.0.2.5", "dest_ip": "192.0.2.10", "alert": {"severity": 1, "signature": "ET SCAN SSH"}}},
    )
    zeek = client.post(
        "/api/security-events/zeek",
        json={"payload": {"uid": "Cabc", "ts": "2026-01-01T00:00:02Z", "id": {"orig_h": "192.0.2.5"}, "service": "ssh"}},
    )

    assert wazuh.status_code == suricata.status_code == zeek.status_code == 201
    assert wazuh.json()["asset"] == "edge-1"
    assert wazuh.json()["severity"] == "Critical"
    assert suricata.json()["eventType"] == "ET SCAN SSH"
    assert suricata.json()["severity"] == "Critical"
    assert zeek.json()["eventType"] == "ssh"


def test_blockchain_verification_falls_back_when_gateway_is_unavailable(monkeypatch):
    def raise_gateway_error(*args, **kwargs):
        raise RequestException("fabric endpoint unavailable")

    monkeypatch.setattr(main, "anchor_record", lambda **kwargs: (_ for _ in ()).throw(RequestException("fabric endpoint unavailable")))
    monkeypatch.setattr(main, "verify_record", lambda **kwargs: (_ for _ in ()).throw(RequestException("fabric endpoint unavailable")))

    client = TestClient(app)
    anchor = client.post(
        "/api/blockchain/anchor",
        json={
            "record_type": "ANALYSIS",
            "analysis_id": "analysis-blockchain-test",
            "payload": {"fileName": "demo.cfg", "overallScore": 82},
            "device_id": "dev-1",
            "vendor": "Cisco",
            "framework": "CIS Benchmarks",
            "actor": "qa-user",
        },
    )
    assert anchor.status_code == 200
    assert anchor.json()["status"] in {"local-only", "anchored"}
    assert anchor.json()["hash"]

    verify = client.post(
        "/api/blockchain/verify/analysis-blockchain-test",
        json={
            "record_type": "ANALYSIS",
            "analysis_id": "analysis-blockchain-test",
            "payload": {"fileName": "demo.cfg", "overallScore": 82},
            "device_id": "dev-1",
            "vendor": "Cisco",
            "framework": "CIS Benchmarks",
            "actor": "qa-user",
            "previous_hash": "",
        },
    )
    assert verify.status_code == 200
    assert verify.json()["verified"] is True
    assert verify.json()["status"] in {"local-only", "verified"}


def test_security_events_reject_unknown_sources():
    response = TestClient(app).post("/api/security-events/unknown", json={"payload": {}})
    assert response.status_code == 400


def test_security_event_persists_and_correlates_to_analysis(tmp_path, monkeypatch):
    database = tmp_path / "events.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE analyses (
                id TEXT PRIMARY KEY, filename TEXT, vendor TEXT, framework TEXT,
                created_at TEXT, result_json TEXT, upload_url TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "analysis-edge-1", "edge.cfg", "Cisco", "CIS Benchmarks", "2026-01-01",
                json.dumps({
                    "device": {"name": "edge-1", "ipAddress": "192.0.2.10"},
                    "overallScore": 40,
                    "controls": [{"id": "CIS-03", "field": "ssh_version", "result": "Fail", "requirement": "Enforce SSH version 2", "framework": "CIS Benchmarks", "severity": "High", "category": "Management Access", "remediation": "ip ssh version 2", "evidence": "ip ssh version 1", "confidence": 100, "confidence_source": "deterministic"}],
                }), "",
            ),
        )
    monkeypatch.setattr(main, "LOCAL_DB", database)
    monkeypatch.setattr(main, "supabase", None)

    response = TestClient(app).post(
        "/api/security-events/wazuh",
        json={"payload": {"agent": {"name": "edge-1"}, "rule": {"level": 10, "description": "SSH login failures"}}},
    )

    assert response.status_code == 201
    event = response.json()
    assert event["correlations"][0]["analysisId"] == "analysis-edge-1"
    assert event["correlations"][0]["matchedControls"] == ["ssh_version"]
    stored = TestClient(app).get("/api/security-events").json()
    assert stored[0]["id"] == event["id"]
    correlated_findings = TestClient(app).get("/api/findings").json()
    telemetry_finding = next(item for item in correlated_findings if item["id"].startswith("telemetry:"))
    assert telemetry_finding["controlId"] == "ssh_version"
    assert telemetry_finding["confidenceSource"] == "telemetry-correlation"
    assert telemetry_finding["correlationScore"] == 76


def test_vendor_catalog_contains_only_nine_supported_vendors():
    catalog = TestClient(app).get("/api/vendors")
    assert catalog.status_code == 200
    vendors = catalog.json()

    expected = {
        "Arista",
        "Check Point",
        "Cisco",
        "Fortinet",
        "HPE Aruba",
        "Huawei",
        "Juniper",
        "Palo Alto",
        "SONiC",
    }

    names = {item["name"] for item in vendors}
    assert names == expected
    assert len(vendors) == 9
    assert all(item["status"] == "Available" for item in vendors)
    assert all(item["supportLevel"] == "Deterministic parser" for item in vendors)


def test_training_queue_exposes_unknown_commands_with_suggestions(tmp_path, monkeypatch):
    database = tmp_path / "queue.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE analyses (
                id TEXT PRIMARY KEY, filename TEXT, vendor TEXT, framework TEXT,
                created_at TEXT, result_json TEXT, upload_url TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("analysis-1", "router.cfg", "Cisco", "CIS Benchmarks", "2026-01-01", '{"unknownLines":["set custom telnet disabled"]}', ""),
        )
    monkeypatch.setattr(main, "LOCAL_DB", database)
    monkeypatch.setattr(main, "supabase", None)

    response = TestClient(app).get("/api/training-queue")
    assert response.status_code == 200
    item = response.json()[0]
    assert item["rawCommand"] == "set custom telnet disabled"
    assert item["suggestedField"] == "telnet_disabled"
    assert item["status"] == "Suggested"


def test_mapping_suggestion_is_explainable_and_requires_approval(monkeypatch):
    monkeypatch.setenv("NETSECURE_LLM_PROVIDER", "offline")
    client = TestClient(app)
    response = client.post(
        "/api/training-mappings/suggest",
        json={
            "raw_command": "set admin telnet disable",
            "vendor": "Check Point",
        },
    )

    assert response.status_code == 200
    suggestion = response.json()
    assert suggestion["field_name"] == "telnet_disabled"
    assert suggestion["observed_value"] is True
    assert suggestion["confidence_source"] == "offline-heuristic"
    assert suggestion["provider"] == "offline-heuristic"
    assert suggestion["llmUsed"] is False
    assert suggestion["promptVersion"] == "mapping-suggestion-v1"
    assert suggestion["status"] == "Pending Approval"
    assert suggestion["knowledge"]["control"] == "telnet_disabled"
    assert suggestion["knowledge"]["references"][0]["sourceUrl"].startswith("https://")
    assert suggestion["knowledge"]["retrievedDocuments"]
    assert suggestion["knowledge"]["retrievedDocuments"][0]["score"] > 0


def test_configured_llm_without_credentials_falls_back_safely(monkeypatch):
    monkeypatch.setenv("NETSECURE_LLM_PROVIDER", "openai-compatible")
    monkeypatch.delenv("NETSECURE_LLM_ENDPOINT", raising=False)
    monkeypatch.delenv("NETSECURE_LLM_API_KEY", raising=False)

    response = TestClient(app).post(
        "/api/training-mappings/suggest",
        json={"raw_command": "set admin telnet disable", "vendor": "Check Point"},
    )

    assert response.status_code == 200
    assert response.json()["provider"] == "offline-heuristic"
    assert response.json()["llmUsed"] is False


def test_openai_compatible_response_is_structured_and_validated(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"choices":[{"message":{"content":"{\\"field_name\\":\\"telnet_disabled\\",\\"observed_value\\":true,\\"meaning\\":\\"Disables Telnet\\",\\"confidence\\":88,\\"reason\\":\\"The command explicitly disables Telnet.\\"}"}}]}'

    monkeypatch.setenv("NETSECURE_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("NETSECURE_LLM_API_KEY", "test-only-key")
    monkeypatch.setattr(llm_provider, "urlopen", lambda request, timeout, context: FakeResponse())

    response = TestClient(app).post(
        "/api/training-mappings/suggest",
        json={"raw_command": "set admin telnet disable", "vendor": "Check Point"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "remote-llm"
    assert body["llmUsed"] is True
    assert body["confidence"] == 88


def test_gemini_response_is_structured_and_validated(monkeypatch):
    monkeypatch.setenv("NETSECURE_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("NETSECURE_LLM_API_KEY", "test-only-key")
    monkeypatch.setattr(
        llm_provider,
        "_request_json",
        lambda request: {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": '{"field_name":"telnet_disabled","observed_value":true,"meaning":"Disables Telnet","confidence":89,"reason":"The command explicitly disables Telnet."}',
                    }],
                },
            }],
        },
    )

    response = TestClient(app).post(
        "/api/training-mappings/suggest",
        json={"raw_command": "set admin telnet disable", "vendor": "Check Point"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "gemini"
    assert body["llmUsed"] is True
    assert body["model"] == "gemini-flash-latest"
    assert body["confidence"] == 89


def test_knowledge_search_returns_ranked_source_documents():
    response = TestClient(app).post(
        "/api/knowledge/search",
        json={
            "query": "disable telnet and require SSH version 2",
            "vendor": "Cisco",
            "framework": "CIS",
        },
    )

    assert response.status_code == 200
    documents = response.json()["documents"]
    assert documents
    assert documents[0]["title"] == "Management access baseline"
    assert documents[0]["sourceUrl"].startswith("https://")


def test_mapping_suggestion_rejects_unclassifiable_commands():
    response = TestClient(app).post(
        "/api/training-mappings/suggest",
        json={"raw_command": "set vendor proprietary feature enabled"},
    )

    assert response.status_code == 422


def test_api_rate_limit_blocks_excess_requests(monkeypatch):
    monkeypatch.setenv("NETSECURE_API_RATE_LIMIT", "2")
    monkeypatch.setenv("NETSECURE_API_RATE_WINDOW_SECONDS", "60")
    main.API_REQUESTS.clear()
    client = TestClient(app)

    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/dashboard").status_code == 200
    limited = client.get("/api/dashboard")
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "60"
    main.API_REQUESTS.clear()


def test_login_returns_signed_role_session(monkeypatch):
    monkeypatch.setenv("NETSECURE_AUTH_SECRET", "test-secret")
    client = TestClient(app)

    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin@123"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "admin"
    assert "." in body["access_token"]
    assert client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong"},
    ).status_code == 401


def test_login_rate_limit_blocks_repeated_failures(monkeypatch):
    monkeypatch.setenv("NETSECURE_LOGIN_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("NETSECURE_LOGIN_WINDOW_SECONDS", "60")
    main.LOGIN_ATTEMPTS.clear()
    client = TestClient(app)

    for _ in range(2):
        assert client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        ).status_code == 401

    assert client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin@123"},
    ).status_code == 429
    main.LOGIN_ATTEMPTS.clear()


def test_admin_role_is_required_for_training_mutations(monkeypatch):
    monkeypatch.setenv("NETSECURE_AUTH_SECRET", "test-secret")
    monkeypatch.setenv("NETSECURE_ADMIN_ROLE", "viewer")
    client = TestClient(app)
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin@123"},
    )
    token = login.json()["access_token"]

    response = client.post(
        "/api/training-mappings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "raw_command": "set restricted enabled",
            "vendor": "Arista",
            "field_name": "aaa_enabled",
            "observed_value": True,
            "meaning": "Restricted mapping",
        },
    )
    assert response.status_code == 403


def test_configured_viewer_and_auditor_accounts_receive_roles(monkeypatch):
    monkeypatch.setenv("NETSECURE_VIEWER_USERNAME", "viewer")
    monkeypatch.setenv("NETSECURE_VIEWER_PASSWORD", "viewer-password")
    monkeypatch.setenv("NETSECURE_AUDITOR_USERNAME", "auditor")
    monkeypatch.setenv("NETSECURE_AUDITOR_PASSWORD", "auditor-password")
    main.LOGIN_ATTEMPTS.clear()
    client = TestClient(app)

    viewer = client.post(
        "/api/auth/login",
        json={"username": "viewer", "password": "viewer-password"},
    )
    auditor = client.post(
        "/api/auth/login",
        json={"username": "auditor", "password": "auditor-password"},
    )

    assert viewer.status_code == 200
    assert viewer.json()["role"] == "viewer"
    assert auditor.status_code == 200
    assert auditor.json()["role"] == "auditor"
    main.LOGIN_ATTEMPTS.clear()


def test_api_token_guard_protects_api_when_configured(monkeypatch):
    monkeypatch.setenv("NETSECURE_API_TOKEN", "test-token")
    client = TestClient(app)

    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/dashboard", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/dashboard", headers={"Authorization": "Bearer test-token"}).status_code == 200
    assert client.get("/api/health").status_code == 200


def test_static_api_token_can_perform_admin_mutations(monkeypatch):
    monkeypatch.setenv("NETSECURE_API_TOKEN", "service-token")
    client = TestClient(app)

    response = client.post(
        "/api/training-mappings",
        headers={"Authorization": "Bearer service-token"},
        json={
            "raw_command": "set admin token enabled",
            "vendor": "Arista",
            "field_name": "aaa_enabled",
            "observed_value": True,
            "meaning": "Service-issued admin mapping",
        },
    )

    assert response.status_code == 201
    assert response.json()["reviewed_by"] == "api-token"


def test_audit_events_are_persisted_for_training_mapping(tmp_path, monkeypatch):
    database = tmp_path / "audit.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE mappings (
                id TEXT PRIMARY KEY, raw_command TEXT, vendor TEXT, field_name TEXT,
                observed_value TEXT, meaning TEXT, confidence REAL, created_at TEXT
            )
            """
        )
    monkeypatch.setattr(main, "LOCAL_DB", database)
    monkeypatch.setattr(main, "supabase", None)

    client = TestClient(app)
    response = client.post(
        "/api/training-mappings",
        json={
            "raw_command": "set audit-test enabled",
            "vendor": "Arista",
            "field_name": "aaa_enabled",
            "observed_value": True,
            "meaning": "Enables centralized authentication",
        },
    )

    assert response.status_code == 201
    logs = client.get("/api/audit-logs")
    assert logs.status_code == 200
    assert logs.json()[0]["action"] == "AI mapping approved"


def test_mapping_review_provenance_is_persisted_and_rejections_are_not_applied(tmp_path, monkeypatch):
    database = tmp_path / "review.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE mappings (
                id TEXT PRIMARY KEY, raw_command TEXT, vendor TEXT, field_name TEXT,
                observed_value TEXT, meaning TEXT, confidence REAL, created_at TEXT
            )
            """
        )
    monkeypatch.setattr(main, "LOCAL_DB", database)
    monkeypatch.setattr(main, "supabase", None)

    response = TestClient(app).post(
        "/api/training-mappings/reject",
        json={
            "raw_command": "set rejected telnet disabled",
            "vendor": "Cisco",
            "field_name": "telnet_disabled",
            "observed_value": True,
            "meaning": "Rejected test mapping",
            "analysis_id": "analysis-review-1",
            "review_reason": "Needs vendor documentation",
        },
    )

    assert response.status_code == 201
    rejected = response.json()
    assert rejected["review_status"] == "Rejected"
    assert rejected["reviewed_by"] == "Admin"
    assert rejected["analysis_id"] == "analysis-review-1"
    assert main.get_training_mappings("Cisco") == []

    history = TestClient(app).get("/api/training-mappings")
    assert history.status_code == 200
    assert history.json()[0]["reviewStatus"] == "Rejected"
    assert history.json()[0]["createdBy"] == "Admin"


def test_remote_audit_logs_fail_gracefully_when_table_is_missing(monkeypatch):
    class BrokenAuditClient:
        def table(self, name):
            raise RuntimeError("missing table")

    monkeypatch.setattr(main, "supabase", BrokenAuditClient())
    assert TestClient(app).get("/api/audit-logs").json() == []


def test_storage_info_reports_audit_schema_state(monkeypatch):
    class HealthyStorageClient:
        def table(self, name):
            class Query:
                def select(self, *args):
                    return self

                def limit(self, *args):
                    return self

                def execute(self):
                    return type("Response", (), {"data": []})()

            return Query()

    monkeypatch.setattr(main, "supabase", HealthyStorageClient())
    payload = TestClient(app).get("/api/storage-info").json()
    assert payload["audit_events_configured"] is True


def test_governance_retention_and_backup_actions_execute_locally(tmp_path, monkeypatch):
    database = tmp_path / "governance.sqlite3"
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE analyses (id TEXT PRIMARY KEY, created_at TEXT);
            CREATE TABLE mappings (id TEXT PRIMARY KEY, created_at TEXT);
            CREATE TABLE audit_events (id TEXT PRIMARY KEY, timestamp TEXT);
            """
        )
        connection.execute("INSERT INTO analyses VALUES ('analysis-old', '2020-01-01T00:00:00+00:00')")
        connection.execute("INSERT INTO mappings VALUES ('mapping-old', '2020-01-01T00:00:00+00:00')")
        connection.execute("INSERT INTO audit_events VALUES ('audit-old', '2020-01-01T00:00:00+00:00')")
        connection.commit()
    (uploads / "analysis-old_router.cfg").write_text("hostname OLD")
    monkeypatch.setattr(main, "LOCAL_DB", database)
    monkeypatch.setattr(main, "UPLOADS_DIR", uploads)
    monkeypatch.setattr(main, "supabase", None)

    client = TestClient(app)
    preview = client.post("/api/governance/retention/cleanup", json={"days": 30, "apply": False})
    assert preview.status_code == 200
    assert preview.json()["analyses"] == 1

    backup = client.post("/api/governance/backup", json={"archive": str(tmp_path / "backup.tar.gz")})
    assert backup.status_code == 200
    assert backup.json()["uploads"] == 1


def test_retention_cleanup_is_dry_run_then_removes_expired_data(tmp_path):
    database = tmp_path / "retention.sqlite3"
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE analyses (id TEXT PRIMARY KEY, created_at TEXT);
            CREATE TABLE mappings (id TEXT PRIMARY KEY, created_at TEXT);
            CREATE TABLE audit_events (id TEXT PRIMARY KEY, timestamp TEXT);
            """
        )
        connection.execute("INSERT INTO analyses VALUES ('analysis-old', '2020-01-01T00:00:00+00:00')")
        connection.execute("INSERT INTO mappings VALUES ('mapping-old', '2020-01-01T00:00:00+00:00')")
        connection.execute("INSERT INTO audit_events VALUES ('audit-old', '2020-01-01T00:00:00+00:00')")
        connection.commit()
    (uploads / "analysis-old_router.cfg").write_text("hostname OLD")

    preview = cleanup_local_data(database, uploads, days=30)
    assert preview == {"dry_run": True, "analyses": 1, "mappings": 1, "audit_events": 1, "uploads": 0}
    assert (uploads / "analysis-old_router.cfg").exists()

    applied = cleanup_local_data(database, uploads, days=30, apply=True)
    assert applied == {"dry_run": False, "analyses": 1, "mappings": 1, "audit_events": 1, "uploads": 1}
    assert not (uploads / "analysis-old_router.cfg").exists()


def test_local_backup_and_restore_round_trip(tmp_path):
    database = tmp_path / "source.sqlite3"
    uploads = tmp_path / "source-uploads"
    restored_database = tmp_path / "restored.sqlite3"
    restored_uploads = tmp_path / "restored-uploads"
    archive = tmp_path / "backup.tar.gz"
    uploads.mkdir()
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE analyses (id TEXT PRIMARY KEY, filename TEXT)")
        connection.execute("INSERT INTO analyses VALUES ('analysis-1', 'router.cfg')")
        connection.commit()
    (uploads / "analysis-1_router.cfg").write_text("hostname BACKUP")

    created = backup_local_data(archive, database, uploads)
    restored = restore_local_data(archive, restored_database, restored_uploads)

    assert created["uploads"] == 1
    assert restored["uploads"] == 1
    with sqlite3.connect(restored_database) as connection:
        assert connection.execute("SELECT count(*) FROM analyses").fetchone()[0] == 1
    assert (restored_uploads / "analysis-1_router.cfg").read_text() == "hostname BACKUP"
