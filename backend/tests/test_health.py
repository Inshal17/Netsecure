import sqlite3

import backend.main as main
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


def test_mapping_suggestion_is_explainable_and_requires_approval():
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
    assert suggestion["confidence_source"] == "keyword_heuristic"
    assert suggestion["status"] == "Pending Approval"


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
    assert logs.json()[0]["action"] == "AI mapping created"


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
