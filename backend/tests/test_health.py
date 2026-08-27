from fastapi.testclient import TestClient
from backend.main import app


def test_health_endpoint():
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "operational"}
