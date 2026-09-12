from fastapi.testclient import TestClient

from src.app.main import app


def test_threat_feed_status_exposes_cisa_nist_and_epss():
    response = TestClient(app).get("/api/v1/threat-intelligence/feeds")
    assert response.status_code == 200
    feeds = {item["name"]: item for item in response.json()["feeds"]}
    assert set(feeds) == {"CISA KEV", "NIST NVD", "FIRST EPSS"}
    assert feeds["CISA KEV"]["mode"] == "local_mock"
    assert feeds["FIRST EPSS"]["mode"] == "local_mock"
    assert feeds["NIST NVD"]["endpoint"].startswith("https://")
