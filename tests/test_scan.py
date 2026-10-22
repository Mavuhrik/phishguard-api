from routes.scans import scans_bp
from app import app

def test_scan_valid_url():
    client = app.test_client()
    response = client.post("/scan" , json = {"url": "https://example.com"} )
    assert response.status_code == 200 

    data = response.get_json()
    assert data["url"] == "https://example.com"
    assert data["domain"] == "example.com"
    assert data["uses_https"] is True
    assert data["uses_ip"] is False
    assert data["risk_level"] == "low"
    assert data["risk_score"] == 0

def test_scan_missing_url():
    client = app.test_client()
    response = client.post("/scan", json = {})
    assert response.status_code == 400

def test_scan_invalid_url():
    client = app.test_client()
    response = client.post("/scan", json = {"url" : "https://"})
    assert response.status_code == 400

def test_scan_non_json_url():
    client = app.test_client()
    response = client.post("/scan", json = None)
    assert response.status_code == 400

def test_scan_json_string():
    client = app.test_client()
    response = client.post("/scan", json="https://example.com")
    assert response.status_code == 400


def test_scan_non_json_body():
    client = app.test_client()
    response = client.post("/scan", data = "wagwan")
    assert response.status_code == 400