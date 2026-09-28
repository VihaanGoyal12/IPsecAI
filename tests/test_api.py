"""
Tests for FastAPI Endpoints
Verifies health check, demo loading, reports API, testbed generation, and error handling.
"""

import pytest
from fastapi.testclient import TestClient
from backend.api import app

client = TestClient(app)


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "ml_engine_ready" in data


def test_api_demo_load():
    for prof in ["demo_a", "demo_b", "demo_c"]:
        response = client.get(f"/demo/load?profile={prof}")
        assert response.status_code == 200
        data = response.json()
        assert "analysis_id" in data
        assert "security_assessment" in data
        assert 0 <= data["security_assessment"]["overall_score"] <= 100


def test_api_get_findings_and_assessment():
    load_res = client.get("/demo/load?profile=demo_b")
    analysis_id = load_res.json()["analysis_id"]

    # Test findings endpoint
    f_res = client.get(f"/analysis/{analysis_id}/findings")
    assert f_res.status_code == 200
    findings = f_res.json()
    assert isinstance(findings, list)
    assert len(findings) > 0

    # Test assessment endpoint
    a_res = client.get(f"/analysis/{analysis_id}/assessment")
    assert a_res.status_code == 200
    asm = a_res.json()
    assert asm["overall_score"] < 70


def test_api_report_formats():
    response = client.get("/demo/load?profile=demo_a")
    analysis_id = response.json()["analysis_id"]

    for fmt in ["markdown", "html", "json", "csv"]:
        r = client.get(f"/analysis/{analysis_id}/report?format={fmt}")
        assert r.status_code == 200


def test_api_testbed_generate():
    payload = {
        "vpn_mode": "Tunnel",
        "encryption_algorithm": "AES-256-GCM",
        "dh_group": "Group 14",
        "pfs_enabled": True,
        "replay_protection": True,
        "ip_version": "IPv4",
        "traffic_type": "Video",
        "lifetime_hours": 8
    }
    r = client.post("/testbed/generate", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "profile_id" in data
    assert "strongswan_conf" in data


def test_api_stream_batch():
    r = client.get("/demo/stream?count=5")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 5
    assert "inferred_traffic_type" in data[0]
