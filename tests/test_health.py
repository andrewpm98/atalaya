"""Prueba de humo: la API arranca y responde en /health."""

from fastapi.testclient import TestClient

from atalaya.api.main import app

client = TestClient(app)


def test_health_ok() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_root_ok() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["servicio"] == "Atalaya"
