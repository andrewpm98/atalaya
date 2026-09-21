"""Pruebas de los endpoints `/scans`, `/assets` y `/findings`.

`create_scan` se prueba sustituyendo `enumerate_subdomains` (la fuente
externa) por un doble: esta suite prueba el cableado HTTP -> descubrimiento
-> persistencia, no la enumeración en sí (ya cubierta en `test_subdomains.py`).
La sesión de BD se inyecta vía `app.dependency_overrides`, contra SQLite en
memoria — igual que `db_session`, pero por request HTTP en vez de directa.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime, timezone

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from atalaya.api.main import app
from atalaya.core import models  # noqa: F401 - registra las tablas en Base.metadata
from atalaya.core.database import Base, get_session
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[TestClient, None]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session
    yield TestClient(app)
    app.dependency_overrides.clear()
    await engine.dispose()


def _fake_result(domain: str) -> SubdomainScanResult:
    result = SubdomainScanResult(domain=domain)
    result.records = [
        SubdomainRecord(
            hostname=f"www.{domain}",
            status=ResolutionStatus.ACTIVE,
            ip_addresses=["93.184.216.34"],
            sources=[DiscoverySource.CRTSH, DiscoverySource.DNS],
        ),
        SubdomainRecord(
            hostname=f"interno.{domain}",
            status=ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"],
            sources=[DiscoverySource.CRTSH],
        ),
    ]
    result.finished_at = datetime.now(timezone.utc)
    return result


async def test_create_scan_persiste_y_devuelve_detalle(client: TestClient, monkeypatch) -> None:
    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate)

    resp = client.post("/scans", json={"domain": "ejemplo.com"})

    assert resp.status_code == 201
    body = resp.json()
    assert body["domain"] == "ejemplo.com"
    assert body["status"] == "completed"
    assert {a["hostname"] for a in body["assets"]} == {
        "www.ejemplo.com",
        "interno.ejemplo.com",
    }
    interno = next(a for a in body["assets"] if a["hostname"] == "interno.ejemplo.com")
    assert len(interno["findings"]) == 1


async def test_create_scan_dominio_invalido_da_400(client: TestClient) -> None:
    resp = client.post("/scans", json={"domain": "no es un dominio"})
    assert resp.status_code == 400


async def test_create_scan_dominio_no_autorizado_da_403(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "permitido.com")
    resp = client.post("/scans", json={"domain": "otro-dominio.com"})
    assert resp.status_code == 403


async def test_list_and_get_scan(client: TestClient, monkeypatch) -> None:
    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate)

    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    listado = client.get("/scans")
    assert listado.status_code == 200
    assert [s["id"] for s in listado.json()] == [created["id"]]

    detalle = client.get(f"/scans/{created['id']}")
    assert detalle.status_code == 200
    assert detalle.json()["domain"] == "ejemplo.com"

    faltante = client.get("/scans/999")
    assert faltante.status_code == 404


async def test_list_assets_y_findings_filtran_por_scan(client: TestClient, monkeypatch) -> None:
    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate)

    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()
    scan_id = created["id"]

    assets = client.get("/assets", params={"scan_id": scan_id})
    assert assets.status_code == 200
    assert len(assets.json()) == 2

    findings = client.get("/findings", params={"scan_id": scan_id})
    assert findings.status_code == 200
    assert len(findings.json()) == 1
    assert findings.json()[0]["severity"] == "unknown"
