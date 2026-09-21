"""Pruebas de los endpoints `/scans`, `/assets` y `/findings`.

`create_scan` se prueba sustituyendo `enumerate_subdomains` y `enrich_scan`
(las fuentes externas) por dobles: esta suite prueba el cableado HTTP ->
descubrimiento -> persistencia, no la enumeración en sí (ya cubierta en
`test_subdomains.py`) ni puertos/cabeceras/TLS (cubiertos en
`test_ports.py`/`test_headers.py`/`test_tls.py`/`test_enrichment.py`). Sin
mockear `enrich_scan`, un host `ACTIVE` en `_fake_result` dispararía
conexiones de red reales al crear el escaneo -- justo lo que CLAUDE.md pide
evitar ("Tests: deterministas y sin red").

La sesión de BD se inyecta vía `app.dependency_overrides`, contra SQLite en
memoria — igual que `db_session`, pero por request HTTP en vez de directa.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from atalaya.config import settings
from atalaya.discovery.models import (
    DiscoverySource,
    EnrichmentResult,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


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


def _mock_discovery(monkeypatch, *, enrichment: EnrichmentResult | None = None) -> None:
    """Sustituye `enumerate_subdomains` y `enrich_scan` por dobles rápidos y
    sin red, en el módulo del router (no en `discovery/`, que es donde se
    resuelven las llamadas)."""

    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    async def fake_enrich(result: SubdomainScanResult) -> EnrichmentResult:
        return enrichment if enrichment is not None else EnrichmentResult()

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate)
    monkeypatch.setattr("atalaya.api.routes.scans.enrich_scan", fake_enrich)


async def test_create_scan_persiste_y_devuelve_detalle(client: TestClient, monkeypatch) -> None:
    _mock_discovery(monkeypatch)

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
    _mock_discovery(monkeypatch)

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
    _mock_discovery(monkeypatch)

    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()
    scan_id = created["id"]

    assets = client.get("/assets", params={"scan_id": scan_id})
    assert assets.status_code == 200
    assert len(assets.json()) == 2

    findings = client.get("/findings", params={"scan_id": scan_id})
    assert findings.status_code == 200
    assert len(findings.json()) == 1
    assert findings.json()[0]["severity"] == "unknown"


async def test_create_scan_persiste_puertos_y_hallazgos_del_enriquecimiento(
    client: TestClient, monkeypatch
) -> None:
    """`create_scan` no solo persiste subdominios: también aplica el
    resultado de `enrich_scan` (puertos abiertos y hallazgos de
    cabeceras/TLS) sobre los mismos activos, en la misma petición."""
    from atalaya.discovery.models import DiscoveryFinding, HeaderScanResult, TlsScanResult

    enrichment = EnrichmentResult(
        ports_by_ip={"93.184.216.34": [80, 443]},
        header_results=[
            HeaderScanResult(
                hostname="www.ejemplo.com",
                checked_url="https://www.ejemplo.com/",
                findings=[
                    DiscoveryFinding(finding_type="hsts_missing", evidence="sin HSTS")
                ],
            )
        ],
        tls_results=[
            TlsScanResult(
                hostname="www.ejemplo.com",
                findings=[
                    DiscoveryFinding(
                        finding_type="tls_version_obsoleta", evidence="negocia TLSv1.1"
                    )
                ],
            )
        ],
    )
    _mock_discovery(monkeypatch, enrichment=enrichment)

    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    www = next(a for a in created["assets"] if a["hostname"] == "www.ejemplo.com")
    assert www["open_ports"] == [80, 443]
    tipos = {f["finding_type"] for f in www["findings"]}
    assert tipos == {"hsts_missing", "tls_version_obsoleta"}
    assert all(f["severity"] == "unknown" for f in www["findings"])


# ─── GET /scans/{id}/report ──────────────────────────────────────────────────


async def test_download_report_devuelve_pdf(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """Prueba de extremo a extremo: escaneo real (persistencia) -> informe
    real (Jinja2 + xhtml2pdf) -> respuesta HTTP. `reports_dir` se redirige a
    `tmp_path` para no escribir en el directorio del proyecto durante los
    tests."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    _mock_discovery(monkeypatch)
    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    resp = client.get(f"/scans/{created['id']}/report")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
    assert list(tmp_path.glob("*.pdf"))  # el informe se escribió a disco


async def test_download_report_escaneo_inexistente_da_404(client: TestClient) -> None:
    resp = client.get("/scans/999/report")
    assert resp.status_code == 404
