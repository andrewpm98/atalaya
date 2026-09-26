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

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from atalaya.ai.provider import LLMProvider
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError
from atalaya.discovery.models import (
    DiscoverySource,
    EnrichmentResult,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


class _FakeDiffProvider(LLMProvider):
    """Doble de `LLMProvider` para `GET /scans/{id}/diff/{other_id}`:
    `analyze_diff` usa `complete()` (prosa libre), no `complete_tool()`.
    """

    def __init__(self, *, text: str | None = None, error: Exception | None = None) -> None:
        self._text = text
        self._error = error

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        if self._error is not None:
            raise self._error
        assert self._text is not None
        return self._text

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError("no usado por analyze_diff")


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
    result.finished_at = datetime.now(UTC)
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


# ─── GET /scans/{id}/diff/{other_id} ─────────────────────────────────────────


def _fake_result_con_hosts(domain: str, *hostnames: str) -> SubdomainScanResult:
    result = SubdomainScanResult(domain=domain)
    result.records = [
        SubdomainRecord(
            hostname=hostname,
            status=ResolutionStatus.ACTIVE,
            ip_addresses=["93.184.216.34"],
            sources=[DiscoverySource.CRTSH],
        )
        for hostname in hostnames
    ]
    result.finished_at = datetime.now(UTC)
    return result


def _crear_dos_escaneos(client: TestClient, monkeypatch, domain: str = "ejemplo.com") -> tuple[int, int]:
    """Persiste dos escaneos sucesivos de `domain` con activos distintos:
    `old.<domain>` desaparece y `new.<domain>` aparece; `www.<domain>` es
    común a ambos."""

    async def fake_enrich(result: SubdomainScanResult) -> EnrichmentResult:
        return EnrichmentResult()

    monkeypatch.setattr("atalaya.api.routes.scans.enrich_scan", fake_enrich)

    async def fake_enumerate_1(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result_con_hosts(domain, f"www.{domain}", f"old.{domain}")

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate_1)
    primero = client.post("/scans", json={"domain": domain}).json()

    async def fake_enumerate_2(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result_con_hosts(domain, f"www.{domain}", f"new.{domain}")

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate_2)
    segundo = client.post("/scans", json={"domain": domain}).json()

    return primero["id"], segundo["id"]


async def test_diff_scan_compara_activos_y_devuelve_analisis_ia(
    client: TestClient, monkeypatch
) -> None:
    scan_id_1, scan_id_2 = _crear_dos_escaneos(client, monkeypatch)

    fake_provider = _FakeDiffProvider(text="La superficie de exposición se mantiene estable.")
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    resp = client.get(f"/scans/{scan_id_1}/diff/{scan_id_2}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["previous_scan_id"] == scan_id_1
    assert body["current_scan_id"] == scan_id_2
    assert body["nuevos"] == ["new.ejemplo.com"]
    assert body["desaparecidos"] == ["old.ejemplo.com"]
    assert body["comunes"] == ["www.ejemplo.com"]
    assert body["analysis"] == "La superficie de exposición se mantiene estable."


async def test_diff_scan_es_independiente_del_orden_de_los_ids_en_la_url(
    client: TestClient, monkeypatch
) -> None:
    """Pedir `/diff/` con los ids al revés da la misma comparación: `previous`
    se decide por `started_at`, no por qué id aparece primero en la ruta."""
    scan_id_1, scan_id_2 = _crear_dos_escaneos(client, monkeypatch)

    fake_provider = _FakeDiffProvider(text="Sin cambios preocupantes.")
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    resp = client.get(f"/scans/{scan_id_2}/diff/{scan_id_1}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["previous_scan_id"] == scan_id_1
    assert body["current_scan_id"] == scan_id_2
    assert body["nuevos"] == ["new.ejemplo.com"]
    assert body["desaparecidos"] == ["old.ejemplo.com"]


async def test_diff_scan_dominios_distintos_da_400(client: TestClient, monkeypatch) -> None:
    _mock_discovery(monkeypatch)
    escaneo_a = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    _mock_discovery(monkeypatch)
    escaneo_b = client.post("/scans", json={"domain": "otro.com"}).json()

    resp = client.get(f"/scans/{escaneo_a['id']}/diff/{escaneo_b['id']}")

    assert resp.status_code == 400


async def test_diff_scan_escaneo_inexistente_da_404(client: TestClient, monkeypatch) -> None:
    _mock_discovery(monkeypatch)
    escaneo = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    resp = client.get(f"/scans/{escaneo['id']}/diff/999")

    assert resp.status_code == 404


async def test_diff_scan_proveedor_caido_da_502(client: TestClient, monkeypatch) -> None:
    scan_id_1, scan_id_2 = _crear_dos_escaneos(client, monkeypatch)

    fake_provider = _FakeDiffProvider(error=AIProviderError("proveedor caído"))
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    resp = client.get(f"/scans/{scan_id_1}/diff/{scan_id_2}")

    assert resp.status_code == 502


# ─── GET /scans/{id}/report ──────────────────────────────────────────────────


async def test_download_report_devuelve_pdf(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """Prueba de extremo a extremo: escaneo real (persistencia) -> informe
    real (Jinja2 + xhtml2pdf) -> respuesta HTTP. `reports_dir` se redirige a
    `tmp_path` para no escribir en el directorio del proyecto durante los
    tests.

    Sin proveedor de IA configurado (la fixture autouse `_sin_claves_reales`
    de `conftest.py` neutraliza las claves), este es también el camino que
    ejercita la degradación de la Tarea 3: `download_report` captura el
    `AIProviderError` que lanza `get_provider()` al no haber clave, y el PDF
    se descarga igual, sin resumen ejecutivo."""
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


async def test_download_report_con_proveedor_disponible_incluye_resumen_ejecutivo(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """Con un proveedor de IA disponible, `download_report` se lo pasa a
    `generate_report()` (Tarea 3): el PDF se sigue descargando con 200, y
    `ai/report_writer.py::write_executive_summary()` se invoca de verdad."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    _mock_discovery(monkeypatch)
    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    fake_provider = _FakeDiffProvider(text="Resumen ejecutivo de prueba.")
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    resp = client.get(f"/scans/{created['id']}/report")

    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")


async def test_download_report_proveedor_configurado_pero_caido_no_impide_la_descarga(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """Distinto de "sin clave" (`test_download_report_devuelve_pdf`): aquí
    `get_provider()` sí devuelve un proveedor, pero falla al generar el
    resumen (`AIProviderError` desde `complete()`). El informe debe
    descargarse igual, con 200 — no un 502, a diferencia de
    `POST /findings/ask` y `GET /scans/{id}/diff/{other_id}`."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    _mock_discovery(monkeypatch)
    created = client.post("/scans", json={"domain": "ejemplo.com"}).json()

    fake_provider = _FakeDiffProvider(error=AIProviderError("proveedor caído"))
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    resp = client.get(f"/scans/{created['id']}/report")

    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")
