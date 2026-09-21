"""Pruebas de `discovery/enrichment.py`: orquestación de puertos, cabeceras
y TLS sobre los hosts activos de un `SubdomainScanResult`.

`scan_ports`/`analyze_headers`/`inspect_tls` se sustituyen por dobles: esta
suite prueba el cableado (qué se llama, con qué argumentos, cómo se combinan
los resultados), no cada técnica en sí — ya cubiertas en `test_ports.py`,
`test_headers.py` y `test_tls.py`.
"""

from __future__ import annotations

from atalaya.discovery.enrichment import enrich_scan
from atalaya.discovery.models import (
    DiscoveryFinding,
    DiscoverySource,
    HeaderScanResult,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
    TlsScanResult,
)


def _result(*records: SubdomainRecord) -> SubdomainScanResult:
    result = SubdomainScanResult(domain="ejemplo.com")
    result.records = list(records)
    return result


async def test_enrich_scan_sin_hosts_activos_no_llama_a_nada(monkeypatch) -> None:
    llamado = {"ports": False, "headers": False, "tls": False}

    async def fake_ports(host, ports=None, **kwargs):
        llamado["ports"] = True
        return []

    async def fake_headers(url, **kwargs):
        llamado["headers"] = True
        return HeaderScanResult(hostname="x")

    async def fake_tls(host, port=443, **kwargs):
        llamado["tls"] = True
        return TlsScanResult(hostname=host)

    monkeypatch.setattr("atalaya.discovery.enrichment.scan_ports", fake_ports)
    monkeypatch.setattr("atalaya.discovery.enrichment.analyze_headers", fake_headers)
    monkeypatch.setattr("atalaya.discovery.enrichment.inspect_tls", fake_tls)

    result = _result(
        SubdomainRecord(
            hostname="interno.ejemplo.com",
            status=ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"],
            sources=[DiscoverySource.CRTSH],
        )
    )

    enrichment = await enrich_scan(result)

    assert enrichment.ports_by_ip == {}
    assert enrichment.header_results == []
    assert enrichment.tls_results == []
    assert not any(llamado.values())


async def test_enrich_scan_combina_puertos_cabeceras_y_tls(monkeypatch) -> None:
    async def fake_ports(host: str, ports=None, **kwargs) -> list[int]:
        return {"93.184.216.34": [80, 443]}.get(host, [])

    async def fake_headers(url: str, **kwargs) -> HeaderScanResult:
        hostname = url.split("//", 1)[1].rstrip("/")
        return HeaderScanResult(
            hostname=hostname,
            findings=[DiscoveryFinding(finding_type="hsts_missing", evidence="sin HSTS")],
        )

    async def fake_tls(host: str, port: int = 443, **kwargs) -> TlsScanResult:
        return TlsScanResult(
            hostname=host,
            findings=[
                DiscoveryFinding(finding_type="tls_version_obsoleta", evidence="TLSv1.1")
            ],
        )

    monkeypatch.setattr("atalaya.discovery.enrichment.scan_ports", fake_ports)
    monkeypatch.setattr("atalaya.discovery.enrichment.analyze_headers", fake_headers)
    monkeypatch.setattr("atalaya.discovery.enrichment.inspect_tls", fake_tls)

    result = _result(
        SubdomainRecord(
            hostname="www.ejemplo.com",
            status=ResolutionStatus.ACTIVE,
            ip_addresses=["93.184.216.34"],
            sources=[DiscoverySource.CRTSH, DiscoverySource.DNS],
        ),
        SubdomainRecord(
            hostname="interno.ejemplo.com",
            status=ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"],
            sources=[DiscoverySource.CRTSH],
        ),
    )

    enrichment = await enrich_scan(result)

    assert enrichment.ports_by_ip == {"93.184.216.34": [80, 443]}
    assert [r.hostname for r in enrichment.header_results] == ["www.ejemplo.com"]
    assert [r.hostname for r in enrichment.tls_results] == ["www.ejemplo.com"]

    grouped = enrichment.findings_by_hostname()
    assert {f.finding_type for f in grouped["www.ejemplo.com"]} == {
        "hsts_missing",
        "tls_version_obsoleta",
    }
    assert "interno.ejemplo.com" not in grouped


async def test_enrich_scan_no_escanea_ips_no_enrutables(monkeypatch) -> None:
    ips_escaneadas: list[str] = []

    async def fake_ports(host: str, ports=None, **kwargs) -> list[int]:
        ips_escaneadas.append(host)
        return []

    async def fake_headers(url: str, **kwargs) -> HeaderScanResult:
        return HeaderScanResult(hostname=url)

    async def fake_tls(host: str, port: int = 443, **kwargs) -> TlsScanResult:
        return TlsScanResult(hostname=host)

    monkeypatch.setattr("atalaya.discovery.enrichment.scan_ports", fake_ports)
    monkeypatch.setattr("atalaya.discovery.enrichment.analyze_headers", fake_headers)
    monkeypatch.setattr("atalaya.discovery.enrichment.inspect_tls", fake_tls)

    result = _result(
        SubdomainRecord(
            hostname="mixto.ejemplo.com",
            status=ResolutionStatus.ACTIVE,
            ip_addresses=["93.184.216.34", "10.0.0.5"],  # una enrutable, otra no
            sources=[DiscoverySource.CRTSH],
        )
    )

    await enrich_scan(result)

    assert ips_escaneadas == ["93.184.216.34"]
