"""Pruebas de `discovery/enrichment.py`: orquestación de puertos, cabeceras,
TLS y detección de takeover sobre un `SubdomainScanResult`.

`scan_ports`/`analyze_headers`/`inspect_tls`/`find_takeover_candidates` se
sustituyen por dobles: esta suite prueba el cableado (qué se llama, con qué
argumentos, cómo se combinan los resultados), no cada técnica en sí — ya
cubiertas en `test_ports.py`, `test_headers.py`, `test_tls.py` y
`test_takeover.py`.
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
    TakeoverCandidate,
    TlsScanResult,
)


def _result(*records: SubdomainRecord) -> SubdomainScanResult:
    result = SubdomainScanResult(domain="ejemplo.com")
    result.records = list(records)
    return result


def _sin_takeover(monkeypatch) -> None:
    """Neutraliza `find_takeover_candidates` en pruebas que no lo ejercitan:
    sin esto, `enrich_scan` intentaría resolver CNAME por DNS real."""

    async def fake_takeover(records):
        return []

    monkeypatch.setattr(
        "atalaya.discovery.enrichment.find_takeover_candidates", fake_takeover
    )


async def test_enrich_scan_sin_hosts_activos_no_llama_a_ports_headers_tls(
    monkeypatch,
) -> None:
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
    _sin_takeover(monkeypatch)

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


async def test_enrich_scan_busca_takeover_aunque_no_haya_hosts_activos(monkeypatch) -> None:
    """La detección de takeover no depende de que haya hosts activos: la
    señal que busca vive en los hosts que NO resuelven por A/AAAA."""
    recibidos: list[SubdomainRecord] = []

    async def fake_ports(host, ports=None, **kwargs):
        return []

    async def fake_headers(url, **kwargs):
        return HeaderScanResult(hostname="x")

    async def fake_tls(host, port=443, **kwargs):
        return TlsScanResult(hostname=host)

    async def fake_takeover(records):
        recibidos.extend(records)
        return [
            TakeoverCandidate(
                hostname="old.ejemplo.com",
                cname="old.ejemplo.com.github.io",
                provider="GitHub Pages",
                pattern_matched="github.io",
            )
        ]

    monkeypatch.setattr("atalaya.discovery.enrichment.scan_ports", fake_ports)
    monkeypatch.setattr("atalaya.discovery.enrichment.analyze_headers", fake_headers)
    monkeypatch.setattr("atalaya.discovery.enrichment.inspect_tls", fake_tls)
    monkeypatch.setattr(
        "atalaya.discovery.enrichment.find_takeover_candidates", fake_takeover
    )

    record = SubdomainRecord(
        hostname="old.ejemplo.com",
        status=ResolutionStatus.NO_ANSWER,
        sources=[DiscoverySource.CRTSH],
    )
    result = _result(record)

    enrichment = await enrich_scan(result)

    assert recibidos == [record]  # recibe TODOS los registros, no solo activos
    assert len(enrichment.takeover_candidates) == 1
    assert enrichment.takeover_candidates[0].provider == "GitHub Pages"


async def test_enrich_scan_combina_puertos_cabeceras_tls_y_takeover(monkeypatch) -> None:
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

    async def fake_takeover(records) -> list[TakeoverCandidate]:
        return [
            TakeoverCandidate(
                hostname="interno.ejemplo.com",
                cname="interno.ejemplo.com.herokuapp.com",
                provider="Heroku",
                pattern_matched="herokuapp.com",
            )
        ]

    monkeypatch.setattr("atalaya.discovery.enrichment.scan_ports", fake_ports)
    monkeypatch.setattr("atalaya.discovery.enrichment.analyze_headers", fake_headers)
    monkeypatch.setattr("atalaya.discovery.enrichment.inspect_tls", fake_tls)
    monkeypatch.setattr(
        "atalaya.discovery.enrichment.find_takeover_candidates", fake_takeover
    )

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
    assert enrichment.takeover_candidates[0].hostname == "interno.ejemplo.com"

    # findings_by_hostname() agrupa cabeceras/TLS y takeover, cada uno con su
    # propio hostname -- el hallazgo de takeover no depende de que el host
    # tenga también hallazgos de cabeceras/TLS (aquí "interno" no los tiene).
    grouped = enrichment.findings_by_hostname()
    assert {f.finding_type for f in grouped["www.ejemplo.com"]} == {
        "hsts_missing",
        "tls_version_obsoleta",
    }
    assert {f.finding_type for f in grouped["interno.ejemplo.com"]} == {
        "subdomain_takeover_risk"
    }
    assert "Heroku" in grouped["interno.ejemplo.com"][0].evidence


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
