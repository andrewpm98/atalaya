"""Enriquecimiento de un escaneo de subdominios con puertos, cabeceras de
seguridad HTTP y configuración TLS (Paso 2, resto).

**Desviación del stub original:** CLAUDE.md no preveía este fichero — solo
`ports.py`, `headers.py` y `tls.py`. Sin él, `POST /scans` tendría que
orquestar tres escaneos concurrentes con sus propios semáforos directamente
en el endpoint, mezclando la capa HTTP con lógica de descubrimiento. Se
separa aquí por el mismo motivo que `ai/query.py` se separó de
`ai/triage.py`: compone módulos independientes, no pertenece a ninguno de
ellos en particular. No hace I/O de base de datos — produce un
`EnrichmentResult` en memoria que `core/persistence.py` traduce a filas,
igual patrón que `enumerate_subdomains` → `save_subdomain_scan`.

Solo se enriquecen los hosts *activos* (`SubdomainScanResult.active_records`)
y las IPs enrutables (`scan_targets()`): un host que no resuelve, o que solo
resuelve a direccionamiento interno, no tiene un servicio HTTP/TLS real que
inspeccionar, y sondearlo igualmente no aportaría nada más que tráfico
innecesario hacia una dirección que no es un objetivo válido de escaneo.
"""

from __future__ import annotations

import asyncio
import logging

from atalaya.config import settings
from atalaya.discovery.headers import analyze_headers
from atalaya.discovery.models import (
    EnrichmentResult,
    HeaderScanResult,
    SubdomainScanResult,
    TlsScanResult,
)
from atalaya.discovery.ports import scan_ports
from atalaya.discovery.tls import inspect_tls

logger = logging.getLogger(__name__)


async def enrich_scan(result: SubdomainScanResult) -> EnrichmentResult:
    """Ejecuta puertos, cabeceras y TLS sobre los hosts activos de *result*.

    Las tres técnicas son independientes entre sí y se lanzan concurrentemente
    (`asyncio.gather`), cada una acotada por su propio semáforo de
    `settings.enrichment_host_concurrency` hosts en paralelo — sin este
    límite, un escaneo con muchos subdominios activos dispararía cientos de
    conexiones simultáneas sin control (CLAUDE.md, restricción de seguridad 5).
    """
    active = result.active_records
    if not active:
        return EnrichmentResult()

    hostnames = [record.hostname for record in active]
    ips = result.scan_targets()

    port_semaphore = asyncio.Semaphore(settings.enrichment_host_concurrency)
    header_semaphore = asyncio.Semaphore(settings.enrichment_host_concurrency)
    tls_semaphore = asyncio.Semaphore(settings.enrichment_host_concurrency)

    async def _ports(ip: str) -> tuple[str, list[int]]:
        async with port_semaphore:
            return ip, await scan_ports(ip)

    async def _headers(hostname: str) -> HeaderScanResult:
        async with header_semaphore:
            return await analyze_headers(f"https://{hostname}/")

    async def _tls(hostname: str) -> TlsScanResult:
        async with tls_semaphore:
            return await inspect_tls(hostname)

    port_pairs, header_results, tls_results = await asyncio.gather(
        asyncio.gather(*(_ports(ip) for ip in ips)),
        asyncio.gather(*(_headers(hostname) for hostname in hostnames)),
        asyncio.gather(*(_tls(hostname) for hostname in hostnames)),
    )

    logger.info(
        "Enriquecimiento de %s completado: %d IPs escaneadas, %d hosts analizados "
        "(cabeceras + TLS)",
        result.domain,
        len(port_pairs),
        len(hostnames),
    )
    return EnrichmentResult(
        ports_by_ip=dict(port_pairs),
        header_results=list(header_results),
        tls_results=list(tls_results),
    )
