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

La detección de *subdomain takeover* (`discovery/takeover.py`) es la
excepción deliberada a ese criterio: se ejecuta sobre **todos** los
registros (`result.records`), no solo los activos, porque la señal que
busca vive precisamente en los hosts que no resuelven por A/AAAA -- ver el
docstring de `discovery/takeover.py`.
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
from atalaya.discovery.takeover import find_takeover_candidates
from atalaya.discovery.takeover_verify import verify_candidates
from atalaya.discovery.tls import inspect_tls

logger = logging.getLogger(__name__)


async def enrich_scan(result: SubdomainScanResult) -> EnrichmentResult:
    """Ejecuta puertos, cabeceras, TLS y detección de takeover sobre *result*.

    Puertos, cabeceras y TLS solo actúan sobre los hosts *activos*: son
    independientes entre sí y se lanzan concurrentemente (`asyncio.gather`),
    cada una acotada por su propio semáforo de
    `settings.enrichment_host_concurrency` hosts en paralelo — sin este
    límite, un escaneo con muchos subdominios activos dispararía cientos de
    conexiones simultáneas sin control (CLAUDE.md, restricción de seguridad 5).

    La detección de takeover (`discovery/takeover.py::find_takeover_candidates`)
    es la cuarta rama del `gather`, pero recibe *todos* los registros
    (`result.records`), no solo los activos: sin hosts activos, las otras tres
    técnicas no tienen nada que hacer, pero la búsqueda de takeover sigue
    siendo relevante -- por eso ya no hay una salida temprana cuando
    `result.active_records` está vacío.

    Tras el `gather`, si `TAKEOVER_VERIFY` está activo, `verify_candidates`
    (`discovery/takeover_verify.py`) hace un `GET` a la página de error del
    proveedor de cada candidato para buscar la huella de "recurso no
    reclamado". Es opt-in (off por defecto): sin el flag, devuelve los
    candidatos sin tocar y no hace ninguna petición HTTP.
    """
    active = result.active_records
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

    port_pairs, header_results, tls_results, takeover_candidates = await asyncio.gather(
        asyncio.gather(*(_ports(ip) for ip in ips)),
        asyncio.gather(*(_headers(hostname) for hostname in hostnames)),
        asyncio.gather(*(_tls(hostname) for hostname in hostnames)),
        find_takeover_candidates(result.records),
    )

    # Verificación HTTP opt-in (TAKEOVER_VERIFY, off por defecto). Va DESPUÉS
    # del gather, no dentro: depende de que los candidatos ya existan, y solo
    # sobre ellos. Con el flag desactivado, `verify_candidates` los devuelve
    # sin tocar y sin ninguna petición HTTP -- el flujo por defecto no cambia.
    takeover_candidates = await verify_candidates(list(takeover_candidates))

    logger.info(
        "Enriquecimiento de %s completado: %d IPs escaneadas, %d hosts analizados "
        "(cabeceras + TLS), %d candidatos a takeover",
        result.domain,
        len(port_pairs),
        len(hostnames),
        len(takeover_candidates),
    )
    return EnrichmentResult(
        ports_by_ip=dict(port_pairs),
        header_results=list(header_results),
        tls_results=list(tls_results),
        takeover_candidates=list(takeover_candidates),
    )
