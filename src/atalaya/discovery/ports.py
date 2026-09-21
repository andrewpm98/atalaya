"""Escaneo asíncrono de puertos TCP sobre hosts descubiertos (Paso 2).

Intrusividad acotada (CLAUDE.md, restricción de seguridad 5): concurrencia
limitada por semáforo — mismo patrón que `resolve_hostname` en
`discovery/subdomains.py` — y, por defecto, un conjunto reducido de puertos
habituales, no un barrido exhaustivo de los 65535. Un escaneo agresivo puede
degradar el servicio del objetivo y es indistinguible de un ataque.
"""

from __future__ import annotations

import asyncio
import logging

from atalaya.config import settings

logger = logging.getLogger(__name__)

#: Puertos habitualmente relevantes en superficie de ataque: web, correo,
#: bases de datos comunes y gestión remota. No es una lista exhaustiva a
#: propósito — cubre lo que más importa para ASM sin convertir el escaneo
#: por defecto en un barrido intrusivo.
COMMON_PORTS: tuple[int, ...] = (
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    587,   # SMTP (submission)
    993,   # IMAPS
    995,   # POP3S
    1433,  # SQL Server
    1521,  # Oracle
    2049,  # NFS
    3000,  # dev servers habituales
    3306,  # MySQL/MariaDB
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # HTTP alternativo
    8080,  # HTTP alternativo / proxies
    8443,  # HTTPS alternativo
    9200,  # Elasticsearch
    27017,  # MongoDB
)


async def _probe_port(
    host: str, port: int, timeout: float, semaphore: asyncio.Semaphore
) -> int | None:
    """Prueba un único puerto TCP. Nunca lanza: cerrado, filtrado o con
    timeout se refleja devolviendo `None`, mismo criterio de degradación
    controlada que `resolve_hostname` — un puerto problemático no debe
    abortar el resto del escaneo del host.
    """
    async with semaphore:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (TimeoutError, OSError):
            return None

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass  # la conexión ya se dio por cerrada; nada que limpiar
        return port


async def scan_ports(
    host: str,
    ports: list[int] | None = None,
    *,
    timeout: float | None = None,
    concurrency: int | None = None,
) -> list[int]:
    """Devuelve, ordenados, los puertos TCP abiertos en *host*.

    *host* debe ser una dirección IP enrutable (ver
    `SubdomainScanResult.scan_targets()`): este módulo no resuelve DNS ni
    valida autorización — ambas ya se hicieron en la fase de subdominios que
    produce los objetivos de escaneo.

    Args:
        host: Dirección IP a sondear.
        ports: Puertos a probar. Por defecto, `COMMON_PORTS`.
        timeout: Timeout por conexión, en segundos. Por defecto,
            `settings.port_scan_timeout`.
        concurrency: Conexiones simultáneas. Por defecto,
            `settings.port_scan_concurrency`.
    """
    puertos = ports if ports is not None else list(COMMON_PORTS)
    to = timeout if timeout is not None else settings.port_scan_timeout
    semaphore = asyncio.Semaphore(concurrency or settings.port_scan_concurrency)

    resultados = await asyncio.gather(
        *(_probe_port(host, port, to, semaphore) for port in puertos)
    )
    abiertos = sorted(p for p in resultados if p is not None)
    logger.info(
        "Escaneo de puertos en %s: %d/%d abiertos", host, len(abiertos), len(puertos)
    )
    return abiertos
