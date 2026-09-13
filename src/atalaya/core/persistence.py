"""Persistencia de resultados de descubrimiento en base de datos.

Cada módulo de descubrimiento (subdominios ahora; puertos, cabeceras y TLS
después) produce un resultado normalizado en memoria que se pierde al acabar
la ejecución. Este módulo lo traduce a un `Scan` con sus `Asset`, de modo que
los escaneos puedan compararse en el tiempo — el motivo original de esta fase
(ver CLAUDE.md, "Variabilidad del DNS").
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus
from atalaya.discovery.models import SubdomainScanResult


async def save_subdomain_scan(session: AsyncSession, result: SubdomainScanResult) -> Scan:
    """Persiste un `SubdomainScanResult` como un `Scan` con sus `Asset`.

    Un host con `leaks_internal_addressing` genera además un `Finding`: no es
    solo un dato de inventario, es un hallazgo por derecho propio (ver
    `SubdomainRecord.leaks_internal_addressing`).

    No hace commit: la transacción queda a cargo de quien llama, para que
    pueda combinarse con otras escrituras en la misma unidad de trabajo.
    """
    scan = Scan(
        domain=result.domain,
        status=ScanStatus.COMPLETED if result.finished_at else ScanStatus.RUNNING,
        started_at=result.started_at,
        finished_at=result.finished_at,
        errors=list(result.errors),
    )

    for record in result.records:
        asset = Asset(
            hostname=record.hostname,
            status=record.status.value,
            ip_addresses=list(record.ip_addresses),
            sources=[source.value for source in record.sources],
            is_active=record.is_active,
            leaks_internal_addressing=record.leaks_internal_addressing,
        )
        if record.leaks_internal_addressing:
            detalle = ", ".join(
                f"{ip} ({scope.value})" for ip, scope in record.ip_scopes.items()
            )
            asset.findings.append(
                Finding(
                    finding_type="internal_addressing_leak",
                    evidence=f"{record.hostname} resuelve a direccionamiento interno: {detalle}",
                    severity=FindingSeverity.UNKNOWN,
                )
            )
        scan.assets.append(asset)

    session.add(scan)
    await session.flush()
    return scan
