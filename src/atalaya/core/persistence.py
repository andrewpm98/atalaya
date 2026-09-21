"""Persistencia de resultados de descubrimiento en base de datos.

Cada módulo de descubrimiento (subdominios, puertos, cabeceras, TLS) produce
un resultado normalizado en memoria que se pierde al acabar la ejecución.
Este módulo lo traduce a un `Scan` con sus `Asset`/`Finding`, de modo que los
escaneos puedan compararse en el tiempo — el motivo original de esta fase
(ver CLAUDE.md, "Variabilidad del DNS").
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus
from atalaya.discovery.models import DiscoveryFinding, SubdomainScanResult


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
            findings=[],  # ver nota más abajo
        )
        # `findings=[]` explícito, no solo para los que sí generan uno: deja
        # la relación *cargada* mientras `asset` es transitorio (antes del
        # flush), que no cuesta una consulta -- un objeto que aún no existe
        # en BD no puede tener hijos que traer. Sin esto, tocar
        # `asset.findings` en cualquier código posterior al `flush()` de más
        # abajo (p. ej. `apply_discovery_findings`, Paso 2) dispara un
        # lazy-load fuera de contexto async (`MissingGreenlet`): una vez
        # persistente, SQLAlchemy no puede asumir que la colección sigue
        # vacía sin consultar, salvo que ya conste como cargada.
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


def apply_port_scan(scan: Scan, ports_by_ip: dict[str, list[int]]) -> None:
    """Actualiza `Asset.open_ports` a partir de un `EnrichmentResult.ports_by_ip`.

    Mutación pura en memoria, sin `flush` ni `commit`: los `Asset` de *scan*
    ya están adjuntos a la sesión (se flushearon en `save_subdomain_scan`),
    así que SQLAlchemy detecta el cambio de atributo y lo persiste en el
    siguiente commit de quien llama — mismo criterio que el resto de este
    módulo ("la transacción queda a cargo de quien llama").

    Un host puede compartir IP con otros (balanceo, CDN); se le asignan los
    puertos de *todas* las IPs en las que resuelve, no solo la primera.
    """
    for asset in scan.assets:
        abiertos: set[int] = set()
        for ip in asset.ip_addresses:
            abiertos.update(ports_by_ip.get(ip, []))
        if abiertos:
            asset.open_ports = sorted(abiertos)


def apply_discovery_findings(
    scan: Scan, findings_by_hostname: dict[str, list[DiscoveryFinding]]
) -> None:
    """Añade hallazgos de descubrimiento (cabeceras, TLS...) a los `Asset`
    correspondientes, con severidad `unknown` — igual criterio que el
    hallazgo `internal_addressing_leak` que genera `save_subdomain_scan`: la
    severidad real la razona el triaje por IA (Paso 5), nunca el módulo de
    descubrimiento que lo detecta.

    Un hostname sin `Asset` correspondiente en *scan* (no debería ocurrir:
    `findings_by_hostname` se construye a partir de los mismos hosts que
    `save_subdomain_scan` ya persistió) se ignora en vez de fallar — la
    persistencia de hallazgos no es motivo para abortar el resto del escaneo.
    """
    assets_by_hostname = {asset.hostname: asset for asset in scan.assets}
    for hostname, findings in findings_by_hostname.items():
        asset = assets_by_hostname.get(hostname)
        if asset is None:
            continue
        for finding in findings:
            asset.findings.append(
                Finding(
                    finding_type=finding.finding_type,
                    evidence=finding.evidence,
                    severity=FindingSeverity.UNKNOWN,
                )
            )
