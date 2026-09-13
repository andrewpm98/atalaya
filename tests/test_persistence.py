"""Pruebas de `core/persistence.py`: mapeo de un resultado de descubrimiento
a filas de base de datos.

El `SubdomainScanResult` se construye a mano, no vía `enumerate_subdomains`:
esta suite prueba la traducción a BD, no la enumeración (ya cubierta en
`test_subdomains.py`).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import Asset, Finding, ScanStatus
from atalaya.core.persistence import save_subdomain_scan
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


def _result() -> SubdomainScanResult:
    result = SubdomainScanResult(domain="ejemplo.com", errors=["crt.sh no disponible tras 3 intentos"])
    result.records = [
        SubdomainRecord(
            hostname="www.ejemplo.com",
            status=ResolutionStatus.ACTIVE,
            ip_addresses=["140.82.121.3"],
            sources=[DiscoverySource.CRTSH, DiscoverySource.DNS],
        ),
        SubdomainRecord(
            hostname="interno.ejemplo.com",
            status=ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"],
            sources=[DiscoverySource.CRTSH],
        ),
        SubdomainRecord(
            hostname="viejo.ejemplo.com",
            status=ResolutionStatus.NXDOMAIN,
            sources=[DiscoverySource.CRTSH],
        ),
    ]
    result.finished_at = datetime.now(timezone.utc)
    return result


async def test_save_subdomain_scan_persiste_scan_y_assets(db_session: AsyncSession) -> None:
    scan = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    assert scan.id is not None
    assert scan.domain == "ejemplo.com"
    assert scan.status is ScanStatus.COMPLETED
    assert scan.errors == ["crt.sh no disponible tras 3 intentos"]

    assets = (await db_session.execute(select(Asset).order_by(Asset.hostname))).scalars().all()
    assert [a.hostname for a in assets] == [
        "interno.ejemplo.com",
        "viejo.ejemplo.com",
        "www.ejemplo.com",
    ]

    activo = next(a for a in assets if a.hostname == "www.ejemplo.com")
    assert activo.is_active is True
    assert activo.ip_addresses == ["140.82.121.3"]
    assert activo.sources == ["crt.sh", "dns"]
    assert activo.leaks_internal_addressing is False


async def test_save_subdomain_scan_genera_finding_por_direccionamiento_interno(
    db_session: AsyncSession,
) -> None:
    await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    interno = (
        await db_session.execute(select(Asset).where(Asset.hostname == "interno.ejemplo.com"))
    ).scalar_one()
    assert interno.leaks_internal_addressing is True

    findings = (
        await db_session.execute(select(Finding).where(Finding.asset_id == interno.id))
    ).scalars().all()
    assert len(findings) == 1
    assert findings[0].finding_type == "internal_addressing_leak"
    assert "10.0.0.5" in findings[0].evidence


async def test_save_subdomain_scan_sin_resolver_queda_running(db_session: AsyncSession) -> None:
    result = SubdomainScanResult(domain="ejemplo.com")
    result.records = [
        SubdomainRecord(
            hostname="ejemplo.com", status=ResolutionStatus.ACTIVE, ip_addresses=["1.2.3.4"]
        )
    ]
    # finished_at no establecido: el escaneo aún no ha terminado.

    scan = await save_subdomain_scan(db_session, result)
    await db_session.commit()

    assert scan.status is ScanStatus.RUNNING
