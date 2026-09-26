"""Pruebas de `core/repository.py`: consultas de lectura sobre escaneos,
activos y hallazgos ya persistidos.

Los datos se crean con `save_subdomain_scan` (ya probado en
`test_persistence.py`): esta suite prueba las consultas, no la escritura.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import ScanStatus
from atalaya.core.persistence import save_subdomain_scan
from atalaya.core.repository import (
    diff_scans,
    get_latest_scan,
    get_scan,
    list_assets,
    list_findings,
    list_scans,
)
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


def _result(domain: str = "ejemplo.com", hostnames: list[str] | None = None) -> SubdomainScanResult:
    hostnames = hostnames if hostnames is not None else ["www.ejemplo.com", "interno.ejemplo.com"]
    result = SubdomainScanResult(domain=domain)
    result.records = [
        SubdomainRecord(
            hostname=host,
            status=ResolutionStatus.ACTIVE if "interno" not in host else ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"] if "interno" in host else ["140.82.121.3"],
            sources=[DiscoverySource.CRTSH],
        )
        for host in hostnames
    ]
    result.finished_at = datetime.now(UTC)
    return result


async def test_get_scan_devuelve_none_si_no_existe(db_session: AsyncSession) -> None:
    assert await get_scan(db_session, 999) is None


async def test_get_scan_precarga_assets_y_findings(db_session: AsyncSession) -> None:
    saved = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    scan = await get_scan(db_session, saved.id)

    assert scan is not None
    assert {a.hostname for a in scan.assets} == {"www.ejemplo.com", "interno.ejemplo.com"}
    interno = next(a for a in scan.assets if a.hostname == "interno.ejemplo.com")
    assert len(interno.findings) == 1


async def test_list_scans_ordena_por_mas_reciente_y_filtra_por_dominio(
    db_session: AsyncSession,
) -> None:
    primero = await save_subdomain_scan(db_session, _result(domain="uno.com"))
    await db_session.commit()
    segundo = await save_subdomain_scan(db_session, _result(domain="dos.com"))
    await db_session.commit()

    todos = await list_scans(db_session)
    assert [s.id for s in todos] == [segundo.id, primero.id]

    solo_uno = await list_scans(db_session, domain="uno.com")
    assert [s.id for s in solo_uno] == [primero.id]


async def test_get_latest_scan_ignora_escaneos_no_completados(db_session: AsyncSession) -> None:
    sin_terminar = SubdomainScanResult(domain="ejemplo.com")
    sin_terminar.records = [
        SubdomainRecord(hostname="a.ejemplo.com", status=ResolutionStatus.ACTIVE, ip_addresses=["1.2.3.4"])
    ]
    # finished_at no establecido -> Scan queda en RUNNING.
    await save_subdomain_scan(db_session, sin_terminar)
    await db_session.commit()

    assert await get_latest_scan(db_session, "ejemplo.com") is None

    completo = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    latest = await get_latest_scan(db_session, "ejemplo.com")
    assert latest is not None
    assert latest.id == completo.id
    assert latest.status is ScanStatus.COMPLETED


async def test_list_assets_filtra_por_scan(db_session: AsyncSession) -> None:
    uno = await save_subdomain_scan(db_session, _result(domain="uno.com"))
    await db_session.commit()
    await save_subdomain_scan(db_session, _result(domain="dos.com"))
    await db_session.commit()

    assets = await list_assets(db_session, scan_id=uno.id)
    assert {a.hostname for a in assets} == {"www.ejemplo.com", "interno.ejemplo.com"}


async def test_list_findings_filtra_por_asset_y_por_scan(db_session: AsyncSession) -> None:
    scan = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    interno = next(a for a in scan.assets if a.hostname == "interno.ejemplo.com")

    por_asset = await list_findings(db_session, asset_id=interno.id)
    assert len(por_asset) == 1

    por_scan = await list_findings(db_session, scan_id=scan.id)
    assert len(por_scan) == 1

    sin_filtro = await list_findings(db_session)
    assert len(sin_filtro) == 1


async def test_diff_scans_detecta_nuevos_y_desaparecidos(db_session: AsyncSession) -> None:
    anterior = await save_subdomain_scan(
        db_session, _result(hostnames=["a.ejemplo.com", "b.ejemplo.com"])
    )
    await db_session.commit()
    actual = await save_subdomain_scan(
        db_session, _result(hostnames=["b.ejemplo.com", "c.ejemplo.com"])
    )
    await db_session.commit()

    anterior_cargado = await get_scan(db_session, anterior.id)
    actual_cargado = await get_scan(db_session, actual.id)
    assert anterior_cargado is not None
    assert actual_cargado is not None

    diff = diff_scans(anterior_cargado, actual_cargado)

    assert diff.nuevos == ["c.ejemplo.com"]
    assert diff.desaparecidos == ["a.ejemplo.com"]
    assert diff.comunes == ["b.ejemplo.com"]
