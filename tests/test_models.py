"""Pruebas de los modelos ORM: relaciones y borrado en cascada.

No dependen de Postgres: usan el esquema SQLite en memoria de `conftest.py`.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus


async def test_scan_asset_finding_se_relacionan(db_session: AsyncSession) -> None:
    scan = Scan(domain="ejemplo.com", status=ScanStatus.COMPLETED)
    asset = Asset(hostname="www.ejemplo.com", status="active", is_active=True)
    finding = Finding(
        finding_type="internal_addressing_leak",
        evidence="www.ejemplo.com resuelve a 10.0.0.1",
    )
    asset.findings.append(finding)
    scan.assets.append(asset)

    db_session.add(scan)
    await db_session.commit()

    assert scan.id is not None
    assert asset.scan_id == scan.id
    assert finding.asset_id == asset.id
    assert finding.severity is FindingSeverity.UNKNOWN  # sin triaje IA todavía


async def test_borrar_scan_arrastra_assets_y_findings(db_session: AsyncSession) -> None:
    scan = Scan(domain="ejemplo.com", status=ScanStatus.COMPLETED)
    asset = Asset(hostname="www.ejemplo.com", status="active")
    asset.findings.append(
        Finding(finding_type="internal_addressing_leak", evidence="evidencia")
    )
    scan.assets.append(asset)
    db_session.add(scan)
    await db_session.commit()

    await db_session.delete(scan)
    await db_session.commit()

    assert (await db_session.execute(select(Asset))).scalar_one_or_none() is None
    assert (await db_session.execute(select(Finding))).scalar_one_or_none() is None


async def test_status_por_defecto_es_running(db_session: AsyncSession) -> None:
    scan = Scan(domain="ejemplo.com")
    db_session.add(scan)
    await db_session.commit()

    assert scan.status is ScanStatus.RUNNING
    assert scan.finished_at is None
    assert scan.errors == []
