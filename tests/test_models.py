"""Pruebas de los modelos ORM: relaciones y borrado en cascada.

No dependen de Postgres: usan el esquema SQLite en memoria de `conftest.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from sqlalchemy import DateTime, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.database import Base
from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus, UtcDateTime


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


# --- UtcDateTime: fechas aware contra columnas sin zona horaria -----------------
# Regresión de un bug que la suite no podía ver: SQLite acepta un datetime
# aware en TIMESTAMP WITHOUT TIME ZONE, asyncpg (PostgreSQL) lo rechaza y
# ningún escaneo llegaba a guardarse. Estas pruebas no necesitan Postgres.


def test_utc_datetime_convierte_aware_a_utc_naive() -> None:
    madrid = timezone(timedelta(hours=2))
    valor = datetime(2026, 9, 27, 21, 30, tzinfo=madrid)

    guardado = UtcDateTime().process_bind_param(valor, postgresql.dialect())

    # Se convierte a UTC antes de quitar la zona: no se descarta sin más.
    assert guardado == datetime(2026, 9, 27, 19, 30)  # noqa: DTZ001 - naive a propósito
    assert guardado is not None and guardado.tzinfo is None


def test_utc_datetime_respeta_naive_y_none() -> None:
    naive = datetime(2026, 9, 27, 19, 30)  # noqa: DTZ001 - naive a propósito
    tipo = UtcDateTime()

    assert tipo.process_bind_param(naive, postgresql.dialect()) == naive
    assert tipo.process_bind_param(None, postgresql.dialect()) is None
    assert tipo.process_bind_param(datetime.now(UTC), postgresql.dialect()).tzinfo is None


def test_toda_columna_de_fecha_usa_utc_datetime() -> None:
    """Una columna `DateTime` nueva sin `UtcDateTime` reabriría el bug en
    PostgreSQL sin que ninguna otra prueba lo detectara."""
    columnas_fecha = [
        f"{tabla.name}.{columna.name}"
        for tabla in Base.metadata.tables.values()
        for columna in tabla.columns
        if isinstance(columna.type, DateTime | UtcDateTime)
    ]
    sin_convertir = [
        f"{tabla.name}.{columna.name}"
        for tabla in Base.metadata.tables.values()
        for columna in tabla.columns
        if isinstance(columna.type, DateTime)
    ]

    assert columnas_fecha, "no se encontró ninguna columna de fecha"
    assert sin_convertir == []


def test_colecciones_con_orden_explicito_por_id() -> None:
    """Sin `order_by`, PostgreSQL devuelve las filas en orden de heap, que
    cambia tras un `UPDATE` (el triaje): los prompts de la capa IA, el informe
    y el dashboard dejarían de ser reproducibles, y el proveedor `replay` de
    la demo no encontraría sus grabaciones. SQLite no lo reproduce, así que
    se comprueba la definición."""
    assert [str(c) for c in Scan.assets.property.order_by] == ["assets.id"]
    assert [str(c) for c in Asset.findings.property.order_by] == ["findings.id"]
