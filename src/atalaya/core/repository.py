"""Repositorio de lectura: consultas sobre escaneos, activos y hallazgos.

`core/persistence.py` solo escribe (resultado de descubrimiento → filas). Este
módulo es su contraparte de lectura: lo que necesitan la API (Paso 4) y el
dashboard (Paso 6) para mostrar escaneos ya persistidos, sin que cada
consumidor construya sus propias consultas SQLAlchemy.

`diff_scans()` existe porque comparar escaneos en el tiempo es el motivo por
el que este proyecto persiste nada en absoluto (ver CLAUDE.md, "Qué hace la
herramienta" y "Variabilidad del DNS"): sin esta función, la BD sería solo un
registro histórico sin explotar.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from atalaya.core.models import Asset, Finding, Scan, ScanStatus


async def get_scan(session: AsyncSession, scan_id: int) -> Scan | None:
    """Devuelve un escaneo por id, con sus activos y hallazgos precargados.

    `selectinload` evita N+1 consultas al serializar la respuesta y, sobre
    todo, evita el lazy-load implícito: en una sesión async, acceder a una
    relación no precargada fuera de un `await` explícito lanza
    `MissingGreenlet` en vez de traer los datos.
    """
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.assets).selectinload(Asset.findings))
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_scans(
    session: AsyncSession, domain: str | None = None, limit: int = 50
) -> list[Scan]:
    """Lista escaneos sin sus relaciones, más recientes primero.

    Pensada para vistas de resumen (tabla de escaneos en el dashboard, listado
    de la API): no precarga activos ni hallazgos porque esa vista no los
    necesita. Para el detalle de un escaneo concreto, usar `get_scan()`.
    """
    stmt = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
    if domain is not None:
        stmt = stmt.where(Scan.domain == domain)
    return list((await session.execute(stmt)).scalars().all())


async def get_latest_scan(session: AsyncSession, domain: str) -> Scan | None:
    """Devuelve el escaneo completado más reciente de un dominio, o `None`.

    Solo considera escaneos `COMPLETED`: uno `RUNNING` o `FAILED` no es una
    base fiable para comparar ("¿qué cambió desde la última vez?").
    """
    stmt = (
        select(Scan)
        .where(Scan.domain == domain, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.started_at.desc())
        .limit(1)
        .options(selectinload(Scan.assets).selectinload(Asset.findings))
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_assets(session: AsyncSession, scan_id: int | None = None) -> list[Asset]:
    """Lista activos, opcionalmente filtrados por escaneo."""
    stmt = select(Asset).order_by(Asset.hostname)
    if scan_id is not None:
        stmt = stmt.where(Asset.scan_id == scan_id)
    return list((await session.execute(stmt)).scalars().all())


async def list_findings(
    session: AsyncSession,
    asset_id: int | None = None,
    scan_id: int | None = None,
) -> list[Finding]:
    """Lista hallazgos, opcionalmente filtrados por activo o por escaneo."""
    stmt = select(Finding).order_by(Finding.created_at.desc())
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if scan_id is not None:
        stmt = stmt.join(Asset).where(Asset.scan_id == scan_id)
    return list((await session.execute(stmt)).scalars().all())


@dataclass
class ScanDiff:
    """Diferencia de activos entre dos escaneos del mismo dominio."""

    nuevos: list[str] = field(default_factory=list)
    desaparecidos: list[str] = field(default_factory=list)
    comunes: list[str] = field(default_factory=list)


def diff_scans(previous: Scan, current: Scan) -> ScanDiff:
    """Compara los hostnames de dos escaneos del mismo dominio.

    Requiere que `previous.assets` y `current.assets` ya estén cargados
    (p. ej. obtenidos con `get_scan()` o `get_latest_scan()`), no los carga
    aquí: esta función es síncrona y de puro cálculo a propósito, para poder
    probarla sin sesión de base de datos.

    Un hostname ausente en `current` no implica necesariamente que el activo
    dejó de existir: la variabilidad de DNS (ver CLAUDE.md) puede causar
    ausencias puntuales. Esta función reporta presencia/ausencia sin intentar
    distinguir señal de ruido; eso corresponde a la capa IA (Paso 5).
    """
    previos = {asset.hostname for asset in previous.assets}
    actuales = {asset.hostname for asset in current.assets}
    return ScanDiff(
        nuevos=sorted(actuales - previos),
        desaparecidos=sorted(previos - actuales),
        comunes=sorted(actuales & previos),
    )
