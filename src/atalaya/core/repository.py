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
class FindingRef:
    """Un hallazgo dentro de un cambio: su tipo y la severidad que tenía.

    La severidad sale del escaneo donde el hallazgo está presente (el actual
    para los nuevos, el previo para los desaparecidos): un hallazgo que
    desaparece se valora por lo grave que era, no por lo que hay ahora.
    """

    finding_type: str
    severity: str


@dataclass
class AssetChange:
    """Qué cambió en un activo presente en los dos escaneos."""

    hostname: str
    estado_anterior: str
    estado_actual: str
    puertos_nuevos: list[int] = field(default_factory=list)
    puertos_desaparecidos: list[int] = field(default_factory=list)
    hallazgos_nuevos: list[FindingRef] = field(default_factory=list)
    hallazgos_desaparecidos: list[FindingRef] = field(default_factory=list)


@dataclass
class ScanDiff:
    """Diferencia de activos entre dos escaneos del mismo dominio.

    `comunes` son todos los hostnames presentes en ambos; `cambiados`, el
    subconjunto de esos que cambió de estado, puertos o hallazgos. Se conserva
    `comunes` completo (y no solo «sin cambios») porque es el contrato que ya
    exponía la API: un cliente existente sigue recibiendo lo mismo.
    """

    nuevos: list[str] = field(default_factory=list)
    desaparecidos: list[str] = field(default_factory=list)
    comunes: list[str] = field(default_factory=list)
    cambiados: list[AssetChange] = field(default_factory=list)


def _findings_by_type(asset: Asset) -> dict[str, FindingRef]:
    """Hallazgos de un activo indexados por tipo.

    Se compara por `finding_type` y no por evidencia: la evidencia cambia
    entre escaneos sin que cambie el problema (los días que faltan para que
    caduque un certificado, el `max-age` exacto). Cada técnica de
    descubrimiento emite como mucho un hallazgo por tipo y host (las cookies
    se agrupan a propósito, ver `discovery/headers.py`), así que el tipo
    identifica el hallazgo dentro de su activo.
    """
    return {
        f.finding_type: FindingRef(finding_type=f.finding_type, severity=f.severity.value)
        for f in asset.findings
    }


def _asset_change(previous: Asset, current: Asset) -> AssetChange | None:
    """Cambios entre dos versiones del mismo activo, o `None` si no hay.

    No se comparan las IPs: con CDN y balanceo, cambian entre dos escaneos
    sin que cambie nada de la exposición, y marcarían como «cambiado» casi
    todo activo detrás de un balanceador.
    """
    puertos_previos, puertos_actuales = set(previous.open_ports), set(current.open_ports)
    hallazgos_previos, hallazgos_actuales = _findings_by_type(previous), _findings_by_type(current)
    change = AssetChange(
        hostname=current.hostname,
        estado_anterior=previous.status,
        estado_actual=current.status,
        puertos_nuevos=sorted(puertos_actuales - puertos_previos),
        puertos_desaparecidos=sorted(puertos_previos - puertos_actuales),
        hallazgos_nuevos=[
            hallazgos_actuales[t] for t in sorted(hallazgos_actuales.keys() - hallazgos_previos)
        ],
        hallazgos_desaparecidos=[
            hallazgos_previos[t] for t in sorted(hallazgos_previos.keys() - hallazgos_actuales)
        ],
    )
    changed = (
        change.estado_anterior != change.estado_actual
        or change.puertos_nuevos
        or change.puertos_desaparecidos
        or change.hallazgos_nuevos
        or change.hallazgos_desaparecidos
    )
    return change if changed else None


def diff_scans(previous: Scan, current: Scan) -> ScanDiff:
    """Compara dos escaneos del mismo dominio: hostnames y, de los comunes,
    estado, puertos abiertos y hallazgos.

    Requiere que `previous.assets` y `current.assets` (y sus `findings`) ya
    estén cargados (p. ej. obtenidos con `get_scan()` o `get_latest_scan()`),
    no los carga aquí: esta función es síncrona y de puro cálculo a propósito,
    para poder probarla sin sesión de base de datos.

    Solo comparar hostnames dejaba fuera lo que más interesa vigilar en el
    tiempo: un activo que ya existía y abre un puerto nuevo, o que deja de
    enviar HSTS, salía como «sin cambios».

    Una ausencia en `current` no implica necesariamente un cambio real: la
    variabilidad de DNS (ver CLAUDE.md) puede hacer desaparecer un hostname,
    y un timeout puede hacer desaparecer un puerto o un hallazgo (si la sonda
    de cabeceras no obtuvo respuesta, no hay cabeceras que evaluar). Por eso
    se llaman «desaparecidos» y no «cerrados» ni «resueltos». Esta función
    reporta presencia/ausencia sin intentar distinguir señal de ruido; eso
    corresponde a la capa IA (`ai/diff_analyst.py`).
    """
    previos = {asset.hostname: asset for asset in previous.assets}
    actuales = {asset.hostname: asset for asset in current.assets}
    comunes = sorted(actuales.keys() & previos.keys())
    cambiados = [
        change
        for hostname in comunes
        if (change := _asset_change(previos[hostname], actuales[hostname])) is not None
    ]
    return ScanDiff(
        nuevos=sorted(actuales.keys() - previos.keys()),
        desaparecidos=sorted(previos.keys() - actuales.keys()),
        comunes=comunes,
        cambiados=cambiados,
    )
