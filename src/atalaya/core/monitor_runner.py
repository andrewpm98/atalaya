"""Vigilancia programada: un escaneo cada cierto tiempo y un aviso por webhook
cuando algo cambia.

Un ASM se define por vigilar en el tiempo, no por escanear a mano. El diff
entre escaneos (`core/repository.py::diff_scans`) ya decía qué cambió; esto
es el disparador. Cada `TICK_SECONDS`, `monitor_loop` (lanzado en el
`lifespan` de la API) busca los monitores a los que les toca y, de uno en uno:

1. Vuelve a comprobar la autorización del dominio (restricción de seguridad
   #1): la allowlist pudo cambiar desde que se creó el monitor.
2. Lanza el escaneo con `core/scan_runner.py::run_scan`, el mismo de
   `POST /scans`.
3. Lo compara **sin IA** con la línea base del monitor (no gasta crédito ni
   depende del proveedor) y, si hay activos nuevos, desaparecidos o
   cambiados, lo avisa al webhook (`core/webhooks.py`, protegido contra SSRF).

De uno en uno y no en paralelo: crt.sh limita a quien le pide mucho a la vez,
y un escaneo ya reparte su propia concurrencia. Si varios monitores coinciden,
esperan su turno.

También se avisa cuando sale mal (evento `escaneo_fallido`): en vigilancia, el
peor fallo es el silencioso, porque una semana sin avisos se lee como «nada ha
cambiado».

Límite: el bucle vive en el proceso de la API. Con varios procesos, cada uno
tendría el suyo, pero cada ejecución se **reclama** con un `UPDATE`
condicional sobre `next_run_at` y solo uno la gana: un monitor no se ejecuta
dos veces.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from atalaya.core import repository
from atalaya.core.authorization import ensure_authorized
from atalaya.core.exceptions import AtalayaError, InvalidWebhookError, WebhookDeliveryError
from atalaya.core.models import Monitor, Scan, ScanStatus
from atalaya.core.repository import ScanDiff, diff_scans
from atalaya.core.scan_runner import run_scan
from atalaya.core.webhooks import send_webhook

logger = logging.getLogger(__name__)

#: Cada cuánto revisa el bucle si a algún monitor le toca.
TICK_SECONDS = 60
#: Intervalo mínimo entre escaneos de un monitor. Un escaneo hace cientos de
#: conexiones al objetivo (puertos, cabeceras, TLS): repetirlo cada pocos
#: minutos sería un barrido continuo, indistinguible de un ataque
#: (restricción de seguridad #5).
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 30


class MonitorEvent(str, Enum):
    """Tipo de aviso, en el cuerpo (`event`) y en la cabecera `X-Atalaya-Event`."""

    CAMBIOS = "cambios"
    ESCANEO_FALLIDO = "escaneo_fallido"


def _now() -> datetime:
    return datetime.now(UTC)


def _cambios_payload(
    monitor: Monitor, previous: Scan, current: Scan, diff: ScanDiff
) -> dict[str, Any]:
    """Cuerpo del aviso de cambios. Sin `comunes`: en un dominio grande son
    cientos de hostnames que no cambiaron y no dicen nada al receptor."""
    nuevos, desaparecidos = len(diff.nuevos), len(diff.desaparecidos)
    summary = (
        f"Vigilancia de {monitor.domain}: "
        f"{nuevos} {'activo nuevo' if nuevos == 1 else 'activos nuevos'}, "
        f"{desaparecidos} {'desaparecido' if desaparecidos == 1 else 'desaparecidos'} y "
        f"{len(diff.cambiados)} con cambios "
        f"(escaneo #{current.id} frente al #{previous.id})"
    )
    return {
        "event": MonitorEvent.CAMBIOS.value,
        "monitor_id": monitor.id,
        "domain": monitor.domain,
        "summary": summary,
        "previous_scan_id": previous.id,
        "current_scan_id": current.id,
        "nuevos": diff.nuevos,
        "desaparecidos": diff.desaparecidos,
        "cambiados": [asdict(change) for change in diff.cambiados],
        # Incidencias del escaneo actual (p. ej. una fuente caída): el receptor
        # debe poder saber si un «desaparecido» viene de un escaneo degradado.
        "errors": list(current.errors),
        "sent_at": _now().isoformat(),
    }


def _fallo_payload(
    monitor: Monitor, scan_id: int | None, reason: str, errors: list[str]
) -> dict[str, Any]:
    return {
        "event": MonitorEvent.ESCANEO_FALLIDO.value,
        "monitor_id": monitor.id,
        "domain": monitor.domain,
        "summary": f"Vigilancia de {monitor.domain}: {reason}",
        "scan_id": scan_id,
        "reason": reason,
        "errors": errors,
        "sent_at": _now().isoformat(),
    }


async def _notify(
    monitor: Monitor,
    event: MonitorEvent,
    payload: dict[str, Any],
    *,
    problem: str | None = None,
) -> bool:
    """Envía el aviso y deja el resultado en el monitor. Devuelve si se entregó.

    `problem` es lo que salió mal en la ejecución (un escaneo fallido): queda
    en `last_error` aunque el aviso se entregue, porque la vigilancia no hizo
    su trabajo. Si además el aviso falla, se guardan los dos.
    """
    try:
        await send_webhook(
            monitor.webhook_url, payload, event=event.value, secret=monitor.webhook_secret
        )
    except (WebhookDeliveryError, InvalidWebhookError) as exc:
        logger.warning("Vigilancia de %s: %s", monitor.domain, exc)
        monitor.last_error = "; ".join(p for p in (problem, str(exc)) if p)
        return False
    monitor.last_notified_at = _now()
    monitor.last_error = problem
    return True


async def _start_scan(
    session_factory: async_sessionmaker[AsyncSession], monitor_id: int
) -> int | None:
    """Crea el escaneo del monitor en `running` y devuelve su id, o `None` si
    no hay que escanear (monitor borrado, o dominio ya no autorizado)."""
    async with session_factory() as session:
        monitor = await session.get(Monitor, monitor_id)
        if monitor is None:
            return None
        monitor.last_run_at = _now()
        try:
            domain = ensure_authorized(monitor.domain)
        except AtalayaError as exc:
            # No se escanea, pero se avisa: si alguien sacó el dominio de la
            # allowlist sin borrar el monitor, el receptor dejaría de recibir
            # avisos sin saber por qué.
            reason = f"no se escanea: {exc}"
            await _notify(
                monitor,
                MonitorEvent.ESCANEO_FALLIDO,
                _fallo_payload(monitor, None, reason, []),
                problem=reason,
            )
            await session.commit()
            return None
        scan = Scan(domain=domain, status=ScanStatus.RUNNING, assets=[])
        session.add(scan)
        await session.flush()
        scan_id = scan.id
        monitor.last_scan_id = scan_id
        await session.commit()
        return scan_id


async def _compare_and_notify(
    session_factory: async_sessionmaker[AsyncSession], monitor_id: int, scan_id: int
) -> None:
    """Compara el escaneo recién terminado con la línea base y avisa si toca."""
    async with session_factory() as session:
        monitor = await session.get(Monitor, monitor_id)
        current = await repository.get_scan(session, scan_id)
        if monitor is None or current is None:
            return  # el monitor se borró mientras escaneaba

        if current.status is not ScanStatus.COMPLETED:
            reason = current.errors[-1] if current.errors else "el escaneo falló"
            await _notify(
                monitor,
                MonitorEvent.ESCANEO_FALLIDO,
                _fallo_payload(monitor, scan_id, reason, list(current.errors)),
                problem=reason,
            )
            await session.commit()
            return

        baseline = (
            await repository.get_scan(session, monitor.baseline_scan_id)
            if monitor.baseline_scan_id is not None
            else None
        )
        if baseline is None or baseline.status is not ScanStatus.COMPLETED:
            # Sin historial no hay con qué comparar: este escaneo es la base.
            monitor.baseline_scan_id = scan_id
            monitor.last_error = None
            logger.info(
                "Vigilancia de %s: el escaneo #%d queda como línea base", monitor.domain, scan_id
            )
        elif not current.assets and baseline.assets:
            # crt.sh caído deja un escaneo «completado» (degradación controlada)
            # sin ningún subdominio. Compararlo daría todo el dominio por
            # desaparecido: una falsa alarma. crt.sh es histórico, así que un
            # dominio real nunca vuelve con cero. No basta con mirar si hay
            # incidencias: con clave de Shodan, su 403 sale en todo escaneo.
            reason = (
                f"el escaneo #{scan_id} no encontró ningún subdominio y la línea base "
                f"(#{baseline.id}) tenía {len(baseline.assets)}: lo más probable es que "
                "cayera la fuente de subdominios, no que desaparecieran todos"
            )
            await _notify(
                monitor,
                MonitorEvent.ESCANEO_FALLIDO,
                _fallo_payload(monitor, scan_id, reason, list(current.errors)),
                problem=reason,
            )
        else:
            diff = diff_scans(baseline, current)
            if diff.nuevos or diff.desaparecidos or diff.cambiados:
                payload = _cambios_payload(monitor, baseline, current, diff)
                # La línea base solo avanza si el aviso llegó: si no, la
                # siguiente ejecución compara contra la misma y lo repite.
                if await _notify(monitor, MonitorEvent.CAMBIOS, payload):
                    monitor.baseline_scan_id = scan_id
            else:
                monitor.baseline_scan_id = scan_id
                monitor.last_error = None
        await session.commit()


async def run_monitor(
    session_factory: async_sessionmaker[AsyncSession], monitor_id: int, *, resolve: bool = True
) -> None:
    """Una ejecución de un monitor: escanea, compara y avisa.

    No lanza excepciones: corre en segundo plano, donde nadie las recogería.
    Un escaneo fallido no es una excepción aquí: `run_scan` lo deja en
    `failed` y `_compare_and_notify` lo avisa.
    """
    try:
        scan_id = await _start_scan(session_factory, monitor_id)
        if scan_id is None:
            return
        await run_scan(session_factory, scan_id, resolve=resolve)
        await _compare_and_notify(session_factory, monitor_id, scan_id)
    except Exception as exc:  # nunca tumbar el bucle de vigilancia
        logger.exception("Vigilancia: fallo inesperado en el monitor #%d", monitor_id)
        try:
            async with session_factory() as session:
                monitor = await session.get(Monitor, monitor_id)
                if monitor is not None:
                    monitor.last_error = f"error inesperado ({type(exc).__name__})"
                    await session.commit()
        except Exception:  # noqa: BLE001 - p. ej. la base de datos caída
            logger.warning("Vigilancia: no se pudo registrar el fallo del monitor #%d", monitor_id)


async def _claim(
    session_factory: async_sessionmaker[AsyncSession],
    monitor_id: int,
    expected_next_run: datetime,
    new_next_run: datetime,
) -> bool:
    """Reclama una ejecución: adelanta `next_run_at` solo si nadie lo hizo antes.

    El `WHERE` sobre el valor leído hace que, entre dos procesos que vieron el
    mismo monitor pendiente, solo a uno le afecte el `UPDATE`. Se adelanta
    antes de escanear, y no al terminar: un escaneo largo no debe hacer que el
    siguiente ciclo del bucle lo vuelva a lanzar.
    """
    async with session_factory() as session:
        result = await session.execute(
            update(Monitor)
            .where(
                Monitor.id == monitor_id,
                Monitor.active.is_(True),
                Monitor.next_run_at == expected_next_run,
            )
            .values(next_run_at=new_next_run)
        )
        await session.commit()
        return cast("CursorResult[Any]", result).rowcount == 1


async def run_due_monitors(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    now: datetime | None = None,
    resolve: bool = True,
) -> int:
    """Ejecuta, de uno en uno, los monitores activos a los que les toca.
    Devuelve cuántos ejecutó.

    El siguiente turno se calcula desde `now`, no desde el `next_run_at`
    vencido: tras una API parada un día, un monitor horario se ejecuta una vez,
    no veinticuatro seguidas para «ponerse al día».
    """
    now = now or _now()
    async with session_factory() as session:
        due = (
            await session.execute(
                select(Monitor.id, Monitor.next_run_at, Monitor.interval_hours)
                .where(Monitor.active.is_(True), Monitor.next_run_at <= now)
                .order_by(Monitor.next_run_at, Monitor.id)
            )
        ).all()

    ejecutados = 0
    for monitor_id, next_run_at, interval_hours in due:
        # Se reclama justo antes de ejecutarlo: si la API se para a mitad de
        # la lista, los que quedan siguen pendientes y no pierden su turno.
        if not await _claim(
            session_factory, monitor_id, next_run_at, now + timedelta(hours=interval_hours)
        ):
            continue
        await run_monitor(session_factory, monitor_id, resolve=resolve)
        ejecutados += 1
    return ejecutados


async def monitor_loop(
    session_factory: async_sessionmaker[AsyncSession], *, tick_seconds: float = TICK_SECONDS
) -> None:
    """Bucle de la vigilancia: lo lanza el `lifespan` de la API y termina al
    cancelarse (parada de la API). Un fallo de una vuelta (la base de datos
    caída o sin migrar) se registra y no lo detiene."""
    while True:
        try:
            await run_due_monitors(session_factory)
        except Exception as exc:  # noqa: BLE001 - degradación controlada
            logger.warning(
                "Vigilancia: no se pudieron revisar los monitores: %s", type(exc).__name__
            )
        await asyncio.sleep(tick_seconds)
