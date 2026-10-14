"""Router de vigilancia programada: monitores que escanean un dominio cada
cierto tiempo y avisan por webhook cuando algo cambia.

Las rutas solo guardan la configuración; quien escanea y avisa es el bucle de
`core/monitor_runner.py`, lanzado en el `lifespan` de la API. Un monitor nuevo
se ejecuta en el siguiente minuto: su primer escaneo se compara con el último
completado del dominio, si lo hay, o queda como línea base.

Las mismas comprobaciones que `POST /scans`, y una más:

- Dominio validado y autorizado **antes** de guardar nada (400/403), y otra
  vez en cada ejecución (restricción de seguridad #1).
- Webhook validado contra SSRF (`core/webhooks.py`): `https` y solo
  direcciones públicas (400). Se repite al enviar cada aviso.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.api.schemas import MonitorOut, MonitorRequest, MonitorUpdate
from atalaya.core import repository
from atalaya.core.audit import get_audit_logger
from atalaya.core.authorization import ensure_authorized
from atalaya.core.database import get_session
from atalaya.core.models import Monitor
from atalaya.core.webhooks import mask_webhook_url, validate_webhook_url

router = APIRouter(prefix="/monitors", tags=["vigilancia"])


def _ya_vigilado(domain: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Ya hay un monitor para {domain}: cada dominio se vigila una sola vez.",
    )


async def _get_or_404(session: AsyncSession, monitor_id: int) -> Monitor:
    monitor = await repository.get_monitor(session, monitor_id)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Monitor {monitor_id} no encontrado"
        )
    return monitor


@router.post("", status_code=status.HTTP_201_CREATED, response_model=MonitorOut)
async def create_monitor(
    payload: MonitorRequest, session: AsyncSession = Depends(get_session)
) -> MonitorOut:
    """Vigila un dominio: un escaneo cada `interval_hours` y un aviso al
    webhook cuando aparecen, desaparecen o cambian activos, o cuando el
    escaneo falla.

    409 si el dominio ya tiene monitor: dos lo escanearían dos veces por
    intervalo (restricción de seguridad #5). Para cambiar el intervalo o el
    webhook, se borra y se crea de nuevo.
    """
    domain = ensure_authorized(payload.domain)
    if await repository.get_monitor_by_domain(session, domain) is not None:
        raise _ya_vigilado(domain)
    webhook_url = await validate_webhook_url(payload.webhook_url)

    monitor = Monitor(
        domain=domain,
        interval_hours=payload.interval_hours,
        webhook_url=webhook_url,
        webhook_secret=payload.secret,
        active=True,
        next_run_at=datetime.now(UTC),
        baseline_scan_id=await repository.get_latest_completed_scan_id(session, domain),
    )
    session.add(monitor)
    try:
        await session.commit()
    except IntegrityError as exc:  # otra petición lo creó entre la consulta y el commit
        await session.rollback()
        raise _ya_vigilado(domain) from exc
    # Releído de la base de datos: así las fechas salen con el mismo formato
    # que en `GET /monitors` (UTC sin zona, `UtcDateTime`).
    await session.refresh(monitor)
    get_audit_logger().info(
        "Monitor #%d creado: %s cada %d h, avisos%s a %s",
        monitor.id,
        domain,
        monitor.interval_hours,
        " firmados" if monitor.webhook_secret else "",
        mask_webhook_url(webhook_url),
    )
    return MonitorOut.from_monitor(monitor)


@router.get("", response_model=list[MonitorOut])
async def list_monitors(session: AsyncSession = Depends(get_session)) -> list[MonitorOut]:
    """Lista los monitores, con el resultado de su última ejecución."""
    return [MonitorOut.from_monitor(m) for m in await repository.list_monitors(session)]


@router.get("/{monitor_id}", response_model=MonitorOut)
async def get_monitor(monitor_id: int, session: AsyncSession = Depends(get_session)) -> MonitorOut:
    return MonitorOut.from_monitor(await _get_or_404(session, monitor_id))


@router.patch("/{monitor_id}", response_model=MonitorOut)
async def update_monitor(
    monitor_id: int, payload: MonitorUpdate, session: AsyncSession = Depends(get_session)
) -> MonitorOut:
    """Pausa (`active: false`) o reanuda (`active: true`) la vigilancia."""
    monitor = await _get_or_404(session, monitor_id)
    monitor.active = payload.active
    await session.commit()
    await session.refresh(monitor)
    accion = "reanudado" if monitor.active else "pausado"
    get_audit_logger().info("Monitor #%d de %s %s", monitor.id, monitor.domain, accion)
    return MonitorOut.from_monitor(monitor)


@router.delete("/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitor(monitor_id: int, session: AsyncSession = Depends(get_session)) -> Response:
    """Deja de vigilar el dominio. Sus escaneos se conservan."""
    monitor = await _get_or_404(session, monitor_id)
    domain = monitor.domain
    await session.delete(monitor)
    await session.commit()
    get_audit_logger().info("Monitor #%d de %s borrado", monitor_id, domain)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
