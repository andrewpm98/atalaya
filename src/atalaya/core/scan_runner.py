"""Ejecución de un escaneo completo, separada de la petición que lo pide.

`POST /scans` crea la fila del `Scan` en `running`, responde 202 y deja aquí
el trabajo largo: subdominios, puertos, cabeceras, TLS y su persistencia. Un
escaneo de github.com tarda 19 segundos y el de un dominio grande, minutos;
dentro de la petición, la conexión quedaba abierta todo ese tiempo y un
cliente con timeout (el dashboard usaba 120 s) lo daba por fallido aunque
siguiera corriendo. Con `?wait=true`, la ruta llama a esta misma función y la
espera, así que solo hay un camino de ejecución.

Abre su propia sesión de base de datos: la de la petición se cierra al
responder, antes de que el escaneo termine.

**Un escaneo nunca se queda en `running` para siempre.** Si algo falla, pasa a
`failed` con el motivo en `errors`. Si la API se para a mitad (reinicio,
despliegue), la tarea se cancela sin llegar a marcarlo, y por eso
`fail_interrupted_scans()` los recoge al arrancar.

La autorización (`ensure_authorized`) se comprueba dos veces: en la ruta,
para que un dominio no autorizado dé 403 al momento y no un escaneo `failed`
después, y aquí dentro, porque `enumerate_subdomains` la exige siempre
(restricción #1 de CLAUDE.md): si la allowlist cambia entre la petición y la
ejecución, gana la de la ejecución.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from atalaya.core import repository
from atalaya.core.exceptions import AtalayaError
from atalaya.core.models import Scan, ScanStatus
from atalaya.core.persistence import apply_discovery_findings, apply_port_scan, save_subdomain_scan
from atalaya.discovery.enrichment import enrich_scan
from atalaya.discovery.subdomains import enumerate_subdomains

logger = logging.getLogger(__name__)

#: Incidencia que deja en un escaneo que una parada de la API interrumpió.
INTERRUPTED_ERROR = "interrumpido: la API se detuvo antes de que terminara"


def _reason(exc: Exception) -> str:
    """Motivo del fallo para `errors`, que va al dashboard, al modelo y al PDF.

    Las excepciones propias (dominio no válido o no autorizado) tienen un
    mensaje pensado para el usuario. De las demás solo se guarda el tipo: su
    texto puede llevar una URL con una clave (Shodan solo la acepta en la URL,
    y ya se filtró una vez por un log), y el detalle completo queda en el log
    de la API.
    """
    if isinstance(exc, AtalayaError):
        return str(exc)
    return f"error inesperado ({type(exc).__name__})"


async def _mark_failed(session: AsyncSession, scan_id: int, reason: str) -> None:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = ScanStatus.FAILED
    scan.finished_at = datetime.now(UTC)
    scan.errors = [*scan.errors, f"el escaneo falló: {reason}"]
    await session.commit()


async def run_scan(
    session_factory: async_sessionmaker[AsyncSession], scan_id: int, *, resolve: bool = True
) -> None:
    """Ejecuta el escaneo `scan_id`, ya creado en `running`, y lo deja terminado.

    No lanza excepciones: corre en segundo plano, donde nadie las recogería.
    Termina en `completed` (aunque una fuente externa haya caído: eso es
    degradación controlada y queda en `errors`) o en `failed`. Activos y
    hallazgos se guardan en una sola transacción al final, así que quien
    consulta el escaneo mientras corre lo ve vacío, nunca a medias.
    """
    async with session_factory() as session:
        scan = await repository.get_scan(session, scan_id)
        if scan is None:
            logger.warning("Escaneo #%d no encontrado: nada que ejecutar", scan_id)
            return
        # Leído antes de nada: tras un `rollback` el objeto queda expirado y
        # leerlo dispararía una carga perezosa fuera del contexto async.
        domain = scan.domain
        try:
            result = await enumerate_subdomains(domain, resolve=resolve)
            await save_subdomain_scan(session, result, scan=scan)
            # `enrich_scan` solo actúa sobre hosts activos: con `resolve=False`
            # no hay ninguno y no hace ninguna llamada de red.
            enrichment = await enrich_scan(result)
            apply_port_scan(scan, enrichment.ports_by_ip)
            apply_discovery_findings(scan, enrichment.findings_by_hostname())
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.now(UTC)
            await session.commit()
        except Exception as exc:  # todo fallo acaba en `failed`, nunca en `running`
            await session.rollback()
            logger.exception("Escaneo #%d de %s fallido", scan_id, domain)
            await _mark_failed(session, scan_id, _reason(exc))
            return
        logger.info(
            "Escaneo #%d de %s completado: %d activos, %d incidencias",
            scan_id,
            domain,
            len(scan.assets),
            len(scan.errors),
        )


async def fail_interrupted_scans(session: AsyncSession) -> int:
    """Pasa a `failed` los escaneos que quedaron en `running`. Devuelve cuántos.

    Se llama al arrancar la API: si un escaneo sigue en `running` entonces,
    es que la API anterior se detuvo con él a medias y ya nadie lo terminará.
    Sin esto, el dashboard lo mostraría «en curso» indefinidamente.

    Límite: con varios procesos de API sobre la misma base de datos, uno que
    arranca marcaría como fallidos los escaneos que otro está ejecutando. La
    herramienta se despliega con un solo proceso (Dockerfile, README).
    """
    stmt = select(Scan).where(Scan.status == ScanStatus.RUNNING)
    interrupted = list((await session.execute(stmt)).scalars().all())
    now = datetime.now(UTC)
    for scan in interrupted:
        scan.status = ScanStatus.FAILED
        scan.finished_at = now
        scan.errors = [*scan.errors, INTERRUPTED_ERROR]
    await session.commit()
    return len(interrupted)
