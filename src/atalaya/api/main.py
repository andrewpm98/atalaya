"""Punto de entrada de la API de Atalaya (FastAPI).

Expone la API REST propia de la herramienta (requisito de la práctica) y
monta los routers de cada dominio funcional. En el Paso 1 los routers son
esqueletos; cada fase posterior los va rellenando.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from atalaya import __version__
from atalaya.api.routes import assets, config, findings, monitors, scans
from atalaya.api.security import require_api_key
from atalaya.config import settings
from atalaya.core.database import SessionLocal
from atalaya.core.exceptions import (
    AIProviderError,
    InvalidTargetError,
    InvalidWebhookError,
    UnauthorizedTargetError,
)
from atalaya.core.monitor_runner import monitor_loop
from atalaya.core.scan_runner import fail_interrupted_scans

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Aplica `LOG_LEVEL` a los loggers de la aplicación (`atalaya.*`).

    uvicorn solo configura sus propios loggers (`uvicorn.*`): sin esto, todo
    `logger.info` de la aplicación se descartaba en silencio bajo la API y
    `LOG_LEVEL` no tenía ningún efecto. Un valor no reconocido cae a INFO en
    vez de impedir el arranque. La auditoría (`core/audit.py`) va aparte y no
    depende de este nivel.
    """
    level = logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)
    logger = logging.getLogger("atalaya")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)


_configure_logging()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Al arrancar, cierra como fallidos los escaneos que una parada dejó a
    medias y lanza el bucle de la vigilancia programada; al parar, lo cancela.

    Un escaneo corre en segundo plano dentro de este proceso: si se detiene
    (reinicio, despliegue), la tarea muere y el escaneo quedaría en `running`
    para siempre. Un fallo aquí (base de datos aún sin migrar o caída) se
    registra y no impide arrancar: la API debe poder responder para que se
    vea qué pasa (`/health`, `/config/status`).

    El bucle de vigilancia (`core/monitor_runner.py`) se lanza después, para
    que no ejecute un monitor antes de cerrar los escaneos interrumpidos. Si
    la API se para a mitad de un escaneo programado, ese escaneo es uno más de
    los que el siguiente arranque cierra como fallido.
    """
    try:
        async with SessionLocal() as session:
            interrupted = await fail_interrupted_scans(session)
    except Exception as exc:  # noqa: BLE001 - degradación controlada al arrancar
        logger.warning(
            "No se pudieron revisar los escaneos interrumpidos: %s", type(exc).__name__
        )
    else:
        if interrupted:
            logger.warning(
                "%d escaneo(s) en curso al detenerse la API pasan a fallidos", interrupted
            )
    vigilancia = asyncio.create_task(monitor_loop(SessionLocal), name="vigilancia")
    try:
        yield
    finally:
        vigilancia.cancel()
        with suppress(asyncio.CancelledError):
            await vigilancia


app = FastAPI(
    title="Atalaya API",
    description="Attack Surface Management con triaje por IA",
    version=__version__,
    lifespan=_lifespan,
)

# La clave se exige por router, no en `FastAPI(dependencies=...)`: eso la
# aplicaría también a `/health`, y la sonda del healthcheck de Docker (y la del
# dashboard) no lleva clave — ni debe llevarla: solo dice "estoy vivo". `/docs`
# y `/openapi.json` quedan abiertos por el mismo motivo: describen la API, no
# devuelven datos, y desde `/docs` se introduce la clave con «Authorize».
_auth = [Depends(require_api_key)]

app.include_router(scans.router, dependencies=_auth)
app.include_router(assets.router, dependencies=_auth)
app.include_router(findings.router, dependencies=_auth)
app.include_router(config.router, dependencies=_auth)
app.include_router(monitors.router, dependencies=_auth)


@app.exception_handler(InvalidTargetError)
async def _invalid_target_handler(request: Request, exc: InvalidTargetError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(InvalidWebhookError)
async def _invalid_webhook_handler(request: Request, exc: InvalidWebhookError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(UnauthorizedTargetError)
async def _unauthorized_target_handler(
    request: Request, exc: UnauthorizedTargetError
) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(AIProviderError)
async def _ai_provider_handler(request: Request, exc: AIProviderError) -> JSONResponse:
    # 502: el fallo es de un servicio upstream (el proveedor de IA), no de
    # la propia API ni de la petición del cliente.
    return JSONResponse(status_code=502, content={"detail": str(exc)})


@app.get("/health", tags=["sistema"])
async def health() -> dict[str, str]:
    """Sonda de salud: confirma que la API está viva."""
    return {"status": "ok", "version": __version__}


@app.get("/", tags=["sistema"], dependencies=_auth)
async def root() -> dict[str, str]:
    return {"servicio": "Atalaya", "docs": "/docs"}
