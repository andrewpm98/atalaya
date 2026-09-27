"""Punto de entrada de la API de Atalaya (FastAPI).

Expone la API REST propia de la herramienta (requisito de la práctica) y
monta los routers de cada dominio funcional. En el Paso 1 los routers son
esqueletos; cada fase posterior los va rellenando.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from atalaya import __version__
from atalaya.api.routes import assets, findings, scans
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError, InvalidTargetError, UnauthorizedTargetError


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

app = FastAPI(
    title="Atalaya API",
    description="Attack Surface Management con triaje por IA",
    version=__version__,
)

app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(findings.router)


@app.exception_handler(InvalidTargetError)
async def _invalid_target_handler(request: Request, exc: InvalidTargetError) -> JSONResponse:
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


@app.get("/", tags=["sistema"])
async def root() -> dict[str, str]:
    return {"servicio": "Atalaya", "docs": "/docs"}
