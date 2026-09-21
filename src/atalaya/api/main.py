"""Punto de entrada de la API de Atalaya (FastAPI).

Expone la API REST propia de la herramienta (requisito de la práctica) y
monta los routers de cada dominio funcional. En el Paso 1 los routers son
esqueletos; cada fase posterior los va rellenando.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from atalaya import __version__
from atalaya.api.routes import assets, findings, scans
from atalaya.core.exceptions import InvalidTargetError, UnauthorizedTargetError

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


@app.get("/health", tags=["sistema"])
async def health() -> dict[str, str]:
    """Sonda de salud: confirma que la API está viva."""
    return {"status": "ok", "version": __version__}


@app.get("/", tags=["sistema"])
async def root() -> dict[str, str]:
    return {"servicio": "Atalaya", "docs": "/docs"}
