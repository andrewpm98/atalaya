"""Punto de entrada de la API de Atalaya (FastAPI).

Expone la API REST propia de la herramienta (requisito de la práctica) y
monta los routers de cada dominio funcional. En el Paso 1 los routers son
esqueletos; cada fase posterior los va rellenando.
"""

from __future__ import annotations

from fastapi import FastAPI

from atalaya import __version__
from atalaya.api.routes import assets, findings, scans

app = FastAPI(
    title="Atalaya API",
    description="Attack Surface Management con triaje por IA",
    version=__version__,
)

app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(findings.router)


@app.get("/health", tags=["sistema"])
async def health() -> dict[str, str]:
    """Sonda de salud: confirma que la API está viva."""
    return {"status": "ok", "version": __version__}


@app.get("/", tags=["sistema"])
async def root() -> dict[str, str]:
    return {"servicio": "Atalaya", "docs": "/docs"}
