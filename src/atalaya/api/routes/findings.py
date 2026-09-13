"""Router de hallazgos: riesgos detectados y su triaje por IA."""

from __future__ import annotations

from fastapi import APIRouter, status

router = APIRouter(prefix="/findings", tags=["hallazgos"])


@router.get("", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def list_findings() -> dict[str, str]:
    """Lista los hallazgos priorizados por la capa IA. (Paso 5)."""
    return {"detail": "pendiente"}


@router.post("/ask", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def ask_natural_language() -> dict[str, str]:
    """Consulta la superficie de exposición en lenguaje natural. (Paso 5)."""
    return {"detail": "pendiente: consulta NL sobre hallazgos"}
