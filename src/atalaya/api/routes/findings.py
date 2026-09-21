"""Router de hallazgos: riesgos detectados y su triaje por IA."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.api.schemas import FindingOut
from atalaya.core import repository
from atalaya.core.database import get_session
from atalaya.core.models import Finding

router = APIRouter(prefix="/findings", tags=["hallazgos"])


@router.get("", response_model=list[FindingOut])
async def list_findings(
    asset_id: int | None = Query(default=None, description="Filtra por activo"),
    scan_id: int | None = Query(default=None, description="Filtra por escaneo"),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    """Lista hallazgos, sin triaje IA todavía (severidad `unknown` hasta Paso 5)."""
    return await repository.list_findings(session, asset_id=asset_id, scan_id=scan_id)


@router.post("/ask", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def ask_natural_language() -> dict[str, str]:
    """Consulta la superficie de exposición en lenguaje natural. (Paso 5)."""
    return {"detail": "pendiente: consulta NL sobre hallazgos"}
