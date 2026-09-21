"""Router de hallazgos: riesgos detectados y consulta en lenguaje natural."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.ai.provider import get_provider
from atalaya.ai.query import ask as ask_scan
from atalaya.api.schemas import AskRequest, AskResponse, FindingOut
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
    """Lista hallazgos. `severity` es `unknown` hasta triarlos (`POST /scans/{id}/triage`)."""
    return await repository.list_findings(session, asset_id=asset_id, scan_id=scan_id)


@router.post("/ask", response_model=AskResponse)
async def ask_natural_language(
    payload: AskRequest, session: AsyncSession = Depends(get_session)
) -> AskResponse:
    """Responde, en lenguaje natural, una pregunta sobre un escaneo persistido.

    Usa `payload.scan_id` si se indica; si no, el último escaneo completado
    de `payload.domain` (ver `core/repository.py::get_latest_scan`).
    """
    if payload.scan_id is not None:
        scan = await repository.get_scan(session, payload.scan_id)
    else:
        scan = await repository.get_latest_scan(session, payload.domain)

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No hay un escaneo completado para ese dominio o id.",
        )

    provider = get_provider()
    answer = await ask_scan(provider, scan, payload.question)
    return AskResponse(scan_id=scan.id, domain=scan.domain, question=payload.question, answer=answer)
