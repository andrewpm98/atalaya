"""Router de hallazgos: riesgos detectados y consulta en lenguaje natural."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.ai.prompter import route_and_answer
from atalaya.ai.provider import get_provider
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

    La resolución del `Scan` no cambia respecto a antes de introducir la
    capa de agentes: sigue siendo responsabilidad de este endpoint, no de
    `ai/prompter.py` (que recibe el `Scan` ya resuelto, igual que antes
    recibía `ai/query.py::ask()`). Lo que sí cambia es a quién se delega la
    pregunta: `route_and_answer()` decide internamente si la responde el
    agente de visión global (`ai/analyst.py`) o el de riesgo de takeover
    (`ai/takeover_detective.py`), y devuelve siempre un `AnalystResult` —
    `ai/query.py::ask()` (que solo devolvía un `str` de prosa libre) queda
    sin llamador tras este cambio y se elimina junto con su test dedicado
    (`tests/test_ai_query.py`); no lo usa nada más (comprobado con
    `grep -rn "ai\\.query" src tests`).
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
    result = await route_and_answer(provider, scan=scan, question=payload.question)
    return AskResponse(
        scan_id=scan.id,
        domain=scan.domain,
        question=payload.question,
        answer=result.answer,
        patterns=result.patterns,
        concerning_combinations=result.concerning_combinations,
        priorities=result.priorities,
    )
