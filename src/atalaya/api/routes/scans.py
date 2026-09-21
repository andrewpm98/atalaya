"""Router de escaneos: lanzar y consultar escaneos de superficie de exposición.

Paso 2-3 cubren descubrimiento de subdominios + persistencia; `create_scan`
solo encadena ambos. Puertos/cabeceras/TLS se suman al mismo escaneo cuando
esos módulos de descubrimiento existan (Paso 2, resto).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.api.schemas import ScanDetail, ScanRequest, ScanSummary
from atalaya.core import repository
from atalaya.core.database import get_session
from atalaya.core.models import Scan
from atalaya.core.persistence import save_subdomain_scan
from atalaya.discovery.subdomains import enumerate_subdomains

router = APIRouter(prefix="/scans", tags=["escaneos"])


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ScanDetail)
async def create_scan(
    payload: ScanRequest, session: AsyncSession = Depends(get_session)
) -> Scan:
    """Lanza un escaneo de subdominios sobre `payload.domain` y lo persiste.

    `enumerate_subdomains` valida y autoriza el dominio internamente (levanta
    `InvalidTargetError`/`UnauthorizedTargetError`, traducidas a HTTP por los
    manejadores de `api/main.py`): este endpoint no duplica esa comprobación.
    """
    result = await enumerate_subdomains(payload.domain, resolve=payload.resolve)
    scan = await save_subdomain_scan(session, result)
    await session.commit()
    # Se recarga con `selectinload`: `scan.assets` tiene todos los `Asset` (se
    # poblaron en memoria antes del flush), pero `asset.findings` solo está
    # cargado para los assets a los que `save_subdomain_scan` les añadió un
    # finding. Acceder a los demás dispararía un lazy-load fuera de contexto
    # async (`MissingGreenlet`) al serializar la respuesta.
    loaded = await repository.get_scan(session, scan.id)
    assert loaded is not None
    return loaded


@router.get("", response_model=list[ScanSummary])
async def list_scans(
    domain: str | None = Query(default=None, description="Filtra por dominio exacto"),
    session: AsyncSession = Depends(get_session),
) -> list[Scan]:
    """Lista los escaneos realizados, más recientes primero."""
    return await repository.list_scans(session, domain=domain)


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> Scan:
    """Devuelve el detalle de un escaneo, con sus activos y hallazgos."""
    scan = await repository.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {scan_id} no encontrado"
        )
    return scan
