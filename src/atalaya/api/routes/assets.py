"""Router de activos: subdominios, hosts, puertos y servicios descubiertos."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.api.schemas import AssetOut
from atalaya.core import repository
from atalaya.core.database import get_session
from atalaya.core.models import Asset

router = APIRouter(prefix="/assets", tags=["activos"])


@router.get("", response_model=list[AssetOut])
async def list_assets(
    scan_id: int | None = Query(default=None, description="Filtra por escaneo"),
    session: AsyncSession = Depends(get_session),
) -> list[Asset]:
    """Lista los activos expuestos descubiertos, opcionalmente por escaneo."""
    return await repository.list_assets(session, scan_id=scan_id)
