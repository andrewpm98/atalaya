"""Router de activos: subdominios, hosts, puertos y servicios descubiertos."""

from __future__ import annotations

from fastapi import APIRouter, status

router = APIRouter(prefix="/assets", tags=["activos"])


@router.get("", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def list_assets() -> dict[str, str]:
    """Lista los activos expuestos descubiertos. (Paso 3)."""
    return {"detail": "pendiente"}
