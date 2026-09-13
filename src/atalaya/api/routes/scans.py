"""Router de escaneos: lanzar y consultar escaneos de superficie de exposición.

Paso 1: contrato de endpoints definido con stubs.
Paso 2-4: se conectan al motor de descubrimiento y a la base de datos.
"""

from __future__ import annotations

from fastapi import APIRouter, status

router = APIRouter(prefix="/scans", tags=["escaneos"])


@router.post("", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def create_scan() -> dict[str, str]:
    """Lanza un escaneo sobre un dominio objetivo. (Se implementa en Paso 2-4)."""
    return {"detail": "pendiente: descubrimiento (Paso 2) + persistencia (Paso 3)"}


@router.get("", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def list_scans() -> dict[str, str]:
    """Lista los escaneos realizados."""
    return {"detail": "pendiente"}


@router.get("/{scan_id}", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def get_scan(scan_id: int) -> dict[str, str]:
    """Devuelve el detalle de un escaneo por su identificador."""
    return {"detail": "pendiente", "scan_id": str(scan_id)}
