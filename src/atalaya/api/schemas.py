"""Esquemas Pydantic de la API: la frontera entre las tablas y el exterior.

Los modelos ORM (`core/models.py`) no se serializan directamente como
respuesta: acoplaría el contrato público de la API a la forma de las tablas,
y cualquier cambio de esquema de BD rompería a los clientes sin necesidad.
Coherente con la convención del proyecto de usar Pydantic en toda frontera.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from atalaya.core.models import FindingSeverity, ScanStatus


class ScanRequest(BaseModel):
    """Cuerpo de `POST /scans`: qué dominio escanear y cómo."""

    domain: str = Field(description="Dominio a analizar, p. ej. ejemplo.com")
    resolve: bool = Field(
        default=True, description="Verificar DNS de cada subdominio hallado"
    )


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_type: str
    evidence: str
    severity: FindingSeverity
    impact: str | None
    remediation: str | None
    created_at: datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    status: str
    ip_addresses: list[str]
    sources: list[str]
    is_active: bool
    leaks_internal_addressing: bool
    open_ports: list[int]


class AssetDetail(AssetOut):
    findings: list[FindingOut] = Field(default_factory=list)


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime | None
    errors: list[str]


class ScanDetail(ScanSummary):
    assets: list[AssetDetail] = Field(default_factory=list)
