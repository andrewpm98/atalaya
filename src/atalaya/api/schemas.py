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


class TriageResponse(BaseModel):
    """Resultado de `POST /scans/{id}/triage`: cuántos hallazgos se triaron."""

    scan_id: int
    triaged: int
    errors: list[str] = Field(default_factory=list)


class AskRequest(BaseModel):
    """Cuerpo de `POST /findings/ask`."""

    domain: str = Field(description="Dominio sobre el que preguntar")
    question: str = Field(min_length=1, description="Pregunta en lenguaje natural")
    scan_id: int | None = Field(
        default=None,
        description="Escaneo concreto a consultar; por defecto, el último completado",
    )


class AskResponse(BaseModel):
    """Respuesta de `POST /findings/ask`.

    Desde que el endpoint pasa por `ai/prompter.py::route_and_answer()` (que
    devuelve siempre un `AnalystResult`, venga del agente de visión global o
    del de takeover), la respuesta trae más que un `answer` de texto libre:
    `patterns`/`concerning_combinations`/`priorities` son señal real que ya
    razonó el modelo (patrones del conjunto, combinaciones preocupantes, qué
    atender primero). Se exponen todos en vez de recortar a solo `answer`:
    descartarlos aquí obligaría a quien consuma la API (el dashboard, o
    cualquier cliente futuro) a volver a pedirlos con una segunda llamada, y
    no hay motivo de seguridad ni de tamaño de payload para ocultarlos. Con
    `default_factory=list` la respuesta no rompe si el agente de takeover
    (que hoy puebla `answer`/`concerning_combinations`/`priorities` pero deja
    `patterns` vacío) es el que respondió.
    """

    scan_id: int
    domain: str
    question: str
    answer: str
    patterns: list[str] = Field(default_factory=list)
    concerning_combinations: list[str] = Field(default_factory=list)
    priorities: list[str] = Field(default_factory=list)


class ScanDiffOut(BaseModel):
    """Respuesta de `GET /scans/{scan_id}/diff/{other_scan_id}`.

    `previous_scan_id`/`current_scan_id` documentan cuál de los dos escaneos
    se trató como "previo" y cuál como "actual" — no necesariamente en el
    mismo orden en que se pidieron en la URL (ver `scans.py::diff_scan`),
    así que el cliente no debe asumir que `previous_scan_id == scan_id` de
    la ruta.
    """

    previous_scan_id: int
    current_scan_id: int
    nuevos: list[str] = Field(default_factory=list)
    desaparecidos: list[str] = Field(default_factory=list)
    comunes: list[str] = Field(default_factory=list)
    analysis: str
