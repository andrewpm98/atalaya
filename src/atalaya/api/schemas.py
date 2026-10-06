"""Esquemas Pydantic de la API: la frontera entre las tablas y el exterior.

Los modelos ORM (`core/models.py`) no se serializan directamente como
respuesta: acoplaría el contrato público de la API a la forma de las tablas,
y cualquier cambio de esquema de BD rompería a los clientes sin necesidad.
Coherente con la convención del proyecto de usar Pydantic en toda frontera.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from atalaya.core.models import FindingSeverity, ScanStatus
from atalaya.core.scoring import compute_risk_score


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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_score(self) -> int:
        """Índice de riesgo 0-100 (`core/scoring.py`), el mismo que el del PDF.

        Se expone aquí para que el dashboard lo pinte en vez de recalcularlo:
        antes tenía su propia copia de la fórmula, sincronizada a mano.
        """
        return compute_risk_score(
            (finding.severity, finding.finding_type)
            for asset in self.assets
            for finding in asset.findings
        )


class TriageResponse(BaseModel):
    """Resultado de `POST /scans/{id}/triage`: cuántos hallazgos se triaron.

    `triaged` cuenta todos los hallazgos que quedaron triados, llamando al
    modelo o no; `reused` es la parte que copió el triaje de un hallazgo con
    el mismo contexto exacto de otro escaneo del dominio
    (`ai/triage_reuse.py`), y `model_calls`, las llamadas que sí se hicieron
    (incluidas las que fallaron).
    """

    scan_id: int
    triaged: int
    reused: int = 0
    model_calls: int = 0
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


class FindingRefOut(BaseModel):
    """Hallazgo aparecido o desaparecido en un activo común (ver `AssetChangeOut`)."""

    model_config = ConfigDict(from_attributes=True)

    finding_type: str
    #: Del escaneo donde el hallazgo está presente: el actual si es nuevo,
    #: el previo si desapareció.
    severity: FindingSeverity


class AssetChangeOut(BaseModel):
    """Cambios de un activo presente en los dos escaneos.

    «Desaparecido» no significa «cerrado» ni «resuelto»: un timeout de la
    sonda también hace desaparecer un puerto o un hallazgo (ver
    `core/repository.py::diff_scans`).
    """

    model_config = ConfigDict(from_attributes=True)

    hostname: str
    estado_anterior: str
    estado_actual: str
    puertos_nuevos: list[int] = Field(default_factory=list)
    puertos_desaparecidos: list[int] = Field(default_factory=list)
    hallazgos_nuevos: list[FindingRefOut] = Field(default_factory=list)
    hallazgos_desaparecidos: list[FindingRefOut] = Field(default_factory=list)


class ScanDiffOut(BaseModel):
    """Respuesta de `GET /scans/{scan_id}/diff/{other_scan_id}`.

    `previous_scan_id`/`current_scan_id` documentan cuál de los dos escaneos
    se trató como "previo" y cuál como "actual" — no necesariamente en el
    mismo orden en que se pidieron en la URL (ver `scans.py::diff_scan`),
    así que el cliente no debe asumir que `previous_scan_id == scan_id` de
    la ruta.

    `comunes` lista todos los hostnames presentes en ambos escaneos, como
    antes de existir `cambiados`; los «sin cambios» son `comunes` menos los
    hostnames de `cambiados`.
    """

    previous_scan_id: int
    current_scan_id: int
    nuevos: list[str] = Field(default_factory=list)
    desaparecidos: list[str] = Field(default_factory=list)
    comunes: list[str] = Field(default_factory=list)
    cambiados: list[AssetChangeOut] = Field(default_factory=list)
    #: Valoración de `ai/diff_analyst.py`. `None` solo si se pidió
    #: `analysis=false`; por defecto, si el modelo falla, el endpoint da 502.
    analysis: str | None = None
