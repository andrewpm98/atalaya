"""Esquemas Pydantic de la API: la frontera entre las tablas y el exterior.

Los modelos ORM (`core/models.py`) no se serializan directamente como
respuesta: acoplaría el contrato público de la API a la forma de las tablas,
y cualquier cambio de esquema de BD rompería a los clientes sin necesidad.
Coherente con la convención del proyecto de usar Pydantic en toda frontera.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from atalaya.core.models import FindingSeverity, Monitor, ScanStatus
from atalaya.core.monitor_runner import MAX_INTERVAL_HOURS, MIN_INTERVAL_HOURS
from atalaya.core.scoring import compute_risk_score
from atalaya.core.webhooks import mask_webhook_url
from atalaya.onboarding.checks import CheckResult, Status


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


class ConfigStatusOut(BaseModel):
    """Respuesta de `GET /config/status`: una entrada por comprobación.

    Reutiliza `CheckResult` de `onboarding/checks.py` en vez de copiarlo: es
    ya un modelo Pydantic de datos (no una tabla) y es el mismo resultado que
    pinta `atalaya doctor`, así que la terminal y el dashboard no pueden
    describir la misma configuración de dos formas distintas. `key` es
    estable (`config`, `scope`, `database`, `ai`, `shodan`, `api`,
    `secrets`): el dashboard elige por ella, no por el texto.
    """

    checks: list[CheckResult]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def errors(self) -> int:
        return sum(check.status is Status.ERROR for check in self.checks)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def warnings(self) -> int:
        return sum(check.status is Status.WARN for check in self.checks)


class MonitorRequest(BaseModel):
    """Cuerpo de `POST /monitors`: qué dominio vigilar, cada cuánto y a dónde avisar."""

    domain: str = Field(description="Dominio a vigilar, p. ej. ejemplo.com")
    webhook_url: str = Field(
        description=(
            "URL https que recibe cada aviso (POST con JSON). Solo direcciones públicas: "
            "una URL hacia la red interna se rechaza (SSRF)."
        )
    )
    interval_hours: int = Field(
        default=24,
        ge=MIN_INTERVAL_HOURS,
        le=MAX_INTERVAL_HOURS,
        description="Horas entre escaneos. Mínimo 1: un escaneo es intrusivo para el objetivo.",
    )
    secret: str | None = Field(
        default=None,
        min_length=16,
        max_length=256,
        description=(
            "Opcional. Con él, cada aviso lleva `X-Atalaya-Signature: sha256=<HMAC-SHA256 del "
            "cuerpo>` para que el receptor compruebe que viene de Atalaya. No se devuelve nunca."
        ),
    )


class MonitorUpdate(BaseModel):
    """Cuerpo de `PATCH /monitors/{id}`: pausar o reanudar la vigilancia."""

    active: bool = Field(
        description=(
            "false la pausa; true la reanuda (si ya le tocaba, corre en el próximo minuto)."
        )
    )


class MonitorOut(BaseModel):
    """Un monitor tal como lo ve un cliente: sin la URL completa ni el secreto.

    No se construye con `from_attributes` desde la fila: `webhook_url` puede
    llevar un token en la ruta (Slack, Discord) y `webhook_secret` es la clave
    de la firma. Se exponen enmascarada y como «firmado sí/no», con el mismo
    criterio que `GET /config/status`: estado, nunca valores.
    """

    id: int
    domain: str
    interval_hours: int
    webhook: str = Field(description="Destino del aviso, enmascarado: `https://host/…`")
    signed: bool = Field(description="Si los avisos van firmados con HMAC")
    active: bool
    created_at: datetime
    next_run_at: datetime
    last_run_at: datetime | None
    last_scan_id: int | None
    baseline_scan_id: int | None = Field(
        description=(
            "Último escaneo comparado. El siguiente se compara con lo ya avisado: este "
            "escaneo con los cambios pendientes deshechos"
        )
    )
    last_notified_at: datetime | None
    last_error: str | None
    pending_changes: int = Field(
        description=(
            "Cambios vistos y aún sin avisar: los que esperan a que un segundo escaneo "
            "los confirme y, si falló el aviso, los confirmados que se reenviarán"
        )
    )
    last_discarded: int = Field(
        description=(
            "Cambios vistos en un solo escaneo que la última ejecución no repitió: "
            "se descartaron como ruido, sin avisar"
        )
    )

    @classmethod
    def from_monitor(cls, monitor: Monitor) -> MonitorOut:
        return cls(
            id=monitor.id,
            domain=monitor.domain,
            interval_hours=monitor.interval_hours,
            webhook=mask_webhook_url(monitor.webhook_url),
            signed=bool(monitor.webhook_secret),
            active=monitor.active,
            created_at=monitor.created_at,
            next_run_at=monitor.next_run_at,
            last_run_at=monitor.last_run_at,
            last_scan_id=monitor.last_scan_id,
            baseline_scan_id=monitor.baseline_scan_id,
            last_notified_at=monitor.last_notified_at,
            last_error=monitor.last_error,
            pending_changes=len(monitor.pending_changes or []),
            last_discarded=monitor.last_discarded or 0,
        )
