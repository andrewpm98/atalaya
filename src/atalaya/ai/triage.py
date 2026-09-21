"""Triaje por IA: prioriza hallazgos, explica impacto y sugiere remediación.

Es la capa diferencial de Atalaya. Principio central del proyecto: el modelo
recibe **contexto estructurado** — campos concretos de `Asset`/`Finding`,
seleccionados a propósito — nunca un volcado en bruto de las filas de BD.
Eso hace el prompt estable y auditable: no cambia si se añade una columna
interna (`id`, `scan_id`, timestamps) que no aporta a la decisión de
severidad.

Degradación controlada, igual que `discovery/subdomains.py`: triar varios
hallazgos es procesar una colección, y el fallo de uno (el modelo no
responde, la respuesta no valida) no debe abortar el resto. `triage_finding`
nunca lanza excepción; refleja el fallo como valor de retorno.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, ValidationError

from atalaya.ai.provider import LLMProvider
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity

logger = logging.getLogger(__name__)

_TOOL_NAME = "record_triage"

_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": [s.value for s in FindingSeverity if s is not FindingSeverity.UNKNOWN],
            "description": "Severidad razonada del hallazgo, según impacto real.",
        },
        "impact": {
            "type": "string",
            "description": (
                "Impacto explicado en lenguaje natural: qué expone este "
                "hallazgo y por qué importa, para un lector no técnico."
            ),
        },
        "remediation": {
            "type": "string",
            "description": "Remediación concreta y accionable, no genérica.",
        },
    },
    "required": ["severity", "impact", "remediation"],
}

_SYSTEM_PROMPT = (
    "Eres un analista de seguridad ofensiva especializado en Attack Surface "
    "Management (ASM). Se te da un activo expuesto en Internet y un hallazgo "
    "detectado sobre él, ya verificado por herramientas de reconocimiento "
    "(no es una hipótesis). Registra tu triaje llamando SIEMPRE a la "
    "herramienta 'record_triage':\n"
    "- severity: razona sobre impacto real y explotabilidad plausible, no "
    "asumas el peor caso por defecto.\n"
    "- impact: explica en español claro qué expone este hallazgo y a quién "
    "afecta, sin jerga innecesaria.\n"
    "- remediation: una acción concreta, no un principio general de "
    "seguridad.\n"
    "No confirmes ni describas cómo explotar el hallazgo: reconocimiento "
    "señala patrones de riesgo, no verifica explotabilidad."
)


class _TriageOutput(BaseModel):
    """Valida la respuesta de la herramienta antes de aplicarla a un `Finding`.

    El JSON Schema enviado al modelo ya acota bastante, pero no sustituye la
    validación propia: un modelo puede devolver una cadena vacía como
    `impact` sin violar el schema.
    """

    severity: FindingSeverity
    impact: str = Field(min_length=1)
    remediation: str = Field(min_length=1)


def build_finding_context(asset: Asset, finding: Finding) -> dict[str, object]:
    """Construye el contexto estructurado que se envía al modelo.

    Selección deliberada de campos — no `asset.__dict__` ni un `model_dump`
    genérico — para que el prompt no dependa de la forma interna de las
    tablas ni exponga columnas irrelevantes para la decisión de severidad.
    """
    return {
        "asset": {
            "hostname": asset.hostname,
            "ip_addresses": asset.ip_addresses,
            "status": asset.status,
            "sources": asset.sources,
            "is_active": asset.is_active,
            "open_ports": asset.open_ports,
        },
        "finding": {
            "type": finding.finding_type,
            "evidence": finding.evidence,
        },
    }


async def triage_finding(provider: LLMProvider, asset: Asset, finding: Finding) -> str | None:
    """Triaja un único hallazgo y actualiza `finding` in place.

    Nunca lanza excepción: un fallo del proveedor o una respuesta que no
    valida dejan `finding` intacto (mantiene severidad `unknown`) y se
    reportan como valor de retorno, no como excepción — coherente con la
    degradación controlada del resto del proyecto.

    Returns:
        `None` si el triaje tuvo éxito; en caso contrario, un mensaje
        describiendo el fallo.
    """
    context = build_finding_context(asset, finding)
    prompt = (
        "Analiza este hallazgo y registra tu triaje:\n\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )

    try:
        raw = await provider.complete_tool(
            prompt,
            system=_SYSTEM_PROMPT,
            tool_name=_TOOL_NAME,
            tool_schema=_TOOL_SCHEMA,
        )
    except AIProviderError as exc:
        logger.warning("Triaje de finding %s falló: %s", finding.id, exc)
        return f"proveedor IA no disponible: {exc}"

    try:
        output = _TriageOutput.model_validate(raw)
    except ValidationError as exc:
        logger.warning("Triaje de finding %s devolvió una respuesta inválida: %s", finding.id, exc)
        return f"respuesta del modelo no válida: {exc}"

    finding.severity = output.severity
    finding.impact = output.impact
    finding.remediation = output.remediation
    return None


@dataclass
class TriageBatchResult:
    """Resultado de triar varios hallazgos: cuántos se actualizaron y qué falló."""

    triaged: int = 0
    errors: list[str] = field(default_factory=list)


async def triage_findings(
    provider: LLMProvider,
    findings: list[Finding],
    *,
    concurrency: int | None = None,
) -> TriageBatchResult:
    """Triaja varios hallazgos de forma concurrente y acotada.

    Cada hallazgo se procesa de forma independiente — el fallo de uno no
    aborta el resto — con el mismo patrón de semáforo que
    `discovery/subdomains.py::resolve_hostname` usa para DNS.

    Requiere que `finding.asset` esté ya cargado en cada `Finding` (ver
    `core/repository.py`, que precarga la relación); esta función no hace
    IO de base de datos, solo llamadas al proveedor de IA.
    """
    semaphore = asyncio.Semaphore(concurrency or settings.ai_concurrency)
    result = TriageBatchResult()

    async def _run(finding: Finding) -> None:
        async with semaphore:
            error = await triage_finding(provider, finding.asset, finding)
        if error is None:
            result.triaged += 1
        else:
            result.errors.append(f"finding #{finding.id} ({finding.finding_type}): {error}")

    await asyncio.gather(*(_run(finding) for finding in findings))
    return result
