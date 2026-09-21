"""Agente 2: visión global del escaneo — patrones, combinaciones preocupantes y prioridades.

Es el reemplazo natural de `ai/query.py::ask()` para preguntas sobre el
escaneo completo: mismo tipo de contexto (el escaneo entero, no un hallazgo
aislado), pero con una respuesta de forma garantizada (`complete_tool`, no
prosa libre) que además razona explícitamente sobre patrones, combinaciones
preocupantes y prioridades, no solo contesta la pregunta literal. **No se
borra `ai/query.py` en este módulo** — si queda obsoleto es una decisión de
quien cablee la capa API contra ambos (ver resumen final del subagente que
implementó esto).

Petición puntual (una pregunta o un resumen bajo demanda, no una colección
de elementos independientes sobre la que tenga sentido degradar) →
propaga `AIProviderError`, igual criterio que `ai/query.py::ask()`. Una
respuesta que no valida contra `AnalystResult` se trata como el mismo tipo
de fallo (el proveedor no cumplió el contrato de forma que se le pidió) y
también se traduce a `AIProviderError`, para que quien llama a este módulo
solo tenga que manejar una única excepción — igual que ya hace
`api/main.py::exception_handler` con el resto de la capa IA.
"""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel, Field, ValidationError

from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import FindingSeverity, Scan

logger = logging.getLogger(__name__)

_TOOL_NAME = "record_analysis"

_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {
            "type": "string",
            "description": "Respuesta directa a la pregunta, o resumen si no hay pregunta.",
        },
        "patterns": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Patrones detectados en el conjunto del escaneo.",
        },
        "concerning_combinations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Combinaciones de activos/hallazgos especialmente preocupantes.",
        },
        "priorities": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Qué atender primero, y por qué.",
        },
    },
    "required": ["answer", "patterns", "concerning_combinations", "priorities"],
}

_SYSTEM_PROMPT = (
    "Eres un analista de seguridad ofensiva especializado en Attack Surface "
    "Management (ASM), con visión de conjunto sobre un escaneo completo (no "
    "un hallazgo aislado). Se te da un resumen del dominio escaneado y sus "
    "hallazgos `critical`/`high`, ya verificados por herramientas de "
    "reconocimiento (no son una hipótesis). Registra tu análisis llamando "
    "SIEMPRE a la herramienta 'record_analysis':\n"
    "- answer: responde la pregunta directamente si se te da una; si no hay "
    "pregunta, un resumen ejecutivo del estado del escaneo.\n"
    "- patterns: patrones que solo son visibles mirando el conjunto (p. ej. "
    "concentración de entornos de prueba sin TLS, varios subdominios con la "
    "misma cabecera ausente).\n"
    "- concerning_combinations: combinaciones de hallazgos que, juntas, son "
    "más graves que cada una por separado.\n"
    "- priorities: qué atender primero, y por qué, en lenguaje claro.\n"
    "No confirmes ni describas cómo explotar ningún hallazgo: reconocimiento "
    "señala patrones de riesgo, no verifica explotabilidad."
)


class AnalystResult(BaseModel):
    """Respuesta con forma garantizada del agente de visión global.

    Reutilizado tal cual por `ai/prompter.py`, para que quien llama a
    `route_and_answer` no tenga que manejar dos formas de respuesta
    distintas según a qué agente especializado se enrutó la pregunta.
    """

    answer: str = Field(min_length=1)
    patterns: list[str] = Field(default_factory=list)
    concerning_combinations: list[str] = Field(default_factory=list)
    priorities: list[str] = Field(default_factory=list)


def build_scan_overview_context(scan: Scan) -> dict[str, object]:
    """Contexto estructurado para la visión global del escaneo.

    Selección deliberada, distinta de `ai/query.py::build_scan_context`
    (que manda TODOS los activos y hallazgos del escaneo): aquí solo hace
    falta el volumen (nº de activos, nº con direccionamiento interno), la
    distribución de severidades, y el detalle de los hallazgos
    `critical`/`high` — los que de verdad mueven la aguja de "qué atender
    primero". Enviar el resto (hallazgos `low`/`medium`/`unknown` en
    detalle, o activos sin hallazgos) infla el prompt sin cambiar la
    priorización que se le pide al modelo.
    """
    severity_counts: dict[str, int] = {severity.value: 0 for severity in FindingSeverity}
    internal_addressing_count = 0
    priority_findings: list[dict[str, object]] = []

    for asset in scan.assets:
        if asset.leaks_internal_addressing:
            internal_addressing_count += 1
        for finding in asset.findings:
            severity_counts[finding.severity.value] += 1
            if finding.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                priority_findings.append(
                    {
                        "hostname": asset.hostname,
                        "type": finding.finding_type,
                        "severity": finding.severity.value,
                        "evidence": finding.evidence,
                        "impact": finding.impact,
                    }
                )

    return {
        "domain": scan.domain,
        "total_assets": len(scan.assets),
        "assets_with_internal_addressing": internal_addressing_count,
        "severity_distribution": severity_counts,
        "critical_high_findings": priority_findings,
    }


async def analyze_scan(
    provider: LLMProvider, scan: Scan, *, question: str | None = None
) -> AnalystResult:
    """Analiza `scan` en conjunto: responde `question` o resume si es `None`.

    Propaga `AIProviderError` (petición puntual, ver docstring del módulo).
    """
    context = build_scan_overview_context(scan)
    header = f"Pregunta: {question}" if question else "Sin pregunta: genera un resumen ejecutivo."
    prompt = (
        f"{header}\n\n"
        f"Datos del escaneo (JSON):\n{json.dumps(context, ensure_ascii=False, indent=2)}"
    )
    logger.info("Análisis global del escaneo #%s (%s)", scan.id, scan.domain)

    raw = await provider.complete_tool(
        prompt, system=_SYSTEM_PROMPT, tool_name=_TOOL_NAME, tool_schema=_TOOL_SCHEMA
    )
    try:
        return AnalystResult.model_validate(raw)
    except ValidationError as exc:
        logger.warning("Análisis global del escaneo #%s devolvió una respuesta inválida: %s", scan.id, exc)
        raise AIProviderError(f"respuesta del modelo no válida: {exc}") from exc
