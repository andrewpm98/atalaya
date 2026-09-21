"""Agente 3: riesgo de *subdomain takeover* — prioriza candidatos ya detectados.

Depende de `discovery.models.TakeoverCandidate`, producido por
`discovery/takeover.py` (reconocimiento DNS pasivo, sin verificar
explotabilidad). Esta capa no descubre candidatos nuevos: prioriza los que
ya existen y explica el motivo del riesgo, con el mismo principio de
contexto estructurado que `ai/triage.py`.

**Colección → degrada con gracia.** `assess_takeover_risk` procesa toda la
lista de candidatos en una sola llamada al proveedor (no una por
candidato: el coste de N llamadas por escaneo no se justifica frente a una
única llamada con la lista completa). Un fallo del proveedor, o una
respuesta que no valida contra el schema esperado, no debe tumbar el resto
del escaneo — se degrada a lista vacía y se deja constancia en el log,
mismo criterio que `ai/triage.py::triage_findings` aplica por elemento; aquí
se aplica al lote completo porque solo hay una llamada que puede fallar
como unidad (no hay "elementos parcialmente triados" que conservar).
"""

from __future__ import annotations

import json
import logging
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.discovery.models import TakeoverCandidate

logger = logging.getLogger(__name__)

_TOOL_NAME = "record_takeover_assessment"

_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "assessments": {
            "type": "array",
            "description": "Una evaluación por cada candidato recibido.",
            "items": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "provider": {"type": "string"},
                    "priority": {
                        "type": "string",
                        "enum": ["alta", "media", "baja"],
                        "description": "Prioridad de revisión manual, no severidad confirmada.",
                    },
                    "reasoning": {
                        "type": "string",
                        "description": (
                            "Por qué esta prioridad, sin confirmar que el recurso "
                            "esté realmente sin reclamar."
                        ),
                    },
                },
                "required": ["hostname", "provider", "priority", "reasoning"],
            },
        }
    },
    "required": ["assessments"],
}

_SYSTEM_PROMPT = (
    "Eres un analista de seguridad ofensiva especializado en Attack Surface "
    "Management (ASM). Se te da una lista de candidatos a *subdomain "
    "takeover*: hosts cuyo CNAME apunta a un servicio de hosting de "
    "terceros con un patrón asociado a este riesgo, detectados por "
    "reconocimiento DNS pasivo (no confirmados, no verificados). Registra tu "
    "evaluación llamando SIEMPRE a la herramienta "
    "'record_takeover_assessment', una entrada por candidato:\n"
    "- priority: 'alta'/'media'/'baja', según qué tan característico es el "
    "patrón del proveedor y qué tan sensible parece el host por su "
    "nombre.\n"
    "- reasoning: por qué esa prioridad.\n"
    "IMPORTANTE: razona sobre la PROBABILIDAD y el MOTIVO del riesgo. NUNCA "
    "afirmes ni sugieras que el recurso está confirmado como secuestrable — "
    "eso exigiría comprobar si el proveedor de terceros responde 'no "
    "existe', y esta herramienta no verifica explotabilidad, solo señala el "
    "patrón de riesgo."
)


class TakeoverAssessment(BaseModel):
    """Evaluación de riesgo de un candidato a takeover, con forma garantizada."""

    hostname: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    priority: Literal["alta", "media", "baja"]
    reasoning: str = Field(min_length=1)


class _AssessmentBatch(BaseModel):
    """Envoltorio de validación de la respuesta completa del modelo."""

    assessments: list[TakeoverAssessment]


def build_takeover_context(candidates: list[TakeoverCandidate]) -> list[dict[str, str]]:
    """Contexto estructurado: los cuatro campos de `TakeoverCandidate`, tal cual.

    A diferencia de `ai/triage.py::build_finding_context`, aquí no hay que
    elegir un subconjunto: `TakeoverCandidate` ya es, en sí mismo, el
    contexto mínimo construido a propósito por `discovery/takeover.py` —
    no un `Asset`/`Finding` de BD con columnas irrelevantes que filtrar.
    """
    return [
        {
            "hostname": c.hostname,
            "cname": c.cname,
            "provider": c.provider,
            "pattern_matched": c.pattern_matched,
        }
        for c in candidates
    ]


async def assess_takeover_risk(
    provider: LLMProvider, candidates: list[TakeoverCandidate]
) -> list[TakeoverAssessment]:
    """Prioriza `candidates` en una sola llamada al proveedor.

    Lista vacía → `[]` sin llamar al proveedor: mismo criterio de
    idempotencia/coste que ya aplica `POST /scans/{id}/triage` (no pagar una
    llamada de IA por un escaneo sin candidatos).

    Degrada con gracia ante cualquier fallo (proveedor no disponible,
    respuesta que no valida): nunca lanza excepción, devuelve `[]` y deja
    constancia en el log — ver docstring del módulo, sección "Colección →
    degrada con gracia".
    """
    if not candidates:
        return []

    context = build_takeover_context(candidates)
    prompt = (
        "Evalúa el riesgo de estos candidatos a subdomain takeover y "
        "registra tu evaluación:\n\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )

    try:
        raw = await provider.complete_tool(
            prompt, system=_SYSTEM_PROMPT, tool_name=_TOOL_NAME, tool_schema=_TOOL_SCHEMA
        )
    except AIProviderError as exc:
        logger.warning("Evaluación de takeover falló (%s candidatos): %s", len(candidates), exc)
        return []

    try:
        batch = _AssessmentBatch.model_validate(raw)
    except ValidationError as exc:
        logger.warning(
            "Evaluación de takeover devolvió una respuesta inválida (%s candidatos): %s",
            len(candidates),
            exc,
        )
        return []

    return batch.assessments
