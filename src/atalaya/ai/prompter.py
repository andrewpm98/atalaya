"""Agente 0: intermediario — enruta una pregunta en lenguaje natural al
agente especializado adecuado y devuelve siempre la misma forma de respuesta.

Recibe la pregunta y el escaneo activo (ya resuelto por quien llama, igual
que hoy hace `POST /findings/ask` con `repository.get_scan()`/
`get_latest_scan()`). Construye un resumen **ligero** del escaneo (no el
contexto completo de `ai/analyst.py`) solo para decidir el enrutado, y con
`complete_tool` + la herramienta `route_query` decide si la pregunta va al
agente de visión global (`ai/analyst.py`) o al de riesgo de takeover
(`ai/takeover_detective.py`), reformulándola con el contexto ya
incorporado.

Para la rama "takeover" **no vuelve a invocar `discovery/takeover.py`**: los
candidatos ya están persistidos como `Finding(finding_type=
"subdomain_takeover_risk")` si el escaneo pasó por el enriquecimiento, así
que se reconstruye el contexto a partir de esos hallazgos (hostname +
evidence, los mismos dos campos que ya usa `ai/triage.py::
build_finding_context` para un `Finding`) y se envuelve el resultado en un
`AnalystResult` — el mismo tipo que devuelve `ai/analyst.py`, reutilizado
tal cual (no se duplica el modelo), para que quien llama a
`route_and_answer` no tenga que manejar dos formas de respuesta distintas.

Petición puntual → si el propio paso de enrutado falla (el proveedor no
responde), `AIProviderError` se propaga sin capturar, igual que
`ai/query.py::ask()` hoy: no hay nada parcial que conservar en una única
pregunta, así que no tiene sentido degradar aquí. Distinto es que la
*clasificación* no esté segura (el modelo no devuelve un `agent` reconocido,
o una `refined_question` vacía): eso no es un fallo del proveedor, así que
se usa `"analyst"` por defecto en vez de propagar — la pregunta nunca debe
quedarse sin responder por un fallo de enrutado.
"""

from __future__ import annotations

import json
import logging

from atalaya.ai.analyst import AnalystResult, analyze_scan
from atalaya.ai.provider import LLMProvider
from atalaya.ai.takeover_detective import TakeoverAssessment
from atalaya.core.models import Scan

logger = logging.getLogger(__name__)

_ROUTE_TOOL_NAME = "route_query"

_ROUTE_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "agent": {
            "type": "string",
            "enum": ["analyst", "takeover"],
            "description": "Agente especializado al que enviar la pregunta.",
        },
        "refined_question": {
            "type": "string",
            "description": "La pregunta reformulada, con el contexto del escaneo incorporado.",
        },
    },
    "required": ["agent", "refined_question"],
}

_ROUTE_SYSTEM_PROMPT = (
    "Eres el enrutador de una plataforma de Attack Surface Management "
    "(ASM). Se te da un resumen ligero de un escaneo y una pregunta en "
    "lenguaje natural. Decide, llamando SIEMPRE a la herramienta "
    "'route_query', qué agente especializado debe responderla:\n"
    "- 'takeover': la pregunta trata específicamente sobre riesgo de "
    "subdomain takeover (candidatos, CNAME sin reclamar, hosting de "
    "terceros).\n"
    "- 'analyst': cualquier otra pregunta sobre el escaneo (patrones, "
    "prioridades, activos, hallazgos generales) — es la opción por defecto "
    "ante la duda.\n"
    "Reformula la pregunta en 'refined_question' incorporando el contexto "
    "ya disponible del escaneo (p. ej. cifras concretas de hallazgos), para "
    "que el agente especializado no tenga que volver a pedirlo."
)

_TAKEOVER_TOOL_NAME = "record_takeover_assessment_batch"

_TAKEOVER_TOOL_SCHEMA = {
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
                    "priority": {"type": "string", "enum": ["alta", "media", "baja"]},
                    "reasoning": {"type": "string"},
                },
                "required": ["hostname", "provider", "priority", "reasoning"],
            },
        }
    },
    "required": ["assessments"],
}

_TAKEOVER_SYSTEM_PROMPT = (
    "Eres un analista de seguridad de Attack Surface Management (ASM) "
    "revisando candidatos a subdomain takeover ya detectados y persistidos "
    "como hallazgos (patrón de CNAME hacia un proveedor de hosting, no "
    "confirmados). Para cada uno, llamando SIEMPRE a "
    "'record_takeover_assessment_batch', razona sobre la probabilidad y el "
    "motivo del riesgo SIN afirmar ni sugerir que el recurso esté "
    "confirmado como secuestrable: describe el patrón observado a partir "
    "de la evidencia, no verifiques explotabilidad."
)


def build_routing_context(scan: Scan) -> dict[str, object]:
    """Resumen ligero del escaneo, solo para decidir el enrutado.

    Deliberadamente mínimo — nº de activos, hallazgos por severidad, si hay
    candidatos de takeover — no el contexto completo que sí necesita
    `ai/analyst.py::build_scan_overview_context`: aquí solo hace falta lo
    justo para clasificar la pregunta, no para responderla.
    """
    severity_counts: dict[str, int] = {}
    has_takeover_candidates = False
    for asset in scan.assets:
        for finding in asset.findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            if finding.finding_type == "subdomain_takeover_risk":
                has_takeover_candidates = True
    return {
        "domain": scan.domain,
        "total_assets": len(scan.assets),
        "findings_by_severity": severity_counts,
        "has_takeover_candidates": has_takeover_candidates,
    }


def _takeover_findings_context(scan: Scan) -> list[dict[str, str]]:
    """Extrae {hostname, evidence} de los hallazgos de takeover ya persistidos.

    No vuelve a invocar `discovery/takeover.py`: los candidatos ya están en
    BD como `Finding(finding_type="subdomain_takeover_risk")` si el escaneo
    pasó por el enriquecimiento. No se reconstruye el `TakeoverCandidate`
    original (cname/provider/pattern_matched) por parseo del texto de
    `evidence` — sería acoplar este módulo al formato exacto que genera
    `discovery/models.py::EnrichmentResult.findings_by_hostname`; en vez de
    eso se manda la evidencia tal cual, mismos dos campos que ya usa
    `ai/triage.py::build_finding_context` para un `Finding`, y se deja que
    el modelo la interprete.
    """
    items: list[dict[str, str]] = []
    for asset in scan.assets:
        for finding in asset.findings:
            if finding.finding_type == "subdomain_takeover_risk":
                items.append({"hostname": asset.hostname, "evidence": finding.evidence})
    return items


async def _assess_takeover_from_scan(
    provider: LLMProvider, scan: Scan, refined_question: str
) -> AnalystResult:
    """Evalúa los hallazgos de takeover ya persistidos en `scan` y envuelve
    el resultado en un `AnalystResult`, para que `route_and_answer` siempre
    devuelva la misma forma sin importar a qué agente se enrutó.
    """
    items = _takeover_findings_context(scan)
    if not items:
        return AnalystResult(
            answer="No se han detectado candidatos a subdomain takeover en este escaneo.",
            patterns=[],
            concerning_combinations=[],
            priorities=[],
        )

    prompt = (
        f"Pregunta: {refined_question}\n\n"
        "Candidatos a takeover ya detectados (JSON):\n"
        f"{json.dumps(items, ensure_ascii=False, indent=2)}"
    )
    raw = await provider.complete_tool(
        prompt,
        system=_TAKEOVER_SYSTEM_PROMPT,
        tool_name=_TAKEOVER_TOOL_NAME,
        tool_schema=_TAKEOVER_TOOL_SCHEMA,
    )
    assessments = [
        TakeoverAssessment.model_validate(item) for item in raw.get("assessments", [])
    ]

    priority_rank = {"alta": 0, "media": 1, "baja": 2}
    assessments.sort(key=lambda a: priority_rank.get(a.priority, 3))

    return AnalystResult(
        answer=(
            f"Se han evaluado {len(assessments)} candidato(s) a subdomain takeover."
            if assessments
            else "No se pudo evaluar el riesgo de los candidatos detectados."
        ),
        patterns=[],
        concerning_combinations=[
            f"{a.hostname} ({a.provider}): prioridad {a.priority}" for a in assessments
        ],
        priorities=[f"{a.hostname}: {a.reasoning}" for a in assessments],
    )


async def route_and_answer(provider: LLMProvider, *, scan: Scan, question: str) -> AnalystResult:
    """Enruta `question` al agente especializado adecuado y devuelve su respuesta.

    Ver docstring del módulo para el criterio de propagación/degradación.
    """
    context = build_routing_context(scan)
    prompt = (
        f"Pregunta del usuario: {question}\n\n"
        f"Resumen del escaneo (JSON):\n{json.dumps(context, ensure_ascii=False, indent=2)}"
    )

    # Paso de enrutado: petición puntual, `AIProviderError` se propaga sin
    # capturar (no hay nada parcial que conservar en una única pregunta).
    raw = await provider.complete_tool(
        prompt,
        system=_ROUTE_SYSTEM_PROMPT,
        tool_name=_ROUTE_TOOL_NAME,
        tool_schema=_ROUTE_TOOL_SCHEMA,
    )

    agent = raw.get("agent")
    refined_question = raw.get("refined_question")
    if agent not in ("analyst", "takeover") or not isinstance(refined_question, str) or not refined_question.strip():
        logger.info("Enrutado inseguro (agent=%r); usando 'analyst' por defecto", agent)
        agent = "analyst"
        refined_question = question

    if agent == "takeover":
        return await _assess_takeover_from_scan(provider, scan, refined_question)
    return await analyze_scan(provider, scan, question=refined_question)
