"""Agente 4: resumen ejecutivo del informe — prosa para un lector no técnico.

Petición puntual (una redacción bajo demanda, no una colección de elementos
independientes) → propaga `AIProviderError`, igual criterio que
`ai/query.py::ask()`. Quien integre este agente en `reporting/generator.py`
decide qué hacer si falla (p. ej. el informe se genera igualmente con un
resumen genérico de reserva) — esa decisión de fallback es de la capa de
reporting, no de este módulo: aquí solo se documenta la excepción y se
detiene.

No calcula `risk_score`: lo recibe ya calculado como parámetro, porque la
ponderación crítica/alta/media/baja es una decisión de quien integra este
agente en `reporting/generator.py`, no de la capa IA.
"""

from __future__ import annotations

import json
import logging

from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Finding

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Eres un consultor de ciberseguridad redactando el resumen ejecutivo de "
    "un informe de superficie de exposición (Attack Surface Management), "
    "dirigido a un lector NO técnico (dirección de la empresa, no un "
    "analista de seguridad). Escribe 2-3 párrafos en prosa clara, en "
    "español. Reglas estrictas:\n"
    "- Nada de jerga técnica: no menciones cabeceras HTTP, nombres de "
    "campos de base de datos, códigos de estado HTTP ni terminología de "
    "protocolo. Traduce cada riesgo a su impacto de negocio (reputación, "
    "continuidad del servicio, datos de clientes, cumplimiento normativo).\n"
    "- No confirmes ni describas cómo explotar ningún hallazgo: describe el "
    "riesgo observado, no verifiques explotabilidad.\n"
    "- Sé directo sobre la gravedad si los datos la justifican; no "
    "suavices un riesgo real, pero tampoco alarmes sin base en los datos."
)


def _finding_brief(finding: Finding) -> dict[str, object]:
    """Selección mínima de un `Finding` para el resumen ejecutivo.

    Solo lo que un lector no técnico necesita para situar qué activo está
    en juego y qué implica: se prioriza `impact` (prosa ya producida por el
    triaje, Paso 5) y solo se cae a `evidence` (más técnica) si el hallazgo
    todavía no fue triado — nunca se manda `remediation` aquí: es una
    instrucción para el equipo técnico, no aporta al resumen ejecutivo.
    """
    hostname = finding.asset.hostname if finding.asset is not None else None
    return {
        "hostname": hostname,
        "type": finding.finding_type,
        "description": finding.impact or finding.evidence,
    }


def build_summary_context(
    *,
    domain: str,
    risk_score: int,
    critical_findings: list[Finding],
    high_findings: list[Finding],
) -> dict[str, object]:
    """Contexto estructurado para el resumen ejecutivo.

    Requiere que `finding.asset` esté precargado en cada `Finding` (igual
    que exige `ai/triage.py::triage_findings`) para poder incluir el
    hostname sin hacer IO de base de datos en este módulo.
    """
    return {
        "domain": domain,
        "risk_score": risk_score,
        "critical_count": len(critical_findings),
        "high_count": len(high_findings),
        "critical_findings": [_finding_brief(f) for f in critical_findings],
        "high_findings": [_finding_brief(f) for f in high_findings],
    }


async def write_executive_summary(
    provider: LLMProvider,
    *,
    domain: str,
    risk_score: int,
    critical_findings: list[Finding],
    high_findings: list[Finding],
) -> str:
    """Redacta 2-3 párrafos de resumen ejecutivo para el informe.

    Propaga `AIProviderError` (petición puntual, ver docstring del módulo).
    """
    context = build_summary_context(
        domain=domain,
        risk_score=risk_score,
        critical_findings=critical_findings,
        high_findings=high_findings,
    )
    prompt = (
        "Redacta el resumen ejecutivo con estos datos del escaneo (JSON):\n\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )
    logger.info("Resumen ejecutivo del informe de %s (risk_score=%s)", domain, risk_score)

    text = await provider.complete(prompt, system=_SYSTEM_PROMPT)
    if not text.strip():
        raise AIProviderError("el modelo devolvió un resumen ejecutivo vacío")
    return text
