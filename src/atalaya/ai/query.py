"""Consulta en lenguaje natural sobre la superficie de exposición escaneada.

**Desviación del stub original:** CLAUDE.md anticipaba solo `provider.py` y
`triage.py` para la capa IA. Esta consulta necesita un contexto distinto al
del triaje: no un hallazgo aislado, sino el escaneo completo (todos los
activos y hallazgos), para poder responder preguntas agregadas como
"¿qué activos exponen direccionamiento interno?". Mezclar ambos casos en
`triage.py` habría acoplado dos prompts con necesidades de contexto muy
distintas; se separa en su propio módulo por la misma razón que
`core/persistence.py` y `core/repository.py` viven separados.
"""

from __future__ import annotations

import json
import logging

from atalaya.ai.provider import LLMProvider
from atalaya.core.models import Scan

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Eres un asistente de Attack Surface Management (ASM). Respondes "
    "preguntas sobre la superficie de exposición de un dominio basándote "
    "EXCLUSIVAMENTE en los datos de escaneo que se te proporcionan a "
    "continuación, en JSON. Si la pregunta no se puede responder con esos "
    "datos, dilo explícitamente en vez de inventar una respuesta. No "
    "confirmes ni describas cómo explotar ningún hallazgo: describe lo que "
    "el escaneo observó, no evalúes explotabilidad."
)


def build_scan_context(scan: Scan) -> dict[str, object]:
    """Construye el contexto estructurado de un escaneo completo.

    Igual que `triage.build_finding_context`: selección deliberada de
    campos, no un dump de las filas de BD.
    """
    return {
        "domain": scan.domain,
        "status": scan.status.value,
        "started_at": scan.started_at.isoformat(),
        "assets": [
            {
                "hostname": asset.hostname,
                "status": asset.status,
                "ip_addresses": asset.ip_addresses,
                "is_active": asset.is_active,
                "leaks_internal_addressing": asset.leaks_internal_addressing,
                "open_ports": asset.open_ports,
                "findings": [
                    {
                        "type": finding.finding_type,
                        "evidence": finding.evidence,
                        "severity": finding.severity.value,
                        "impact": finding.impact,
                        "remediation": finding.remediation,
                    }
                    for finding in asset.findings
                ],
            }
            for asset in scan.assets
        ],
    }


async def ask(provider: LLMProvider, scan: Scan, question: str) -> str:
    """Responde `question` sobre `scan` usando el proveedor de IA.

    A diferencia de `triage_finding`, esta función SÍ propaga
    `AIProviderError`: es una operación puntual bajo petición directa del
    usuario, no un elemento de una colección sobre la que degradar con
    gracia tiene sentido. Quien la llama (el endpoint) decide qué código
    HTTP devolver ante el fallo.
    """
    context = build_scan_context(scan)
    prompt = (
        f"Pregunta: {question}\n\n"
        f"Datos del escaneo (JSON):\n{json.dumps(context, ensure_ascii=False, indent=2)}"
    )
    logger.info("Consulta NL sobre el escaneo #%s (%s)", scan.id, scan.domain)
    return await provider.complete(prompt, system=_SYSTEM_PROMPT)
