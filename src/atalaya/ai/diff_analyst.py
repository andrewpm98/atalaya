"""Agente 5: comparación entre escaneos — qué cambió y si es preocupante.

Petición puntual (un análisis bajo demanda sobre dos escaneos concretos, no
una colección de elementos independientes sobre la que degradar tenga
sentido) → propaga `AIProviderError`, igual criterio que
`ai/query.py::ask()`.

`core/repository.py::ScanDiff` solo trae listas de hostnames (nuevos/
desaparecidos/comunes) — deliberadamente, según su propio docstring: es
"puro cálculo" sin unir con hallazgos, para poder probarse sin sesión de
BD. Este módulo añade el contexto que le falta para ser útil: de los
hostnames nuevos y desaparecidos, cuáles tenían hallazgos `critical`/`high`
en el escaneo correspondiente, usando `current_scan.assets`/
`previous_scan.assets`, ya precargados por quien llama (vía
`repository.get_scan()`).
"""

from __future__ import annotations

import json
import logging

from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import FindingSeverity, Scan
from atalaya.core.repository import ScanDiff

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Eres un analista de seguridad de Attack Surface Management (ASM) "
    "comparando dos escaneos sucesivos del mismo dominio. Se te da qué "
    "hostnames son nuevos, cuáles desaparecieron y cuáles se mantienen, "
    "junto con los hallazgos `critical`/`high` que tenían los hostnames "
    "nuevos o desaparecidos. Escribe un análisis breve en prosa, en "
    "español, valorando:\n"
    "- Si los cambios son preocupantes (p. ej. aparece un activo nuevo con "
    "un hallazgo grave, o desaparece uno que lo tenía).\n"
    "- Si hay un patrón de expansión de la superficie de exposición.\n"
    "- Si algo desaparecido podría 'volver' — recuerda que la variabilidad "
    "de DNS (timeouts, balanceo, caché) no siempre significa un cambio "
    "real; no lo presentes como un hecho consumado si la evidencia no lo "
    "sostiene.\n"
    "No confirmes ni describas cómo explotar ningún hallazgo: describe lo "
    "que cambió, no verifiques explotabilidad."
)


def _priority_findings_by_hostname(scan: Scan, hostnames: set[str]) -> dict[str, list[str]]:
    """De los activos de `scan` cuyo hostname está en `hostnames`, sus tipos
    de hallazgo `critical`/`high`.

    Se construye aquí y no en `core/repository.py`: `ScanDiff` es "puro
    cálculo" sobre hostnames por diseño; cruzarlo con severidad de
    hallazgos es una necesidad específica de este agente, no del
    repositorio genérico que usan también la API y el dashboard.
    """
    result: dict[str, list[str]] = {}
    for asset in scan.assets:
        if asset.hostname not in hostnames:
            continue
        types = [
            finding.finding_type
            for finding in asset.findings
            if finding.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
        if types:
            result[asset.hostname] = types
    return result


def build_diff_context(
    *,
    domain: str,
    diff: ScanDiff,
    previous_scan: Scan,
    current_scan: Scan,
) -> dict[str, object]:
    """Contexto estructurado de la comparación entre dos escaneos."""
    nuevos = set(diff.nuevos)
    desaparecidos = set(diff.desaparecidos)
    return {
        "domain": domain,
        "previous_scan_id": previous_scan.id,
        "current_scan_id": current_scan.id,
        "nuevos": diff.nuevos,
        "desaparecidos": diff.desaparecidos,
        "comunes_count": len(diff.comunes),
        "nuevos_con_hallazgos_graves": _priority_findings_by_hostname(current_scan, nuevos),
        "desaparecidos_con_hallazgos_graves": _priority_findings_by_hostname(
            previous_scan, desaparecidos
        ),
    }


async def analyze_diff(
    provider: LLMProvider,
    *,
    domain: str,
    diff: ScanDiff,
    previous_scan: Scan,
    current_scan: Scan,
) -> str:
    """Analiza en prosa libre qué cambió entre `previous_scan` y `current_scan`.

    Propaga `AIProviderError` (petición puntual, ver docstring del módulo).
    """
    context = build_diff_context(
        domain=domain, diff=diff, previous_scan=previous_scan, current_scan=current_scan
    )
    prompt = (
        "Analiza esta comparación entre dos escaneos (JSON):\n\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )
    logger.info(
        "Análisis de diff para %s (escaneos #%s -> #%s)",
        domain,
        previous_scan.id,
        current_scan.id,
    )

    text = await provider.complete(prompt, system=_SYSTEM_PROMPT)
    if not text.strip():
        raise AIProviderError("el modelo devolvió un análisis de diff vacío")
    return text
