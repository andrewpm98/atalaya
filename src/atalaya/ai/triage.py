"""Triaje por IA: prioriza hallazgos, explica impacto y sugiere remediación.

Es la capa diferencial de Atalaya. Se implementa en el Paso 5.
"""

from __future__ import annotations


async def triage_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Enriquece cada hallazgo con severidad, impacto y remediación."""
    raise NotImplementedError
