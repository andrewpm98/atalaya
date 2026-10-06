"""Reutilización del triaje entre escaneos: misma entrada, misma respuesta.

Un dominio re-escaneado repite casi todo lo que ya tenía: en los dos
escaneos reales de github.com de la demo, 57 de los 211 hallazgos del segundo
generan exactamente el mismo prompt que uno del primero (mismo host, IPs,
estado, fuentes, puertos y evidencia). Pagar otra llamada al modelo para
recibir la respuesta a una pregunta ya contestada no aporta nada.

Lo que **no** se hace aquí, a propósito:

- **Deduplicar dentro de un mismo escaneo.** No hay nada que deduplicar: el
  contexto incluye el activo y cada técnica emite como mucho un hallazgo por
  tipo y host, así que dentro de un escaneo no se repite ningún prompt
  (medido: 204/204 y 211/211 únicos).
- **Agrupar por tipo y evidencia** quitando el activo del prompt. Ahorraría
  mucho más (211 → 11 llamadas), pero el modelo perdería el contexto del host,
  que sí cambia la severidad, y cambiaría todos los prompts.

La clave es el contexto completo que `ai/triage.py::build_finding_context`
construye para el modelo, serializado de forma canónica. El resto del prompt
(prefijo, prompt de sistema, herramienta) es constante, así que mismo
contexto significa mismo prompt: se reutiliza solo lo que el modelo ya
respondió a esa misma entrada exacta, nunca a una "parecida". Vive fuera de
`ai/triage.py` (sin tocar desde el Paso 5) porque no cambia cómo se tría un
hallazgo, solo cuántas veces hace falta preguntarlo.
"""

from __future__ import annotations

import json

from atalaya.ai.triage import build_finding_context
from atalaya.core.models import Finding


def _context_key(finding: Finding) -> str:
    """Huella del contexto que vería el modelo para este hallazgo."""
    context = build_finding_context(finding.asset, finding)
    return json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def reuse_previous_triage(
    pending: list[Finding], triaged: list[Finding]
) -> tuple[list[Finding], int]:
    """Copia a cada hallazgo de `pending` el triaje de uno de `triaged` con el
    mismo contexto exacto.

    `triaged` debe venir del más reciente al más antiguo (como lo da
    `core/repository.py::list_triaged_findings`): ante varios triajes del
    mismo contexto, gana el primero. Requiere `finding.asset` cargado en
    todos.

    Returns:
        Los hallazgos que siguen pendientes (sin equivalente ya triado) y
        cuántos se resolvieron reutilizando.
    """
    previous: dict[str, Finding] = {}
    for finding in triaged:
        previous.setdefault(_context_key(finding), finding)

    still_pending: list[Finding] = []
    reused = 0
    for finding in pending:
        source = previous.get(_context_key(finding))
        if source is None:
            still_pending.append(finding)
            continue
        finding.severity = source.severity
        finding.impact = source.impact
        finding.remediation = source.remediation
        reused += 1
    return still_pending, reused
