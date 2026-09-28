"""Índice de riesgo (0-100) de un escaneo: única fuente de verdad.

Lo usan el informe PDF (`reporting/generator.py`) y la API (`risk_score` de
`GET /scans/{id}`, que es lo que pinta el dashboard). Antes eran dos copias
de la misma fórmula sincronizadas por convención; ahora es una función.

**Por qué no una suma ponderada acotada** (la fórmula anterior,
`min(100, Σ peso·n)`): satura con volumen. github.com — 194 hallazgos `low` y
9 `medium`, ninguno `critical`/`high` — salía «100/100 · riesgo crítico», lo
mismo que un escaneo con diez críticos. El número tiene que responder primero
a *qué tan grave es lo peor que hay* y solo después a *cuánto hay*:

1. **La banda la fija la severidad máxima presente** (`_BANDS`): solo `low`
   → 1-24, `medium` → 25-49, `high` → 50-74, `critical` → 75-100. Ningún
   volumen de hallazgos leves alcanza la banda de uno grave, y un único
   crítico eleva el nivel a crítico aunque esté solo.
2. **Dentro de la banda, el volumen, con rendimientos decrecientes por
   repetición**: cada tipo de hallazgo (`finding_type`) de cada severidad
   aporta `peso · log2(1 + n)`. La misma cabecera ausente en 59 subdominios
   es un patrón (una sola decisión de configuración), no 59 riesgos
   independientes: pesa ~6 veces uno solo, no 59. Tipos distintos sí suman
   enteros.
3. **Saturación suave hacia el techo de la banda**:
   `suelo + (techo - suelo) · (1 - e^(-raw / K))` se acerca al techo sin
   alcanzarlo por volumen.

Monótono por construcción — añadir un hallazgo triado nunca baja el índice:
si no cambia la severidad máxima, `raw` crece; si la sube, el suelo de la
nueva banda supera el techo de la anterior. Lo comprueban
`tests/test_scoring.py` (propiedades, no solo ejemplos).

Los hallazgos `unknown` (sin triar) no puntúan: el índice mide riesgo
confirmado por el triaje, no trabajo pendiente — el dashboard avisa aparte de
cuántos quedan.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable

from atalaya.core.models import FindingSeverity

#: Peso de cada severidad dentro de su banda y en las inferiores. Solo mueve
#: el índice *dentro* de la banda que fija la severidad máxima.
_WEIGHTS: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 25,
    FindingSeverity.HIGH: 10,
    FindingSeverity.MEDIUM: 4,
    FindingSeverity.LOW: 1,
}

#: (suelo, techo) del índice según la severidad máxima presente. Contiguas y
#: sin solape: es lo que hace monótona la subida de banda.
_BANDS: dict[FindingSeverity, tuple[int, int]] = {
    FindingSeverity.LOW: (1, 24),
    FindingSeverity.MEDIUM: (25, 49),
    FindingSeverity.HIGH: (50, 74),
    FindingSeverity.CRITICAL: (75, 100),
}

#: De menor a mayor gravedad, para hallar la severidad máxima.
_RANK = (
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
)

#: Volumen ponderado al que se recorre ~63% de la banda (1 - 1/e). Calibrado
#: con los datos reales de github.com (ver `tests/test_scoring.py`): su
#: volumen de hallazgos leves y medios lo sitúa hacia la mitad de la banda
#: media, no pegado al techo.
_SATURATION = 60.0

#: Etiqueta de la banda en la que cae un índice (límite superior inclusivo).
_BAND_LABELS = ((0, "sin riesgo"), (24, "bajo"), (49, "medio"), (74, "alto"), (100, "crítico"))


def compute_risk_score(findings: Iterable[tuple[FindingSeverity | str, str]]) -> int:
    """Índice 0-100 a partir de pares `(severidad, finding_type)`.

    Acepta la severidad como enum o como su valor en texto: así sirve igual
    para filas ORM, esquemas de la API o el JSON que recibe un cliente.
    """
    by_type = _count_by_type(findings)
    if not by_type:
        return 0

    top = max((sev for sev, _ in by_type), key=_RANK.index)
    floor, ceiling = _BANDS[top]
    return floor + round((ceiling - floor) * (1 - math.exp(-_volume(by_type) / _SATURATION)))


def _count_by_type(
    findings: Iterable[tuple[FindingSeverity | str, str]],
) -> Counter[tuple[FindingSeverity, str]]:
    """Hallazgos triados por `(severidad, finding_type)`; los `unknown` no cuentan."""
    by_type: Counter[tuple[FindingSeverity, str]] = Counter()
    for severity, finding_type in findings:
        sev = FindingSeverity(severity)
        if sev is not FindingSeverity.UNKNOWN:
            by_type[(sev, finding_type)] += 1
    return by_type


def _volume(by_type: Counter[tuple[FindingSeverity, str]]) -> float:
    """Volumen ponderado, antes de redondear: `Σ peso · log2(1 + n)` por tipo."""
    return sum(_WEIGHTS[sev] * math.log2(1 + n) for (sev, _), n in by_type.items())


def risk_band(score: int) -> str:
    """Nombre de la banda de un índice: `sin riesgo`, `bajo`, `medio`, `alto`, `crítico`."""
    for limit, label in _BAND_LABELS:
        if score <= limit:
            return label
    return _BAND_LABELS[-1][1]
