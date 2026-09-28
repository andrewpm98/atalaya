"""Pruebas del índice de riesgo (`core/scoring.py`).

Además de ejemplos, propiedades comprobadas sobre muchos escaneos aleatorios
(con semilla fija, deterministas): el criterio del índice son sus
propiedades — techo por severidad máxima, suelo por un crítico, rendimientos
decrecientes, monotonía —, no un puñado de valores concretos.
"""

from __future__ import annotations

import itertools
import json
import random
from pathlib import Path

import pytest

from atalaya.core.models import FindingSeverity
from atalaya.core.scoring import _count_by_type, _volume, compute_risk_score, risk_band

ROOT = Path(__file__).resolve().parents[1]
_TYPES = ["csp_missing", "hsts_missing", "tls_expired", "takeover", "puerto_expuesto"]
_SEVERITIES = list(FindingSeverity)
_BAND = {
    FindingSeverity.LOW: (1, 24),
    FindingSeverity.MEDIUM: (25, 49),
    FindingSeverity.HIGH: (50, 74),
    FindingSeverity.CRITICAL: (75, 100),
}
_ORDER = [
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
]


def _random_scan(rng: random.Random) -> list[tuple[FindingSeverity, str]]:
    return [(rng.choice(_SEVERITIES), rng.choice(_TYPES)) for _ in range(rng.randint(0, 300))]


def _max_severity(findings: list[tuple[FindingSeverity, str]]) -> FindingSeverity | None:
    triados = [sev for sev, _ in findings if sev is not FindingSeverity.UNKNOWN]
    return max(triados, key=_ORDER.index) if triados else None


# ─── Ejemplos ──────────────────────────────────────────────────────────────


def test_sin_hallazgos_triados_es_cero() -> None:
    assert compute_risk_score([]) == 0
    assert compute_risk_score([(FindingSeverity.UNKNOWN, "csp_missing")] * 50) == 0


def test_acepta_severidad_como_texto() -> None:
    assert compute_risk_score([("high", "x")]) == compute_risk_score([(FindingSeverity.HIGH, "x")])


def test_github_com_real_ya_no_sale_critico() -> None:
    """El caso que destapó el defecto: 194 `low` + 9 `medium`, sin nada grave,
    daba 100/100 «crítico» con la suma acotada. Datos reales del fixture de la
    demo, con su triaje real."""
    fixture = json.loads((ROOT / "demo" / "github.com.json").read_text(encoding="utf-8"))
    previo = fixture["scans"][0]
    score = compute_risk_score(
        (f["severity"], f["finding_type"]) for a in previo["assets"] for f in a["findings"]
    )
    assert 25 <= score <= 49
    assert risk_band(score) == "medio"


def test_un_solo_critico_eleva_a_la_banda_critica() -> None:
    assert compute_risk_score([(FindingSeverity.CRITICAL, "takeover")]) >= 75
    # ...aunque haya cientos de hallazgos leves alrededor.
    ruido = [(FindingSeverity.LOW, f"tipo_{i % 7}") for i in range(500)]
    assert compute_risk_score([*ruido, (FindingSeverity.CRITICAL, "takeover")]) >= 75


def test_bandas_con_nombre() -> None:
    assert [risk_band(s) for s in (0, 1, 24, 25, 49, 50, 74, 75, 100)] == [
        "sin riesgo", "bajo", "bajo", "medio", "medio", "alto", "alto", "crítico", "crítico",
    ]  # fmt: skip


# ─── Propiedades ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("seed", range(5))
def test_nunca_supera_la_banda_de_la_severidad_maxima(seed: int) -> None:
    """Ni 10 000 hallazgos leves alcanzan la banda de uno grave."""
    rng = random.Random(seed)
    for _ in range(200):
        findings = _random_scan(rng)
        top = _max_severity(findings)
        score = compute_risk_score(findings)
        if top is None:
            assert score == 0
        else:
            floor, ceiling = _BAND[top]
            assert floor <= score <= ceiling, (top, score)

    muchos_leves = [(FindingSeverity.LOW, f"t{i % 5}") for i in range(10_000)]
    assert compute_risk_score(muchos_leves) <= 24


@pytest.mark.parametrize("seed", range(5))
def test_monotonia_anadir_un_hallazgo_nunca_baja_el_indice(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(200):
        findings = _random_scan(rng)
        antes = compute_risk_score(findings)
        extra = (rng.choice(_SEVERITIES), rng.choice(_TYPES))
        assert compute_risk_score([*findings, extra]) >= antes


@pytest.mark.parametrize("seed", range(5))
def test_monotonia_subir_la_severidad_de_un_hallazgo_nunca_baja_el_indice(seed: int) -> None:
    """Es lo que pasa al triar: un `unknown` pasa a tener severidad."""
    rng = random.Random(seed)
    for _ in range(200):
        findings = _random_scan(rng)
        if not findings:
            continue
        i = rng.randrange(len(findings))
        sev, tipo = findings[i]
        rank = _SEVERITIES.index(sev)
        mas_grave = rng.choice(_SEVERITIES[rank:])  # FindingSeverity va de unknown a critical
        subido = [*findings[:i], (mas_grave, tipo), *findings[i + 1 :]]
        assert compute_risk_score(subido) >= compute_risk_score(findings)


def test_rendimientos_decrecientes_por_repeticion_del_mismo_tipo() -> None:
    """Cada repetición del mismo tipo aporta menos que la anterior, y menos
    que un tipo nuevo de la misma severidad. Se mide sobre el volumen continuo
    (`_volume`): el índice final se redondea a entero y sus incrementos
    alternan 0 y 1, lo que no dice nada de la curva."""
    incrementos = []
    for n in range(1, 60):
        antes = _volume(_count_by_type([(FindingSeverity.MEDIUM, "csp_missing")] * n))
        despues = _volume(_count_by_type([(FindingSeverity.MEDIUM, "csp_missing")] * (n + 1)))
        incrementos.append(despues - antes)
    assert all(a > b > 0 for a, b in itertools.pairwise(incrementos))

    base = [(FindingSeverity.HIGH, "otro")]
    repetidos = base + [(FindingSeverity.MEDIUM, "csp_missing")] * 10
    distintos = base + [(FindingSeverity.MEDIUM, f"tipo_{i}") for i in range(10)]
    assert compute_risk_score(distintos) > compute_risk_score(repetidos)


def test_el_orden_de_los_hallazgos_no_importa() -> None:
    rng = random.Random(7)
    findings = _random_scan(rng)
    barajados = findings[:]
    rng.shuffle(barajados)
    assert compute_risk_score(barajados) == compute_risk_score(findings)
