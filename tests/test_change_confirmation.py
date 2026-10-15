"""Pruebas de `core/change_confirmation.py`: cambios atómicos, referencia y
confirmación, sin base de datos ni red.

Las dos garantías centrales se prueban con los dos escaneos reales de
github.com de la demo (117 y 118 activos, 204 y 211 hallazgos), no solo con
casos fabricados: que la vigilancia entiende por «cambio» lo mismo que el
diff que se pide a mano, y que deshacer los cambios devuelve exactamente la
referencia (de eso depende no absorber nada sin avisar).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from atalaya.core.change_confirmation import (
    Change,
    Snapshot,
    as_scan_diff,
    changes_between,
    confirm,
    reference,
    snapshot,
)
from atalaya.core.models import Scan
from atalaya.core.repository import diff_scans

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import seed_demo_data


@pytest.fixture(scope="module")
def demo() -> list[Scan]:
    """Los escaneos #1 y #2 de github.com, en memoria (sin base de datos)."""
    return seed_demo_data.build_scans(seed_demo_data.load_fixture())


def _host(status: str = "active", ports: list[int] | None = None, **findings: str) -> dict:
    return {"status": status, "ports": ports or [], "findings": dict(findings)}


@pytest.mark.parametrize("orden", ["previo_a_actual", "actual_a_previo"])
def test_entiende_por_cambio_lo_mismo_que_diff_scans(demo: list[Scan], orden: str) -> None:
    """El monitor y `GET /scans/{id}/diff/{other_id}` no pueden discrepar."""
    a, b = demo if orden == "previo_a_actual" else demo[::-1]
    ref, actual = snapshot(a), snapshot(b)

    assert as_scan_diff(changes_between(ref, actual), ref, actual) == diff_scans(a, b)


def _comparable(snap: Snapshot) -> dict[str, tuple[str, list[int], list[str]]]:
    """Lo que cuenta como cambio: estado, puertos y tipos de hallazgo."""
    return {h: (s["status"], s["ports"], sorted(s["findings"])) for h, s in snap.items()}


@pytest.mark.parametrize("orden", ["previo_a_actual", "actual_a_previo"])
def test_deshacer_los_cambios_devuelve_la_referencia(demo: list[Scan], orden: str) -> None:
    """La base pasa al escaneo nuevo y lo pendiente se guarda con su valor
    anterior: si deshacerlo no diera la referencia, algo se absorbería sin
    avisar o se avisaría dos veces.

    La severidad de un hallazgo que sigue ahí no se deshace, y no hace falta:
    no es un cambio (el diff compara por tipo). Con los datos reales se ve:
    entre los dos escaneos, el triaje dio otra severidad al mismo hallazgo en
    dos hosts. La referencia se queda con la más reciente."""
    a, b = demo if orden == "previo_a_actual" else demo[::-1]

    deshecho = reference(snapshot(b), changes_between(snapshot(a), snapshot(b)))

    assert _comparable(deshecho) == _comparable(snapshot(a))
    assert changes_between(deshecho, snapshot(a)) == []


def test_cambios_atomicos_de_un_timeout() -> None:
    """Un host que desaparece es un cambio, no uno por cada puerto suyo; en
    los comunes, cada puerto y cada tipo de hallazgo va por separado."""
    ref: Snapshot = {
        "a.ejemplo.com": _host(ports=[80, 443], hsts_missing="low"),
        "b.ejemplo.com": _host(ports=[22]),
    }
    actual: Snapshot = {
        "a.ejemplo.com": _host(ports=[80], hsts_missing="low", sin_https="unknown"),
        "c.ejemplo.com": _host(ports=[8080]),
    }

    cambios = changes_between(ref, actual)

    assert [c.token() for c in cambios] == [
        ("host", "c.ejemplo.com", None, True),
        ("host", "b.ejemplo.com", None, False),
        ("port", "a.ejemplo.com", 443, False),
        ("finding", "a.ejemplo.com", "sin_https", True),
    ]
    assert cambios[1].before == _host(ports=[22])  # para poder deshacerlo


def test_confirma_lo_repetido_y_descarta_lo_que_no_se_repite() -> None:
    puerto = Change("port", "a.ejemplo.com", 443, True, False)
    hallazgo = Change("finding", "a.ejemplo.com", "sin_https", None, "unknown")
    nuevo = Change("host", "c.ejemplo.com", None, None, _host())

    resultado = confirm([puerto, nuevo], pending=[puerto, hallazgo])

    assert resultado.confirmed == [puerto]
    assert resultado.unconfirmed == [nuevo]
    assert resultado.discarded == 1  # el `sin_https` no se repitió


def test_un_estado_distinto_no_confirma_el_anterior() -> None:
    """Dos observaciones distintas no son una confirmación: `active` → `timeout`
    y luego `active` → `nxdomain` espera a que se repita una de las dos."""
    antes = Change("status", "a.ejemplo.com", None, "active", "timeout")
    ahora = Change("status", "a.ejemplo.com", None, "active", "nxdomain")

    resultado = confirm([ahora], pending=[antes])

    assert resultado.confirmed == []
    assert resultado.unconfirmed == [ahora]
    assert resultado.discarded == 1


def test_un_host_nuevo_se_confirma_aunque_cambien_sus_puertos() -> None:
    """Lo que se confirma es que el subdominio existe, no su detalle."""
    visto = Change("host", "c.ejemplo.com", None, None, _host(ports=[80]))
    ahora = Change("host", "c.ejemplo.com", None, None, _host(ports=[80, 22]))

    assert confirm([ahora], pending=[visto]).confirmed == [ahora]


def test_un_subconjunto_muestra_el_estado_ya_avisado() -> None:
    """Si se confirma un puerto pero el cambio de estado del mismo host aún
    no, el aviso enseña el estado que el receptor conoce, no el nuevo."""
    ref: Snapshot = {"a.ejemplo.com": _host(ports=[80, 443])}
    actual: Snapshot = {"a.ejemplo.com": _host(status="timeout", ports=[80])}
    puerto = Change("port", "a.ejemplo.com", 443, True, False)

    [cambio] = as_scan_diff([puerto], ref, actual).cambiados

    assert (cambio.estado_anterior, cambio.estado_actual) == ("active", "active")
    assert cambio.puertos_desaparecidos == [443]


def test_los_pendientes_se_guardan_en_json_y_se_recuperan_iguales(demo: list[Scan]) -> None:
    cambios = changes_between(snapshot(demo[0]), snapshot(demo[1]))

    guardado = json.loads(json.dumps([c.to_json() for c in cambios]))

    assert [Change.from_json(c) for c in guardado] == cambios
