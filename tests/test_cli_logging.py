"""Pruebas del log de la CLI (`cli.py::_configure_logging`).

`atalaya subdomains -v` pone el log raíz en INFO, y `httpx` registra a ese
nivel la URL completa de cada petición. Shodan solo acepta la clave en la
URL (`?key=...`), así que sin silenciar `httpx` el modo detallado la imprimía
en claro en la terminal.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import httpx
import pytest

from atalaya.cli import _configure_logging

_CLAVE = "CLAVE-SHODAN-DE-PRUEBA"


@pytest.fixture
def _niveles_intactos() -> Iterator[None]:
    """`_configure_logging` toca loggers globales: se restauran al acabar."""
    nombres = ("httpx", "httpcore")
    previos = {n: logging.getLogger(n).level for n in nombres}
    yield
    for nombre, nivel in previos.items():
        logging.getLogger(nombre).setLevel(nivel)


@pytest.mark.usefixtures("_niveles_intactos")
async def test_el_modo_detallado_no_filtra_claves_de_la_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure_logging(verbose=True)
    transporte = httpx.MockTransport(lambda request: httpx.Response(403))

    with caplog.at_level(logging.INFO):
        async with httpx.AsyncClient(transport=transporte) as client:
            await client.get("https://api.shodan.io/dns/domain/x.com", params={"key": _CLAVE})

    assert _CLAVE not in caplog.text


@pytest.mark.usefixtures("_niveles_intactos")
def test_los_avisos_de_httpx_siguen_visibles() -> None:
    """Se silencia el detalle por petición, no los problemas."""
    _configure_logging(verbose=True)
    assert logging.getLogger("httpx").isEnabledFor(logging.WARNING)
