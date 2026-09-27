"""`LOG_LEVEL` se aplica a los loggers de la aplicación bajo la API.

Regresión: uvicorn solo configura `uvicorn.*`, así que los `logger.info` de
`atalaya.*` se descartaban y `LOG_LEVEL` no tenía ningún efecto.
"""

from __future__ import annotations

import logging

import pytest

from atalaya.api.main import _configure_logging


@pytest.fixture
def app_logger():
    logger = logging.getLogger("atalaya")
    previous = logger.level
    yield logger
    logger.setLevel(previous)


@pytest.mark.parametrize(("valor", "esperado"), [("DEBUG", logging.DEBUG), ("warning", logging.WARNING)])
def test_log_level_se_aplica(monkeypatch, app_logger, valor, esperado) -> None:
    monkeypatch.setattr("atalaya.config.settings.log_level", valor)

    _configure_logging()

    assert app_logger.level == esperado
    assert app_logger.handlers, "sin handler propio, los registros no llegan a ninguna salida"


def test_log_level_invalido_no_impide_arrancar(monkeypatch, app_logger) -> None:
    monkeypatch.setattr("atalaya.config.settings.log_level", "VERBOSISIMO")

    _configure_logging()

    assert app_logger.level == logging.INFO


def test_configurar_dos_veces_no_duplica_handlers(app_logger) -> None:
    _configure_logging()
    _configure_logging()

    assert len(app_logger.handlers) == 1
