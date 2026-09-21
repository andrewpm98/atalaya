"""Pruebas del módulo de enumeración de subdominios vía Shodan.

Mismo criterio de determinismo que `test_subdomains.py`: ninguna prueba
depende de la API real de Shodan. `httpx.MockTransport` sustituye al
transporte HTTP; `_sin_claves_reales` (autouse, `conftest.py`) garantiza que
`settings.shodan_api_key` está vacía salvo que una prueba la fije
explícitamente, sin importar qué haya en el `.env` de quien ejecute la
suite.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from atalaya.config import settings
from atalaya.discovery.shodan import fetch_shodan_subdomains, parse_shodan_payload

DOMAIN = "ejemplo.com"

#: Referencia al sleep original, para poder anularlo sin recursión.
_SLEEP_REAL = asyncio.sleep


def _sin_esperas(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anula el backoff entre reintentos para que las pruebas sean rápidas."""

    async def _noop(_seconds: float) -> None:
        await _SLEEP_REAL(0)

    monkeypatch.setattr("atalaya.discovery.shodan.asyncio.sleep", _noop)


def _con_clave(monkeypatch: pytest.MonkeyPatch, valor: str = "clave-de-prueba") -> None:
    monkeypatch.setattr(settings, "shodan_api_key", valor)


def _client_con_respuesta(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ─── Parseo de la respuesta de Shodan ─────────────────────────────────────


def test_parse_shodan_compone_hostnames_desde_las_etiquetas() -> None:
    payload = {"subdomains": ["www", "api", ""]}
    assert parse_shodan_payload(payload, DOMAIN) == {
        "www.ejemplo.com",
        "api.ejemplo.com",
        "ejemplo.com",  # etiqueta vacía = dominio raíz
    }


def test_parse_shodan_normaliza_mayusculas_y_punto_final() -> None:
    payload = {"subdomains": ["WWW.", " api "]}
    assert parse_shodan_payload(payload, DOMAIN) == {"www.ejemplo.com", "api.ejemplo.com"}


def test_parse_shodan_ignora_entradas_malformadas() -> None:
    payload = {"subdomains": ["www", None, 123, "correo@raro"]}
    assert parse_shodan_payload(payload, DOMAIN) == {"www.ejemplo.com"}


def test_parse_shodan_sin_campo_subdomains_no_falla() -> None:
    assert parse_shodan_payload({}, DOMAIN) == set()


# ─── Cliente HTTP contra la API de Shodan ─────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_shodan_sin_clave_no_toca_la_red(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fuente opcional: sin `SHODAN_API_KEY`, se omite sin ninguna petición HTTP."""
    monkeypatch.setattr(settings, "shodan_api_key", "")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no debería llamarse a la red sin API key configurada")

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == set()
    assert errores == []


@pytest.mark.asyncio
async def test_fetch_shodan_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _con_clave(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "clave-de-prueba"
        return httpx.Response(200, content=json.dumps({"subdomains": ["www", "api"]}))

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == {"www.ejemplo.com", "api.ejemplo.com"}
    assert errores == []


@pytest.mark.asyncio
async def test_fetch_shodan_404_no_es_un_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shodan sin datos indexados para el dominio no es un fallo: solo aporta 0 hosts."""
    _con_clave(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == set()
    assert errores == []


@pytest.mark.asyncio
async def test_fetch_shodan_401_no_reintenta(monkeypatch: pytest.MonkeyPatch) -> None:
    """Una clave rechazada no se arregla reintentando: un único intento."""
    _con_clave(monkeypatch, "clave-invalida")
    intentos = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        intentos["n"] += 1
        return httpx.Response(401)

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == set()
    assert len(errores) == 1
    assert "401" in errores[0]
    assert intentos["n"] == 1


@pytest.mark.asyncio
async def test_fetch_shodan_403_no_reintenta_y_reporta_el_motivo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un 403 (p. ej. plan gratuito sin acceso a /dns/domain) tampoco se
    arregla reintentando, y el mensaje de Shodan se conserva en la incidencia
    -- verificado contra la API real: una clave del plan `oss` devuelve
    exactamente esta forma de respuesta."""
    _con_clave(monkeypatch)
    intentos = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        intentos["n"] += 1
        return httpx.Response(
            403, content=json.dumps({"error": "Requires membership or higher to access"})
        )

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == set()
    assert len(errores) == 1
    assert "403" in errores[0]
    assert "Requires membership or higher to access" in errores[0]
    assert intentos["n"] == 1


@pytest.mark.asyncio
async def test_fetch_shodan_degrada_ante_error_transitorio(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un 5xx sí se reintenta con backoff antes de degradar."""
    _con_clave(monkeypatch)
    _sin_esperas(monkeypatch)
    intentos = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        intentos["n"] += 1
        return httpx.Response(503)

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == set()
    assert len(errores) == 1
    assert intentos["n"] == settings.shodan_retries


@pytest.mark.asyncio
async def test_fetch_shodan_json_invalido(monkeypatch: pytest.MonkeyPatch) -> None:
    _con_clave(monkeypatch)
    _sin_esperas(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content="no soy json")

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_shodan_subdomains(DOMAIN, client=client)

    assert hostnames == set()
    assert errores
