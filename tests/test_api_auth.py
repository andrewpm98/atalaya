"""Pruebas de la autenticación por `X-API-Key` (`api/security.py`).

Tres configuraciones: sin clave configurada (la API se comporta como antes de
existir la autenticación — es la de la demo), clave correcta y clave
incorrecta o ausente. Más una guarda estructural: toda ruta de la API salvo
`/health` debe exigir la clave, para que un endpoint nuevo no nazca abierto
por olvidar la dependencia.
"""

from __future__ import annotations

import re
import secrets

import pytest
from fastapi.testclient import TestClient

from atalaya.api import security
from atalaya.api.main import app
from atalaya.config import settings

CLAVE = "clave-de-prueba-9f2c"

#: Rutas que se pueden pedir sin efectos (sin red ni IA) contra la BD vacía.
_LECTURAS = ["/scans", "/assets", "/findings", "/"]

#: Generadas por FastAPI: describen la API, no devuelven datos. Se dejan
#: abiertas a propósito (ver `api/main.py`); si se quisieran cerrar, esta
#: lista es la que cambia.
_PUBLICAS = {"/health", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}


@pytest.fixture
def con_clave(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_key", CLAVE)


# --- Sin clave configurada ---------------------------------------------------


@pytest.mark.parametrize("path", _LECTURAS)
def test_sin_clave_configurada_no_se_exige_cabecera(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 200


def test_sin_clave_configurada_se_ignora_una_cabecera_cualquiera(client: TestClient) -> None:
    """Un cliente que envía la clave (el dashboard con `ATALAYA_API_KEY`) no
    debe romperse contra una API con la autenticación desactivada."""
    assert client.get("/scans", headers={"X-API-Key": "lo-que-sea"}).status_code == 200


# --- Clave correcta ----------------------------------------------------------


@pytest.mark.usefixtures("con_clave")
@pytest.mark.parametrize("path", _LECTURAS)
def test_clave_correcta_da_acceso(client: TestClient, path: str) -> None:
    assert client.get(path, headers={"X-API-Key": CLAVE}).status_code == 200


@pytest.mark.usefixtures("con_clave")
def test_la_comparacion_usa_compare_digest(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Con `==` la comparación se corta en el primer carácter distinto y el
    tiempo de respuesta filtra el prefijo acertado. Se espía la función para
    que un refactor a `==` no pase desapercibido."""
    llamadas: list[tuple[bytes, bytes]] = []
    original = secrets.compare_digest

    def _espia(a: bytes, b: bytes) -> bool:
        llamadas.append((a, b))
        return original(a, b)

    monkeypatch.setattr(security.secrets, "compare_digest", _espia)
    assert client.get("/scans", headers={"X-API-Key": CLAVE}).status_code == 200
    assert llamadas == [(CLAVE.encode(), CLAVE.encode())]


# --- Clave incorrecta o ausente ----------------------------------------------


@pytest.mark.usefixtures("con_clave")
@pytest.mark.parametrize(
    "headers",
    [
        {"X-API-Key": "clave-incorrecta"},
        {"X-API-Key": CLAVE[:-1]},  # prefijo de la buena
        {"X-API-Key": CLAVE + "x"},  # la buena más un carácter
        {"X-API-Key": ""},
        {},
    ],
    ids=["otra", "prefijo", "sufijo", "vacia", "ausente"],
)
def test_clave_incorrecta_o_ausente_da_401(client: TestClient, headers: dict[str, str]) -> None:
    resp = client.get("/scans", headers=headers)

    assert resp.status_code == 401
    assert "X-API-Key" in resp.json()["detail"]
    assert resp.headers["www-authenticate"] == "X-API-Key"


@pytest.mark.usefixtures("con_clave")
def test_clave_no_ascii_da_401_no_500(client: TestClient) -> None:
    """`compare_digest` lanza `TypeError` con `str` no ASCII: sin comparar en
    bytes, cualquiera podría provocar un 500 con una cabecera latin-1."""
    resp = client.get("/scans", headers={"X-API-Key": "clav\xe9".encode("latin-1")})
    assert resp.status_code == 401


def test_clave_configurada_no_ascii_funciona(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "api_key", "ñandú")
    assert client.get("/scans", headers={"X-API-Key": "otra"}).status_code == 401


@pytest.mark.usefixtures("con_clave")
def test_health_sigue_abierto_con_clave_configurada(client: TestClient) -> None:
    """El healthcheck de Docker y la sonda del dashboard no llevan clave."""
    assert client.get("/health").status_code == 200


@pytest.mark.usefixtures("con_clave")
def test_una_peticion_rechazada_no_llega_a_ejecutar_la_ruta(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El 401 se decide antes de la ruta: sin clave, `POST /scans` no debe
    llegar a enumerar (red) ni `POST /findings/ask` a llamar al proveedor."""
    from atalaya.api.routes import scans as scans_routes

    def _no_debe_llamarse(*args: object, **kwargs: object) -> None:
        raise AssertionError("la ruta se ejecutó sin autenticación")

    monkeypatch.setattr(scans_routes, "enumerate_subdomains", _no_debe_llamarse)
    resp = client.post("/scans", json={"domain": "scanme.nmap.org"})
    assert resp.status_code == 401


# --- Guarda estructural ------------------------------------------------------


def _rutas_de_la_api() -> list[tuple[str, str]]:
    """(método, ruta) de cada operación de la API, sacadas del esquema OpenAPI.

    No de `app.routes`: desde FastAPI 0.141 los routers incluidos aparecen ahí
    envueltos (`_IncludedRouter`) y sus rutas no se ven — la guarda habría
    comprobado solo `/`. El esquema es API pública y lista todas.
    """
    rutas = []
    for path, operaciones in app.openapi()["paths"].items():
        if path in _PUBLICAS:
            continue
        # Parámetros de ruta con un valor válido: así el 401 no se confunde
        # con un 422 de validación.
        concreta = re.sub(r"\{[^}]+\}", "1", path)
        rutas.extend((method.upper(), concreta) for method in operaciones)
    return rutas


@pytest.mark.usefixtures("con_clave")
@pytest.mark.parametrize(("method", "path"), _rutas_de_la_api())
def test_toda_ruta_salvo_health_exige_la_clave(
    client: TestClient, method: str, path: str
) -> None:
    """Si alguien añade un router sin `dependencies=_auth`, falla aquí."""
    assert client.request(method, path).status_code == 401


def test_la_guarda_estructural_cubre_todas_las_rutas_conocidas() -> None:
    """Que la parametrización de arriba no quede vacía en silencio."""
    rutas = {path for _, path in _rutas_de_la_api()}
    assert {"/scans", "/scans/1", "/scans/1/diff/1", "/scans/1/triage", "/scans/1/report"} <= rutas
    assert {"/assets", "/findings", "/findings/ask", "/"} <= rutas


def test_el_esquema_openapi_declara_la_clave_en_cada_ruta_protegida() -> None:
    """Es lo que hace que `/docs` muestre el candado y el botón «Authorize»."""
    esquema = app.openapi()
    assert esquema["components"]["securitySchemes"]["APIKeyHeader"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
    }
    for path, operaciones in esquema["paths"].items():
        for operacion in operaciones.values():
            protegida = {"APIKeyHeader": []} in operacion.get("security", [])
            assert protegida == (path not in _PUBLICAS), path
