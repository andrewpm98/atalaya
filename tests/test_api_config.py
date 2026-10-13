"""Pruebas de `GET /config/status` (`api/routes/config.py`).

Lo que se exige, además del 200: que ningún secreto de la configuración
aparezca en la respuesta, que no salga a la red (la pide el dashboard en cada
carga) y que no cree nada al consultarla. La autenticación la cubre la guarda
estructural de `tests/test_api_auth.py`.

Cada prueba trabaja en un directorio temporal, sin el `.env` de quien ejecuta
la suite, y fija explícitamente la configuración que importa.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from atalaya.config import settings

_SECRETOS = {
    "anthropic_api_key": "sk-ant-api03-SECRETO-ANTHROPIC-a1b2",
    "gemini_api_key": "AIza-SECRETO-GEMINI",
    "shodan_api_key": "SECRETO-SHODAN-9f3c",
}
_CLAVE_API = "SECRETO-API-KEY"


@pytest.fixture
def proyecto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(settings, "scan_allowlist", "ejemplo.com")
    monkeypatch.setattr(settings, "ai_provider", "anthropic")
    monkeypatch.setattr(
        settings, "database_url", f"sqlite+aiosqlite:///{(tmp_path / 'db.sqlite3').as_posix()}"
    )
    return tmp_path


def _por_clave(resp: httpx.Response) -> dict[str, dict[str, object]]:
    return {check["key"]: check for check in resp.json()["checks"]}


def test_devuelve_las_comprobaciones_locales_en_orden(
    client: TestClient, proyecto: Path
) -> None:
    resp = client.get("/config/status")

    assert resp.status_code == 200
    claves = [check["key"] for check in resp.json()["checks"]]
    # Las de `doctor` sin crt.sh, que sale a la red.
    assert claves == ["config", "scope", "database", "ai", "shodan", "api", "secrets"]


def test_ningun_secreto_aparece_en_la_respuesta(
    client: TestClient, proyecto: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for campo, valor in _SECRETOS.items():
        monkeypatch.setattr(settings, campo, valor)
    monkeypatch.setattr(settings, "api_key", _CLAVE_API)
    monkeypatch.setattr(
        settings, "database_url", "postgresql+asyncpg://atalaya:SECRETO-PG@127.0.0.1:1/atalaya"
    )

    resp = client.get("/config/status", headers={"X-API-Key": _CLAVE_API})

    assert resp.status_code == 200
    for secreto in [*_SECRETOS.values(), _CLAVE_API, "SECRETO-PG"]:
        assert secreto not in resp.text
    checks = _por_clave(resp)
    assert checks["database"]["status"] == "err"
    assert "no conecta con 127.0.0.1:1" in str(checks["database"]["detail"])
    assert checks["api"]["status"] == "ok"
    assert resp.json()["errors"] == 1


def test_no_valida_claves_ni_sale_a_la_red(
    client: TestClient, proyecto: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Con claves configuradas, `doctor` las validaría contra cada proveedor.
    Aquí no: cualquier conexión real hace fallar la prueba."""

    async def _sin_red(*args: object, **kwargs: object) -> httpx.Response:
        raise AssertionError("GET /config/status salió a la red")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _sin_red)
    for campo, valor in _SECRETOS.items():
        monkeypatch.setattr(settings, campo, valor)

    resp = client.get("/config/status")

    assert resp.status_code == 200
    checks = _por_clave(resp)
    assert checks["ai"] == {
        "key": "ai",
        "name": "IA",
        "status": "info",
        "detail": "Anthropic · clave configurada, sin validar",
        "hint": None,
        "elapsed_ms": None,
    }
    assert checks["shodan"]["status"] == "info"


def test_consultarla_no_crea_la_base_de_datos(client: TestClient, proyecto: Path) -> None:
    """Un GET no tiene efectos: un SQLite que aún no existe se queda sin crear."""
    resp = client.get("/config/status")

    assert _por_clave(resp)["database"]["status"] == "warn"
    assert not (proyecto / "db.sqlite3").exists()


def test_sin_clave_de_ia_ni_alcance_cuenta_los_avisos(
    client: TestClient, proyecto: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "scan_allowlist", "")

    resp = client.get("/config/status")

    checks = _por_clave(resp)
    assert checks["scope"]["status"] == "warn"
    assert checks["ai"]["status"] == "warn"
    assert checks["shodan"]["status"] == "off"
    assert checks["api"]["status"] == "warn"
    avisos = sum(check["status"] == "warn" for check in resp.json()["checks"])
    assert resp.json()["warnings"] == avisos
    assert resp.json()["errors"] == 0


def test_en_docker_la_configuracion_llega_por_variables_de_entorno(
    client: TestClient, proyecto: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El compose pasa el `.env` como variables y el fichero no existe en el
    contenedor: decir «sin .env, ejecuta atalaya init» sería falso."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://atalaya:atalaya@db:5432/atalaya")
    monkeypatch.setenv("SCAN_ALLOWLIST", "ejemplo.com")

    resp = client.get("/config/status")

    config = _por_clave(resp)["config"]
    assert config["status"] == "ok"
    assert "variables de entorno" in str(config["detail"])
