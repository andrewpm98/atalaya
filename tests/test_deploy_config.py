"""Pruebas estáticas de la configuración de despliegue (Docker y `.env.example`).

No levantan contenedores ni hacen red: leen los ficheros como texto. Existen
porque cada defecto que cubren se encontró en ejecución y ninguna otra prueba
de la suite lo habría detectado:

- la imagen de la API no copiaba `migrations/` ni aplicaba las migraciones:
  PostgreSQL arrancaba sin tablas y `POST /scans` devolvía 500;
- el `DATABASE_URL` de un `.env` de desarrollo (SQLite) llegaba al contenedor
  y la API ignoraba el Postgres del compose sin avisar;
- la imagen del dashboard no copiaba `.streamlit/`, así que las tablas salían
  sin el tema;
- los puertos se publicaban en todas las interfaces: una BD con credenciales
  fijas y una API sin autenticación, accesibles desde la red local.

Se comprueba texto, no YAML parseado, para no depender de una librería que no
es dependencia declarada del proyecto.
"""

from __future__ import annotations

import re
from pathlib import Path

from atalaya.config import Settings

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _compose_service(name: str) -> str:
    """Bloque de texto de un servicio de `docker-compose.yml`."""
    compose = _read("docker-compose.yml")
    match = re.search(rf"^  {name}:\n(.*?)(?=^  \S|^\S|\Z)", compose, re.MULTILINE | re.DOTALL)
    assert match, f"servicio {name!r} no encontrado en docker-compose.yml"
    return match.group(1)


def _published_ports(compose: str) -> list[str]:
    ports: list[str] = []
    in_ports = False
    for line in compose.splitlines():
        stripped = line.strip()
        if stripped == "ports:":
            in_ports = True
            continue
        if in_ports and stripped.startswith("- "):
            ports.append(stripped[2:].strip().strip('"'))
        elif in_ports and stripped:
            in_ports = False
    return ports


# --- Imagen de la API --------------------------------------------------------


def test_imagen_api_incluye_migraciones_y_las_aplica_antes_de_arrancar() -> None:
    dockerfile = _read("docker/Dockerfile.api")

    assert re.search(r"^COPY alembic\.ini ", dockerfile, re.MULTILINE)
    assert re.search(r"^COPY migrations ", dockerfile, re.MULTILINE)
    cmd = next(line for line in dockerfile.splitlines() if line.startswith("CMD"))
    # Migrar primero y solo arrancar si ha ido bien; `exec` para que uvicorn
    # sea PID 1 y reciba el SIGTERM de `docker stop`.
    assert "alembic upgrade head && exec uvicorn" in cmd


# --- Imagen del dashboard ----------------------------------------------------


def test_imagen_dashboard_incluye_el_tema() -> None:
    dockerfile = _read("docker/Dockerfile.dashboard")

    assert re.search(r"^COPY \.streamlit ", dockerfile, re.MULTILINE)
    assert (ROOT / ".streamlit" / "config.toml").is_file()


# --- docker-compose.yml ------------------------------------------------------


def test_api_usa_siempre_el_postgres_del_compose() -> None:
    api = _compose_service("api")

    match = re.search(r"^\s+DATABASE_URL:\s*(\S+)", api, re.MULTILINE)
    assert match, "la API debe fijar DATABASE_URL en `environment`, no heredarlo de .env"
    assert match.group(1).startswith("postgresql+asyncpg://")
    assert "@db:5432/" in match.group(1)


def test_env_file_es_opcional() -> None:
    """Sin `.env` el stack debe arrancar (solo la IA queda sin clave)."""
    api = _compose_service("api")

    assert re.search(r"path:\s*\.env\s*\n\s*required:\s*false", api)


def test_dashboard_no_recibe_secretos() -> None:
    """El dashboard es un cliente HTTP puro: no necesita ninguna clave."""
    code = [
        line for line in _compose_service("dashboard").splitlines()
        if not line.strip().startswith("#")
    ]
    assert not any("env_file" in line for line in code)


def test_puertos_publicados_solo_en_localhost() -> None:
    ports = _published_ports(_read("docker-compose.yml"))

    assert ports, "no se encontró ningún puerto publicado"
    expuestos = [port for port in ports if not port.startswith("127.0.0.1:")]
    assert expuestos == []


def test_dockerignore_excluye_secretos_y_entornos_locales() -> None:
    entries = {line.strip() for line in _read(".dockerignore").splitlines()}

    assert ".env" in entries
    assert ".venv/" in entries


# --- .env.example ------------------------------------------------------------


def test_env_example_coincide_con_config() -> None:
    """Contrato de configuración: cada campo de `Settings` tiene su línea en
    `.env.example` y viceversa (regla de la sección "Documentación" de CLAUDE.md)."""
    declared = {
        match.group(1).lower()
        for match in re.finditer(r"^([A-Z][A-Z0-9_]*)=", _read(".env.example"), re.MULTILINE)
    }

    assert declared == set(Settings.model_fields)
