"""Comprobaciones de la puesta en marcha: qué está configurado y si funciona.

Las usan `atalaya doctor` (todas), `atalaya init` (para validar cada paso al
momento) y, más adelante, `GET /config/status` (solo las que no salen a la
red). Por eso devuelven `CheckResult` —datos, no texto pintado— y reciben los
valores explícitamente en vez de leer `settings`: así `doctor` puede seguir
diagnosticando aunque el `.env` tenga un valor que impide cargar la
configuración.

**Ninguna comprobación devuelve un secreto.** El detalle dice «clave válida»,
nunca la clave; las URL de base de datos salen sin contraseña (`mask_url`).
Hay un test que lo exige sobre la salida completa de `doctor`.

**Validación sin coste.** Las claves se comprueban con llamadas gratuitas: la
lista de modelos (Anthropic, Gemini) y `/api-info` (Shodan). Ninguna consume
crédito, y por lo mismo **ninguna comprueba el saldo**: una clave válida sin
crédito pasa. Se dice así en vez de prometer lo que no se comprobó.
"""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from pydantic import BaseModel

if TYPE_CHECKING:
    from alembic.config import Config

ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"
GEMINI_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"
#: Plan gratuito de Shodan: su API no incluye `/dns/domain` (verificado en real:
#: 403 «Requires membership or higher»).
SHODAN_FREE_PLANS = frozenset({"oss"})
#: Timeout de cada comprobación de red: un diagnóstico no puede tardar lo que
#: un escaneo.
CHECK_TIMEOUT = 8.0


class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    ERROR = "err"
    INFO = "info"
    OFF = "off"


class CheckResult(BaseModel):
    """Resultado de una comprobación. `detail` y `hint` nunca llevan secretos."""

    key: str
    name: str
    status: Status
    detail: str
    hint: str | None = None
    elapsed_ms: int | None = None


# ─── Validación de claves ───────────────────────────────────────────────────


class KeyRejected(Exception):
    """El proveedor rechazó la clave (401/403, o 400 de clave inválida en Google)."""


class CheckUnavailable(Exception):
    """No se pudo comprobar: sin red, timeout o respuesta inesperada."""


async def _get(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, str | int] | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    try:
        return await client.get(url, params=params, headers=headers, timeout=CHECK_TIMEOUT)
    except httpx.HTTPError as exc:
        raise CheckUnavailable(type(exc).__name__) from exc


async def anthropic_models(client: httpx.AsyncClient, api_key: str) -> list[str]:
    """Modelos disponibles para la clave. Llamada gratuita: no usa ningún modelo."""
    response = await _get(
        client,
        ANTHROPIC_MODELS_URL,
        params={"limit": 1000},
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    if response.status_code in (401, 403):
        raise KeyRejected(f"Anthropic rechazó la clave (HTTP {response.status_code})")
    if response.status_code != 200:
        raise CheckUnavailable(f"HTTP {response.status_code}")
    return [item["id"] for item in response.json().get("data", []) if "id" in item]


async def gemini_models(client: httpx.AsyncClient, api_key: str) -> list[str]:
    """Modelos disponibles para la clave de Google AI Studio.

    La clave va en la cabecera `x-goog-api-key`, no en `?key=`: en la URL
    acabaría en cualquier log que registre peticiones (ya pasó con Shodan).
    """
    response = await _get(
        client,
        GEMINI_MODELS_URL,
        params={"pageSize": 1000},
        headers={"x-goog-api-key": api_key},
    )
    if response.status_code in (400, 401, 403):
        raise KeyRejected(f"Google rechazó la clave (HTTP {response.status_code})")
    if response.status_code != 200:
        raise CheckUnavailable(f"HTTP {response.status_code}")
    return [
        item["name"].removeprefix("models/")
        for item in response.json().get("models", [])
        if "name" in item
    ]


async def shodan_plan(client: httpx.AsyncClient, base_url: str, api_key: str) -> str:
    """Plan de la clave de Shodan (`/api-info`, gratuito).

    Shodan solo acepta la clave en la URL; la CLI deja `httpx` en WARNING para
    que no salga en el log (`cli.py::_configure_logging`).
    """
    response = await _get(client, f"{base_url.rstrip('/')}/api-info", params={"key": api_key})
    if response.status_code in (401, 403):
        raise KeyRejected(f"Shodan rechazó la clave (HTTP {response.status_code})")
    if response.status_code != 200:
        raise CheckUnavailable(f"HTTP {response.status_code}")
    return str(response.json().get("plan") or "desconocido")


# ─── Base de datos y migraciones ────────────────────────────────────────────


@dataclass
class DbProbe:
    """Estado de una base de datos, sin modificarla."""

    reachable: bool
    backend: str
    location: str
    version: str = ""
    exists: bool = True
    current_revision: str | None = None
    head_revision: str | None = None
    error: str = ""

    @property
    def up_to_date(self) -> bool:
        return self.head_revision is not None and self.current_revision == self.head_revision


def alembic_config(project_root: Path, database_url: str) -> Config | None:
    """Configuración de Alembic para *database_url*, o `None` sin `alembic.ini`.

    Se crea **sin** fichero de configuración: `migrations/env.py` solo llama a
    `fileConfig()` cuando hay uno, y eso reconfiguraría el logging de la CLI en
    mitad de la pantalla. La URL va en `attributes` (ver `migrations/env.py`)
    porque `init` migra la base de datos elegida antes de que exista el `.env`
    nuevo que la contiene.
    """
    from alembic.config import Config

    ini = project_root / "alembic.ini"
    if not ini.exists():
        return None
    script_location = Config(str(ini)).get_main_option("script_location")
    config = Config()
    config.set_main_option("script_location", script_location or str(project_root / "migrations"))
    config.attributes["database_url"] = database_url
    return config


def _head_revision(project_root: Path, database_url: str) -> str | None:
    from alembic.script import ScriptDirectory

    config = alembic_config(project_root, database_url)
    if config is None:
        return None
    return ScriptDirectory.from_config(config).get_current_head()


def _short_error(exc: BaseException, secret: str | None) -> str:
    message = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    if secret:
        message = message.replace(secret, "••••")
    return message[:140]


async def probe_database(database_url: str, project_root: Path) -> DbProbe:
    """Conecta, lee la versión del motor y la revisión de Alembic. No escribe nada.

    Un SQLite que aún no existe no se abre: conectarse lo crearía, y `init`
    promete no tocar nada hasta confirmar.
    """
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ArgumentError
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    try:
        url = make_url(database_url)
    except ArgumentError:
        return DbProbe(False, "?", "?", error="URL de base de datos no válida")

    head = _head_revision(project_root, database_url)
    backend = url.get_backend_name()
    if backend == "sqlite":
        location = url.database or ":memory:"
        if location != ":memory:" and not Path(location).exists():
            return DbProbe(
                True, "sqlite", location, f"SQLite {sqlite3.sqlite_version}",
                exists=False, head_revision=head,
            )
        connect_args: dict[str, object] = {}
    else:
        location = f"{url.host or 'localhost'}:{url.port or 5432}"
        connect_args = {"timeout": 5}

    engine = create_async_engine(database_url, poolclass=NullPool, connect_args=connect_args)
    try:
        async with asyncio.timeout(CHECK_TIMEOUT):
            async with engine.connect() as conn:
                if backend == "sqlite":
                    raw = (await conn.execute(text("select sqlite_version()"))).scalar()
                    version = f"SQLite {raw}"
                else:
                    raw = (await conn.execute(text("show server_version"))).scalar()
                    version = f"PostgreSQL {str(raw).split()[0]}"
                try:
                    current = (
                        await conn.execute(text("select version_num from alembic_version"))
                    ).scalar()
                except Exception:  # noqa: BLE001 - sin tabla = sin migrar
                    current = None
    except Exception as exc:  # noqa: BLE001 - cualquier fallo es «no conecta»
        return DbProbe(False, backend, location, error=_short_error(exc, url.password))
    finally:
        await engine.dispose()
    return DbProbe(True, backend, location, version, current_revision=current, head_revision=head)


async def apply_migrations(database_url: str, project_root: Path) -> None:
    """`alembic upgrade head` sobre *database_url*, en un hilo aparte.

    En un hilo porque `migrations/env.py` hace `asyncio.run()`, que no se puede
    llamar dentro del bucle de eventos de la CLI.
    """
    from alembic import command

    config = alembic_config(project_root, database_url)
    if config is None:
        raise FileNotFoundError("no se encontró alembic.ini en el directorio actual")
    await asyncio.to_thread(command.upgrade, config, "head")


# ─── Git: que los secretos no lleguen al repositorio ────────────────────────


GitRunner = Callable[[list[str], Path], "subprocess.CompletedProcess[str]"]


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=5, check=False
    )


def check_secrets(project_root: Path, run_git: GitRunner = _run_git) -> CheckResult:
    """`.env` (y sus copias) fuera de git: ni versionados ni sin ignorar."""
    name = "Secretos"
    env_files = [p for p in (project_root / ".env",) if p.exists()]
    env_files += sorted(project_root.glob(".env.bak-*"))
    if not env_files:
        return CheckResult(key="secrets", name=name, status=Status.OK, detail="sin .env que proteger")
    try:
        inside = run_git(["rev-parse", "--is-inside-work-tree"], project_root)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return CheckResult(key="secrets", name=name, status=Status.INFO, detail="git no disponible")
    if inside.returncode != 0:
        return CheckResult(
            key="secrets", name=name, status=Status.OK, detail="no es un repositorio git"
        )
    for path in env_files:
        relative = path.name
        tracked = run_git(["ls-files", "--error-unmatch", relative], project_root)
        if tracked.returncode == 0:
            return CheckResult(
                key="secrets", name=name, status=Status.ERROR,
                detail=f"{relative} está versionado en git",
                hint=f"git rm --cached {relative} y cambia las claves: ya están en el historial.",
            )
        ignored = run_git(["check-ignore", "-q", relative], project_root)
        if ignored.returncode != 0:
            return CheckResult(
                key="secrets", name=name, status=Status.ERROR,
                detail=f"{relative} no está en .gitignore",
                hint=f"Añade {relative} a .gitignore antes del próximo commit.",
            )
    return CheckResult(
        key="secrets", name=name, status=Status.OK, detail=".env ignorado por git"
    )


# ─── Comprobaciones de doctor ───────────────────────────────────────────────


@dataclass
class DoctorInputs:
    """Lo que `doctor` necesita saber, ya leído de la configuración."""

    project_root: Path
    env_exists: bool
    env_keys: list[str]
    known_keys: set[str]
    allowlist_raw: str
    database_url: str
    ai_provider: str
    anthropic_api_key: str
    ai_model: str
    gemini_api_key: str
    gemini_model: str
    ai_replay_file: str
    shodan_api_key: str
    shodan_url: str
    crtsh_url: str
    api_key: str
    offline: bool = False


def check_config(inputs: DoctorInputs) -> CheckResult:
    name = "Configuración"
    if not inputs.env_exists:
        return CheckResult(
            key="config", name=name, status=Status.WARN,
            detail="sin .env: se usan los valores por defecto",
            hint="Ejecuta atalaya init para crearlo paso a paso.",
        )
    unknown = sorted(k for k in inputs.env_keys if k.upper() not in inputs.known_keys)
    if unknown:
        return CheckResult(
            key="config", name=name, status=Status.WARN,
            detail="clave desconocida en .env: " + ", ".join(unknown),
            hint="Atalaya no las usa y las ignora sin avisar: ¿errata o configuración "
            "antigua? Puedes borrarlas.",
        )
    return CheckResult(
        key="config", name=name, status=Status.OK,
        detail=f".env cargado · {len(inputs.env_keys)} campos válidos",
    )


def check_scope(allowlist_raw: str) -> CheckResult:
    from atalaya.core.authorization import normalize_domain
    from atalaya.core.exceptions import InvalidTargetError

    name = "Alcance"
    entries = [e.strip() for e in allowlist_raw.split(",") if e.strip()]
    if not entries:
        return CheckResult(
            key="scope", name=name, status=Status.WARN,
            detail="sin restricción: se puede escanear cualquier dominio",
            hint="Limítalo a los dominios autorizados con atalaya init (SCAN_ALLOWLIST).",
        )
    invalid = []
    for entry in entries:
        try:
            normalize_domain(entry)
        except InvalidTargetError:
            invalid.append(entry)
    if invalid:
        return CheckResult(
            key="scope", name=name, status=Status.ERROR,
            detail="entrada no válida en SCAN_ALLOWLIST: " + ", ".join(invalid),
            hint="Cada entrada debe ser un dominio (ejemplo.com), separadas por comas.",
        )
    noun = "dominio autorizado" if len(entries) == 1 else "dominios autorizados"
    return CheckResult(key="scope", name=name, status=Status.OK, detail=f"{len(entries)} {noun}")


async def check_database(database_url: str, project_root: Path) -> CheckResult:
    name = "Base de datos"
    probe = await probe_database(database_url, project_root)
    if not probe.reachable:
        hint = "Revisa DATABASE_URL."
        if probe.backend == "postgresql" and probe.location.startswith(("localhost", "127.0.0.1")):
            hint = "¿Está levantado PostgreSQL? docker compose up -d db"
        return CheckResult(
            key="database", name=name, status=Status.ERROR,
            detail=f"no conecta con {probe.location}: {probe.error}", hint=hint,
        )
    if not probe.exists:
        return CheckResult(
            key="database", name=name, status=Status.WARN,
            detail=f"{probe.version} · {probe.location} aún no existe",
            hint="Créala con: alembic upgrade head",
        )
    if probe.head_revision is None:
        return CheckResult(
            key="database", name=name, status=Status.INFO,
            detail=f"{probe.version} · migraciones no comprobadas (sin alembic.ini aquí)",
        )
    if probe.current_revision is None:
        return CheckResult(
            key="database", name=name, status=Status.WARN,
            detail=f"{probe.version} · sin migrar", hint="Aplica el esquema: alembic upgrade head",
        )
    if not probe.up_to_date:
        return CheckResult(
            key="database", name=name, status=Status.WARN,
            detail=f"{probe.version} · migraciones pendientes",
            hint="Actualiza el esquema: alembic upgrade head",
        )
    return CheckResult(
        key="database", name=name, status=Status.OK,
        detail=f"{probe.version} · migraciones al día",
    )


async def check_ai(inputs: DoctorInputs, client: httpx.AsyncClient) -> CheckResult:
    name = "IA"
    provider = inputs.ai_provider.lower()
    if provider == "replay":
        replay = inputs.project_root / inputs.ai_replay_file
        if replay.exists():
            return CheckResult(
                key="ai", name=name, status=Status.OK,
                detail="replay · respuestas grabadas (demo sin red)",
            )
        return CheckResult(
            key="ai", name=name, status=Status.ERROR,
            detail=f"replay sin grabaciones: falta {inputs.ai_replay_file}",
        )
    if provider not in ("anthropic", "gemini"):
        return CheckResult(
            key="ai", name=name, status=Status.ERROR,
            detail=f"AI_PROVIDER desconocido: {inputs.ai_provider}",
            hint="Valores válidos: anthropic, gemini o replay.",
        )
    label = "Anthropic" if provider == "anthropic" else "Gemini"
    key = inputs.anthropic_api_key if provider == "anthropic" else inputs.gemini_api_key
    model = inputs.ai_model if provider == "anthropic" else inputs.gemini_model
    if not key:
        return CheckResult(
            key="ai", name=name, status=Status.WARN,
            detail=f"{label} sin clave: triaje, consultas y resúmenes no disponibles",
            hint="Añade la clave con atalaya init.",
        )
    if inputs.offline:
        return CheckResult(
            key="ai", name=name, status=Status.INFO, detail=f"{label} · clave sin comprobar (--offline)"
        )
    fetch = anthropic_models if provider == "anthropic" else gemini_models
    try:
        models = await fetch(client, key)
    except KeyRejected as exc:
        return CheckResult(
            key="ai", name=name, status=Status.ERROR, detail=str(exc),
            hint="Genera una clave nueva y guárdala con atalaya init.",
        )
    except CheckUnavailable as exc:
        return CheckResult(
            key="ai", name=name, status=Status.WARN,
            detail=f"{label} · no se pudo comprobar la clave ({exc})",
        )
    if model not in models:
        return CheckResult(
            key="ai", name=name, status=Status.WARN,
            detail=f"{label} · clave válida, pero el modelo {model} no está disponible",
            hint="Elige un modelo de la lista con atalaya init.",
        )
    return CheckResult(
        key="ai", name=name, status=Status.OK, detail=f"{label} · clave válida · {model}"
    )


async def check_shodan(inputs: DoctorInputs, client: httpx.AsyncClient) -> CheckResult:
    name = "Shodan"
    if not inputs.shodan_api_key:
        return CheckResult(key="shodan", name=name, status=Status.OFF, detail="no configurado (opcional)")
    if inputs.offline:
        return CheckResult(
            key="shodan", name=name, status=Status.INFO, detail="clave sin comprobar (--offline)"
        )
    try:
        plan = await shodan_plan(client, inputs.shodan_url, inputs.shodan_api_key)
    except KeyRejected as exc:
        return CheckResult(key="shodan", name=name, status=Status.ERROR, detail=str(exc))
    except CheckUnavailable as exc:
        return CheckResult(
            key="shodan", name=name, status=Status.WARN, detail=f"no se pudo comprobar ({exc})"
        )
    if plan in SHODAN_FREE_PLANS:
        return CheckResult(
            key="shodan", name=name, status=Status.WARN,
            detail=f"clave válida · el plan {plan} no incluye la búsqueda DNS",
            hint="Opcional: la búsqueda DNS de Shodan exige un plan de pago.",
        )
    return CheckResult(key="shodan", name=name, status=Status.OK, detail=f"clave válida · plan {plan}")


async def check_crtsh(inputs: DoctorInputs, client: httpx.AsyncClient) -> CheckResult:
    name = "crt.sh"
    if inputs.offline:
        return CheckResult(key="crtsh", name=name, status=Status.INFO, detail="sin comprobar (--offline)")
    try:
        response = await _get(client, inputs.crtsh_url)
    except CheckUnavailable as exc:
        return CheckResult(
            key="crtsh", name=name, status=Status.WARN, detail=f"no responde ({exc})",
            hint="El escaneo continúa solo con DNS si crt.sh falla (degradación controlada).",
        )
    if response.status_code >= 500:
        return CheckResult(
            key="crtsh", name=name, status=Status.WARN,
            detail=f"responde con error (HTTP {response.status_code})",
            hint="crt.sh falla a menudo; el escaneo continúa solo con DNS.",
        )
    return CheckResult(key="crtsh", name=name, status=Status.OK, detail="accesible")


def check_api(api_key: str) -> CheckResult:
    if api_key:
        return CheckResult(key="api", name="API", status=Status.OK, detail="protegida con X-API-Key")
    return CheckResult(
        key="api", name="API", status=Status.WARN, detail="sin autenticación",
        hint="Aceptable solo en local (puertos en 127.0.0.1). Genera una clave con atalaya init.",
    )


async def timed(check: Awaitable[CheckResult]) -> CheckResult:
    """Ejecuta una comprobación y anota cuánto tardó."""
    start = time.perf_counter()
    result = await check
    result.elapsed_ms = round((time.perf_counter() - start) * 1000)
    return result


async def run_checks(inputs: DoctorInputs, client: httpx.AsyncClient) -> list[CheckResult]:
    """Todas las comprobaciones de `doctor`, las de red en paralelo."""
    database, ai, shodan, crtsh = await asyncio.gather(
        timed(check_database(inputs.database_url, inputs.project_root)),
        timed(check_ai(inputs, client)),
        timed(check_shodan(inputs, client)),
        timed(check_crtsh(inputs, client)),
    )
    return [
        check_config(inputs),
        check_scope(inputs.allowlist_raw),
        database,
        ai,
        shodan,
        crtsh,
        check_api(inputs.api_key),
        check_secrets(inputs.project_root),
    ]
