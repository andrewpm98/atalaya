"""Pruebas de `onboarding/checks.py`: lo que `doctor` e `init` comprueban.

Sin red: los proveedores se sustituyen por `httpx.MockTransport`. La base de
datos es SQLite real en un directorio temporal (y un PostgreSQL inalcanzable
en el puerto 1 de 127.0.0.1, que falla sin salir de la máquina). Git, real,
en un repositorio temporal: es justo lo que se quiere comprobar.
"""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from atalaya.onboarding.checks import (
    CheckUnavailable,
    DoctorInputs,
    KeyRejected,
    Status,
    anthropic_models,
    check_ai,
    check_api,
    check_config,
    check_crtsh,
    check_database,
    check_scope,
    check_secrets,
    check_shodan,
    environ_settings,
    gemini_models,
    probe_database,
    run_local_checks,
    shodan_plan,
)

_RAIZ = Path(__file__).resolve().parents[1]


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _sin_red(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"no debía salir a la red: {request.url}")


def _inputs(**overrides: object) -> DoctorInputs:
    base: dict[str, object] = {
        "project_root": _RAIZ,
        "env_exists": True,
        "env_keys": ["AI_PROVIDER"],
        "known_keys": {"AI_PROVIDER", "API_KEY"},
        "allowlist_raw": "ejemplo.com",
        "database_url": "sqlite+aiosqlite:///:memory:",
        "ai_provider": "anthropic",
        "anthropic_api_key": "sk-ant-prueba",
        "ai_model": "claude-sonnet-4-6",
        "gemini_api_key": "",
        "gemini_model": "gemini-2.5-flash",
        "ai_replay_file": "demo/ai_recordings.json",
        "shodan_api_key": "",
        "shodan_url": "https://api.shodan.io",
        "crtsh_url": "https://crt.sh",
        "api_key": "",
        "offline": False,
    }
    base.update(overrides)
    return DoctorInputs(**base)  # type: ignore[arg-type]


# ─── Claves de los proveedores ──────────────────────────────────────────────


async def test_anthropic_lista_los_modelos_con_las_cabeceras_de_la_api() -> None:
    vistas: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        vistas.append(request)
        return httpx.Response(200, json={"data": [{"id": "claude-sonnet-4-6"}, {"id": "otro"}]})

    async with _client(handler) as client:
        modelos = await anthropic_models(client, "sk-ant-prueba")

    assert modelos == ["claude-sonnet-4-6", "otro"]
    assert vistas[0].headers["x-api-key"] == "sk-ant-prueba"
    assert vistas[0].headers["anthropic-version"] == "2023-06-01"
    assert vistas[0].url.path == "/v1/models"  # listar modelos no consume crédito


@pytest.mark.parametrize(
    ("respuesta", "error"),
    [(httpx.Response(401), KeyRejected), (httpx.Response(500), CheckUnavailable)],
)
async def test_anthropic_distingue_clave_rechazada_de_no_comprobable(
    respuesta: httpx.Response, error: type[Exception]
) -> None:
    async with _client(lambda request: respuesta) as client:
        with pytest.raises(error):
            await anthropic_models(client, "sk-ant-prueba")


async def test_sin_conexion_es_no_comprobable_y_no_clave_rechazada() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sin red", request=request)

    async with _client(handler) as client:
        with pytest.raises(CheckUnavailable):
            await anthropic_models(client, "sk-ant-prueba")


async def test_gemini_envia_la_clave_en_cabecera_nunca_en_la_url() -> None:
    """En la URL acabaría en cualquier log que registre peticiones."""
    vistas: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        vistas.append(request)
        return httpx.Response(200, json={"models": [{"name": "models/gemini-2.5-flash"}]})

    async with _client(handler) as client:
        modelos = await gemini_models(client, "AIza-secreta")

    assert modelos == ["gemini-2.5-flash"]
    assert "AIza-secreta" not in str(vistas[0].url)
    assert vistas[0].headers["x-goog-api-key"] == "AIza-secreta"


async def test_gemini_400_es_clave_rechazada() -> None:
    """Google responde 400 INVALID_ARGUMENT a una clave inválida, no 401."""
    async with _client(lambda request: httpx.Response(400)) as client:
        with pytest.raises(KeyRejected):
            await gemini_models(client, "mala")


async def test_shodan_devuelve_el_plan() -> None:
    async with _client(lambda request: httpx.Response(200, json={"plan": "oss"})) as client:
        assert await shodan_plan(client, "https://api.shodan.io", "k") == "oss"


async def test_check_ai_con_clave_valida_y_modelo_disponible() -> None:
    respuesta = {"data": [{"id": "claude-sonnet-4-6"}]}
    async with _client(lambda request: httpx.Response(200, json=respuesta)) as client:
        resultado = await check_ai(_inputs(), client)
    assert resultado.status is Status.OK
    assert "sk-ant-prueba" not in resultado.detail


async def test_check_ai_avisa_si_el_modelo_configurado_no_existe() -> None:
    respuesta = {"data": [{"id": "claude-opus-5-5"}]}
    async with _client(lambda request: httpx.Response(200, json=respuesta)) as client:
        resultado = await check_ai(_inputs(), client)
    assert resultado.status is Status.WARN
    assert "claude-sonnet-4-6" in resultado.detail


async def test_check_ai_con_clave_rechazada_es_error() -> None:
    async with _client(lambda request: httpx.Response(401)) as client:
        resultado = await check_ai(_inputs(), client)
    assert resultado.status is Status.ERROR


async def test_check_ai_sin_clave_avisa_sin_salir_a_la_red() -> None:
    async with _client(_sin_red) as client:
        resultado = await check_ai(_inputs(anthropic_api_key=""), client)
    assert resultado.status is Status.WARN
    assert "triaje" in resultado.detail


async def test_check_ai_offline_no_sale_a_la_red() -> None:
    async with _client(_sin_red) as client:
        resultado = await check_ai(_inputs(offline=True), client)
    assert resultado.status is Status.INFO


async def test_check_ai_replay_comprueba_las_grabaciones() -> None:
    async with _client(_sin_red) as client:
        con = await check_ai(_inputs(ai_provider="replay"), client)
        sin = await check_ai(_inputs(ai_provider="replay", ai_replay_file="no/existe.json"), client)
    assert con.status is Status.OK
    assert sin.status is Status.ERROR


async def test_check_ai_proveedor_desconocido_es_error() -> None:
    async with _client(_sin_red) as client:
        resultado = await check_ai(_inputs(ai_provider="openai"), client)
    assert resultado.status is Status.ERROR


@pytest.mark.parametrize(
    ("plan", "estado"), [("oss", Status.WARN), ("dev", Status.OK)]
)
async def test_check_shodan_avisa_del_plan_sin_busqueda_dns(plan: str, estado: Status) -> None:
    async with _client(lambda request: httpx.Response(200, json={"plan": plan})) as client:
        resultado = await check_shodan(_inputs(shodan_api_key="k"), client)
    assert resultado.status is estado


async def test_check_shodan_sin_clave_es_opcional() -> None:
    async with _client(_sin_red) as client:
        resultado = await check_shodan(_inputs(), client)
    assert resultado.status is Status.OFF


@pytest.mark.parametrize(("codigo", "estado"), [(200, Status.OK), (502, Status.WARN)])
async def test_check_crtsh(codigo: int, estado: Status) -> None:
    async with _client(lambda request: httpx.Response(codigo)) as client:
        resultado = await check_crtsh(_inputs(), client)
    assert resultado.status is estado


# ─── Configuración, alcance y API ───────────────────────────────────────────


def test_check_config_sin_env_aconseja_init() -> None:
    resultado = check_config(_inputs(env_exists=False))
    assert resultado.status is Status.WARN
    assert "atalaya init" in (resultado.hint or "")


def test_check_config_sin_env_pero_con_variables_de_entorno() -> None:
    """Así llega la configuración a la API en Docker: sin fichero `.env`."""
    resultado = check_config(_inputs(env_exists=False, env_keys=[], environ_keys=["API_KEY"]))
    assert resultado.status is Status.OK
    assert resultado.detail == "sin .env · 1 campo desde variables de entorno"


def test_environ_settings_solo_cuenta_campos_conocidos_sin_distinguir_mayusculas() -> None:
    entorno = {"api_key": "x", "AI_PROVIDER": "gemini", "PATH": "/usr/bin", "API_HOST": "0.0.0.0"}
    assert environ_settings({"AI_PROVIDER", "API_KEY"}, entorno) == ["AI_PROVIDER", "API_KEY"]


def test_check_config_detecta_claves_que_atalaya_no_conoce() -> None:
    """Pydantic las ignora sin avisar: una errata dejaba un campo sin efecto."""
    resultado = check_config(_inputs(env_keys=["AI_PROVIDER", "ANTHROPIC_APIKEY"]))
    assert resultado.status is Status.WARN
    assert "ANTHROPIC_APIKEY" in resultado.detail


def test_check_scope() -> None:
    assert check_scope("").status is Status.WARN
    assert check_scope("ejemplo.com, ejemplo.es").detail == "2 dominios autorizados"
    assert check_scope("ejemplo.com").detail == "1 dominio autorizado"
    invalido = check_scope("ejemplo.com, no es un dominio")
    assert invalido.status is Status.ERROR
    assert "no es un dominio" in invalido.detail


def test_check_api() -> None:
    assert check_api("clave").status is Status.OK
    assert check_api("").status is Status.WARN


# ─── Base de datos ──────────────────────────────────────────────────────────


def _url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


async def test_un_sqlite_que_no_existe_no_se_crea_al_comprobarlo(tmp_path: Path) -> None:
    """`init` promete no tocar nada hasta confirmar: abrirlo lo crearía."""
    fichero = tmp_path / "nueva.sqlite3"

    resultado = await check_database(_url(fichero), _RAIZ)

    assert resultado.status is Status.WARN
    assert "aún no existe" in resultado.detail
    assert not fichero.exists()


async def test_sqlite_sin_migrar(tmp_path: Path) -> None:
    fichero = tmp_path / "vacia.sqlite3"
    sqlite3.connect(fichero).close()

    resultado = await check_database(_url(fichero), _RAIZ)

    assert resultado.status is Status.WARN
    assert "sin migrar" in resultado.detail


async def test_sqlite_con_el_esquema_al_dia(tmp_path: Path) -> None:
    fichero = tmp_path / "al_dia.sqlite3"
    probe = await probe_database(_url(fichero), _RAIZ)
    assert probe.head_revision  # sale de migrations/versions
    with sqlite3.connect(fichero) as conn:
        conn.execute("create table alembic_version (version_num varchar(32) primary key)")
        conn.execute("insert into alembic_version values (?)", (probe.head_revision,))

    resultado = await check_database(_url(fichero), _RAIZ)

    assert resultado.status is Status.OK
    assert "migraciones al día" in resultado.detail


async def test_postgres_inalcanzable_no_muestra_la_contrasena() -> None:
    url = "postgresql+asyncpg://atalaya:s3creta-pg@127.0.0.1:1/atalaya"

    resultado = await check_database(url, _RAIZ)

    assert resultado.status is Status.ERROR
    assert "s3creta-pg" not in resultado.detail + (resultado.hint or "")
    assert "docker compose up -d db" in (resultado.hint or "")


# ─── Secretos en git ────────────────────────────────────────────────────────

requiere_git = pytest.mark.skipif(shutil.which("git") is None, reason="git no instalado")


def _repo(path: Path, gitignore: str) -> Path:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / ".gitignore").write_text(gitignore, encoding="utf-8")
    (path / ".env").write_text("API_KEY=secreta\n", encoding="utf-8")
    return path


@requiere_git
def test_env_ignorado_por_git(tmp_path: Path) -> None:
    assert check_secrets(_repo(tmp_path, ".env\n.env.bak-*\n")).status is Status.OK


@requiere_git
def test_env_sin_ignorar_es_error(tmp_path: Path) -> None:
    resultado = check_secrets(_repo(tmp_path, "*.pyc\n"))
    assert resultado.status is Status.ERROR
    assert ".gitignore" in resultado.detail


@requiere_git
def test_una_copia_del_env_sin_ignorar_tambien_es_error(tmp_path: Path) -> None:
    """Las copias de `init` contienen las mismas claves que el `.env`."""
    repo = _repo(tmp_path, ".env\n")
    (repo / ".env.bak-20261012-113005").write_text("API_KEY=secreta\n", encoding="utf-8")

    resultado = check_secrets(repo)

    assert resultado.status is Status.ERROR
    assert ".env.bak-20261012-113005" in resultado.detail


@requiere_git
def test_env_versionado_es_error_aunque_ahora_este_ignorado(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "")
    subprocess.run(["git", "add", ".env"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")

    resultado = check_secrets(repo)

    assert resultado.status is Status.ERROR
    assert "versionado" in resultado.detail


def test_fuera_de_un_repositorio_no_hay_nada_que_proteger_en_git(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")

    def no_repo(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 128, "", "not a git repository")

    assert check_secrets(tmp_path, run_git=no_repo).status is Status.OK


# ─── Comprobaciones locales (GET /config/status) ────────────────────────────


async def test_run_local_checks_no_valida_claves_aunque_no_se_pida_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Las comprobaciones locales son offline siempre, no según quien llama."""

    async def _no_debe_llamarse(*args: object) -> list[str]:
        raise AssertionError("validó una clave contra el proveedor")

    monkeypatch.setattr("atalaya.onboarding.checks.anthropic_models", _no_debe_llamarse)
    resultados = await run_local_checks(_inputs(offline=False, shodan_api_key="clave"))

    por_clave = {r.key: r for r in resultados}
    assert [r.key for r in resultados] == [
        "config", "scope", "database", "ai", "shodan", "api", "secrets",
    ]
    assert por_clave["ai"].status is Status.INFO
    assert por_clave["shodan"].status is Status.INFO
    assert "crtsh" not in por_clave

