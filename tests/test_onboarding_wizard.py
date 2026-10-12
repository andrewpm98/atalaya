"""Pruebas de `atalaya init` de principio a fin, con un guion de respuestas.

Real todo lo local: el `.env` se escribe en un proyecto temporal (con copia
de `alembic.ini` y `migrations/`) y la base de datos SQLite se migra de
verdad. Los proveedores (Anthropic, Shodan) son `httpx.MockTransport`.

Lo que más importa: que nada se escriba antes de confirmar (Ctrl+C, sin
autorización, «no» al resumen), que lo que ya había se conserve, y que
ningún secreto aparezca en pantalla.
"""

from __future__ import annotations

import asyncio
import io
import shutil
import sqlite3
from pathlib import Path

import httpx
import pytest
from rich.console import Console
from rich.text import Text

from atalaya.cli import build_parser
from atalaya.config import Settings
from atalaya.onboarding import ui
from atalaya.onboarding.envfile import read_env
from atalaya.onboarding.wizard import (
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_SHODAN_URL,
    DEFAULT_SQLITE_URL,
    NonInteractiveOptions,
    Wizard,
    normalize_database_url,
    run_non_interactive,
)

_RAIZ = Path(__file__).resolve().parents[1]
_CLAVE_IA = "sk-ant-api03-SECRETA-DE-PRUEBA-a1b2"
_CLAVE_SHODAN = "SHODAN-SECRETA-DE-PRUEBA-9f3c"
CTRL_C = object()


class Guion:
    """Responde en orden y deja en pantalla lo que vería el operador."""

    def __init__(self, term: ui.Terminal, respuestas: list[object]) -> None:
        self.term = term
        self.respuestas = list(respuestas)
        self.preguntas: list[str] = []

    def ask(self, prompt: Text, *, secret: bool = False) -> str:
        self.preguntas.append(prompt.plain)
        if not self.respuestas:
            raise AssertionError(f"pregunta sin respuesta en el guion: {prompt.plain!r}")
        respuesta = self.respuestas.pop(0)
        if respuesta is CTRL_C:
            raise KeyboardInterrupt
        assert isinstance(respuesta, str)
        visible = prompt.copy()
        visible.append("•" * len(respuesta) if secret else respuesta)
        self.term.console.print(visible)
        return respuesta


def _proveedores(request: httpx.Request) -> httpx.Response:
    if request.url.host == "api.anthropic.com":
        if request.headers.get("x-api-key") != _CLAVE_IA:
            return httpx.Response(401)
        return httpx.Response(200, json={"data": [{"id": DEFAULT_ANTHROPIC_MODEL}]})
    if request.url.path == "/api-info":
        return httpx.Response(200, json={"plan": "oss"})
    raise AssertionError(f"petición inesperada: {request.url}")


@pytest.fixture
def proyecto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    shutil.copy(_RAIZ / ".env.example", tmp_path / ".env.example")
    shutil.copy(_RAIZ / "alembic.ini", tmp_path / "alembic.ini")
    shutil.copytree(_RAIZ / "migrations", tmp_path / "migrations", ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.chdir(tmp_path)  # la URL SQLite por defecto es relativa
    return tmp_path


async def _init(
    proyecto: Path, respuestas: list[object], *, allow_any: bool = False
) -> tuple[int, str, Guion]:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    term = ui.make_terminal(stream, width=120)
    guion = Guion(term, respuestas)
    async with httpx.AsyncClient(transport=httpx.MockTransport(_proveedores)) as client:
        code = await Wizard(term, guion, proyecto, client, allow_any=allow_any).run()
    stream.flush()
    buffer = stream.buffer
    assert isinstance(buffer, io.BytesIO)
    return code, buffer.getvalue().decode("utf-8"), guion


#: Recorrido completo aceptando lo propuesto: SQLite, Anthropic, Shodan, API protegida.
_COMPLETO: list[object] = [
    "Ejemplo.com, ejemplo.es, ejemplo.com",  # 1. alcance (se normaliza y deduplica)
    "s",  # autorización
    "",  # 2. base de datos: SQLite (propuesta)
    "1",  # 3. Anthropic
    _CLAVE_IA,
    "",  # modelo propuesto
    _CLAVE_SHODAN,  # 4. Shodan
    "",  # 5. proteger la API: sí
    "",  # verificación de takeover: no
    "",  # escribir: sí
]


async def test_recorrido_completo_escribe_el_env_y_migra(proyecto: Path) -> None:
    code, salida, guion = await _init(proyecto, _COMPLETO)

    assert code == 0, salida
    assert not guion.respuestas
    env = read_env(proyecto / ".env")
    assert env["SCAN_ALLOWLIST"] == "ejemplo.com,ejemplo.es"
    assert env["DATABASE_URL"] == DEFAULT_SQLITE_URL
    assert env["AI_PROVIDER"] == "anthropic"
    assert env["ANTHROPIC_API_KEY"] == _CLAVE_IA
    assert env["AI_MODEL"] == DEFAULT_ANTHROPIC_MODEL
    assert env["SHODAN_API_KEY"] == _CLAVE_SHODAN
    assert len(env["API_KEY"]) >= 43  # 256 bits en base64url
    assert env["TAKEOVER_VERIFY"] == "false"
    # Parte de la plantilla: los comentarios que explican cada campo siguen ahí.
    assert "# ─── Capa IA" in (proyecto / ".env").read_text(encoding="utf-8")
    # El esquema se aplicó de verdad sobre la base de datos elegida.
    with sqlite3.connect(proyecto / "atalaya.sqlite3") as conn:
        tablas = {fila[0] for fila in conn.execute("select name from sqlite_master")}
    assert {"scans", "assets", "findings", "alembic_version"} <= tablas
    assert "Atalaya está listo." in salida
    assert "El plan oss no incluye búsqueda DNS" in salida


async def test_ningun_secreto_aparece_en_pantalla(proyecto: Path) -> None:
    code, salida, _ = await _init(proyecto, _COMPLETO)

    api_key = read_env(proyecto / ".env")["API_KEY"]
    assert code == 0
    for secreto in (_CLAVE_IA, _CLAVE_SHODAN, api_key):
        assert secreto not in salida
    assert "sk-ant-…a1b2" in salida  # enmascarada en el resumen


async def test_ctrl_c_antes_de_confirmar_no_toca_nada(proyecto: Path) -> None:
    respuestas = _COMPLETO[:6] + [CTRL_C]

    code, salida, _ = await _init(proyecto, respuestas)

    assert code == 130
    assert "no se ha escrito nada" in salida
    assert not (proyecto / ".env").exists()
    assert not (proyecto / "atalaya.sqlite3").exists()  # ni siquiera se creó


async def test_sin_autorizacion_no_se_configura_nada(proyecto: Path) -> None:
    code, salida, _ = await _init(proyecto, ["ejemplo.com", ""])  # [s/N]: Enter = no

    assert code == 1
    assert "Sin autorización no se configura el alcance" in salida
    assert not (proyecto / ".env").exists()


async def test_el_alcance_vacio_o_invalido_se_vuelve_a_pedir(proyecto: Path) -> None:
    respuestas = ["", "no es un dominio", "ejemplo.com", CTRL_C]

    _, salida, guion = await _init(proyecto, respuestas)

    assert "Hace falta al menos un dominio" in salida
    assert "no es un dominio válido" in salida
    assert sum("Dominios autorizados" in p for p in guion.preguntas) == 3


async def test_allow_any_permite_el_alcance_sin_restriccion(proyecto: Path) -> None:
    respuestas = ["", "", "3", "", "n", "", ""]  # sin dominios, SQLite, IA más tarde...

    code, salida, _ = await _init(proyecto, respuestas, allow_any=True)

    assert code == 0, salida
    assert read_env(proyecto / ".env")["SCAN_ALLOWLIST"] == ""
    assert "sin restricción" in salida


async def test_una_clave_rechazada_se_vuelve_a_pedir(proyecto: Path) -> None:
    respuestas = ["ejemplo.com", "s", "", "1", "sk-ant-mala-0000", _CLAVE_IA, "", CTRL_C]

    _, salida, _ = await _init(proyecto, respuestas)

    assert "Clave rechazada" in salida
    assert "Clave válida" in salida


async def test_un_modelo_no_disponible_se_vuelve_a_pedir(proyecto: Path) -> None:
    respuestas = ["ejemplo.com", "s", "", "1", _CLAVE_IA, "claude-inventado", "", CTRL_C]

    _, salida, _ = await _init(proyecto, respuestas)

    assert "claude-inventado no está disponible" in salida


async def test_una_base_de_datos_inalcanzable_permite_elegir_otra(proyecto: Path) -> None:
    respuestas = [
        "ejemplo.com", "s",
        "3", "postgresql://atalaya:SECRETA-PG@127.0.0.1:1/atalaya",  # no conecta
        "1",  # SQLite
        CTRL_C,
    ]

    _, salida, _ = await _init(proyecto, respuestas)

    assert "No conecta con 127.0.0.1:1" in salida
    assert "SECRETA-PG" not in salida
    assert "se creará al confirmar" in salida


async def test_con_un_env_previo_enter_conserva_cada_valor(proyecto: Path) -> None:
    (proyecto / ".env").write_text(
        "# mi comentario\n"
        "SCAN_ALLOWLIST=previo.com\n"
        f"ANTHROPIC_API_KEY={_CLAVE_IA}\n"
        "API_KEY=clave-previa-de-la-api\n"
        "LOG_LEVEL=DEBUG\n",
        encoding="utf-8",
    )
    respuestas = ["", "s", "", "1", "", "", "", "", "", ""]

    code, salida, _ = await _init(proyecto, respuestas)

    assert code == 0, salida
    env = read_env(proyecto / ".env")
    assert env["SCAN_ALLOWLIST"] == "previo.com"
    assert env["ANTHROPIC_API_KEY"] == _CLAVE_IA
    assert env["API_KEY"] == "clave-previa-de-la-api"
    assert env["LOG_LEVEL"] == "DEBUG"  # lo que init no pregunta, intacto
    assert "# mi comentario" in (proyecto / ".env").read_text(encoding="utf-8")
    copias = list(proyecto.glob(".env.bak-*"))
    assert len(copias) == 1
    assert "clave-previa-de-la-api" in copias[0].read_text(encoding="utf-8")


async def test_decir_no_al_resumen_no_escribe_nada(proyecto: Path) -> None:
    respuestas = [*_COMPLETO[:-1], "n"]

    code, _, _ = await _init(proyecto, respuestas)

    assert code == 1
    assert not (proyecto / ".env").exists()


# ─── Modo no interactivo ────────────────────────────────────────────────────


async def _no_interactivo(
    proyecto: Path, options: NonInteractiveOptions, environ: dict[str, str]
) -> tuple[int, str]:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    term = ui.make_terminal(stream, width=120)
    async with httpx.AsyncClient(transport=httpx.MockTransport(_proveedores)) as client:
        code = await run_non_interactive(term, proyecto, client, options, environ)
    stream.flush()
    buffer = stream.buffer
    assert isinstance(buffer, io.BytesIO)
    return code, buffer.getvalue().decode("utf-8")


async def test_no_interactivo_toma_los_secretos_del_entorno(proyecto: Path) -> None:
    options = NonInteractiveOptions(
        allowlist="ejemplo.com", ai_provider="anthropic", protect_api=True
    )

    code, salida = await _no_interactivo(
        proyecto, options, {"ANTHROPIC_API_KEY": _CLAVE_IA, "SHODAN_API_KEY": _CLAVE_SHODAN}
    )

    assert code == 0, salida
    env = read_env(proyecto / ".env")
    assert env["ANTHROPIC_API_KEY"] == _CLAVE_IA
    assert env["SHODAN_API_KEY"] == _CLAVE_SHODAN
    assert env["API_KEY"]
    for secreto in (_CLAVE_IA, _CLAVE_SHODAN, env["API_KEY"]):
        assert secreto not in salida


@pytest.mark.parametrize(
    ("options", "environ"),
    [
        (NonInteractiveOptions(), {}),  # sin alcance
        (NonInteractiveOptions(allowlist="ejemplo.com", ai_provider="anthropic"), {}),  # sin clave
    ],
)
async def test_no_interactivo_incompleto_sale_con_2_sin_escribir(
    proyecto: Path, options: NonInteractiveOptions, environ: dict[str, str]
) -> None:
    code, _ = await _no_interactivo(proyecto, options, environ)

    assert code == 2
    assert not (proyecto / ".env").exists()


async def test_no_interactivo_con_clave_rechazada_sale_con_1(proyecto: Path) -> None:
    options = NonInteractiveOptions(allowlist="ejemplo.com", ai_provider="anthropic")

    code, _ = await _no_interactivo(proyecto, options, {"ANTHROPIC_API_KEY": "sk-ant-mala"})

    assert code == 1
    assert not (proyecto / ".env").exists()


# ─── Detalles ───────────────────────────────────────────────────────────────


def test_los_valores_por_defecto_coinciden_con_config() -> None:
    """`wizard.py` los repite para no importar la configuración (un `.env`
    roto la haría fallar); este test impide que se desalineen."""
    campos = Settings.model_fields
    assert campos["database_url"].default == DEFAULT_SQLITE_URL
    assert campos["ai_model"].default == DEFAULT_ANTHROPIC_MODEL
    assert campos["gemini_model"].default == DEFAULT_GEMINI_MODEL
    assert campos["shodan_url"].default == DEFAULT_SHODAN_URL


def test_una_url_sincrona_pasa_al_driver_asincrono() -> None:
    assert normalize_database_url("postgresql://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"
    assert normalize_database_url("postgres://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"
    assert normalize_database_url("sqlite:///./a.db") == "sqlite+aiosqlite:///./a.db"
    assert normalize_database_url(DEFAULT_SQLITE_URL) == DEFAULT_SQLITE_URL


def test_init_sin_terminal_interactiva_explica_como_seguir(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bajo pytest la entrada no es una terminal, como en Git Bash o un pipe."""
    args = build_parser().parse_args(["init"])

    code = asyncio.run(args.func(args))

    assert code == 2
    assert "--non-interactive" in capsys.readouterr().out


def test_rich_prompter_no_muestra_la_clave_y_deja_constancia_con_puntos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """En una terminal real la clave se lee con getpass (no se ve al escribir)
    y la línea se reescribe con puntos, nunca con la clave."""
    from atalaya.onboarding.wizard import RichPrompter

    monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: _CLAVE_IA)
    stream = io.StringIO()
    term = ui.Terminal(
        console=Console(file=stream, force_terminal=True, width=100, legacy_windows=False),
        glyphs=ui.UNICODE,
    )

    respuesta = RichPrompter(term).ask(ui.prompt_text(term, "Clave de Anthropic"), secret=True)

    assert respuesta == _CLAVE_IA
    salida = stream.getvalue()
    assert _CLAVE_IA not in salida
    assert "•" * 24 in salida  # constancia de que se recibió, sin la longitud real
    assert "\x1b[2K" in salida  # la línea del prompt se borra y se reescribe
