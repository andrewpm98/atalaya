"""`atalaya init`: configuración guiada en cinco pasos, cada dato comprobado al momento.

1. **Alcance autorizado** — primero y obligatorio: `SCAN_ALLOWLIST` vacía
   significa «sin restricción», así que hay que nombrar al menos un dominio y
   confirmar que se tiene autorización (o pedir lo permisivo con `--allow-any`).
2. **Base de datos** — SQLite local, PostgreSQL del compose o una URL propia.
   Se conecta y se informa del esquema, pero **no se migra todavía**.
3. **IA** — Anthropic, Gemini o más tarde. Clave validada con la lista de
   modelos (gratuita, no comprueba el saldo: se dice).
4. **Shodan** — opcional; se avisa si el plan no incluye la búsqueda DNS.
5. **Seguridad** — clave de la API (generada) y verificación de takeover.

**Nada se escribe hasta confirmar el resumen.** Ctrl+C antes de ese punto
sale sin cambios; por eso las migraciones se aplican al final, después de
escribir el `.env`, y no al elegir la base de datos.

Las preguntas pasan por un `Prompter`: en la terminal, `RichPrompter`; en los
tests, respuestas fijas. El modo no interactivo (`run_non_interactive`) reúne
las mismas respuestas desde opciones y variables de entorno —los secretos,
**nunca** como argumentos: quedarían en el historial y en la lista de
procesos— y comparte la validación y la escritura.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import httpx
from rich.console import RenderableType
from rich.control import Control
from rich.segment import ControlType
from rich.status import Status as Spinner
from rich.text import Text

from atalaya.onboarding import ui
from atalaya.onboarding.checks import (
    CheckUnavailable,
    DbProbe,
    KeyRejected,
    Status,
    anthropic_models,
    apply_migrations,
    check_secrets,
    gemini_models,
    probe_database,
    shodan_plan,
)
from atalaya.onboarding.envfile import (
    EnvWriteError,
    mask_secret,
    mask_url,
    read_env,
    write_env,
)

# Mismos valores por defecto que `config.py` (un test lo comprueba). No se
# importan de allí: con un `.env` roto, importar la configuración falla, y
# `init` es precisamente cómo se arregla.
DEFAULT_SQLITE_URL = "sqlite+aiosqlite:///./atalaya.sqlite3"
DOCKER_POSTGRES_URL = "postgresql+asyncpg://atalaya:atalaya@localhost:5432/atalaya"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_SHODAN_URL = "https://api.shodan.io"
#: Intentos con una clave rechazada antes de dejar la IA sin cambios.
MAX_KEY_ATTEMPTS = 3
TOTAL_STEPS = 5


class Aborted(Exception):
    """El operador no puede seguir (p. ej. sin autorización): nada se escribe."""


class Prompter(Protocol):
    def ask(self, prompt: Text, *, secret: bool = False) -> str: ...


class RichPrompter:
    """Preguntas en la terminal real.

    Una clave no se ve mientras se escribe (`getpass`); al terminar, la línea
    se reescribe con puntos para que quede constancia de que se recibió, sin
    mostrar su longitud real más allá de 24.
    """

    def __init__(self, term: ui.Terminal) -> None:
        self.term = term

    def ask(self, prompt: Text, *, secret: bool = False) -> str:
        console = self.term.console
        answer = console.input(prompt, password=secret)
        if secret and answer and console.is_terminal and not console.legacy_windows:
            console.control(
                Control.move_to_column(0, -1), Control((ControlType.ERASE_IN_LINE, 2))
            )
            shown = prompt.copy()
            shown.append(self.term.glyphs.bullet * min(len(answer), 24), style=f"bold {ui.TEXT}")
            console.print(shown)
        return answer


@dataclass
class AiAnswer:
    provider: str
    key_name: str
    key: str
    model_name: str
    model: str

    @property
    def label(self) -> str:
        return "Anthropic" if self.provider == "anthropic" else "Gemini"


@dataclass
class Answers:
    """Lo que se va a escribir. `None` en un campo = no tocar lo que haya."""

    allowlist: list[str] = field(default_factory=list)
    database_url: str = DEFAULT_SQLITE_URL
    probe: DbProbe | None = None
    ai: AiAnswer | None = None
    ai_provider_only: str | None = None
    shodan_key: str | None = None
    shodan_plan: str | None = None
    api_key: str | None = None
    takeover_verify: bool | None = None

    def updates(self) -> dict[str, str]:
        values = {
            "SCAN_ALLOWLIST": ",".join(self.allowlist),
            "DATABASE_URL": self.database_url,
        }
        if self.ai is not None:
            values["AI_PROVIDER"] = self.ai.provider
            values[self.ai.key_name] = self.ai.key
            values[self.ai.model_name] = self.ai.model
        elif self.ai_provider_only is not None:
            values["AI_PROVIDER"] = self.ai_provider_only
        if self.shodan_key is not None:
            values["SHODAN_API_KEY"] = self.shodan_key
        if self.api_key is not None:
            values["API_KEY"] = self.api_key
        if self.takeover_verify is not None:
            values["TAKEOVER_VERIFY"] = "true" if self.takeover_verify else "false"
        return values


def normalize_database_url(url: str) -> str:
    """La aplicación es asíncrona: `postgresql://` → `postgresql+asyncpg://`."""
    for plain, driver in (
        ("postgresql://", "postgresql+asyncpg://"),
        ("postgres://", "postgresql+asyncpg://"),
        ("sqlite://", "sqlite+aiosqlite://"),
    ):
        if url.startswith(plain):
            return driver + url[len(plain):]
    return url


def parse_allowlist(raw: str) -> tuple[list[str], list[str]]:
    """(dominios normalizados sin repetir, entradas no válidas)."""
    from atalaya.core.authorization import normalize_domain
    from atalaya.core.exceptions import InvalidTargetError

    valid: list[str] = []
    invalid: list[str] = []
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        try:
            domain = normalize_domain(entry)
        except InvalidTargetError:
            invalid.append(entry)
            continue
        if domain not in valid:
            valid.append(domain)
    return valid, invalid


def _elapsed(start: float) -> str:
    return ui.format_elapsed(round((time.perf_counter() - start) * 1000))


class _Steps:
    """Piezas comunes a los dos modos: validar, resumir, escribir y migrar."""

    def __init__(self, term: ui.Terminal, project_root: Path, client: httpx.AsyncClient) -> None:
        self.term = term
        self.root = project_root
        self.client = client
        self.env_path = project_root / ".env"
        self.current = read_env(self.env_path)

    def say(self, *items: RenderableType) -> None:
        self.term.print(*items)

    def status(self, kind: ui.Kind, text: str, detail: str = "", elapsed: str = "") -> None:
        self.say(ui.status(self.term, kind, text, detail.replace("·", self.term.glyphs.sep), elapsed))

    def spinner(self, message: str) -> Spinner:
        suffix = self.term.glyphs.ellipsis
        return self.term.console.status(
            Text(f"{message}{suffix}", style=ui.MUTED),
            spinner="dots" if self.term.unicode else "line",
            spinner_style=ui.ACCENT,
        )

    def report_probe(self, probe: DbProbe, elapsed: str) -> None:
        if not probe.exists:
            self.status("ok", f"SQLite {self.term.glyphs.sep} {probe.location}", "se creará al confirmar")
        else:
            self.status("ok", f"Conectado a {probe.location}", probe.version, elapsed)
        if probe.head_revision is None:
            self.status("info", "Esquema sin comprobar", "ejecuta init desde la raíz del proyecto")
        elif probe.up_to_date:
            self.status("ok", "Esquema al día", "(head)")
        else:
            self.status("info", "Esquema pendiente", "se aplicará al confirmar")

    def summary_rows(self, answers: Answers) -> list[tuple[str, str, ui.Kind]]:
        sep = self.term.glyphs.sep
        rows: list[tuple[str, str, ui.Kind]] = []
        if answers.allowlist:
            rows.append(("Alcance", ", ".join(answers.allowlist), "ok"))
        else:
            rows.append(("Alcance", "sin restricción (--allow-any)", "warn"))

        probe = answers.probe
        backend = "SQLite" if answers.database_url.startswith("sqlite") else "PostgreSQL"
        location = probe.location if probe else mask_url(answers.database_url)
        if probe is None or probe.head_revision is None:
            state = "esquema sin comprobar"
        elif not probe.exists or not probe.up_to_date:
            state = "se migrará"
        else:
            state = "migrada"
        rows.append(("Base de datos", f"{backend} {sep} {location} {sep} {state}", "ok"))

        if answers.ai is not None:
            ai = answers.ai
            rows.append(("IA", f"{ai.label} {sep} {mask_secret(ai.key)} {sep} {ai.model}", "ok"))
        elif answers.ai_provider_only is not None:
            rows.append(("IA", f"{answers.ai_provider_only} (respuestas grabadas)", "ok"))
        else:
            rows.append(("IA", "sin cambios", "off"))

        if answers.shodan_key is None:
            rows.append(("Shodan", "sin cambios", "off"))
        elif not answers.shodan_key:
            rows.append(("Shodan", "sin Shodan (crt.sh es la fuente)", "off"))
        elif answers.shodan_plan in ("oss",):
            rows.append(
                ("Shodan", f"{mask_secret(answers.shodan_key)} {sep} sin búsqueda DNS (plan oss)", "warn")
            )
        else:
            plan = f"plan {answers.shodan_plan}" if answers.shodan_plan else "sin comprobar"
            rows.append(("Shodan", f"{mask_secret(answers.shodan_key)} {sep} {plan}", "ok"))

        if answers.api_key is None:
            rows.append(("API", "sin cambios", "off"))
        elif answers.api_key:
            rows.append(("API", "protegida con X-API-Key", "ok"))
        else:
            rows.append(("API", "sin autenticación (solo en local)", "warn"))

        if answers.takeover_verify is None:
            rows.append(("Takeover", "sin cambios", "off"))
        elif answers.takeover_verify:
            rows.append(("Takeover", "verificación HTTP activa (opt-in)", "info"))
        else:
            rows.append(("Takeover", "solo patrón DNS (verificación desactivada)", "ok"))
        return rows

    async def write_and_migrate(self, answers: Answers) -> int:
        """Escribe el `.env`, comprueba git y aplica el esquema. Devuelve el código."""
        try:
            result = write_env(self.env_path, answers.updates(), template=self.root / ".env.example")
        except EnvWriteError as exc:
            self.status("err", "No se ha escrito el .env", str(exc))
            return 1
        if result.backup is not None:
            self.status("ok", ".env escrito", f"copia del anterior en {result.backup.name}")
        else:
            self.status("ok", ".env escrito", "nuevo, a partir de .env.example")

        exit_code = 0
        git = check_secrets(self.root)
        if git.status is Status.ERROR:
            self.status("err", git.detail, git.hint or "")
            exit_code = 1
        elif git.status is Status.OK and "ignorado" in git.detail:
            self.status("ok", ".env está en .gitignore", "los secretos no llegarán al repositorio")

        probe = answers.probe
        if probe is not None and probe.head_revision is not None and not (
            probe.exists and probe.up_to_date
        ):
            start = time.perf_counter()
            try:
                with self.spinner("Aplicando el esquema"):
                    await apply_migrations(answers.database_url, self.root)
            except Exception as exc:  # noqa: BLE001 - se informa y se sigue
                message = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
                self.status("err", "No se pudo aplicar el esquema", f"{message[:90]} · alembic upgrade head")
                exit_code = 1
            else:
                self.status("ok", "Migraciones aplicadas", "esquema al día (head)", _elapsed(start))
        return exit_code

    def closing(self, exit_code: int) -> None:
        title = "Atalaya está listo." if exit_code == 0 else "Configuración guardada, con errores que revisar."
        self.say(
            Text(""),
            ui.next_steps(
                self.term,
                title,
                [
                    ("uvicorn atalaya.api.main:app", "API        → http://127.0.0.1:8000/docs"),
                    ("streamlit run dashboard/app.py", "Dashboard  → http://127.0.0.1:8501"),
                    ("atalaya doctor", "Revisar la configuración cuando quieras"),
                ],
            ),
            ui.note("Si la API o el dashboard ya estaban en marcha, reinícialos: leen el .env al arrancar."),
            Text(""),
        )


class Wizard(_Steps):
    """El asistente interactivo."""

    def __init__(
        self,
        term: ui.Terminal,
        prompter: Prompter,
        project_root: Path,
        client: httpx.AsyncClient,
        *,
        allow_any: bool = False,
    ) -> None:
        super().__init__(term, project_root, client)
        self.prompter = prompter
        self.allow_any = allow_any
        self.written = False

    # ─── Entrada ────────────────────────────────────────────────────────────

    def ask(self, label: str, hint: str = "", *, secret: bool = False) -> str:
        return self.prompter.ask(ui.prompt_text(self.term, label, hint), secret=secret).strip()

    def confirm(self, label: str, *, default: bool, extra: str = "") -> bool:
        hint = "[S/n]" if default else "[s/N]"
        if extra:
            hint = f"{hint} {self.term.glyphs.sep} {extra}"
        while True:
            answer = self.ask(label, hint).lower()
            if not answer:
                return default
            if answer in ("s", "si", "sí", "y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.status("err", "Responde s o n")

    def choose(self, rows: list[tuple[str, str, str, bool]], default: str) -> str:
        self.say(ui.choices(rows), Text(""))
        keys = [row[0] for row in rows]
        while True:
            answer = self.ask("Elige", f"[{default}]") or default
            if answer in keys:
                return answer
            self.status("err", "Opción no válida", "elige " + ", ".join(keys))

    # ─── Pasos ──────────────────────────────────────────────────────────────

    async def run(self) -> int:
        try:
            return await self._run()
        except Aborted as exc:
            self.status("err", str(exc), "no se ha escrito nada")
            self.say(Text(""))
            return 1
        except (KeyboardInterrupt, EOFError, asyncio.CancelledError):
            self.say(Text(""))
            if self.written:
                self.status("warn", "Interrumpido", "el .env ya estaba escrito · revisa con atalaya doctor")
            else:
                self.status("off", "Cancelado", "no se ha escrito nada")
            self.say(Text(""))
            return 130

    async def _run(self) -> int:
        intro = Text()
        intro.append("Configuración inicial", style=f"bold {ui.TEXT}")
        sep = self.term.glyphs.sep
        intro.append(f" {sep} {TOTAL_STEPS} pasos {sep} unos 2 minutos\n", style=ui.MUTED)
        intro.append("Cada dato se comprueba al momento y sin coste. ", style=ui.MUTED)
        intro.append("Ctrl+C", style=f"bold {ui.ACCENT}")
        intro.append(" sale sin tocar nada.", style=ui.MUTED)
        self.say(Text(""), ui.banner(self.term), Text(""), ui.panel(intro))
        if self.env_path.exists():
            self.say(ui.note("Ya hay un .env: Enter conserva cada valor actual."))

        answers = Answers()
        answers.allowlist = self.step_scope()
        answers.database_url, answers.probe = await self.step_database()
        answers.ai = await self.step_ai()
        answers.shodan_key, answers.shodan_plan = await self.step_shodan()
        answers.api_key, answers.takeover_verify = self.step_security()

        self.say(Text(""), ui.summary(self.term, self.summary_rows(answers)), Text(""))
        if not self.confirm("¿Escribir la configuración en .env?", default=True):
            self.status("off", "No se ha escrito nada", "vuelve a ejecutar atalaya init cuando quieras")
            self.say(Text(""))
            return 1
        self.written = True
        exit_code = await self.write_and_migrate(answers)
        self.closing(exit_code)
        return exit_code

    def step_scope(self) -> list[str]:
        self.say(ui.step(self.term, 1, TOTAL_STEPS, "Alcance autorizado"))
        self.say(
            ui.note("Atalaya solo escaneará estos dominios y sus subdominios."),
            ui.note("Escanear sin autorización del propietario puede ser delito."),
            Text(""),
        )
        current = self.current.get("SCAN_ALLOWLIST", "")
        hint = "(separados por comas)" + (f" [{current}]" if current else "")
        while True:
            raw = self.ask("Dominios autorizados", hint) or current
            domains, invalid = parse_allowlist(raw)
            if invalid:
                for entry in invalid:
                    self.status("err", entry, "no es un dominio válido")
                continue
            if not domains:
                if self.allow_any:
                    self.status("warn", "Sin restricción", "--allow-any: se podrá escanear cualquier dominio")
                    return []
                self.status("err", "Hace falta al menos un dominio", "o ejecuta init con --allow-any")
                continue
            for domain in domains:
                self.status("ok", domain, "y sus subdominios")
            break
        if not self.confirm("¿Tienes autorización para escanearlos?", default=False):
            raise Aborted("Sin autorización no se configura el alcance")
        return domains

    async def step_database(self) -> tuple[str, DbProbe]:
        self.say(ui.step(self.term, 2, TOTAL_STEPS, "Base de datos"))
        current = self.current.get("DATABASE_URL", "")
        if not current or current == DEFAULT_SQLITE_URL:
            default = "1"
        elif current == DOCKER_POSTGRES_URL:
            default = "2"
        else:
            default = "3"
        rows = [
            ("1", "SQLite local", "Sin instalar nada · ideal para probar", True),
            ("2", "PostgreSQL (Docker)", "docker compose up -d db", False),
            ("3", "PostgreSQL propio", "Introducir la URL de conexión", False),
        ]
        while True:
            key = self.choose(rows, default)
            if key == "1":
                url = DEFAULT_SQLITE_URL
            elif key == "2":
                url = DOCKER_POSTGRES_URL
            else:
                keep = default == "3" and current
                hint = f"(Enter conserva {mask_url(current)})" if keep else "(no se muestra)"
                url = normalize_database_url(self.ask("URL de conexión", hint, secret=True)) or current
                if not url:
                    self.status("err", "Hace falta una URL", "postgresql://usuario:clave@host:5432/base")
                    continue
            start = time.perf_counter()
            with self.spinner("Conectando"):
                probe = await probe_database(url, self.root)
            if probe.reachable:
                self.report_probe(probe, _elapsed(start))
                return url, probe
            self.status("err", f"No conecta con {probe.location}", probe.error)
            if key == "2":
                self.say(ui.note("¿Está levantado? docker compose up -d db"))
            default = key

    async def step_ai(self) -> AiAnswer | None:
        self.say(ui.step(self.term, 3, TOTAL_STEPS, "Triaje por IA"))
        provider_now = self.current.get("AI_PROVIDER", "anthropic")
        later = "Mantiene replay (demo sin red)" if provider_now == "replay" else "No cambia la IA actual"
        rows = [
            ("1", "Anthropic", "Claude · recomendado para el triaje", True),
            ("2", "Google Gemini", "Cuota gratuita · ~20 peticiones/día", False),
            ("3", "Más tarde", later, False),
        ]
        key = self.choose(rows, "2" if provider_now == "gemini" else "1")
        if key == "3":
            self.status("off", "IA sin cambios", "triaje, consultas y resúmenes según la configuración actual")
            return None
        if key == "1":
            provider, label, key_name, model_name = "anthropic", "Anthropic", "ANTHROPIC_API_KEY", "AI_MODEL"
            fetch, default_model = anthropic_models, DEFAULT_ANTHROPIC_MODEL
        else:
            provider, label, key_name, model_name = "gemini", "Gemini", "GEMINI_API_KEY", "GEMINI_MODEL"
            fetch, default_model = gemini_models, DEFAULT_GEMINI_MODEL

        current_key = self.current.get(key_name, "")
        hint = f"(Enter conserva {mask_secret(current_key)})" if current_key else "(no se muestra)"
        models: list[str] | None = None
        attempts = 0
        while True:
            api_key = self.ask(f"Clave de {label}", hint, secret=True) or current_key
            if not api_key:
                self.status("warn", "Sin clave", "la IA queda como estaba")
                return None
            start = time.perf_counter()
            try:
                with self.spinner("Validando la clave"):
                    models = await fetch(self.client, api_key)
            except KeyRejected as exc:
                attempts += 1
                self.status("err", "Clave rechazada", str(exc))
                if attempts >= MAX_KEY_ATTEMPTS:
                    self.status("warn", "Demasiados intentos", "la IA queda como estaba")
                    return None
                continue
            except CheckUnavailable as exc:
                self.status("warn", "No se pudo comprobar la clave", f"({exc})")
                if not self.confirm("¿Guardarla sin comprobar?", default=True):
                    continue
                models = None
            else:
                sep = self.term.glyphs.sep
                self.status(
                    "ok", "Clave válida", f"{mask_secret(api_key)} {sep} {len(models)} modelos", _elapsed(start)
                )
            break

        current_model = self.current.get(model_name) or default_model
        while True:
            model = self.ask("Modelo", f"[{current_model}]") or current_model
            if models is None or model in models:
                break
            family = "claude" if provider == "anthropic" else "gemini"
            options = sorted(m for m in models if family in m)[:4]
            self.status("warn", f"{model} no está disponible con esta clave", ", ".join(options))
        if provider == "anthropic":
            self.status("info", "La validación no comprueba el saldo", "sin crédito, el triaje dará 502")
        else:
            self.status("info", "La cuota gratuita se agota pronto", "~20 peticiones al día")
        return AiAnswer(provider, key_name, api_key, model_name, model)

    async def step_shodan(self) -> tuple[str | None, str | None]:
        self.say(ui.step(self.term, 4, TOTAL_STEPS, "Shodan · opcional"))
        self.say(ui.note("Segunda fuente de subdominios. Enter para omitirla."), Text(""))
        current = self.current.get("SHODAN_API_KEY", "")
        hint = f"(Enter conserva {mask_secret(current)})" if current else "(Enter para omitir)"
        base_url = self.current.get("SHODAN_URL") or DEFAULT_SHODAN_URL
        while True:
            api_key = self.ask("Clave de Shodan", hint, secret=True)
            if not api_key:
                if current:
                    self.status("ok", "Se mantiene la clave actual", mask_secret(current))
                    return None, None
                self.status("off", "Sin Shodan", "crt.sh será la fuente de subdominios")
                return None, None
            start = time.perf_counter()
            try:
                with self.spinner("Validando la clave"):
                    plan = await shodan_plan(self.client, base_url, api_key)
            except KeyRejected as exc:
                self.status("err", "Clave rechazada", f"{exc} · Enter para omitir")
                continue
            except CheckUnavailable as exc:
                self.status("warn", "No se pudo comprobar la clave", f"({exc}) · se guarda igualmente")
                return api_key, None
            self.status("ok", "Clave válida", f"plan {plan}", _elapsed(start))
            if plan == "oss":
                self.status("warn", "El plan oss no incluye búsqueda DNS", "crt.sh seguirá siendo la fuente")
            return api_key, plan

    def step_security(self) -> tuple[str | None, bool]:
        self.say(ui.step(self.term, 5, TOTAL_STEPS, "Seguridad"))
        current = self.current.get("API_KEY", "")
        api_key: str | None
        if self.confirm("¿Proteger la API con clave (X-API-Key)?", default=True):
            if current:
                api_key = None
                self.status("ok", "Se mantiene la clave actual", mask_secret(current))
            else:
                api_key = secrets.token_urlsafe(32)
                self.status("ok", "Clave generada", "256 bits aleatorios · el dashboard la usa sola")
        else:
            api_key = ""
            self.status("warn", "API sin autenticación", "aceptable solo en local (127.0.0.1)")
        verify_now = self.current.get("TAKEOVER_VERIFY", "").lower() in ("1", "true", "yes", "on")
        verify = self.confirm(
            "¿Verificación HTTP de takeover?", default=verify_now, extra="opt-in, más intrusiva"
        )
        if verify:
            self.status("info", "Verificación HTTP activa", "solo sobre hosts del alcance, con auditoría")
        else:
            self.status("off", "Solo detección pasiva", "patrón de CNAME, sin peticiones a terceros")
        return api_key, verify


# ─── Modo no interactivo ────────────────────────────────────────────────────


@dataclass
class NonInteractiveOptions:
    allowlist: str | None = None
    allow_any: bool = False
    database: str | None = None  # "sqlite" | "docker" | None (DATABASE_URL o la actual)
    ai_provider: str = "keep"  # "anthropic" | "gemini" | "replay" | "keep"
    ai_model: str | None = None
    protect_api: bool = False
    takeover_verify: bool | None = None
    offline: bool = False


async def run_non_interactive(
    term: ui.Terminal,
    project_root: Path,
    client: httpx.AsyncClient,
    options: NonInteractiveOptions,
    environ: Mapping[str, str] | None = None,
) -> int:
    """`init --non-interactive`: mismas comprobaciones, sin preguntas.

    Devuelve 2 ante opciones incompletas y 1 si algo no valida; en ambos
    casos sin escribir nada.
    """
    env = os.environ if environ is None else environ
    steps = _Steps(term, project_root, client)
    steps.say(Text(""), ui.header(term, "init"), ui.rule(term))
    answers = Answers()

    if options.allowlist:
        domains, invalid = parse_allowlist(options.allowlist)
        if invalid:
            steps.status("err", "Alcance no válido", ", ".join(invalid))
            return 2
        answers.allowlist = domains
        steps.status("ok", "Alcance", ", ".join(domains))
    elif options.allow_any:
        steps.status("warn", "Sin restricción", "--allow-any: se podrá escanear cualquier dominio")
    else:
        steps.status("err", "Falta el alcance", "--allowlist ejemplo.com (o --allow-any)")
        return 2

    if env.get("DATABASE_URL"):
        url = normalize_database_url(env["DATABASE_URL"])
    elif options.database == "docker":
        url = DOCKER_POSTGRES_URL
    elif options.database == "sqlite":
        url = DEFAULT_SQLITE_URL
    else:
        url = steps.current.get("DATABASE_URL") or DEFAULT_SQLITE_URL
    start = time.perf_counter()
    probe = await probe_database(url, project_root)
    if not probe.reachable:
        steps.status("err", f"No conecta con {probe.location}", probe.error)
        return 1
    steps.report_probe(probe, _elapsed(start))
    answers.database_url, answers.probe = url, probe

    if options.ai_provider in ("anthropic", "gemini"):
        anthropic = options.ai_provider == "anthropic"
        key_name = "ANTHROPIC_API_KEY" if anthropic else "GEMINI_API_KEY"
        model_name = "AI_MODEL" if anthropic else "GEMINI_MODEL"
        api_key = env.get(key_name, "")
        if not api_key:
            steps.status("err", f"Falta {key_name}", "pásala como variable de entorno, no como argumento")
            return 2
        model = (
            options.ai_model
            or steps.current.get(model_name)
            or (DEFAULT_ANTHROPIC_MODEL if anthropic else DEFAULT_GEMINI_MODEL)
        )
        if not options.offline:
            fetch = anthropic_models if anthropic else gemini_models
            try:
                models = await fetch(client, api_key)
            except KeyRejected as exc:
                steps.status("err", "Clave rechazada", str(exc))
                return 1
            except CheckUnavailable as exc:
                steps.status("warn", "No se pudo comprobar la clave", f"({exc})")
            else:
                if model not in models:
                    steps.status("err", f"{model} no está disponible con esta clave")
                    return 1
                steps.status("ok", "Clave válida", f"{mask_secret(api_key)} · {model}")
        answers.ai = AiAnswer(options.ai_provider, key_name, api_key, model_name, model)
    elif options.ai_provider == "replay":
        answers.ai_provider_only = "replay"

    shodan_key = env.get("SHODAN_API_KEY", "")
    if shodan_key:
        answers.shodan_key = shodan_key
        if not options.offline:
            base_url = steps.current.get("SHODAN_URL") or DEFAULT_SHODAN_URL
            try:
                answers.shodan_plan = await shodan_plan(client, base_url, shodan_key)
            except KeyRejected as exc:
                steps.status("err", "Clave de Shodan rechazada", str(exc))
                return 1
            except CheckUnavailable as exc:
                steps.status("warn", "No se pudo comprobar la clave de Shodan", f"({exc})")
            else:
                steps.status("ok", "Clave de Shodan válida", f"plan {answers.shodan_plan}")
                if answers.shodan_plan == "oss":
                    steps.status(
                        "warn", "El plan oss no incluye búsqueda DNS", "crt.sh seguirá siendo la fuente"
                    )

    if options.protect_api:
        answers.api_key = (
            env.get("API_KEY") or steps.current.get("API_KEY") or secrets.token_urlsafe(32)
        )
    answers.takeover_verify = options.takeover_verify

    steps.say(Text(""), ui.summary(term, steps.summary_rows(answers)), Text(""))
    exit_code = await steps.write_and_migrate(answers)
    steps.say(Text(""))
    return exit_code
