"""`atalaya doctor`: qué está configurado, si funciona y cómo arreglar lo que no.

Sale con código 1 si alguna comprobación da error (sirve en CI o antes de una
demo); los avisos no cuentan como fallo. `--offline` omite todo lo que sale a
la red (validar claves, crt.sh), para diagnosticar sin conexión.

Un `.env` con un valor que impide cargar la configuración (p. ej.
`AI_MAX_TOKENS=mil`) no hace fallar el comando: es precisamente lo que tiene
que diagnosticar. Por eso `atalaya.config` se importa aquí dentro y no al
cargar el módulo.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from pydantic import ValidationError
from rich.console import Group
from rich.table import Table
from rich.text import Text

from atalaya.onboarding import ui
from atalaya.onboarding.checks import (
    CheckResult,
    DoctorInputs,
    Status,
    check_secrets,
    run_checks,
)
from atalaya.onboarding.envfile import read_env

_KIND: dict[Status, ui.Kind] = {
    Status.OK: "ok",
    Status.WARN: "warn",
    Status.ERROR: "err",
    Status.INFO: "info",
    Status.OFF: "off",
}


def load_inputs(project_root: Path, *, offline: bool) -> DoctorInputs | CheckResult:
    """Lee la configuración; si no se puede cargar, devuelve el error como resultado."""
    env_path = project_root / ".env"
    env_values = read_env(env_path)
    try:
        from atalaya.config import Settings

        current = Settings()
    except ValidationError as exc:
        fields = sorted({str(error["loc"][0]).upper() for error in exc.errors() if error["loc"]})
        return CheckResult(
            key="config",
            name="Configuración",
            status=Status.ERROR,
            detail="valor no válido en .env: " + ", ".join(fields),
            hint="Corrige ese valor o vuelve a ejecutar atalaya init.",
        )
    return DoctorInputs(
        project_root=project_root,
        env_exists=env_path.exists(),
        env_keys=list(env_values),
        known_keys={name.upper() for name in Settings.model_fields},
        allowlist_raw=current.scan_allowlist,
        database_url=current.database_url,
        ai_provider=current.ai_provider,
        anthropic_api_key=current.anthropic_api_key,
        ai_model=current.ai_model,
        gemini_api_key=current.gemini_api_key,
        gemini_model=current.gemini_model,
        ai_replay_file=current.ai_replay_file,
        shodan_api_key=current.shodan_api_key,
        shodan_url=current.shodan_url,
        crtsh_url=current.crtsh_url,
        api_key=current.api_key,
        offline=offline,
    )


def render(term: ui.Terminal, results: list[CheckResult]) -> int:
    """Pinta el diagnóstico y devuelve el código de salida (1 si hay errores)."""
    table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    table.add_column(width=3)
    table.add_column(style=f"bold {ui.TEXT}", width=15)
    table.add_column(style=ui.MUTED, ratio=1)
    table.add_column(style=ui.MUTED, justify="right", width=8)
    for result in results:
        table.add_row(
            ui.icon(term, _KIND[result.status]),
            result.name,
            result.detail.replace("·", term.glyphs.sep),
            ui.format_elapsed(result.elapsed_ms) if result.elapsed_ms else "",
        )

    errors = sum(r.status is Status.ERROR for r in results)
    warnings = sum(r.status is Status.WARN for r in results)
    fine = len(results) - errors - warnings
    def count(n: int, singular: str, plural: str, color: str) -> Text:
        # Un contador a cero no es una señal: se pinta apagado, no en rojo.
        return Text(f"{n} {singular if n == 1 else plural}", style=f"bold {color}" if n else ui.MUTED)

    totals = Text("  ")
    totals.append_text(count(errors, "error", "errores", ui.ERROR))
    totals.append(f" {term.glyphs.sep} ", style=ui.MUTED)
    totals.append_text(count(warnings, "aviso", "avisos", ui.WARN))
    totals.append(f" {term.glyphs.sep} ", style=ui.MUTED)
    totals.append_text(count(fine, "correcto", "correctos", ui.OK))
    exit_code = 1 if errors else 0
    totals.append(f"      código de salida {exit_code}", style=ui.MUTED)

    term.print(Text(""), ui.header(term, "doctor"), ui.rule(term), table, ui.rule(term), totals)

    pending = [r for r in results if r.hint and r.status in (Status.ERROR, Status.WARN)]
    if pending:
        hints = Table.grid(padding=(0, 1))
        hints.add_column(width=2)
        hints.add_column(width=14)
        hints.add_column()
        for result in pending:
            color = ui.ERROR if result.status is Status.ERROR else ui.WARN
            glyph = term.glyphs.err if result.status is Status.ERROR else term.glyphs.warn
            hints.add_row(
                Text(glyph, style=f"bold {color}"),
                Text(result.name, style=f"bold {color}"),
                Text(result.hint or "", style=ui.MUTED),
            )
        term.print(
            Text(""),
            ui.panel(Group(Text("Cómo resolverlo", style=f"bold {ui.TEXT}"), hints)),
        )
    term.print(Text(""))
    return exit_code


async def run_doctor(term: ui.Terminal, project_root: Path, *, offline: bool = False) -> int:
    loaded = load_inputs(project_root, offline=offline)
    if isinstance(loaded, CheckResult):
        return render(term, [loaded, check_secrets(project_root)])
    spinner = "dots" if term.unicode else "line"
    with term.console.status(
        Text("Comprobando la configuración…" if term.unicode else "Comprobando la configuración...",
             style=ui.MUTED),
        spinner=spinner,
        spinner_style=ui.ACCENT,
    ):
        async with httpx.AsyncClient() as client:
            results = await run_checks(loaded, client)
    return render(term, results)
