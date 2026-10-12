"""Identidad visual de Atalaya en la terminal: logo, paleta y piezas de pantalla.

Misma paleta que el dashboard (`.streamlit/config.toml`): un solo acento frío
para la marca y lo interactivo, y el rojo reservado a los fallos reales. Las
piezas devuelven *renderables* de `rich` y no imprimen nada: quien las usa
decide la consola, y los tests pueden capturarlas.

**Terminales sin UTF-8.** Con la salida redirigida en Windows (cp1252) o una
consola antigua, escribir `●` o `✔` lanza `UnicodeEncodeError` dentro de
`rich` (reproducido al maquetar). `make_terminal()` detecta la codificación y
cambia logo e iconos a ASCII; `rich` ya sustituye por sí solo los bordes de
paneles y reglas cuando la codificación no es UTF-8. Como red de seguridad,
la salida se reconfigura con `errors="replace"`: un carácter imposible sale
como `?` en vez de abortar el comando.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TextIO

from rich import box
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from atalaya import __version__

# Paleta de marca (coincide con .streamlit/config.toml).
ACCENT = "#00c8e8"
ACCENT_DIM = "#0a7f94"
TEXT = "#e4edf6"
MUTED = "#66798c"
LINE = "#2a3644"
OK = "#39d353"
WARN = "#e3c341"
ERROR = "#ff4d4d"

Kind = Literal["ok", "warn", "err", "info", "off"]


@dataclass(frozen=True)
class Glyphs:
    """Iconos de estado y separadores, en Unicode o en ASCII."""

    ok: str
    warn: str
    err: str
    info: str
    off: str
    prompt: str
    sep: str
    ellipsis: str
    dot_on: str
    dot_off: str
    bullet: str


UNICODE = Glyphs("✔", "⚠", "✖", "ℹ", "○", "›", "·", "…", "●", "○", "•")
ASCII = Glyphs("+", "!", "x", "i", "-", ">", "|", "...", "*", "o", "*")

#: Letras de bloque del nombre (dos filas de semibloques).
_WORDMARK = ("▄▀█ ▀█▀ ▄▀█ █   ▄▀█ █▄█ ▄▀█", "█▀█  █  █▀█ █▄▄ █▀█  █  █▀█")

#: Torre de celosía con baliza: una torre de vigilancia que es también una A.
#: Cada fila es una lista de (texto, estilo) para poder apagar las ondas.
_TOWER: tuple[tuple[tuple[str, str], ...], ...] = (
    (("   ( ", ACCENT_DIM), ("●", f"bold {ACCENT}"), (" )   ", ACCENT_DIM)),
    (("    ╱█╲    ", f"bold {ACCENT}"),),
    (("   ╱╲█╱╲   ", f"bold {ACCENT}"),),
    (("  ╱ ╱█╲ ╲  ", f"bold {ACCENT}"),),
    ((" ▔▔▔▔▔▔▔▔▔ ", f"bold {ACCENT}"),),
)
_TOWER_ASCII = ("   ( o )   ", "    /|\\    ", "   /\\|/\\   ", "  / /|\\ \\  ", " --------- ")


@dataclass
class Terminal:
    """Consola de `rich` más los glifos que admite su codificación."""

    console: Console
    glyphs: Glyphs

    @property
    def unicode(self) -> bool:
        return self.glyphs is UNICODE

    def print(self, *renderables: RenderableType) -> None:
        for renderable in renderables:
            self.console.print(renderable)


def _is_utf8(stream: TextIO) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
    return encoding == "utf8"


def make_terminal(stream: TextIO | None = None, *, width: int | None = None) -> Terminal:
    """Consola lista para escribir en *stream* (por defecto, la salida estándar).

    No se fuerza UTF-8 sobre una salida que no lo es: si quien la recibe
    (p. ej. un `| Out-File` de PowerShell) espera cp1252, bytes UTF-8 se
    leerían como basura. Se adapta lo que se escribe, no la codificación.
    """
    import sys

    target: TextIO = stream if stream is not None else sys.stdout
    unicode_ok = _is_utf8(target)
    if not unicode_ok:
        reconfigure = getattr(target, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    console = Console(file=target, highlight=False, emoji=False, width=width)
    return Terminal(console=console, glyphs=UNICODE if unicode_ok else ASCII)


# ─── Marca ──────────────────────────────────────────────────────────────────


def banner(term: Terminal, tagline: str = "Attack Surface Management · triaje por IA") -> Text:
    """Logo completo: solo al dar la bienvenida (`init`)."""
    right = [
        Text(_WORDMARK[0], style=f"bold {TEXT}") if term.unicode else Text(
            "A T A L A Y A", style=f"bold {TEXT}"
        ),
        Text(_WORDMARK[1], style=f"bold {TEXT}") if term.unicode else Text(""),
        Text(""),
        Text(tagline.replace("·", term.glyphs.sep), style=MUTED),
        Text(f"v{__version__}", style=MUTED),
    ]
    text = Text()
    for index in range(len(_TOWER)):
        if index:
            text.append("\n")
        text.append("  ")
        if term.unicode:
            for chunk, style in _TOWER[index]:
                text.append(chunk, style=style)
        else:
            text.append(_TOWER_ASCII[index], style=f"bold {ACCENT}")
        text.append("    ")
        text.append_text(right[index])
    return text


def header(term: Terminal, command: str) -> Text:
    """Cabecera de una línea para el resto de comandos (la marca no se repite)."""
    mark = "▲" if term.unicode else "^"
    text = Text("  ")
    text.append(f"{mark} ", style=f"bold {ACCENT}")
    text.append("A T A L A Y A", style=f"bold {TEXT}")
    text.append(f"   {command} {term.glyphs.sep} v{__version__}", style=MUTED)
    return text


# ─── Piezas de pantalla ─────────────────────────────────────────────────────


def rule(term: Terminal) -> Rule:
    """Línea horizontal; en ASCII, con guiones (rich no lo sustituye solo)."""
    return Rule(characters="─" if term.unicode else "-", style=LINE)


def step(term: Terminal, number: int, total: int, title: str) -> Group:
    """Cabecera de paso: «PASO n DE total · TÍTULO» y el progreso a la derecha."""
    grid = Table.grid(expand=True, padding=0)
    grid.add_column()
    grid.add_column(justify="right")
    left = Text("  ")
    left.append(f"PASO {number} DE {total}", style=f"bold {ACCENT}")
    left.append(f"  {term.glyphs.sep}  ", style=MUTED)
    left.append(title.upper(), style=f"bold {TEXT}")
    dots = Text()
    for index in range(1, total + 1):
        if index < number:
            dots.append(f"{term.glyphs.dot_on} ", style=ACCENT_DIM)
        elif index == number:
            dots.append(f"{term.glyphs.dot_on} ", style=f"bold {ACCENT}")
        else:
            dots.append(f"{term.glyphs.dot_off} ", style=LINE)
    grid.add_row(left, dots)
    return Group(Text(""), grid, rule(term))


def note(text: str) -> Text:
    """Texto explicativo, apagado."""
    return Text(f"  {text}", style=MUTED)


def prompt_text(term: Terminal, label: str, hint: str = "") -> Text:
    """La parte fija de una pregunta: «› Etiqueta (pista): »."""
    text = Text("  ")
    text.append(f"{term.glyphs.prompt} ", style=f"bold {ACCENT}")
    text.append(label, style=TEXT)
    if hint:
        text.append(f" {hint}", style=MUTED)
    text.append(": ", style=TEXT)
    return text


def answered(term: Terminal, label: str, answer: str, hint: str = "") -> Text:
    """Una pregunta ya respondida, tal como queda en pantalla."""
    text = prompt_text(term, label, hint)
    text.append(answer, style=f"bold {TEXT}")
    return text


def icon(term: Terminal, kind: Kind) -> Text:
    """Icono de estado con su color semántico."""
    glyph, color = {
        "ok": (term.glyphs.ok, OK),
        "warn": (term.glyphs.warn, WARN),
        "err": (term.glyphs.err, ERROR),
        "info": (term.glyphs.info, ACCENT),
        "off": (term.glyphs.off, MUTED),
    }[kind]
    return Text(glyph, style=f"bold {color}")


def status(term: Terminal, kind: Kind, text: str, detail: str = "", elapsed: str = "") -> Table:
    """Línea de resultado: icono, qué pasó, detalle apagado y duración a la derecha."""
    grid = Table.grid(expand=True, padding=0)
    grid.add_column(width=4)
    grid.add_column(ratio=1)
    grid.add_column(justify="right", width=10)
    body = Text(text, style=TEXT)
    if detail:
        body.append(f"  {detail}", style=MUTED)
    mark = Text("  ")
    mark.append_text(icon(term, kind))
    grid.add_row(mark, body, Text(elapsed, style=MUTED))
    return grid


def choices(rows: list[tuple[str, str, str, bool]]) -> Padding:
    """Menú numerado: (tecla, opción, descripción, recomendada)."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style=f"bold {ACCENT}", justify="right")
    table.add_column(style=f"bold {TEXT}")
    table.add_column(style=MUTED)
    table.add_column()
    for key, label, description, recommended in rows:
        badge = Text(" RECOMENDADO ", style=f"bold #070a0f on {ACCENT}") if recommended else Text("")
        table.add_row(key, label, description, badge)
    return Padding(table, (0, 0, 0, 4))


def summary(term: Terminal, rows: list[tuple[str, str, Kind]]) -> Padding:
    """Panel «RESUMEN» con lo que se va a escribir."""
    table = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    table.add_column(style=MUTED, width=15)
    table.add_column(style=TEXT)
    table.add_column(justify="right", width=3)
    for key, value, kind in rows:
        table.add_row(key, value, icon(term, kind))
    panel = Panel(
        table,
        title=Text(" RESUMEN ", style=f"bold {ACCENT}"),
        title_align="left",
        border_style=LINE,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    return Padding(panel, (0, 2))


def panel(content: RenderableType, *, accent: bool = False) -> Padding:
    """Panel con borde: neutro, o con el acento apagado para el cierre."""
    return Padding(
        Panel(
            content,
            border_style=ACCENT_DIM if accent else LINE,
            box=box.ROUNDED,
            padding=(1, 2) if accent else (0, 2),
        ),
        (0, 2),
    )


def next_steps(term: Terminal, title: str, steps: list[tuple[str, str]]) -> Padding:
    """Cierre: mensaje principal y comandos numerados para seguir."""
    done = Text()
    done.append(f"{term.glyphs.ok} ", style=f"bold {OK}")
    done.append(title, style=f"bold {TEXT}")
    table = Table.grid(padding=(0, 2))
    table.add_column(style=f"bold {ACCENT}", justify="right")
    table.add_column(style=f"bold {TEXT}")
    table.add_column(style=MUTED)
    for index, (command, description) in enumerate(steps, start=1):
        table.add_row(str(index), command, description)
    return panel(Group(done, Text(""), Text("Siguientes pasos", style=MUTED), table), accent=True)


def format_elapsed(milliseconds: int | None) -> str:
    """«142 ms» o «1,2 s», con coma decimal (la herramienta habla español)."""
    if milliseconds is None:
        return ""
    if milliseconds < 1000:
        return f"{milliseconds} ms"
    return f"{milliseconds / 1000:.1f} s".replace(".", ",")
