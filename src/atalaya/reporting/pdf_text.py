"""Texto del modelo → HTML apto para el PDF (xhtml2pdf).

Dos defectos que se veían en el informe de la demo (github.com):

1. **Markdown literal.** El modelo escribe Markdown aunque no se le pida:
   de 1232 textos reales (triaje, resumen ejecutivo), 530 llevan `código`
   entre acentos graves, y el resumen trae `##`, `**` y `---`. La plantilla
   los imprimía tal cual. `markdown_to_html` renderiza ese subconjunto.
2. **Glifos que no existen.** Las fuentes estándar del PDF (Helvetica,
   Courier) solo cubren Windows-1252; `→` (12 veces en la demo) salía en
   blanco. `pdf_safe` lo sustituye por un equivalente representable.

**Por qué un renderizador propio y no la librería `markdown`:** esa librería
deja pasar HTML crudo y convierte `![](url)` en `<img>`, y xhtml2pdf descarga
las imágenes al generar el PDF — el texto del modelo podría hacer que el
servidor pidiera una URL arbitraria. Aquí se escapa todo primero y solo
después se añaden las etiquetas del subconjunto: el texto del modelo nunca
aporta marcado propio.
"""

from __future__ import annotations

import re
import unicodedata

from markupsafe import Markup, escape

#: Sustitutos legibles para símbolos frecuentes fuera de Windows-1252.
_GLYPHS = {
    "→": "->",
    "←": "<-",
    "↔": "<->",
    "⇒": "=>",
    "⇐": "<=",
    "≥": ">=",
    "≤": "<=",
    "≠": "!=",
    "≈": "~",
    "✓": "OK",
    "✔": "OK",
    "✗": "X",
    "✘": "X",
    "⚠": "(!)",
    "️": "",  # selector de variante emoji: no se ve, solo acompaña
}


def pdf_safe(text: str) -> str:
    """Sustituye lo que las fuentes del PDF no pueden dibujar.

    Primero la tabla de sustitutos; si no está, la descomposición a ASCII
    (p. ej. letras con diacríticos fuera de Windows-1252); y si tampoco, `?`
    — visible, a diferencia del hueco en blanco que dejaría el PDF.
    """
    out: list[str] = []
    for char in text:
        if char in _GLYPHS:
            out.append(_GLYPHS[char])
            continue
        try:
            char.encode("cp1252")
        except UnicodeEncodeError:
            ascii_ = unicodedata.normalize("NFKD", char).encode("ascii", "ignore").decode()
            out.append(ascii_ or "?")
        else:
            out.append(char)
    return "".join(out)


_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
# Cursiva solo con asteriscos: con guiones bajos rompería identificadores
# como hsts_missing escritos sin acentos graves.
_ITALIC = re.compile(r"(?<![*\w])\*(?!\s)(.+?)(?<!\s)\*(?![*\w])")
_HEADING = re.compile(r"#{1,6}\s+(.*)")
_RULE = re.compile(r"[-*_]{3,}")
_BULLET = re.compile(r"[-*•]\s+(.*)")
_NUMBERED = re.compile(r"(\d+)[.)]\s+(.*)")


def _inline(text: str) -> str:
    """Formato en línea sobre texto ya escapado. El código se aparta antes para
    que un `**` o `*` dentro de acentos graves no se interprete."""
    escaped = str(escape(pdf_safe(text)))
    codes: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        codes.append(match.group(1))
        return f"\x00{len(codes) - 1}\x00"

    escaped = _CODE.sub(_stash, escaped)
    escaped = _BOLD.sub(r"<b>\1</b>", escaped)
    escaped = _ITALIC.sub(r"<i>\1</i>", escaped)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", escaped)


def markdown_to_html(text: str | None) -> Markup:
    """Bloques: párrafos, encabezados (en negrita), listas y separadores."""
    if not text:
        return Markup("")

    blocks: list[str] = []
    paragraph: list[str] = []
    items: list[str] = []
    list_tag = "ul"

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append(f"<p>{_inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    def flush_list() -> None:
        if items:
            body = "".join(f"<li>{item}</li>" for item in items)
            blocks.append(f"<{list_tag}>{body}</{list_tag}>")
            items.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            flush_paragraph()
            flush_list()
        elif _RULE.fullmatch(line):
            flush_paragraph()
            flush_list()
            blocks.append("<hr/>")
        elif heading := _HEADING.fullmatch(line):
            flush_paragraph()
            flush_list()
            blocks.append(f'<p class="md-h">{_inline(heading.group(1))}</p>')
        elif item := _BULLET.fullmatch(line) or _NUMBERED.fullmatch(line):
            flush_paragraph()
            tag = "ul" if item.re is _BULLET else "ol"
            if items and tag != list_tag:
                flush_list()
            list_tag = tag
            items.append(_inline(item.group(item.lastindex or 1)))
        else:
            flush_list()
            paragraph.append(line)
    flush_paragraph()
    flush_list()
    return Markup("".join(blocks))


def markdown_inline(text: str | None) -> Markup:
    """Para un campo corto que va tras una etiqueta («Impacto: ...»): formato
    en línea, y los saltos de línea como `<br/>` en vez de bloques, para no
    separar el texto de su etiqueta."""
    if not text:
        return Markup("")
    lines = [_inline(line.strip()) for line in text.splitlines() if line.strip()]
    return Markup("<br/>".join(lines))


def finalize(value: object) -> object:
    """`finalize` de Jinja: toda salida de la plantilla pasa por `pdf_safe`.

    Lo que ya es `Markup` (salida de los filtros de arriba) ya lo pasó y no se
    toca: volver a convertirlo a `str` haría que se escapara dos veces.
    """
    if isinstance(value, Markup) or not isinstance(value, str):
        return value
    return pdf_safe(value)
