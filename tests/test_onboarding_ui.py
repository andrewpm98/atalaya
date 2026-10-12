"""Pruebas de `onboarding/ui.py`: identidad visual y terminales sin UTF-8.

El estilo no se prueba (eso se mira, como el dashboard); se prueba lo que
rompería el comando: escribir en una salida cp1252 sin `UnicodeEncodeError`
(reproducido al maquetar) y que el modo ASCII no use caracteres que esa
codificación no tiene.
"""

from __future__ import annotations

import io

from atalaya.onboarding import ui


def _stream(encoding: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, newline="")


def _output(stream: io.TextIOWrapper) -> bytes:
    stream.flush()
    buffer = stream.buffer
    assert isinstance(buffer, io.BytesIO)
    return buffer.getvalue()


def _todas_las_piezas(term: ui.Terminal) -> None:
    term.print(
        ui.banner(term),
        ui.header(term, "doctor"),
        ui.step(term, 2, 5, "Base de datos"),
        ui.answered(term, "Dominios autorizados", "ejemplo.com", "(separados por comas)"),
        ui.status(term, "ok", "Conectado", "PostgreSQL 16.4", "142 ms"),
        ui.status(term, "warn", "Plan oss", "sin DNS"),
        ui.status(term, "err", "Clave rechazada"),
        ui.choices([("1", "SQLite local", "Sin instalar nada", True)]),
        ui.summary(term, [("IA", "Anthropic · sk-ant-…a1b2", "ok")]),
        ui.next_steps(term, "Atalaya está listo.", [("atalaya doctor", "Revisar")]),
        ui.rule(term),
    )


def test_una_salida_utf8_usa_el_logo_y_los_iconos_unicode() -> None:
    stream = _stream("utf-8")
    term = ui.make_terminal(stream, width=90)
    assert term.unicode

    _todas_las_piezas(term)

    salida = _output(stream).decode("utf-8")
    assert "▄▀█" in salida  # letras de bloque del nombre
    assert "✔" in salida


def test_una_salida_cp1252_pasa_a_ascii_sin_romper() -> None:
    """Con la salida redirigida en Windows, `rich` lanzaba UnicodeEncodeError
    al escribir `●`. En ASCII se pinta todo y es cp1252 válido de principio a fin."""
    stream = _stream("cp1252")
    term = ui.make_terminal(stream, width=90)
    assert not term.unicode

    _todas_las_piezas(term)

    salida = _output(stream).decode("cp1252")
    assert "A T A L A Y A" in salida
    assert "?" not in salida.replace("¿", "")  # ningún carácter sustituido
    assert "─" not in salida  # las reglas también pasan a guiones


def test_una_salida_sin_codificacion_conocida_tambien_usa_ascii() -> None:
    assert not ui.make_terminal(io.StringIO()).unicode


def test_la_duracion_se_escribe_en_espanol() -> None:
    assert ui.format_elapsed(142) == "142 ms"
    assert ui.format_elapsed(1234) == "1,2 s"
    assert ui.format_elapsed(None) == ""
