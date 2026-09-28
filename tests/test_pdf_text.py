"""Pruebas del texto del modelo en el PDF (`reporting/pdf_text.py`)."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.config import settings
from atalaya.core import repository
from atalaya.reporting.generator import generate_report, render_html
from atalaya.reporting.pdf_text import markdown_inline, markdown_to_html, pdf_safe

ROOT = Path(__file__).resolve().parents[1]


# ─── Glifos ────────────────────────────────────────────────────────────────


def test_pdf_safe_sustituye_la_flecha_y_conserva_el_espanol() -> None:
    assert pdf_safe("CNAME → heroku") == "CNAME -> heroku"
    # Tildes, eñes, «», €, — y … existen en las fuentes del PDF: no se tocan.
    texto = "Añade «HSTS» — cuesta 0 € y evita esto…"
    assert pdf_safe(texto) == texto


def test_pdf_safe_nunca_deja_un_caracter_irrepresentable() -> None:
    resultado = pdf_safe("⚠️ ≥ 3 ✓ 漢 ⇒ ok")
    resultado.encode("cp1252")  # no lanza
    assert "?" in resultado  # lo que no tiene equivalente se ve, no queda en blanco


# ─── Markdown ──────────────────────────────────────────────────────────────


def test_markdown_formato_en_linea() -> None:
    html = str(markdown_inline("Falta **HSTS** en `api.github.com`, *revisar*"))
    assert html == "Falta <b>HSTS</b> en <code>api.github.com</code>, <i>revisar</i>"


def test_markdown_bloques_del_resumen_ejecutivo() -> None:
    html = str(
        markdown_to_html(
            "## Resumen Ejecutivo\n\n**Dominio:** github.com\n\n---\n\n"
            "Primer párrafo\nsigue aquí.\n\n- uno\n- dos\n\n1. a\n2. b"
        )
    )
    assert '<p class="md-h">Resumen Ejecutivo</p>' in html
    assert "<p><b>Dominio:</b> github.com</p>" in html
    assert "<hr/>" in html
    assert "<p>Primer párrafo sigue aquí.</p>" in html
    assert "<ul><li>uno</li><li>dos</li></ul>" in html
    assert "<ol><li>a</li><li>b</li></ol>" in html
    assert "#" not in html and "**" not in html


def test_markdown_no_toca_guiones_bajos_ni_asteriscos_dentro_de_codigo() -> None:
    html = str(markdown_inline("tipo hsts_missing y `a*b*c` y `**x**`"))
    assert "hsts_missing" in html
    assert "<code>a*b*c</code>" in html
    assert "<code>**x**</code>" in html


def test_markdown_escapa_el_html_del_modelo() -> None:
    """El texto del modelo nunca aporta etiquetas: una `<img>` haría que
    xhtml2pdf descargara esa URL al generar el PDF."""
    for render in (markdown_to_html, markdown_inline):
        html = str(render('<img src="http://interno/x"> y <script>x</script> **ok**'))
        assert "<img" not in html and "<script" not in html
        assert "&lt;img" in html
        assert "<b>ok</b>" in html


def test_markdown_de_texto_vacio() -> None:
    assert str(markdown_to_html(None)) == "" == str(markdown_inline(""))


# ─── Integración con la plantilla y xhtml2pdf ──────────────────────────────


async def _demo_scan(db_session: AsyncSession):  # type: ignore[no-untyped-def]
    sys.path.insert(0, str(ROOT / "scripts"))
    import seed_demo_data

    await seed_demo_data.seed(db_session, seed_demo_data.load_fixture(), reset=True)
    scan = await repository.get_scan(db_session, 2)
    assert scan is not None
    return scan


def _resumen_grabado() -> str:
    """El resumen ejecutivo real grabado para la demo, con su Markdown."""
    entries = json.loads((ROOT / "demo" / "ai_recordings.json").read_text(encoding="utf-8"))
    return next(
        e["response"]
        for e in entries["entries"].values()
        if e["label"].startswith("texto libre · Redacta el resumen ejecutivo")
    )


async def test_el_html_del_informe_de_la_demo_no_lleva_markdown_ni_flechas(
    db_session: AsyncSession,
) -> None:
    scan = await _demo_scan(db_session)
    html = render_html(scan, executive_summary=_resumen_grabado())

    assert "→" not in html
    assert "**" not in html
    assert "`" not in html
    assert "## " not in html
    assert "<code>" in html  # los identificadores entre acentos graves, en monoespaciada


async def test_el_pdf_de_la_demo_no_tiene_glifos_sin_fuente(
    db_session: AsyncSession,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """El síntoma real: xhtml2pdf avisaba «No font this document has can draw
    '→'» y la flecha salía en blanco. Se genera el PDF entero de la demo."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    scan = await _demo_scan(db_session)

    class _Resumen:
        async def complete(self, prompt: str, *, system: str | None = None) -> str:
            return _resumen_grabado() + "\n\nCNAME → proveedor ⚠️"

    with caplog.at_level(logging.WARNING, logger="xhtml2pdf"):
        path = await generate_report(scan, provider=_Resumen())  # type: ignore[arg-type]

    assert path.read_bytes().startswith(b"%PDF")
    avisos = [r.getMessage() for r in caplog.records if "can draw" in r.getMessage()]
    assert avisos == []
