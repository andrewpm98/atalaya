"""Script de verificación visual del dashboard. No forma parte del proyecto.

Levanta un navegador real contra un dashboard ya en marcha y captura las
pantallas que hay que mirar para juzgar el aspecto. No lanza escaneos por
defecto (tardan minutos y hacen red): reutiliza los que ya hay en la base de
datos. Con `--scan` sí lanza uno real contra `scanme.nmap.org`.

Uso:
    python _shot.py [--port 8502] [--out .claude/shots] [--scan] [--triage]
"""

from __future__ import annotations

import argparse
import pathlib

from playwright.sync_api import Page, sync_playwright

VIEWPORT = {"width": 1600, "height": 1000}


def _settle(page: Page, timeout: int = 90000) -> None:
    """Espera a que Streamlit termine de reejecutar el script.

    Mientras dura una reejecución, Streamlit marca los elementos con
    `data-stale="true"` y los pinta atenuados. Sin esta espera las capturas
    salen a medio gas y se juzga un fotograma que el usuario nunca ve.
    """
    page.wait_for_function(
        "() => !document.querySelector('[data-stale=\"true\"]')", timeout=timeout
    )
    page.wait_for_timeout(700)


def _snap(page: Page, out: pathlib.Path, name: str, full: bool = True) -> None:
    _settle(page)
    page.screenshot(path=str(out / f"{name}.png"), full_page=full)
    print("  ->", name)


def _pick_scan(page: Page, etiqueta_contiene: str) -> None:
    """Elige en el selectbox la primera opción que contenga el texto dado."""
    caja = page.get_by_role("combobox").first
    caja.click()
    page.wait_for_timeout(500)
    caja.fill(etiqueta_contiene)
    page.wait_for_timeout(1200)
    caja.press("Enter")
    page.wait_for_timeout(2000)
    _settle(page)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8502)
    ap.add_argument("--out", default=".claude/shots")
    ap.add_argument("--scan", action="store_true", help="lanza un escaneo real (lento)")
    ap.add_argument("--triage", action="store_true", help="pulsa el botón de triaje con IA")
    ap.add_argument("--ask", action="store_true", help="lanza una pregunta real a la IA")
    args = ap.parse_args()

    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    url = f"http://127.0.0.1:{args.port}"

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT)
        page.goto(url, wait_until="networkidle")
        # `_settle` no sirve en la primera ejecución (aún no hay nada marcado
        # como obsoleto): se espera a que el script llegue a pintar las
        # pestañas, que es su último elemento de primer nivel.
        page.wait_for_selector('[data-testid="stTabs"]', timeout=90000)
        page.wait_for_timeout(2500)

        # 01 — primera impresión: masthead, barra lateral, pestaña por defecto.
        _snap(page, out, "01_inicio", full=False)
        _snap(page, out, "01b_inicio_full")

        # 02 — barra lateral aislada (donde estaba el solape N/A · SCORE).
        page.get_by_test_id("stSidebar").screenshot(path=str(out / "02_sidebar.png"))
        print("  -> 02_sidebar")

        if args.scan:
            page.get_by_placeholder("ejemplo.com").first.fill("scanme.nmap.org")
            page.get_by_role("button", name="Escanear").click()
            page.wait_for_selector("text=completado", timeout=180000)
            page.wait_for_timeout(1200)
            _snap(page, out, "03_escaneo_resultado")

        # 04 — listado + detalle del escaneo más reciente.
        page.get_by_role("tab", name="Escaneos").click()
        page.wait_for_selector('[data-testid="stExpander"]', timeout=60000)
        page.wait_for_timeout(2500)
        _snap(page, out, "04_escaneos_viewport", full=False)
        _snap(page, out, "04b_escaneos_full")

        # 05 — un activo desplegado (chips de IP/puertos + hallazgos).
        exps = page.get_by_test_id("stExpander")
        if exps.count():
            exps.first.click()
            page.wait_for_timeout(1200)
            exps.first.scroll_into_view_if_needed()
            page.wait_for_timeout(600)
            _snap(page, out, "05_activo_desplegado", full=False)
            _snap(page, out, "05b_activo_desplegado_full")

        if args.triage:
            boton = page.get_by_role("button", name="Triar con IA")
            if boton.count():
                boton.first.click()
                page.wait_for_selector("text=triado(s)", timeout=600000)
                page.wait_for_timeout(2000)
                page.locator(".atl-scanhead").first.scroll_into_view_if_needed()
                page.wait_for_timeout(600)
                _snap(page, out, "06_triado_viewport", full=False)
                _snap(page, out, "06b_triado_full")
            else:
                print("  !! no hay botón de triaje (ya está todo triado)")

        # 07 — un escaneo grande (github.com: 117 activos) para ver la densidad.
        try:
            _pick_scan(page, "github.com")
            _snap(page, out, "07_escaneo_grande_viewport", full=False)
            page.get_by_test_id("stExpander").first.click()
            page.wait_for_timeout(1200)
            _snap(page, out, "07b_escaneo_grande_activo")
        except Exception as exc:  # noqa: BLE001 - script de usar y tirar
            print("  !! no se pudo abrir github.com:", exc)

        # 08 — pestaña Preguntar (con `--ask`, con una respuesta real de la IA).
        page.get_by_role("tab", name="Preguntar").click()
        page.wait_for_timeout(2000)
        _snap(page, out, "08_preguntar", full=False)
        if args.ask:
            page.get_by_placeholder("ejemplo.com").last.fill("scanme.nmap.org")
            page.get_by_placeholder("¿Algún activo").fill(
                "¿Qué riesgo real tienen las cabeceras que faltan en este dominio?"
            )
            page.get_by_role("button", name="Preguntar").click()
            page.wait_for_selector("text=Escaneo #", timeout=180000)
            page.wait_for_timeout(1500)
            _snap(page, out, "09_respuesta", full=False)
            _snap(page, out, "09b_respuesta_full")

        browser.close()
    print("OK ->", out)


if __name__ == "__main__":
    main()
