"""Dashboard web de Atalaya (Streamlit).

Aplicación web (requisito de la práctica). Consume exclusivamente la API
REST — nunca la base de datos ni los módulos de `core`/`discovery`
directamente — porque es, precisamente, un cliente más de la API, igual que
la CLI o cualquier integración externa (ver `docs/ARQUITECTURA.md`, 2.6).

Permite: lanzar un escaneo, listar los realizados, explorar activos y
hallazgos de cada uno, triar con IA un escaneo, y preguntar en lenguaje
natural sobre un dominio ya escaneado.

**Nota sobre `async`:** el resto del proyecto es asíncrono porque el
descubrimiento lanza decenas de operaciones de red en paralelo (Paso 2).
Aquí no hay ese patrón: Streamlit reejecuta el script completo en cada
interacción del usuario y atiende una petición HTTP a la vez, así que
`httpx.Client` síncrono es la elección correcta — envolver cada llamada en
`asyncio.run()` añadiría complejidad sin nada que paralelizar.

**Nota sobre el aspecto:** la piel visual vive en `_CSS`, inyectado una sola
vez al arrancar el script, y en `.streamlit/config.toml` (colores base del
tema). Se separan porque no cubren lo mismo: el CSS reescribe el DOM que
Streamlit genera en HTML, mientras que `st.dataframe` se pinta sobre un
`<canvas>` (glide-data-grid) al que **ninguna regla CSS llega** — sus
colores solo se pueden tocar desde el tema. Ver el comentario sobre
limitaciones al final de `_CSS`.
"""

from __future__ import annotations

import os
from html import escape
from typing import Any

import httpx
import streamlit as st

API_URL = os.getenv("ATALAYA_API_URL", "http://localhost:8000")

#: Etiqueta monoespaciada por severidad. Sustituye a los emoji de semáforo
#: de la versión anterior: la misma señal (y el mismo orden de lectura) con
#: una estética de consola en vez de la de un chat, y sin depender de cómo
#: pinte cada sistema operativo un emoji de color.
_SEVERITY_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "unknown": "N/A",
}

#: Orden de gravedad decreciente. Se usa para ordenar hallazgos y activos:
#: lo crítico va arriba, lo informativo abajo, para que nunca compitan por
#: la atención del lector.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")
_SEVERITY_RANK = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}

#: Peso de cada severidad en el score de riesgo (0-100).
#:
#: **Fuente de verdad: `src/atalaya/reporting/generator.py::_RISK_WEIGHTS`.**
#: Los valores están duplicados aquí a propósito, no importados: el
#: dashboard es un cliente HTTP puro de la API (ver el docstring del módulo)
#: y no importa código del backend ni siquiera para una constante. El precio
#: de esa independencia es esta nota: **si cambias un peso allí, cámbialo
#: aquí**, o el número que ve el usuario en pantalla contradirá al del PDF
#: que se descarga de ese mismo escaneo.
_RISK_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "unknown": 0}

#: Cortes de banda del score: (límite superior exclusivo, etiqueta, clase CSS).
#: Un solo hallazgo crítico (25) ya sale de la banda baja; dos (50) entran en
#: la alta, coherente con la proporción de pesos que documenta
#: `reporting/generator.py`.
_SCORE_BANDS = (
    (25, "RIESGO BAJO", "low"),
    (50, "RIESGO MEDIO", "medium"),
    (75, "RIESGO ALTO", "high"),
    (101, "RIESGO CRÍTICO", "critical"),
)

st.set_page_config(
    page_title="ATALAYA · Attack Surface Management",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ─── Piel visual ────────────────────────────────────────────────────────────

#: CSS propio. Se inyecta **una sola vez**, al principio del script, y toda
#: la paleta sale de las variables de `:root` — para repintar la herramienta
#: entera basta con tocar ese bloque, no hay hexadecimales sueltos repartidos
#: por las reglas.
#:
#: Los selectores están escritos contra el DOM real de Streamlit 1.63, que
#: migró sus widgets de BaseWeb a react-aria: las pestañas ya no son
#: `button[data-baseweb="tab"]` sino `[data-testid="stTab"][role="tab"]`, y
#: las entradas de texto/select exponen `*RootElement`/`[role="group"]` en
#: vez de `[data-baseweb="input"]`. Un selector obsoleto no da error, la
#: regla simplemente no pinta nada — por eso conviene revisarlos con el
#: navegador abierto y no de memoria al subir de versión.
#:
#: **Cuidado con los comentarios de este bloque:** `st.html()` sanea el HTML
#: con DOMPurify, que borra entera cualquier etiqueta cuyo texto contenga
#: algo con forma de etiqueta HTML (defensa contra mXSS). Escribir «`<p>`» o
#: «`<input>`» dentro de un comentario CSS **tumba la hoja de estilos
#: completa**, sin error ni aviso: la aplicación aparece sin pintar. Por eso
#: aquí se habla de «párrafo» o «campo» y nunca se escribe una etiqueta.
_CSS = """
<style>
/* Las tipografías se piden con `@import` y no con una etiqueta de enlace
   porque el saneado de `st.html()` borra esas etiquetas: el enlace nunca
   llegaba al documento y las fuentes caían en la alternativa del sistema
   sin que se notase. Dentro de la hoja de estilos sí sobrevive. */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap');

:root {
  /* Superficies: casi negro azulado, tres niveles de elevación. */
  --bg:            #070a0f;
  --bg-panel:      #0d1117;
  --bg-elev:       #131a23;
  --bg-input:      #0a0f16;
  --bg-bar:        #090d13;

  /* Trazos. El CSS de Streamlit usa bordes de 1px por todas partes; aquí
     se recolorean para que el chasis se lea como una rejilla técnica. */
  --line:          #1b2430;
  --line-strong:   #2b3846;

  /* Texto. */
  --fg:            #e4edf6;
  --fg-dim:        #8b9bad;
  --fg-faint:      #5a6b7d;

  /* Acento único (frío). Todo lo interactivo y toda métrica neutra. */
  --accent:        #00c8e8;
  --accent-soft:   rgba(0, 200, 232, 0.14);
  --accent-line:   rgba(0, 200, 232, 0.42);

  /* Severidad. El rojo NO aparece en ningún otro sitio: ni en botones, ni
     en bordes decorativos, ni en cabeceras. Solo severidad crítica. */
  --sev-critical:  #ff4d4d;
  --sev-high:      #ff9640;
  --sev-medium:    #e3c341;
  --sev-low:       #4f9dfb;
  --sev-unknown:   #66798c;
  --ok:            #39d353;

  --mono: 'JetBrains Mono', 'Cascadia Mono', 'Consolas', ui-monospace, monospace;
  --sans: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif;
}

/* ── Chasis ───────────────────────────────────────────────────────────── */

html, body, [data-testid="stAppViewContainer"], .stApp {
  background: var(--bg);
  color: var(--fg);
  font-family: var(--sans);
}

/* Streamlit resta 1rem al contenedor de cada bloque markdown para cancelar
   el margen inferior del párrafo que normalmente lo cierra. Nuestro HTML no
   acaba en párrafo, así que ese -1rem se comía 16px de alto real y cada
   bloque se solapaba con el siguiente (se veía en la barra lateral: «N/A»
   pisando «SCORE»). `.atl-blk` los devuelve, y `flow-root` impide que el
   margen del último hijo se colapse fuera del envoltorio y se pierdan otra
   vez. Ver `_html()`. */
.atl-blk { display: flow-root; margin-bottom: 1rem; }

/* Trama de fondo: una rejilla de 1px muy tenue. Es textura de instrumento,
   no ilustración — no añade elementos ni tapa nada. */
[data-testid="stAppViewContainer"] {
  background-image:
    linear-gradient(rgba(255,255,255,0.016) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.016) 1px, transparent 1px);
  background-size: 64px 64px, 64px 64px;
}

/* La barra multicolor y la cabecera por defecto son la firma visual de
   Streamlit; fuera. La cabecera se deja como banda transparente para no
   perder el botón de plegar la barra lateral. */
[data-testid="stDecoration"], [data-testid="stToolbar"], #MainMenu, footer {
  display: none !important;
}
header[data-testid="stHeader"] {
  background: transparent !important;
  height: 0;
}

[data-testid="stMainBlockContainer"], .block-container {
  padding: 1.1rem 2.2rem 4rem 2.2rem;
  max-width: 1480px;
}

/* Ritmo vertical. Streamlit separa cada elemento 1rem, pensado para una
   página de lectura; una consola de seguridad quiere densidad: el aire lo
   ponen los rótulos de sección, no el hueco entre cajas contiguas. */
[data-testid="stMainBlockContainer"] [data-testid="stVerticalBlock"] { gap: 0.55rem; }
[data-testid="stForm"] [data-testid="stVerticalBlock"] { gap: 0.8rem; }

h1, h2, h3, h4, h5 { font-family: var(--sans); letter-spacing: -0.01em; }

/* Código en línea (`hostname`) = dato técnico: monoespaciado y en acento. */
[data-testid="stMarkdownContainer"] code, .stMarkdown code {
  font-family: var(--mono);
  font-size: 0.80rem;
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid var(--accent-line);
  border-radius: 2px;
  padding: 0.05rem 0.34rem;
}

/* ── Masthead ─────────────────────────────────────────────────────────── */

/* Se sangra en negativo hasta los bordes del contenedor principal para que
   se lea como la barra superior de una aplicación y no como un título
   suelto dentro del lienzo. */
.atl-masthead {
  display: flex; align-items: flex-end; justify-content: space-between;
  gap: 1rem; flex-wrap: wrap;
  background: linear-gradient(180deg, var(--bg-panel) 0%, var(--bg-bar) 100%);
  border-bottom: 1px solid var(--line-strong);
  margin: -1.1rem -2.2rem 1.3rem -2.2rem;
  padding: 0.95rem 2.2rem 0.8rem 2.2rem;
}
.atl-wordmark {
  font-family: var(--mono); font-weight: 700; font-size: 1.5rem;
  letter-spacing: 0.30em; color: var(--fg); line-height: 1;
}
.atl-wordmark::before {
  content: "◈"; color: var(--accent);
  margin-right: 0.55rem; font-size: 1.05rem; vertical-align: 0.12em;
}
.atl-tagline {
  font-family: var(--mono); font-size: 0.64rem; letter-spacing: 0.24em;
  color: var(--fg-faint); text-transform: uppercase; margin-top: 0.42rem;
}
.atl-masthead-meta {
  font-family: var(--mono); font-size: 0.62rem; letter-spacing: 0.16em;
  color: var(--fg-faint); text-transform: uppercase; text-align: right;
  line-height: 1.7;
}
.atl-masthead-meta b { color: var(--fg-dim); font-weight: 500; }

/* ── Pestañas: control segmentado de consola ──────────────────────────── */
/* Streamlit 1.63 pinta las pestañas con react-aria: `[data-testid="stTab"]`
   con `role="tab"`, y el subrayado de la activa es un div aparte
   (`.react-aria-SelectionIndicator`). No queda nada de BaseWeb. */

[data-testid="stTabs"] [role="tablist"] {
  gap: 2px; background: var(--bg-panel);
  border: 1px solid var(--line); border-radius: 3px;
  padding: 3px; display: inline-flex; width: fit-content;
}
[data-testid="stTabs"] > div[data-orientation="horizontal"] {
  border-bottom: none !important; margin-bottom: 1.3rem;
}
[data-testid="stTab"] {
  background: transparent; color: var(--fg-faint);
  border-radius: 2px; padding: 0.4rem 1.15rem;
}
[data-testid="stTab"] [data-testid="stMarkdownContainer"] p {
  font-family: var(--mono); font-size: 0.71rem; font-weight: 500;
  letter-spacing: 0.15em; text-transform: uppercase; color: inherit;
}
[data-testid="stTab"]:hover { color: var(--fg); background: var(--bg-elev); }
[data-testid="stTab"][aria-selected="true"] {
  background: var(--accent-soft); color: var(--accent);
  box-shadow: inset 0 0 0 1px var(--accent-line);
}
/* El subrayado de react-aria sobra: la pestaña activa ya se distingue por
   el relleno de acento del control segmentado. */
[data-testid="stTab"] .react-aria-SelectionIndicator { display: none !important; }
[data-testid="stTabs"] [role="tabpanel"] { padding-top: 0; }

/* ── Barra lateral: franja de estado compacta ─────────────────────────── */

[data-testid="stSidebar"] {
  background: var(--bg-panel);
  border-right: 1px solid var(--line);
  width: 268px !important; min-width: 268px !important;
}
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] { padding: 1.15rem 1rem 1rem 1rem; }
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: 0.55rem; }

.atl-side-h {
  font-family: var(--mono); font-size: 0.6rem; letter-spacing: 0.22em;
  color: var(--fg-faint); text-transform: uppercase;
  border-bottom: 1px solid var(--line);
  padding-bottom: 0.4rem; margin: 0 0 0.55rem 0;
}
/* Cada bloque de la barra lateral es un `st.markdown` distinto, así que no
   son hermanos en el DOM y no hay selector que los separe: el rótulo que
   abre una sección que no es la primera lo pide explícitamente. */
.atl-side-h--gap { margin-top: 0.9rem; }
.atl-side-kv {
  display: flex; justify-content: space-between; gap: 0.5rem;
  font-family: var(--mono); font-size: 0.68rem;
  color: var(--fg-dim); padding: 0.18rem 0;
}
.atl-side-kv span:last-child { color: var(--fg); }
.atl-legend { display: flex; flex-direction: column; gap: 0.3rem; }
.atl-legend-row {
  display: flex; align-items: center; gap: 0.5rem;
  font-family: var(--mono); font-size: 0.64rem; color: var(--fg-dim);
}
.atl-legend-row i { width: 3px; height: 11px; border-radius: 1px; flex: none; }
.atl-legend-row b { font-weight: 500; letter-spacing: 0.08em; width: 2.7rem; }

/* ── Avisos (st.success / warning / error / info) ─────────────────────── */

/* Misma medida que la tarjeta de score: un aviso a 1.500px de ancho para
   una línea de texto se lee como un banner de cookies, no como el registro
   de incidencias de un escaneo. */
[data-testid="stAlert"] { background: transparent; max-width: 1080px; }
[data-testid="stAlertContainer"] {
  background: var(--bg-elev) !important;
  border: 1px solid var(--line-strong) !important;
  border-left-width: 2px !important;
  border-radius: 2px; padding: 0.5rem 0.8rem;
  font-size: 0.80rem; color: var(--fg-dim) !important;
}
[data-testid="stAlertContainer"] p { font-size: 0.80rem; margin: 0; }
/* Al quitarle el margen al párrafo hay que quitar también el -1rem con que
   Streamlit lo compensaba, o la caja del aviso queda 16px más corta que su
   propio texto y este se desborda por arriba y por abajo. */
[data-testid="stAlertContainer"] [data-testid="stMarkdownContainer"] {
  margin-bottom: 0 !important;
}
/* El tipo de aviso solo se distingue por el filo izquierdo. Hay que colgarlo
   del contenedor, que es quien tiene el borde, mirando qué clase de
   contenido lleva dentro: Streamlit pinta el tipo en el hijo
   (`stAlertContentError`, ...) y no lo expone como atributo en el padre. Con
   la regla puesta sobre el hijo —que no tiene borde— los cuatro tipos se
   veían idénticos: un error y un éxito eran la misma caja gris.
   El rojo aquí no es decoración: es la única señal de que algo ha fallado. */
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]) {
  border-left-color: var(--ok) !important;
}
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentInfo"]) {
  border-left-color: var(--accent) !important;
}
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]) {
  border-left-color: var(--sev-medium) !important;
}
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]) {
  border-left-color: var(--sev-critical) !important;
}
[data-testid="stSidebar"] [data-testid="stAlertContainer"] {
  font-family: var(--mono); font-size: 0.65rem; padding: 0.4rem 0.6rem;
}
[data-testid="stSidebar"] [data-testid="stAlertContainer"] p {
  font-size: 0.65rem; letter-spacing: 0.02em;
}

/* ── Botones ──────────────────────────────────────────────────────────── */
/* Fondo plano + trazo de acento. Nunca rojo: el rojo es severidad. */

[data-testid="stBaseButton-secondary"],
[data-testid="stBaseButton-primary"],
[data-testid="stBaseButton-secondaryFormSubmit"],
[data-testid="stBaseButton-primaryFormSubmit"],
[data-testid="stDownloadButton"] button {
  font-family: var(--mono) !important;
  font-size: 0.70rem !important; font-weight: 500 !important;
  letter-spacing: 0.13em; text-transform: uppercase;
  background: var(--bg-elev) !important;
  color: var(--fg) !important;
  border: 1px solid var(--line-strong) !important;
  border-radius: 2px !important;
  padding: 0.42rem 1.05rem !important;
  min-height: 0; transition: none;
}
[data-testid="stBaseButton-secondary"]:hover,
[data-testid="stBaseButton-secondaryFormSubmit"]:hover,
[data-testid="stDownloadButton"] button:hover {
  background: var(--accent-soft) !important;
  border-color: var(--accent-line) !important;
  color: var(--accent) !important;
}
[data-testid="stBaseButton-primaryFormSubmit"],
[data-testid="stBaseButton-primary"] {
  background: var(--accent-soft) !important;
  border-color: var(--accent-line) !important;
  color: var(--accent) !important;
}
[data-testid="stBaseButton-primaryFormSubmit"]:hover,
[data-testid="stBaseButton-primary"]:hover {
  background: rgba(0, 200, 232, 0.24) !important;
}
[data-testid="stBaseButton-secondary"]:focus,
[data-testid="stBaseButton-secondaryFormSubmit"]:focus { box-shadow: none !important; }

/* ── Entradas ─────────────────────────────────────────────────────────── */
/* El marco lo pinta el `*RootElement` (texto/área) o el `[role="group"]`
   del combobox; el campo de dentro va transparente para que no haya dos
   cajas superpuestas. */

[data-testid="stTextInputRootElement"],
[data-testid="stTextAreaRootElement"],
[data-testid="stSelectbox"] [role="group"] {
  background: var(--bg-input) !important;
  border: 1px solid var(--line-strong) !important;
  border-radius: 2px !important;
  box-shadow: none !important;
}
[data-testid="stTextInputRootElement"]:focus-within,
[data-testid="stTextAreaRootElement"]:focus-within,
[data-testid="stSelectbox"] [role="group"]:focus-within {
  border-color: var(--accent-line) !important;
}
[data-testid="stTextInputField"],
[data-testid="stTextArea"] textarea,
[data-testid="stSelectbox"] input {
  font-family: var(--mono) !important; font-size: 0.82rem !important;
  background: transparent !important; border: none !important;
  color: var(--fg) !important;
}
[data-testid="stTextInputField"]::placeholder,
[data-testid="stTextArea"] textarea::placeholder,
[data-testid="stSelectbox"] input::placeholder { color: var(--fg-faint) !important; }
[data-testid="stSelectbox"] { max-width: 470px; }
[data-testid="stSelectbox"] button svg { fill: var(--fg-faint); }

[data-testid="stWidgetLabel"] p {
  font-family: var(--mono) !important; font-size: 0.62rem !important;
  letter-spacing: 0.16em; text-transform: uppercase;
  color: var(--fg-faint) !important; font-weight: 500 !important;
}
/* Un formulario de una herramienta no es un cuestionario a pantalla
   completa: se acota para que el campo tenga el ancho del dato que espera. */
[data-testid="stForm"] {
  background: var(--bg-panel); border: 1px solid var(--line);
  border-radius: 3px; padding: 1rem 1.15rem 0.9rem 1.15rem;
  max-width: 620px;
}
/* La casilla es el único `div` sin `data-testid` dentro del `label`. */
[data-testid="stCheckbox"] label > div:not([data-testid]) {
  background: var(--bg-input) !important;
  border: 1px solid var(--line-strong) !important;
  border-radius: 2px !important;
}
[data-testid="stCheckbox"] label[data-selected="true"] > div:not([data-testid]) {
  background: var(--accent-soft) !important; border-color: var(--accent-line) !important;
}
[data-testid="stCheckbox"] label > div:not([data-testid]) svg { stroke: var(--accent); }
[data-testid="stCheckbox"] [data-testid="stWidgetLabel"] p {
  font-family: var(--mono) !important; font-size: 0.71rem !important;
  color: var(--fg-dim) !important; letter-spacing: 0.04em; text-transform: none;
}
[role="listbox"] {
  background: var(--bg-elev) !important;
  border: 1px solid var(--line-strong) !important; border-radius: 2px !important;
}
[role="option"] {
  font-family: var(--mono) !important; font-size: 0.78rem !important;
  color: var(--fg-dim) !important;
}
[role="option"][data-selected="true"], [role="option"][data-focused="true"] {
  background: var(--accent-soft) !important; color: var(--accent) !important;
}

/* ── Métricas ─────────────────────────────────────────────────────────── */

/* Tres cifras de contexto, no tres tarjetas: se dejan al ancho de su
   contenido (van en un contenedor horizontal) para que no compitan con el
   score, que es la métrica principal. */

[data-testid="stMetric"] {
  background: var(--bg-panel); border: 1px solid var(--line);
  border-radius: 3px; padding: 0.42rem 0.9rem 0.48rem 0.9rem;
  min-width: 132px;
}
/* El contenedor horizontal reparte el ancho entre sus hijos; aquí no
   interesa: cada contador debe medir lo que mide su cifra. */
[class*="st-key-atl-cifras"] > div { flex: 0 0 auto !important; width: auto !important; }
[data-testid="stMetricLabel"] p {
  font-family: var(--mono) !important; font-size: 0.57rem !important;
  letter-spacing: 0.2em; text-transform: uppercase; color: var(--fg-faint) !important;
}
[data-testid="stMetricValue"], [data-testid="stMetricValue"] p {
  font-family: var(--mono) !important; font-weight: 700 !important;
  font-size: 1.3rem !important; color: var(--fg) !important; line-height: 1.3;
}

/* ── Hero: score de riesgo ────────────────────────────────────────────── */

.atl-hero {
  display: flex; align-items: stretch; gap: 1.5rem; flex-wrap: wrap;
  background: var(--bg-panel);
  border: 1px solid var(--line); border-left: 3px solid var(--band);
  border-radius: 3px; padding: 0.85rem 1.2rem 0.9rem 1.2rem;
  margin-bottom: 0.5rem; max-width: 1080px;
}
.atl-hero-low      { --band: var(--accent);       }
.atl-hero-medium   { --band: var(--sev-medium);   }
.atl-hero-high     { --band: var(--sev-high);     }
.atl-hero-critical { --band: var(--sev-critical); }

.atl-hero-main {
  min-width: 178px; padding-right: 1.5rem;
  border-right: 1px solid var(--line);
}
.atl-hero-label {
  font-family: var(--mono); font-size: 0.58rem; letter-spacing: 0.26em;
  color: var(--fg-faint); text-transform: uppercase;
}
.atl-hero-num {
  font-family: var(--mono); font-weight: 700; font-size: 3.3rem; line-height: 1.05;
  color: var(--band); margin-top: 0.05rem; letter-spacing: -0.035em;
}
.atl-hero-den {
  font-size: 1rem; font-weight: 400; color: var(--fg-faint); letter-spacing: 0;
}
.atl-hero-band {
  display: inline-block; margin-top: 0.3rem;
  font-family: var(--mono); font-size: 0.6rem; font-weight: 700;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--band); border: 1px solid var(--band);
  border-radius: 2px; padding: 0.13rem 0.5rem;
}
.atl-hero-side {
  flex: 1 1 380px; display: flex; flex-direction: column; justify-content: center;
  min-width: 0;
}
/* Barra con marcas cada 25 puntos: el mismo corte que las bandas de riesgo,
   para que un score se sitúe de un vistazo sin leer el número. */
.atl-gauge {
  position: relative; height: 9px; background: var(--bg-input);
  border: 1px solid var(--line); border-radius: 2px; overflow: hidden;
}
.atl-gauge-fill { display: block; height: 100%; background: var(--band); }
.atl-gauge::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: repeating-linear-gradient(
    90deg, transparent 0 calc(25% - 1px), var(--line-strong) calc(25% - 1px) 25%);
}
.atl-gauge-scale {
  display: flex; justify-content: space-between;
  font-family: var(--mono); font-size: 0.55rem; color: var(--fg-faint);
  letter-spacing: 0.1em; margin-top: 0.16rem;
}
/* Celdas al ancho de su contenido: estiradas a todo el panel parecían un
   gráfico vacío en vez de un recuento. */
.atl-dist { display: flex; gap: 0.32rem; flex-wrap: wrap; margin-top: 0.75rem; }
.atl-dist-cell {
  flex: 1 1 0; min-width: 62px;
  background: var(--bg-input);
  border: 1px solid var(--line); border-top: 2px solid var(--c);
  border-radius: 2px; padding: 0.26rem 0.5rem 0.3rem 0.5rem;
}
.atl-dist-cell.is-zero { opacity: 0.38; }
.atl-dist-n {
  font-family: var(--mono); font-weight: 700; font-size: 1.05rem;
  color: var(--c); line-height: 1.2;
}
.atl-dist-k {
  font-family: var(--mono); font-size: 0.54rem; letter-spacing: 0.16em;
  color: var(--fg-faint); text-transform: uppercase;
}
.atl-hero-note {
  font-family: var(--mono); font-size: 0.6rem; color: var(--fg-faint);
  letter-spacing: 0.04em; margin-top: 0.62rem;
}

/* ── Cabecera de un escaneo ───────────────────────────────────────────── */

.atl-scanhead {
  display: flex; align-items: baseline; gap: 0.85rem; flex-wrap: wrap;
  border-bottom: 1px solid var(--line); padding-bottom: 0.6rem; margin-bottom: 0.45rem;
}
.atl-scanhead-id {
  font-family: var(--mono); font-size: 0.68rem; font-weight: 700; letter-spacing: 0.16em;
  color: var(--accent); border: 1px solid var(--accent-line);
  background: var(--accent-soft); border-radius: 2px; padding: 0.12rem 0.45rem;
}
.atl-scanhead-domain {
  font-family: var(--mono); font-size: 1.28rem; font-weight: 700;
  color: var(--fg); letter-spacing: -0.01em;
}
.atl-scanhead-meta {
  margin-left: auto; display: flex; gap: 1.1rem; flex-wrap: wrap;
  font-family: var(--mono); font-size: 0.62rem; letter-spacing: 0.1em;
  color: var(--fg-faint); text-transform: uppercase;
}
.atl-scanhead-meta b { color: var(--fg-dim); font-weight: 500; }

/* ── Rótulos de sección ───────────────────────────────────────────────── */

.atl-sec {
  display: flex; align-items: center; gap: 0.75rem;
  font-family: var(--mono); font-size: 0.63rem; letter-spacing: 0.24em;
  color: var(--fg-faint); text-transform: uppercase;
  margin: 1.5rem 0 0.7rem 0;
}
.atl-sec::after { content: ""; flex: 1; height: 1px; background: var(--line); }
.atl-sec em { font-style: normal; color: var(--accent); letter-spacing: 0.1em; }
/* Doble clase a propósito: la regla propia de Streamlit para los párrafos
   de un bloque markdown es `[data-testid=...] p`, más específica que una
   clase suelta, y se comía el tamaño de texto de abajo. */
.atl-blk p.atl-note {
  font-family: var(--sans); font-size: 0.79rem; line-height: 1.55;
  color: var(--fg-dim); max-width: 96ch; margin: 0 0 0.9rem 0;
}
.atl-note code {
  font-family: var(--mono); font-size: 0.74rem; color: var(--accent); background: none; border: none;
}

/* ── Hallazgos ────────────────────────────────────────────────────────── */

.atl-finding {
  border: 1px solid var(--line); border-left: 2px solid var(--c);
  background: var(--bg-input); border-radius: 2px;
  padding: 0.52rem 0.75rem 0.58rem 0.75rem; margin-bottom: 0.4rem;
}
.atl-sev-critical { --c: var(--sev-critical); }
.atl-sev-high     { --c: var(--sev-high);     }
.atl-sev-medium   { --c: var(--sev-medium);   }
.atl-sev-low      { --c: var(--sev-low);      }
.atl-sev-unknown  { --c: var(--sev-unknown);  }

/* Los hallazgos críticos y altos pesan más: fondo elevado y tipo mayor.
   Los informativos quedan deliberadamente apagados para no competir. */
.atl-finding.atl-sev-critical, .atl-finding.atl-sev-high { background: var(--bg-elev); }
.atl-finding.atl-sev-low .atl-finding-type,
.atl-finding.atl-sev-unknown .atl-finding-type { color: var(--fg-dim); }

.atl-finding-top { display: flex; align-items: center; gap: 0.6rem; }
.atl-tag {
  font-family: var(--mono); font-size: 0.58rem; font-weight: 700; letter-spacing: 0.14em;
  color: var(--c); border: 1px solid var(--c); border-radius: 2px;
  padding: 0.05rem 0.34rem; flex: none; min-width: 3.1rem; text-align: center;
}
.atl-finding.atl-sev-critical .atl-tag { background: rgba(255, 77, 77, 0.13); }
.atl-finding-type {
  font-family: var(--mono); font-size: 0.84rem; font-weight: 500; color: var(--fg);
  word-break: break-all;
}
/* Doble clase por el mismo motivo que `.atl-note`. `max-width` en `ch`: una
   línea de 1.400px es ilegible por larga, y la evidencia es lo que de verdad
   se lee de un hallazgo. */
.atl-blk p.atl-finding-ev {
  font-family: var(--mono); font-size: 0.735rem; color: var(--fg-dim);
  margin: 0.3rem 0 0 0; line-height: 1.5; max-width: 118ch;
}
.atl-kv { display: flex; gap: 0.6rem; margin: 0.3rem 0 0 0; line-height: 1.5; }
.atl-kv-k {
  font-family: var(--mono); font-size: 0.55rem; letter-spacing: 0.16em;
  color: var(--fg-faint); text-transform: uppercase;
  flex: none; width: 5.4rem; padding-top: 0.16rem;
}
/* Impacto y remediación los escribe el modelo y son prosa, no dato: van en
   sans y con la línea acotada. Sin el tope, una explicación de tres frases
   se estiraba a 1.100px y dejaba de leerse de corrido. */
.atl-kv-v {
  font-family: var(--sans); font-size: 0.79rem; line-height: 1.55;
  color: var(--fg); max-width: 88ch;
}

/* ── Activos (expanders) ──────────────────────────────────────────────── */

[data-testid="stExpander"] details {
  background: var(--bg-panel); border: 1px solid var(--line);
  border-left: 2px solid var(--line-strong);
  border-radius: 3px; margin-bottom: 0.28rem;
}
[data-testid="stExpander"] summary {
  padding: 0.38rem 0.7rem; background: transparent;
}
[data-testid="stExpander"] summary:hover { background: var(--bg-elev); }
[data-testid="stExpander"] summary p {
  font-family: var(--mono) !important; font-size: 0.78rem !important; color: var(--fg-dim);
}
[data-testid="stExpander"] summary code {
  background: none !important; border: none !important; padding: 0 !important;
  color: var(--fg) !important; font-size: 0.81rem !important; font-weight: 500;
}
[data-testid="stExpander"] summary [data-testid="stIconMaterial"] {
  font-size: 1rem !important; color: var(--fg-faint) !important;
}
[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
  padding: 0.25rem 0.7rem 0.6rem 0.7rem;
  border-top: 1px solid var(--line);
}

/* Filo izquierdo del activo = su peor severidad, el mismo lenguaje que las
   tarjetas de hallazgo. La clase la pone `st.container(key=...)`, que es API
   pública de Streamlit (`st-key-` + la clave) — a diferencia de los
   `data-testid`, que son internos. */
[class*="st-key-atl-asset-critical"] [data-testid="stExpander"] details {
  border-left-color: var(--sev-critical);
}
[class*="st-key-atl-asset-high"] [data-testid="stExpander"] details {
  border-left-color: var(--sev-high);
}
[class*="st-key-atl-asset-medium"] [data-testid="stExpander"] details {
  border-left-color: var(--sev-medium);
}
[class*="st-key-atl-asset-low"] [data-testid="stExpander"] details {
  border-left-color: var(--sev-low);
}
[class*="st-key-atl-asset-unknown"] [data-testid="stExpander"] details {
  border-left-color: var(--sev-unknown);
}
[class*="st-key-atl-asset-none"] [data-testid="stExpander"] details {
  border-left-color: var(--line);
}
[class*="st-key-atl-asset-"] [data-testid="stVerticalBlock"] { gap: 0; }

.atl-chips { display: flex; gap: 0.7rem; flex-wrap: wrap; margin: 0.55rem 0 0.7rem 0; }
.atl-chipset { display: flex; align-items: center; gap: 0.3rem; flex-wrap: wrap; }
.atl-chipset > b {
  font-family: var(--mono); font-size: 0.55rem; letter-spacing: 0.16em;
  color: var(--fg-faint); text-transform: uppercase; font-weight: 500; margin-right: 0.12rem;
}
.atl-chip {
  font-family: var(--mono); font-size: 0.68rem; color: var(--fg);
  background: var(--bg-input); border: 1px solid var(--line-strong);
  border-radius: 2px; padding: 0.06rem 0.38rem;
}
.atl-chip-empty { color: var(--fg-faint); border-style: dashed; }
.atl-chip-port { color: var(--accent); border-color: var(--accent-line); }
.atl-subsec {
  font-family: var(--mono); font-size: 0.55rem; letter-spacing: 0.2em;
  color: var(--fg-faint); text-transform: uppercase; margin: 0.55rem 0 0.32rem 0;
}

/* ── Tabla de escaneos ────────────────────────────────────────────────── */

[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 3px; }

/* ── Varios ───────────────────────────────────────────────────────────── */

[data-testid="stCaptionContainer"] p, [data-testid="stCaptionContainer"] {
  font-family: var(--mono) !important; font-size: 0.66rem !important;
  color: var(--fg-faint) !important; letter-spacing: 0.06em;
}
[data-testid="stSpinner"] p {
  font-family: var(--mono) !important; font-size: 0.72rem !important;
  letter-spacing: 0.1em; color: var(--accent) !important;
}
[data-testid="stSpinnerIcon"] {
  border-top-color: var(--accent) !important; border-right-color: var(--accent) !important;
  border-bottom-color: var(--line-strong) !important;
  border-left-color: var(--line-strong) !important;
}
/* Respuesta de «Preguntar»: es prosa del modelo, con su propio markdown
   (negritas, listas), así que no se puede meter en un contenedor propio sin
   perder el formato — el panel se pinta sobre el contenedor, que lleva
   clase porque `st.container(key=...)` la añade (`st-key-` + la clave). */
[class*="st-key-atl-answer"] {
  background: var(--bg-panel); border: 1px solid var(--line);
  border-left: 2px solid var(--accent-line);
  border-radius: 3px; padding: 0.8rem 1.15rem 0.85rem 1.15rem;
  max-width: 920px;
}
/* El tema pone la monoespaciada como familia base (la necesita el canvas de
   la tabla), así que aquí hay que devolver la sans a todo lo que el modelo
   escribe en prosa — párrafos, viñetas y negritas — o la respuesta se lee
   como un volcado de consola. */
[class*="st-key-atl-answer"] [data-testid="stMarkdownContainer"] p,
[class*="st-key-atl-answer"] [data-testid="stMarkdownContainer"] li,
[class*="st-key-atl-answer"] [data-testid="stMarkdownContainer"] strong {
  font-family: var(--sans); font-size: 0.85rem; color: var(--fg-dim); line-height: 1.6;
}
[class*="st-key-atl-answer"] [data-testid="stMarkdownContainer"] strong {
  color: var(--fg); font-weight: 600;
}
[class*="st-key-atl-answer"] [data-testid="stMarkdownContainer"] ul { margin: 0.2rem 0; }
[class*="st-key-atl-answer"] .atl-answer-head {
  font-family: var(--mono); font-size: 0.64rem; letter-spacing: 0.1em;
  color: var(--fg-faint); text-transform: none;
  padding-bottom: 0.45rem; margin-bottom: 0.2rem;
  border-bottom: 1px solid var(--line);
}
.atl-answer-head b {
  color: var(--accent); font-weight: 700;
  letter-spacing: 0.16em; text-transform: uppercase;
}
hr { border-color: var(--line); }
::-webkit-scrollbar { width: 9px; height: 9px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--line-strong); border-radius: 0; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-line); }
</style>
"""

# Limitaciones asumidas del restyling (documentadas en vez de hackeadas):
#
# 1. `st.dataframe` se pinta en un `<canvas>` (glide-data-grid). No hay
#    selector CSS que alcance una celda: su tipografía y sus colores salen
#    del tema de Streamlit, por eso existe `.streamlit/config.toml`. Forzar
#    una tabla HTML propia daría control total pero perdería el ordenado por
#    columna y el redimensionado nativos — mal cambio.
# 2. El `label` de `st.expander`/`st.metric` admite markdown pero no HTML,
#    así que la etiqueta de severidad de un activo usa los colores de
#    markdown de Streamlit (`:red[...]`), no las variables de `:root`.
# 3. Los `data-testid` son API interna de Streamlit y pueden cambiar entre
#    versiones mayores. Es el precio de restylear el framework; la
#    alternativa (un frontend propio) está fuera del plazo del proyecto.

st.html(_CSS)


# ─── Cliente de la API ──────────────────────────────────────────────────────


def api_get(path: str, **params: Any) -> Any | None:
    """GET contra la API. Devuelve `None` y muestra el error en la propia
    página si falla — nunca lanza excepción hacia el resto del script, para
    que un fallo puntual no tumbe todo el panel."""
    try:
        with httpx.Client(base_url=API_URL, timeout=120.0) as client:
            resp = client.get(path, params=params or None)
    except httpx.HTTPError as exc:
        st.error(f"No se pudo contactar con la API ({path}): {exc}")
        return None
    if resp.status_code >= 400:
        st.error(f"{path} → {resp.status_code}: {_detail(resp)}")
        return None
    return resp.json()


def api_post(path: str, json: dict[str, Any] | None = None) -> Any | None:
    """POST contra la API, mismo criterio de degradación que `api_get`."""
    try:
        with httpx.Client(base_url=API_URL, timeout=120.0) as client:
            resp = client.post(path, json=json)
    except httpx.HTTPError as exc:
        st.error(f"No se pudo contactar con la API ({path}): {exc}")
        return None
    if resp.status_code >= 400:
        st.error(f"{path} → {resp.status_code}: {_detail(resp)}")
        return None
    return resp.json()


def api_get_bytes(path: str) -> bytes | None:
    """GET contra la API devolviendo el cuerpo crudo, no JSON — para el PDF
    del informe (`/scans/{id}/report`). Mismo criterio de degradación que
    `api_get`: nunca lanza, informa el error en la propia página."""
    try:
        with httpx.Client(base_url=API_URL, timeout=120.0) as client:
            resp = client.get(path)
    except httpx.HTTPError as exc:
        st.error(f"No se pudo contactar con la API ({path}): {exc}")
        return None
    if resp.status_code >= 400:
        st.error(f"{path} → {resp.status_code}: {_detail(resp)}")
        return None
    return resp.content


def _detail(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("detail", resp.text))
    except ValueError:
        return resp.text


# ─── Score de riesgo ────────────────────────────────────────────────────────


def severity_counts(scan: dict[str, Any]) -> dict[str, int]:
    """Cuenta los hallazgos del escaneo por severidad.

    Una severidad desconocida (una que la API añadiera en el futuro y este
    cliente no conociese) se contabiliza como `unknown` en vez de romper el
    recuento: mismo criterio de degradación controlada que `api_get`.
    """
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for asset in scan["assets"]:
        for finding in asset["findings"]:
            sev = finding["severity"] if finding["severity"] in counts else "unknown"
            counts[sev] += 1
    return counts


def compute_risk_score(scan: dict[str, Any]) -> int:
    """Score de riesgo 0-100 del escaneo, calculado en el propio dashboard.

    `GET /scans/{id}` no expone un `risk_score`, pero sí la severidad de cada
    hallazgo, que es todo lo que necesita la fórmula. Se replica aquí la de
    `reporting/generator.py::_compute_risk_score()` — suma ponderada acotada
    a 100 — para que el número de la pantalla y el del PDF del mismo escaneo
    no puedan contradecirse (ver la nota de `_RISK_WEIGHTS`).

    Los hallazgos sin triar pesan 0: el score mide riesgo *confirmado por el
    triaje*, no volumen de trabajo pendiente. Por eso la tarjeta avisa
    aparte de cuántos quedan sin triar — un score bajo con 40 pendientes no
    significa lo mismo que un score bajo con todo triado.
    """
    counts = severity_counts(scan)
    total = sum(_RISK_WEIGHTS[sev] * n for sev, n in counts.items())
    return min(100, total)


def risk_band(score: int) -> tuple[str, str]:
    """(etiqueta, clase CSS) de la banda en la que cae un score."""
    for limite, etiqueta, clase in _SCORE_BANDS:
        if score < limite:
            return etiqueta, clase
    return _SCORE_BANDS[-1][1], _SCORE_BANDS[-1][2]


def render_risk_score(scan: dict[str, Any]) -> None:
    """Tarjeta principal del detalle: score grande, banda de color, reparto
    por severidad y aviso de pendientes de triar."""
    score = compute_risk_score(scan)
    etiqueta, clase = risk_band(score)
    counts = severity_counts(scan)

    celdas = "".join(
        f'<div class="atl-dist-cell{" is-zero" if counts[sev] == 0 else ""}" '
        f'style="--c: var(--sev-{sev})">'
        f'<div class="atl-dist-n">{counts[sev]}</div>'
        f'<div class="atl-dist-k">{_SEVERITY_TAG[sev]}</div>'
        f"</div>"
        for sev in _SEVERITY_ORDER
    )
    pendientes = counts["unknown"]
    nota = (
        f"{pendientes} hallazgo(s) sin triar no puntúan — el score subirá al triarlos"
        if pendientes
        else "Todos los hallazgos están triados: el score refleja el escaneo completo"
    )

    _html(
        f'<div class="atl-hero atl-hero-{clase}">'
        f'<div class="atl-hero-main">'
        f'<div class="atl-hero-label">Score de riesgo</div>'
        f'<div class="atl-hero-num">{score}<span class="atl-hero-den">/100</span></div>'
        f'<div class="atl-hero-band">{etiqueta}</div>'
        f"</div>"
        f'<div class="atl-hero-side">'
        f'<div class="atl-gauge"><span class="atl-gauge-fill" style="width:{score}%"></span></div>'
        f'<div class="atl-gauge-scale"><span>0</span><span>25</span><span>50</span>'
        f"<span>75</span><span>100</span></div>"
        f'<div class="atl-dist">{celdas}</div>'
        f'<div class="atl-hero-note">{escape(nota)}</div>'
        f"</div></div>"
    )


# ─── Componentes de render ──────────────────────────────────────────────────


def _html(markup: str) -> None:
    """Pinta HTML propio como un bloque markdown de Streamlit.

    El envoltorio `.atl-blk` no es decorativo: Streamlit le resta `1rem` de
    margen inferior al contenedor de todo bloque markdown, para cancelar el
    margen del último `<p>` que normalmente lo cierra. Nuestro HTML no acaba
    en `<p>`, así que ese `-1rem` recortaba 16px del alto real del bloque y
    cada uno se solapaba con el siguiente — se veía sobre todo en la barra
    lateral, con «N/A» pisando el rótulo «SCORE». La clase los devuelve (ver
    su regla en `_CSS`), y centralizarlo aquí evita tener que acordarse en
    cada llamada.
    """
    st.markdown(f'<div class="atl-blk">{markup}</div>', unsafe_allow_html=True)


def _seccion(titulo: str, extra: str = "") -> None:
    sufijo = f"<em>{escape(extra)}</em>" if extra else ""
    _html(f'<div class="atl-sec">{escape(titulo)}{sufijo}</div>')


def render_finding(finding: dict[str, Any]) -> None:
    """Renderiza un hallazgo. Genérico por diseño: no mira `finding_type`, de
    modo que un tipo nuevo en la API (p. ej. `subdomain_takeover_risk`) se
    pinta por este mismo camino sin tocar el dashboard."""
    sev = finding["severity"] if finding["severity"] in _SEVERITY_RANK else "unknown"
    partes = [
        f'<div class="atl-finding atl-sev-{sev}">',
        '<div class="atl-finding-top">',
        f'<span class="atl-tag">{_SEVERITY_TAG[sev]}</span>',
        f'<span class="atl-finding-type">{escape(str(finding["finding_type"]))}</span>',
        "</div>",
        f'<p class="atl-finding-ev">{escape(str(finding["evidence"]))}</p>',
    ]
    for clave, valor in (("Impacto", finding["impact"]), ("Remediación", finding["remediation"])):
        if valor:
            partes.append(
                f'<div class="atl-kv"><span class="atl-kv-k">{clave}</span>'
                f'<span class="atl-kv-v">{escape(str(valor))}</span></div>'
            )
    partes.append("</div>")
    _html("".join(partes))


def _chipset(etiqueta: str, valores: list[str], clase: str = "") -> str:
    if not valores:
        return (
            f'<div class="atl-chipset"><b>{escape(etiqueta)}</b>'
            f'<span class="atl-chip atl-chip-empty">ninguno</span></div>'
        )
    chips = "".join(f'<span class="atl-chip {clase}">{escape(str(v))}</span>' for v in valores)
    return f'<div class="atl-chipset"><b>{escape(etiqueta)}</b>{chips}</div>'


def _etiqueta_activo(asset: dict[str, Any]) -> str:
    """Título del expander de un activo. Markdown, no HTML: `st.expander` no
    admite HTML en el `label`, así que el hostname va en `backticks` (se
    restylean a monoespaciada en `_CSS`).

    Sin colores de markdown (`:red[...]`): los de Streamlit son los de su
    propia paleta, no los de `:root`, y mezclarlos rompía la coherencia de
    la escala de severidad. El color lo lleva el filo izquierdo del activo,
    que sí sale de la paleta propia (ver `render_asset`).
    """
    partes = [f"`{asset['hostname']}`", f"· {asset['status']}"]
    if asset["leaks_internal_addressing"]:
        partes.append("· LEAK INTERNO")
    counts: dict[str, int] = {}
    for finding in asset["findings"]:
        sev = finding["severity"] if finding["severity"] in _SEVERITY_RANK else "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        partes.append("· sin hallazgos")
    for sev in _SEVERITY_ORDER:
        if counts.get(sev):
            partes.append(f"· {_SEVERITY_TAG[sev]} {counts[sev]}")
    return " ".join(partes)


def _peor_severidad(asset: dict[str, Any]) -> int:
    """Rango de la peor severidad del activo (0 = crítica). Ordena la lista
    de activos: lo crítico arriba, el ruido abajo."""
    return min(
        (_SEVERITY_RANK.get(f["severity"], len(_SEVERITY_ORDER)) for f in asset["findings"]),
        default=len(_SEVERITY_ORDER),
    )


def render_asset(asset: dict[str, Any], indice: int) -> None:
    """Un activo, como fila plegable.

    Va envuelto en un `st.container(key=...)` porque la clave se convierte en
    una clase CSS (`st-key-<clave>`) y ahí es donde `_CSS` cuelga el color
    del filo izquierdo según la peor severidad del activo. Es API pública de
    Streamlit, a diferencia de los `data-testid` que usa el resto de la hoja
    de estilos; `indice` solo garantiza que la clave sea única.
    """
    rango = _peor_severidad(asset)
    peor = _SEVERITY_ORDER[rango] if rango < len(_SEVERITY_ORDER) else "none"
    with st.container(key=f"atl-asset-{peor}-{indice}"), st.expander(_etiqueta_activo(asset)):
        _html(
            '<div class="atl-chips">'
            + _chipset("IP", list(asset["ip_addresses"]))
            + _chipset("Puertos", [str(p) for p in asset["open_ports"]], "atl-chip-port")
            + _chipset("Fuentes", list(asset["sources"]))
            + "</div>"
        )
        if not asset["findings"]:
            _html('<div class="atl-subsec">Sin hallazgos registrados</div>')
            return

        ordenados = sorted(
            asset["findings"],
            key=lambda f: _SEVERITY_RANK.get(f["severity"], len(_SEVERITY_ORDER)),
        )
        prioritarios = [f for f in ordenados if f["severity"] in ("critical", "high")]
        resto = [f for f in ordenados if f["severity"] not in ("critical", "high")]
        for titulo, grupo in (("Prioritarios", prioritarios), ("Resto", resto)):
            if not grupo:
                continue
            if prioritarios and resto:
                _html(f'<div class="atl-subsec">{titulo} · {len(grupo)}</div>')
            for finding in grupo:
                render_finding(finding)


def _sin_triar(scan: dict[str, Any]) -> int:
    return sum(1 for a in scan["assets"] for f in a["findings"] if f["severity"] == "unknown")


def _marca_de_tiempo(valor: object) -> str:
    """`2026-09-22T02:16:53.026079` → `2026-09-22 02:16:53`.

    El ISO con microsegundos es ruido para quien lee: seis decimales de
    segundo no ayudan a situar un escaneo y ensanchan cualquier columna.
    """
    texto = str(valor or "—")
    return texto[:19].replace("T", " ")


def render_scan_detail(scan: dict[str, Any]) -> None:
    _html(
        f'<div class="atl-scanhead">'
        f'<span class="atl-scanhead-id">SCAN #{escape(str(scan["id"]))}</span>'
        f'<span class="atl-scanhead-domain">{escape(str(scan["domain"]))}</span>'
        f'<span class="atl-scanhead-meta">'
        f'<span>estado <b>{escape(str(scan["status"]))}</b></span>'
        f'<span>inicio <b>{escape(_marca_de_tiempo(scan["started_at"]))}</b></span>'
        f'<span>fin <b>{escape(_marca_de_tiempo(scan["finished_at"]))}</b></span>'
        f"</span></div>"
    )

    # El score y las métricas se reservan aquí pero se pintan al final: el
    # botón de triaje de más abajo puede sustituir `scan` por una versión
    # recién releída, y estas cifras tienen que reflejar *esa*. Mismo motivo
    # por el que el triaje no usa `st.rerun()`: no se puede reordenar el
    # código sin perder o el orden visual o la frescura del dato, así que se
    # separa el hueco (arriba) del relleno (abajo).
    hueco = st.container()

    if scan["errors"]:
        st.warning("Incidencias del escaneo: " + "; ".join(scan["errors"]))

    acciones = st.container(horizontal=True)

    pendientes = _sin_triar(scan)
    if pendientes > 0 and acciones.button(
        f"Triar con IA · {pendientes} pendiente(s)", key=f"triage-{scan['id']}", type="primary"
    ):
        with st.spinner("Consultando al modelo de IA..."):
            resultado = api_post(f"/scans/{scan['id']}/triage")
        if resultado is not None:
            st.success(f"{resultado['triaged']} hallazgo(s) triado(s).")
            if resultado["errors"]:
                st.warning("Fallos durante el triaje: " + "; ".join(resultado["errors"]))
            # Se relee el escaneo para reflejar las nuevas severidades en esta
            # misma ejecución, sin depender de `st.rerun()`: un rerun
            # inmediato descartaría los mensajes de éxito/aviso de arriba
            # antes de que el usuario llegue a verlos.
            actualizado = api_get(f"/scans/{scan['id']}")
            if actualizado is not None:
                scan = actualizado

    # `st.download_button` necesita los bytes ya en mano al renderizarse —
    # a diferencia de un botón normal, no admite generar el contenido en su
    # propio callback. Por eso el PDF se pide a la API en un botón previo y
    # se guarda en `session_state`, y solo entonces aparece el botón de
    # descarga, con el mismo criterio de dos pasos que el triaje de arriba.
    report_key = f"report_bytes_{scan['id']}"
    if acciones.button("Generar informe PDF", key=f"report-{scan['id']}"):
        with st.spinner("Generando el informe..."):
            pdf_bytes = api_get_bytes(f"/scans/{scan['id']}/report")
        if pdf_bytes is not None:
            st.session_state[report_key] = pdf_bytes

    if st.session_state.get(report_key) is not None:
        acciones.download_button(
            "Descargar informe PDF",
            data=st.session_state[report_key],
            file_name=f"atalaya_informe_{scan['domain']}_{scan['id']}.pdf",
            mime="application/pdf",
            key=f"download-{scan['id']}",
        )

    total_findings = sum(len(a["findings"]) for a in scan["assets"])
    with hueco:
        render_risk_score(scan)
        # Contenedor horizontal en vez de `st.columns(3)`: en columnas cada
        # métrica ocupa un tercio del ancho y se convierte en tres tarjetas
        # enormes que compiten con el score. Aquí quedan al ancho de su
        # contenido, como una tira de contadores.
        cifras = st.container(horizontal=True, key="atl-cifras")
        cifras.metric("Activos", len(scan["assets"]))
        cifras.metric("Hallazgos", total_findings)
        cifras.metric("Sin triar", _sin_triar(scan))

    _seccion("Activos", f"{len(scan['assets'])}")
    if not scan["assets"]:
        st.caption("Sin activos.")
    # Orden por peor severidad: un activo con un hallazgo crítico nunca debe
    # quedar por debajo de uno sin hallazgos solo por el orden alfabético.
    ordenados = sorted(scan["assets"], key=lambda a: (_peor_severidad(a), a["hostname"]))
    for indice, asset in enumerate(ordenados):
        render_asset(asset, indice)


# ─── Página ─────────────────────────────────────────────────────────────────

_html(
    '<div class="atl-masthead">'
    "<div>"
    '<div class="atl-wordmark">ATALAYA</div>'
    '<div class="atl-tagline">Attack Surface Management · Triaje asistido por IA</div>'
    "</div>"
    '<div class="atl-masthead-meta">'
    "<div>Descubrimiento <b>CT · DNS · Puertos · Cabeceras · TLS</b></div>"
    "<div>Priorización <b>LLM sobre evidencia verificada</b></div>"
    "</div></div>"
)

with st.sidebar:
    _html('<div class="atl-side-h">Estado del sistema</div>')
    try:
        with httpx.Client(timeout=3) as client:
            r = client.get(f"{API_URL}/health")
        if r.status_code == 200:
            st.success(f"API conectada · v{r.json().get('version', '?')}")
        else:
            st.warning(f"API respondió {r.status_code}")
    except httpx.HTTPError:
        st.error("API no disponible")
    _html(f'<div class="atl-side-kv"><span>endpoint</span><span>{escape(API_URL)}</span></div>')

    _html(
        '<div class="atl-side-h atl-side-h--gap">Severidad · peso</div>'
        '<div class="atl-legend">'
        + "".join(
            f'<div class="atl-legend-row"><i style="background: var(--sev-{sev})"></i>'
            f"<b>{_SEVERITY_TAG[sev]}</b><span>{peso} pts</span></div>"
            for sev, peso in _RISK_WEIGHTS.items()
        )
        + "</div>"
    )
    _html(
        '<div class="atl-side-h atl-side-h--gap">Bandas de score</div>'
        '<div class="atl-side-kv"><span>0 – 24</span><span>bajo</span></div>'
        '<div class="atl-side-kv"><span>25 – 49</span><span>medio</span></div>'
        '<div class="atl-side-kv"><span>50 – 74</span><span>alto</span></div>'
        '<div class="atl-side-kv"><span>75 – 100</span><span>crítico</span></div>'
    )

tab_nuevo, tab_escaneos, tab_preguntar = st.tabs(
    ["Nuevo escaneo", "Escaneos", "Preguntar"]
)

with tab_nuevo:
    _seccion("Lanzar un escaneo")
    _html(
        '<p class="atl-note">Enumera subdominios (Certificate Transparency + DNS) y los '
        "persiste. Pasa por <code>SCAN_ALLOWLIST</code>: solo se admiten dominios "
        "autorizados.</p>"
    )
    with st.form("nuevo_escaneo"):
        domain = st.text_input("Dominio", placeholder="ejemplo.com")
        resolve = st.checkbox("Verificar por DNS", value=True)
        enviado = st.form_submit_button("Escanear", type="primary")

    if enviado:
        if not domain.strip():
            st.warning("Introduce un dominio.")
        else:
            with st.spinner(f"Escaneando {domain}..."):
                scan = api_post("/scans", json={"domain": domain.strip(), "resolve": resolve})
            if scan is not None:
                total = sum(len(a["findings"]) for a in scan["assets"])
                st.success(
                    f"Escaneo #{scan['id']} completado: "
                    f"{len(scan['assets'])} activo(s), {total} hallazgo(s)."
                )
                if scan["errors"]:
                    st.warning("Incidencias: " + "; ".join(scan["errors"]))
                st.caption("Consulta el detalle en la pestaña «Escaneos».")

with tab_escaneos:
    scans = api_get("/scans") or []
    _seccion("Escaneos realizados", f"{len(scans)}")

    if not scans:
        st.info("Todavía no hay escaneos. Lanza uno en la pestaña «Nuevo escaneo».")
    else:
        st.dataframe(
            [
                {
                    "id": s["id"],
                    "dominio": s["domain"],
                    "estado": s["status"],
                    "iniciado": _marca_de_tiempo(s["started_at"]),
                    "incidencias": len(s["errors"]),
                }
                for s in scans
            ],
            hide_index=True,
            row_height=30,
            # `width="content"` en vez del ancho del contenedor: estirada, la
            # tabla repartía el sobrante entre cinco columnas y quedaban
            # celdas de 300px para un identificador de una cifra. Aquí mide lo
            # que miden sus datos, como la tabla de una consola.
            width="content",
            # Sin `width` por columna: con la tabla al ancho de su contenido,
            # los anchos fijos de Streamlit («small», «medium») recortaban
            # valores — «completed» se leía «complete». Auto ajusta cada
            # columna a su dato, que es justo lo que se busca aquí.
            column_config={
                "id": st.column_config.NumberColumn("ID"),
                "dominio": st.column_config.TextColumn("DOMINIO"),
                "estado": st.column_config.TextColumn("ESTADO"),
                "iniciado": st.column_config.TextColumn("INICIADO"),
                "incidencias": st.column_config.NumberColumn("INCID."),
            },
        )

        opciones = {f"#{s['id']} — {s['domain']} ({s['status']})": s["id"] for s in scans}
        etiqueta_elegida = st.selectbox("Ver detalle de", options=list(opciones.keys()))
        scan_id = opciones[etiqueta_elegida]

        detalle = api_get(f"/scans/{scan_id}")
        if detalle is not None:
            render_scan_detail(detalle)

with tab_preguntar:
    _seccion("Consulta en lenguaje natural")
    _html(
        '<p class="atl-note">Responde sobre el último escaneo completado de un dominio. El '
        "modelo solo ve los datos de ese escaneo — no inventa fuera de él.</p>"
    )
    with st.form("preguntar"):
        domain_q = st.text_input("Dominio", placeholder="ejemplo.com", key="ask_domain")
        question = st.text_area(
            "Pregunta", placeholder="¿Algún activo filtra direccionamiento interno?"
        )
        preguntado = st.form_submit_button("Preguntar", type="primary")

    if preguntado:
        if not domain_q.strip() or not question.strip():
            st.warning("Indica dominio y pregunta.")
        else:
            with st.spinner("Consultando al modelo de IA..."):
                respuesta = api_post(
                    "/findings/ask",
                    json={"domain": domain_q.strip(), "question": question.strip()},
                )
            if respuesta is not None:
                # La respuesta del modelo trae su propio markdown (negritas,
                # listas), así que se deja pasar por `st.write` en vez de
                # meterla en HTML propio, que la mostraría en crudo. El panel
                # lo pinta `_CSS` sobre la clase del contenedor.
                with st.container(key="atl-answer"):
                    _html(
                        '<div class="atl-answer-head">'
                        f"<b>Escaneo #{escape(str(respuesta['scan_id']))}</b>"
                        f" · {escape(str(respuesta['domain']))}</div>"
                    )
                    st.write(respuesta["answer"])
