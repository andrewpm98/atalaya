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
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import streamlit as st

API_URL = os.getenv("ATALAYA_API_URL", "http://localhost:8000")

_SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "unknown": "⚪",
}

st.set_page_config(page_title="Atalaya ASM", page_icon="🛡️", layout="wide")


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


# ─── Componentes de render ──────────────────────────────────────────────────


def render_finding(finding: dict[str, Any]) -> None:
    icono = _SEVERITY_ICON.get(finding["severity"], "⚪")
    st.markdown(f"{icono} **{finding['finding_type']}** — severidad: `{finding['severity']}`")
    st.caption(finding["evidence"])
    if finding["impact"]:
        st.write(f"**Impacto:** {finding['impact']}")
    if finding["remediation"]:
        st.write(f"**Remediación:** {finding['remediation']}")
    st.divider()


def _sin_triar(scan: dict[str, Any]) -> int:
    return sum(1 for a in scan["assets"] for f in a["findings"] if f["severity"] == "unknown")


def render_scan_detail(scan: dict[str, Any]) -> None:
    st.markdown(f"### Escaneo #{scan['id']} — {scan['domain']}")

    if scan["errors"]:
        st.warning("Incidencias del escaneo: " + "; ".join(scan["errors"]))

    pendientes = _sin_triar(scan)
    if pendientes > 0 and st.button(
        f"🧠 Triar con IA ({pendientes} pendiente(s))", key=f"triage-{scan['id']}"
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

    total_findings = sum(len(a["findings"]) for a in scan["assets"])
    col1, col2, col3 = st.columns(3)
    col1.metric("Activos", len(scan["assets"]))
    col2.metric("Hallazgos", total_findings)
    col3.metric("Sin triar", _sin_triar(scan))

    # `st.download_button` necesita los bytes ya en mano al renderizarse —
    # a diferencia de un botón normal, no admite generar el contenido en su
    # propio callback. Por eso el PDF se pide a la API en un botón previo y
    # se guarda en `session_state`, y solo entonces aparece el botón de
    # descarga, con el mismo criterio de dos pasos que el triaje de arriba.
    report_key = f"report_bytes_{scan['id']}"
    if st.button("📄 Generar informe PDF", key=f"report-{scan['id']}"):
        with st.spinner("Generando el informe..."):
            pdf_bytes = api_get_bytes(f"/scans/{scan['id']}/report")
        if pdf_bytes is not None:
            st.session_state[report_key] = pdf_bytes

    if st.session_state.get(report_key) is not None:
        st.download_button(
            "⬇️ Descargar informe PDF",
            data=st.session_state[report_key],
            file_name=f"atalaya_informe_{scan['domain']}_{scan['id']}.pdf",
            mime="application/pdf",
            key=f"download-{scan['id']}",
        )

    st.markdown("#### Activos")
    if not scan["assets"]:
        st.caption("Sin activos.")
    for asset in scan["assets"]:
        etiqueta = f"{asset['hostname']} — {asset['status']}"
        if asset["leaks_internal_addressing"]:
            etiqueta += " ⚠️ direccionamiento interno"
        with st.expander(etiqueta):
            st.write(f"IPs: {', '.join(asset['ip_addresses']) or '—'}")
            st.write(f"Fuentes: {', '.join(asset['sources']) or '—'}")
            puertos = ", ".join(str(p) for p in asset["open_ports"])
            st.write(f"Puertos abiertos: {puertos or '—'}")
            if not asset["findings"]:
                st.caption("Sin hallazgos.")
            for finding in asset["findings"]:
                render_finding(finding)


# ─── Página ─────────────────────────────────────────────────────────────────

st.title("🛡️ Atalaya — Attack Surface Management")
st.caption("Descubre, prioriza y explica tu superficie de exposición con IA.")

with st.sidebar:
    st.header("Estado del sistema")
    try:
        with httpx.Client(timeout=3) as client:
            r = client.get(f"{API_URL}/health")
        if r.status_code == 200:
            st.success(f"API conectada · v{r.json().get('version', '?')}")
        else:
            st.warning(f"API respondió {r.status_code}")
    except httpx.HTTPError:
        st.error("API no disponible")
    st.caption(f"`{API_URL}`")

tab_nuevo, tab_escaneos, tab_preguntar = st.tabs(
    ["Nuevo escaneo", "Escaneos", "Preguntar"]
)

with tab_nuevo:
    st.subheader("Lanzar un escaneo")
    st.caption(
        "Enumera subdominios (Certificate Transparency + DNS) y los persiste. "
        "Pasa por `SCAN_ALLOWLIST`: solo se admiten dominios autorizados."
    )
    with st.form("nuevo_escaneo"):
        domain = st.text_input("Dominio", placeholder="ejemplo.com")
        resolve = st.checkbox("Verificar por DNS", value=True)
        enviado = st.form_submit_button("Escanear")

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
    st.subheader("Escaneos realizados")
    scans = api_get("/scans") or []

    if not scans:
        st.info("Todavía no hay escaneos. Lanza uno en la pestaña «Nuevo escaneo».")
    else:
        st.dataframe(
            [
                {
                    "id": s["id"],
                    "dominio": s["domain"],
                    "estado": s["status"],
                    "iniciado": s["started_at"],
                    "incidencias": len(s["errors"]),
                }
                for s in scans
            ],
            hide_index=True,
        )

        opciones = {f"#{s['id']} — {s['domain']} ({s['status']})": s["id"] for s in scans}
        etiqueta_elegida = st.selectbox("Ver detalle de", options=list(opciones.keys()))
        scan_id = opciones[etiqueta_elegida]

        detalle = api_get(f"/scans/{scan_id}")
        if detalle is not None:
            render_scan_detail(detalle)

with tab_preguntar:
    st.subheader("Consulta en lenguaje natural")
    st.caption(
        "Responde sobre el último escaneo completado de un dominio. El "
        "modelo solo ve los datos de ese escaneo — no inventa fuera de él."
    )
    with st.form("preguntar"):
        domain_q = st.text_input("Dominio", placeholder="ejemplo.com", key="ask_domain")
        question = st.text_area(
            "Pregunta", placeholder="¿Algún activo filtra direccionamiento interno?"
        )
        preguntado = st.form_submit_button("Preguntar")

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
                st.markdown(f"**Escaneo #{respuesta['scan_id']} — {respuesta['domain']}**")
                st.write(respuesta["answer"])
