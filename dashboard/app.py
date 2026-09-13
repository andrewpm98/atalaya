"""Dashboard web de Atalaya (Streamlit).

Aplicación web (requisito de la práctica). En el Paso 1 muestra el estado de
la API; en el Paso 6 se convierte en el panel completo: lanzar escaneos,
explorar activos y hallazgos, y consultar en lenguaje natural.
"""

from __future__ import annotations

import os

import httpx
import streamlit as st

API_URL = os.getenv("ATALAYA_API_URL", "http://localhost:8000")

st.set_page_config(page_title="Atalaya ASM", page_icon="🛡️", layout="wide")
st.title("🛡️ Atalaya — Attack Surface Management")
st.caption("Descubre, prioriza y explica tu superficie de exposición con IA.")

with st.sidebar:
    st.header("Estado del sistema")
    try:
        r = httpx.get(f"{API_URL}/health", timeout=3)
        if r.status_code == 200:
            st.success(f"API conectada · v{r.json().get('version', '?')}")
        else:
            st.warning(f"API respondió {r.status_code}")
    except Exception:
        st.error("API no disponible")

st.info(
    "Esqueleto inicial (Paso 1). El panel de escaneos, activos y hallazgos "
    "se construye en los Pasos 2–6."
)
