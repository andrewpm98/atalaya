"""Análisis de cabeceras de seguridad HTTP.

Núcleo reutilizado del proyecto previo `header-analyzer`. Se integra en el
Paso 2 adaptando su salida al modelo de hallazgos de Atalaya.
"""

from __future__ import annotations


async def analyze_headers(url: str) -> dict[str, object]:
    """Evalúa las cabeceras de seguridad de *url* (HSTS, CSP, X-Frame-Options...).

    TODO(Paso 2): portar la lógica de header-analyzer y normalizar la salida.
    """
    raise NotImplementedError
