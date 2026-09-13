"""Descubrimiento de subdominios vía Certificate Transparency (crt.sh) y DNS.

Se implementa en el Paso 2.
"""

from __future__ import annotations


async def enumerate_subdomains(domain: str) -> list[str]:
    """Devuelve los subdominios encontrados para *domain*.

    TODO(Paso 2): consultar crt.sh (CT logs) y resolución DNS.
    """
    raise NotImplementedError
