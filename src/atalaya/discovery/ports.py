"""Escaneo ligero de puertos/servicios sobre hosts descubiertos (Paso 2)."""

from __future__ import annotations


async def scan_ports(host: str, ports: list[int] | None = None) -> list[int]:
    """Devuelve la lista de puertos abiertos en *host*.

    TODO(Paso 2): conexiones asíncronas con timeout; puertos comunes por defecto.
    """
    raise NotImplementedError
