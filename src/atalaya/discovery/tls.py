"""Inspección de certificados y configuración TLS (Paso 2)."""

from __future__ import annotations


async def inspect_tls(host: str, port: int = 443) -> dict[str, object]:
    """Devuelve versión TLS, validez del certificado, emisor y caducidad.

    TODO(Paso 2): usar `cryptography` para parsear el certificado.
    """
    raise NotImplementedError
