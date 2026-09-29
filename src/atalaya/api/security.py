"""Autenticación de la API por clave compartida en la cabecera `X-API-Key`.

Opcional por diseño: con `API_KEY` vacía (el valor por defecto) la API se
comporta exactamente igual que antes de existir este módulo. Así la demo sin
red, el stack de Docker sin `.env` y la suite siguen funcionando sin
configurar nada, y quien despliegue la API fuera de `127.0.0.1` activa la
protección con una sola variable.

Una clave compartida, no usuarios ni tokens: la herramienta tiene un único
operador y un único cliente propio (el dashboard). Un esquema con cuentas
añadiría una tabla, un flujo de login y rotación de tokens sin nada que
proteger que no cubra ya una clave larga y aleatoria.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from atalaya.config import settings

API_KEY_HEADER = "X-API-Key"

#: `auto_error=False`: sin la cabecera, FastAPI respondería 403 por su cuenta.
#: Se decide aquí para devolver 401 en los dos casos (ausente e incorrecta) y,
#: sobre todo, para no exigir nada cuando la autenticación está desactivada.
#: Declararla con `APIKeyHeader`, y no con un `Header()` suelto, es lo que la
#: publica en el esquema OpenAPI: `/docs` muestra el botón «Authorize».
_api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


async def require_api_key(provided: str | None = Security(_api_key_header)) -> None:
    """Dependencia que exige `X-API-Key` cuando `API_KEY` está configurada.

    Se lee `settings.api_key` en cada petición, no al importar el módulo, para
    que activar o desactivar la clave no dependa del orden de importación (y
    para que los tests puedan cambiarla con `monkeypatch`).

    La comparación usa `secrets.compare_digest`, de tiempo constante respecto
    al contenido: con `==`, la comparación se corta en el primer carácter
    distinto y el tiempo de respuesta revela cuántos caracteres iniciales
    acertó quien prueba claves, lo que permite adivinarla carácter a carácter.
    Se compara en bytes porque `compare_digest` rechaza `str` no ASCII con un
    `TypeError`, que aquí sería un 500 provocable desde fuera.
    """
    expected = settings.api_key
    if not expected:
        return
    if provided is None or not secrets.compare_digest(
        provided.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Falta la cabecera {API_KEY_HEADER} o no es válida.",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )
