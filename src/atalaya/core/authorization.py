"""Salvaguarda de autorización sobre los objetivos de escaneo.

Atalaya realiza reconocimiento sobre infraestructura. Este módulo centraliza
la comprobación de que un objetivo está autorizado, de forma que ninguna fase
de descubrimiento pueda ejecutarse sobre un dominio no permitido.

La política se define en `SCAN_ALLOWLIST` (.env):
  - vacía  → sin restricción (entornos de desarrollo controlados)
  - con valores → solo esos dominios y sus subdominios
"""

from __future__ import annotations

import re

from atalaya.config import settings
from atalaya.core.exceptions import InvalidTargetError, UnauthorizedTargetError

#: Etiquetas de 1-63 caracteres alfanuméricos/guion, separadas por puntos.
_DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def normalize_domain(domain: str) -> str:
    """Normaliza un dominio: minúsculas, sin espacios ni punto final.

    Raises:
        InvalidTargetError: si el resultado no es un nombre de dominio válido.
    """
    candidate = (domain or "").strip().lower().rstrip(".")
    candidate = candidate.removeprefix("*.")
    if not candidate or not _DOMAIN_RE.match(candidate):
        raise InvalidTargetError(f"Dominio no válido: {domain!r}")
    return candidate


def is_authorized(domain: str) -> bool:
    """Indica si *domain* puede escanearse según la allowlist configurada.

    Normaliza y valida el formato del dominio antes de mirar la allowlist,
    de modo que una entrada malformada nunca se considere autorizada aunque
    `SCAN_ALLOWLIST` esté vacía (sin restricción).

    Raises:
        InvalidTargetError: si el dominio está mal formado.
    """
    candidate = normalize_domain(domain)
    allowlist = settings.allowlist
    if not allowlist:
        return True
    return any(
        candidate == allowed or candidate.endswith(f".{allowed}") for allowed in allowlist
    )


def ensure_authorized(domain: str) -> str:
    """Valida y autoriza un objetivo, devolviéndolo normalizado.

    Raises:
        InvalidTargetError: si el dominio está mal formado.
        UnauthorizedTargetError: si no está en la allowlist.
    """
    candidate = normalize_domain(domain)
    if not is_authorized(candidate):
        raise UnauthorizedTargetError(
            f"El dominio {candidate!r} no está en SCAN_ALLOWLIST. "
            "Escanea solo infraestructura propia o con autorización explícita."
        )
    return candidate
