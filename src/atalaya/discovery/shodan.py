"""Descubrimiento de subdominios vía la API DNS de Shodan.

Segunda fuente de enumeración pasiva, junto a Certificate Transparency
(`discovery/subdomains.py`), tal como anticipaba la deuda técnica de
CLAUDE.md: crt.sh solo revela lo que **se certificó alguna vez**; Shodan
indexa DNS observado por escaneo propio y otras fuentes, y puede aportar
hosts que nunca tuvieron un certificado TLS público.

Es una fuente **opcional**: a diferencia de crt.sh, que es la fuente
primaria y obligatoria, la ausencia de `SHODAN_API_KEY` no es un fallo — el
escaneo simplemente continúa con la cobertura que ya tenía. Con clave
configurada, sigue el mismo criterio de degradación controlada que crt.sh:
reintentos con backoff exponencial ante un fallo transitorio, e incidencia
registrada (no excepción) si la fuente sigue sin responder.

No depende de `discovery/subdomains.py`: normaliza sus propios candidatos de
forma independiente para no introducir un import circular (`subdomains.py`
sí importa este módulo, para incorporar sus resultados a la enumeración).
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from atalaya.config import settings
from atalaya.core.exceptions import DiscoveryError

logger = logging.getLogger(__name__)


def _error_detail(response: httpx.Response) -> str:
    """Mensaje de error de Shodan, si lo trae (`{"error": "..."}`), o el
    texto crudo de la respuesta como último recurso."""
    try:
        payload = response.json()
    except ValueError:
        return response.text
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload["error"]
    return response.text


def parse_shodan_payload(payload: dict, domain: str) -> set[str]:
    """Extrae hostnames normalizados del campo ``subdomains`` de la respuesta.

    Shodan devuelve etiquetas de subdominio sueltas (p. ej. ``"www"``,
    ``"api"``), no el hostname completo: hay que componerlas con el dominio
    raíz consultado. Una etiqueta vacía representa el propio dominio raíz.

    Args:
        payload: Cuerpo JSON de ``GET /dns/domain/{domain}``.
        domain: Dominio raíz consultado, usado para componer cada hostname.

    Returns:
        Conjunto de hostnames únicos y normalizados.
    """
    hostnames: set[str] = set()
    raw_subdomains = payload.get("subdomains")
    if not isinstance(raw_subdomains, list):
        return hostnames

    for label in raw_subdomains:
        if not isinstance(label, str):
            continue
        candidate = label.strip().lower().rstrip(".")
        if not candidate:
            hostnames.add(domain)
            continue
        if "@" in candidate or any(c.isspace() for c in candidate):
            continue
        hostnames.add(f"{candidate}.{domain}")

    return hostnames


async def fetch_shodan_subdomains(
    domain: str, client: httpx.AsyncClient | None = None
) -> tuple[set[str], list[str]]:
    """Consulta la API DNS de Shodan y devuelve los subdominios encontrados.

    Sin ``SHODAN_API_KEY`` configurada, se omite de inmediato sin tocar la
    red ni generar ninguna incidencia: es una fuente opcional que amplía
    cobertura, no un requisito del escaneo.

    Con clave configurada:

    - ``404`` significa que Shodan no tiene datos indexados para el dominio
      — no es un fallo, se devuelve un resultado vacío sin incidencia.
    - ``401``/``403`` significan una clave rechazada o sin permiso para este
      endpoint (p. ej. `/dns/domain` exige un plan de pago; el plan gratuito
      `oss` no lo incluye) — no tiene sentido reintentar un fallo de
      autorización, se registra como incidencia de inmediato.
    - Cualquier otro fallo (red, 5xx, JSON inválido) se reintenta con
      backoff exponencial, igual criterio que `fetch_crtsh`; si persiste
      tras agotar los reintentos, se registra como incidencia y el escaneo
      continúa sin esta fuente.

    Returns:
        Tupla ``(hostnames, errores_no_fatales)``.
    """
    if not settings.shodan_api_key:
        return set(), []

    url = f"{settings.shodan_url}/dns/domain/{domain}"
    params = {"key": settings.shodan_api_key}
    errors: list[str] = []

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": "Atalaya-ASM/0.1"},
        )

    try:
        for attempt in range(1, settings.shodan_retries + 1):
            try:
                response = await client.get(url, params=params)

                if response.status_code == 404:
                    logger.info("Shodan no tiene datos indexados para %s", domain)
                    return set(), errors
                if response.status_code in (401, 403):
                    errors.append(
                        f"Shodan rechazó la petición ({response.status_code}): "
                        f"{_error_detail(response)}"
                    )
                    return set(), errors
                if response.status_code != 200:
                    raise DiscoveryError(f"Shodan respondió {response.status_code}")

                payload = response.json()
                if not isinstance(payload, dict):
                    raise DiscoveryError("Shodan devolvió un formato inesperado")

                hostnames = parse_shodan_payload(payload, domain)
                logger.info("Shodan devolvió %d subdominios para %s", len(hostnames), domain)
                return hostnames, errors

            except (httpx.HTTPError, ValueError, DiscoveryError) as exc:
                logger.warning(
                    "Shodan intento %d/%d: %s", attempt, settings.shodan_retries, exc
                )
                if attempt == settings.shodan_retries:
                    errors.append(f"Shodan no disponible tras {attempt} intentos: {exc}")
                    return set(), errors
                await asyncio.sleep(2 ** (attempt - 1))
    finally:
        if owns_client:
            await client.aclose()

    return set(), errors
