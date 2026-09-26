"""Verificación HTTP **opt-in** del riesgo de subdomain takeover.

`discovery/takeover.py` detecta candidatos por patrón de CNAME, sin tocar
HTTP — reconocimiento pasivo puro. Este módulo es el segundo nivel: cuando
`TAKEOVER_VERIFY=true`, hace un `GET` a la página de error del proveedor
apuntado por el CNAME y busca su huella de "recurso no reclamado" (p. ej. el
404 «There isn't a GitHub Pages site here» de GitHub Pages, o el
`NoSuchBucket` de S3). Si la encuentra, el candidato se eleva a *alta
sospecha* (`TakeoverCandidate.unclaimed_indicator`), **nunca a "confirmado"**.

**Por qué vive aparte de `takeover.py`.** La detección debe permanecer
estrictamente pasiva (y un test estático garantiza que `takeover.py` no
importa `httpx`). La única petición HTTP a un tercero vive aquí, en un módulo
que solo se ejecuta bajo opt-in explícito. Es la "Excepción acotada" de la
restricción de seguridad #6 de CLAUDE.md, con sus tres salvaguardas:

1. **Opt-in** (`settings.takeover_verify`, off por defecto): sin él,
   `verify_candidates` devuelve los candidatos sin tocar y no hace ninguna
   petición.
2. **Limitado a `SCAN_ALLOWLIST`**: cada candidato pasa `is_authorized()`
   antes de que se sondee su destino.
3. **Auditoría**: cada petición a un tercero se registra en el log
   (`logger.info`), con hostname, destino y resultado.

Degradación controlada, como el resto del descubrimiento: si el destino no
resuelve, la conexión falla o no hay huella, el candidato se queda en
detección por patrón, nunca en error.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from atalaya.config import settings
from atalaya.core.authorization import is_authorized
from atalaya.core.exceptions import InvalidTargetError
from atalaya.discovery.models import TakeoverCandidate

logger = logging.getLogger(__name__)

#: Sufijo de proveedor -> huellas textuales de "recurso no reclamado" en su
#: página de error pública. Subconjunto **deliberadamente menor** que
#: `TAKEOVER_PATTERNS`: solo proveedores con una huella pública, estable y
#: bien documentada. Un candidato cuyo proveedor tiene patrón pero no huella
#: se queda en detección por patrón, sin verificar — igual de honesto que no
#: inventar una huella frágil (mismo criterio que la tabla de patrones y
#: `COMMON_PORTS`). Las claves se alinean con los sufijos de
#: `takeover.py::TAKEOVER_PATTERNS`.
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "github.io": ("There isn't a GitHub Pages site here.",),
    "herokuapp.com": ("No such app",),
    "s3.amazonaws.com": ("NoSuchBucket", "The specified bucket does not exist"),
    "myshopify.com": ("Sorry, this shop is currently unavailable",),
    "fastly.net": ("Fastly error: unknown domain",),
    "pantheonsite.io": (
        "The gods are wise, but do not know of the site which you seek",
        "404 error unknown site",
    ),
    "tumblr.com": ("Whatever you were looking for doesn't currently exist at this address",),
    "surge.sh": ("project not found",),
    "ghost.io": ("The thing you were looking for is no longer here, or never was",),
    "wpengine.com": ("The site you were looking for couldn't be found",),
    "unbouncepages.com": ("The requested URL was not found on this server",),
    "webflow.io": ("The page you are looking for doesn't exist or has been moved",),
}


def match_fingerprint(pattern_matched: str, body: str) -> str | None:
    """Busca la huella de "no reclamado" del proveedor de *pattern_matched*
    en *body*.

    Comparación insensible a mayúsculas. Devuelve la huella concreta que hizo
    match (para poder citarla en la evidencia), o ``None`` si el proveedor no
    tiene huella en la tabla o ninguna aparece en el cuerpo.
    """
    markers = TAKEOVER_FINGERPRINTS.get(pattern_matched)
    if not markers:
        return None
    body_lower = body.lower()
    for marker in markers:
        if marker.lower() in body_lower:
            return marker
    return None


async def _probe(cname: str, client: httpx.AsyncClient) -> tuple[str, int | None, str]:
    """Hace un `GET` al destino del CNAME y devuelve ``(url, status, body)``.

    Intenta HTTPS y, si la conexión falla, HTTP: la página de error del
    proveedor puede servirse por cualquiera de los dos. Nunca lanza: un fallo
    de conexión/timeout devuelve ``status=None`` y cuerpo vacío, y el llamante
    lo trata como "sin huella" (degradación controlada).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{cname}/"
        try:
            response = await client.get(url)
            return url, response.status_code, response.text
        except (httpx.ConnectError, httpx.ConnectTimeout):
            continue  # prueba el siguiente esquema
        except httpx.HTTPError as exc:
            logger.debug("Verificación de takeover: fallo HTTP en %s: %s", url, exc)
            return url, None, ""
    return f"https://{cname}/", None, ""


async def _verify_one(
    candidate: TakeoverCandidate, client: httpx.AsyncClient
) -> TakeoverCandidate:
    """Verifica un único candidato. Nunca lanza; devuelve una copia con
    `verification_attempted=True` y `unclaimed_indicator` puesto si hubo
    huella.

    Salvaguarda de allowlist: si el hostname del candidato no está autorizado
    (o está malformado), no se sondea su destino y se deja constancia — el
    candidato vuelve tal cual, sin marca de verificación.
    """
    try:
        authorized = is_authorized(candidate.hostname)
    except InvalidTargetError:
        authorized = False
    if not authorized:
        logger.warning(
            "Verificación de takeover OMITIDA para %s: no está en SCAN_ALLOWLIST",
            candidate.hostname,
        )
        return candidate

    url, status, body = await _probe(candidate.cname, client)
    indicator = match_fingerprint(candidate.pattern_matched, body) if body else None

    # Auditoría: toda petición a un tercero deja traza, con o sin huella.
    logger.info(
        "Verificación de takeover [auditoría]: %s -> GET %s (HTTP %s) -> %s",
        candidate.hostname,
        url,
        status if status is not None else "sin respuesta",
        f"huella «{indicator}»" if indicator else "sin huella",
    )

    return candidate.model_copy(
        update={
            "verification_attempted": True,
            "unclaimed_indicator": (
                f"«{indicator}» en {url} (HTTP {status})" if indicator else None
            ),
        }
    )


async def verify_candidates(
    candidates: list[TakeoverCandidate],
    *,
    client: httpx.AsyncClient | None = None,
) -> list[TakeoverCandidate]:
    """Verifica por HTTP los `candidates`, si `TAKEOVER_VERIFY` está activo.

    **Opt-in**: con `settings.takeover_verify` en False (por defecto) devuelve
    los candidatos sin tocar y no hace ninguna petición — el comportamiento
    por defecto de la herramienta no cambia.

    Concurrencia acotada por `settings.enrichment_host_concurrency`, mismo
    límite que el resto del enriquecimiento. Nunca lanza: cada candidato se
    verifica con degradación controlada (`_verify_one`).
    """
    if not settings.takeover_verify or not candidates:
        return candidates

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=settings.takeover_verify_timeout,
            follow_redirects=True,
            headers={"User-Agent": "Atalaya-ASM/0.1"},
        )

    semaphore = asyncio.Semaphore(settings.enrichment_host_concurrency)

    async def _bounded(candidate: TakeoverCandidate) -> TakeoverCandidate:
        async with semaphore:
            return await _verify_one(candidate, client)

    try:
        logger.info(
            "Verificación de takeover activada (TAKEOVER_VERIFY): %d candidatos",
            len(candidates),
        )
        return list(await asyncio.gather(*(_bounded(c) for c in candidates)))
    finally:
        if owns_client:
            await client.aclose()
