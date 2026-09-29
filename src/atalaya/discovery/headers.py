"""Análisis de cabeceras de seguridad HTTP (Paso 2).

Evalúa las cabeceras que más influyen en el riesgo real de un sitio web:
HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy y
Permissions-Policy. Degradación controlada, igual criterio que
`discovery/subdomains.py`: un host que no responde no aborta el análisis del
resto del escaneo — se refleja en `HeaderScanResult.error`, nunca lanzando
excepción.

`evaluate_headers()` (pura, sobre un `httpx.Headers` ya obtenido) se separa
de `analyze_headers()` (hace la petición HTTP) para poder probar cada regla
sin red, mismo criterio que `parse_crtsh_payload`/`fetch_crtsh` en
`subdomains.py`.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from atalaya.config import settings
from atalaya.discovery.models import DiscoveryFinding, HeaderScanResult

logger = logging.getLogger(__name__)

#: Antigüedad mínima razonable de HSTS: por debajo, un atacante en ruta tiene
#: una ventana de downgrade a HTTP más amplia de la deseable. 180 días es el
#: umbral que usan hstspreload.org y Mozilla Observatory.
_HSTS_MIN_MAX_AGE = 15_552_000


def _parse_max_age(value: str) -> int | None:
    for part in value.split(";"):
        key, _, raw = part.strip().partition("=")
        if key.lower() == "max-age":
            try:
                return int(raw)
            except ValueError:
                return None
    return None


def _check_hsts(headers: httpx.Headers) -> DiscoveryFinding | None:
    value = headers.get("strict-transport-security")
    if value is None:
        return DiscoveryFinding(
            finding_type="hsts_missing",
            evidence=(
                "No se envía Strict-Transport-Security: un navegador puede "
                "downgradear a HTTP en la próxima visita si no hay HSTS precargado."
            ),
        )
    max_age = _parse_max_age(value)
    if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
        return DiscoveryFinding(
            finding_type="hsts_max_age_bajo",
            evidence=f"Strict-Transport-Security con max-age demasiado bajo: {value!r}",
        )
    return None


def _check_csp(headers: httpx.Headers) -> DiscoveryFinding | None:
    if headers.get("content-security-policy") is None:
        return DiscoveryFinding(
            finding_type="csp_missing",
            evidence=(
                "No se envía Content-Security-Policy: sin mitigación a nivel de "
                "cabecera contra XSS e inyección de contenido."
            ),
        )
    return None


def _check_clickjacking(headers: httpx.Headers) -> DiscoveryFinding | None:
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy") or ""
    if xfo is not None or "frame-ancestors" in csp.lower():
        return None
    return DiscoveryFinding(
        finding_type="clickjacking_sin_proteccion",
        evidence=(
            "Sin X-Frame-Options ni frame-ancestors en la CSP: la página puede "
            "embeberse en un iframe ajeno (clickjacking)."
        ),
    )


def _check_content_type_options(headers: httpx.Headers) -> DiscoveryFinding | None:
    value = headers.get("x-content-type-options")
    if value is None or value.strip().lower() != "nosniff":
        return DiscoveryFinding(
            finding_type="mime_sniffing_habilitado",
            evidence=(
                f"X-Content-Type-Options ausente o distinto de 'nosniff' "
                f"(valor observado: {value!r}): el navegador puede reinterpretar "
                "el tipo de un recurso servido."
            ),
        )
    return None


def _check_referrer_policy(headers: httpx.Headers) -> DiscoveryFinding | None:
    if headers.get("referrer-policy") is None:
        return DiscoveryFinding(
            finding_type="referrer_policy_missing",
            evidence=(
                "No se envía Referrer-Policy: el navegador aplica su política por "
                "defecto, que puede filtrar la URL completa de origen a terceros."
            ),
        )
    return None


def _check_permissions_policy(headers: httpx.Headers) -> DiscoveryFinding | None:
    if headers.get("permissions-policy") is None:
        return DiscoveryFinding(
            finding_type="permissions_policy_missing",
            evidence=(
                "No se envía Permissions-Policy: no se restringe desde la cabecera "
                "el acceso a APIs sensibles del navegador (cámara, geolocalización...)."
            ),
        )
    return None


#: Orden deliberado: de mayor a menor impacto típico (HSTS/CSP primero).
_CHECKS = (
    _check_hsts,
    _check_csp,
    _check_clickjacking,
    _check_content_type_options,
    _check_referrer_policy,
    _check_permissions_policy,
)


def evaluate_headers(headers: httpx.Headers) -> list[DiscoveryFinding]:
    """Aplica todas las comprobaciones sobre un conjunto de cabeceras HTTP
    ya obtenido. Pura y síncrona: no hace red, así que cada regla se prueba
    de forma aislada y determinista.
    """
    return [finding for check in _CHECKS if (finding := check(headers)) is not None]


def _http_sin_redireccion(
    hostname: str | None, http_url: str, response: httpx.Response
) -> DiscoveryFinding | None:
    """Hallazgo si el acceso por HTTP no acaba en HTTPS.

    `response` es la de `http_url` siguiendo redirecciones: si la URL final es
    HTTPS, el servidor redirige (directamente o en cadena) y no hay hallazgo.
    Si no, sirve contenido en claro. HSTS no lo compensa del todo: solo protege
    a partir de la primera visita por HTTPS (salvo que el dominio esté en la
    lista de precarga), y esa primera petición en claro es justo la que un
    atacante en ruta puede interceptar (SSL stripping).
    """
    if response.url.scheme == "https":
        return None
    return DiscoveryFinding(
        finding_type="http_sin_redireccion_https",
        evidence=(
            f"{http_url} responde {response.status_code} por HTTP sin redirigir a HTTPS "
            f"(URL final: {response.url}): el acceso sin cifrar no se eleva a TLS."
        ),
    )


async def _fetch(client: httpx.AsyncClient, url: str) -> httpx.Response | httpx.HTTPError:
    """GET que devuelve el error en vez de lanzarlo, para poder lanzar las dos
    peticiones (HTTPS y HTTP) a la vez con `asyncio.gather` y decidir después.

    Sigue redirecciones por petición, no por configuración del cliente: la
    comprobación HTTP → HTTPS mira la URL final y no puede depender de cómo
    se haya construido el cliente que se le pasa.
    """
    try:
        return await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return exc


async def analyze_headers(
    url: str, *, client: httpx.AsyncClient | None = None
) -> HeaderScanResult:
    """Evalúa las cabeceras de seguridad de *url*.

    Si *url* es HTTPS se pide también su equivalente HTTP, en paralelo, que
    sirve para dos cosas:

    - si HTTPS responde, comprobar que HTTP redirige a HTTPS
      (``http_sin_redireccion_https`` si no). Que HTTP no responda (p. ej.
      puerto 80 cerrado) no es un hallazgo: no se sirve nada en claro;
    - si HTTPS no responde, distinguir "el host no tiene servicio HTTP" de
      "el servicio solo se ofrece sin cifrar", que es un hallazgo en sí
      mismo (``sin_https``).

    En paralelo y no en secuencia porque un puerto 80 filtrado no contesta
    nunca: en serie, cada host así sumaría un timeout completo al escaneo.
    """
    hostname = httpx.URL(url).host
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=settings.header_scan_timeout,
            follow_redirects=True,
            verify=False,  # se evalúan cabeceras, no la cadena de certificación
            headers={"User-Agent": "Atalaya-ASM/0.1"},
        )

    http_url = "http://" + url.removeprefix("https://") if url.startswith("https://") else None

    try:
        if http_url is None:
            primary, fallback = await _fetch(client, url), None
        else:
            primary, fallback = await asyncio.gather(
                _fetch(client, url), _fetch(client, http_url)
            )

        if isinstance(primary, httpx.Response):
            findings = evaluate_headers(primary.headers)
            if http_url is not None and isinstance(fallback, httpx.Response):
                redirect = _http_sin_redireccion(hostname, http_url, fallback)
                if redirect is not None:
                    findings.append(redirect)
            return HeaderScanResult(hostname=hostname, checked_url=url, findings=findings)

        if http_url is not None and isinstance(fallback, httpx.Response):
            # Solo respondió por HTTP, no por HTTPS.
            findings = evaluate_headers(fallback.headers)
            findings.append(
                DiscoveryFinding(
                    finding_type="sin_https",
                    evidence=f"{hostname} solo respondió por HTTP ({http_url}), sin TLS.",
                )
            )
            return HeaderScanResult(hostname=hostname, checked_url=http_url, findings=findings)

        logger.warning("Análisis de cabeceras de %s falló: %s", hostname, primary)
        return HeaderScanResult(hostname=hostname, error=str(primary))
    finally:
        if owns_client:
            await client.aclose()
