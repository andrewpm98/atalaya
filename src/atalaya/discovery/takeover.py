"""Detección de riesgo de *subdomain takeover*.

Un subdominio cuyo registro CNAME apunta a un servicio de hosting de terceros
(GitHub Pages, Heroku, S3, Azure...) es indistinguible, para un atacante, de
un activo listo para secuestrar cuando el recurso apuntado ya no está
reclamado: cualquiera puede dar de alta ese mismo nombre en el proveedor y
servir contenido bajo el dominio de la víctima.

**Por qué se mira `no_answer`/`nxdomain`/`unroutable`, no `active`.** Un host
`active` ya resuelve a una IP real: tiene un servicio propio detrás, no
depende de un CNAME de terceros sin reclamar. La señal característica de
takeover vive precisamente en los hosts que **no** resuelven por A/AAAA
(`discovery/subdomains.py::ResolutionStatus`): existen en DNS (crt.sh los
certificó alguna vez, o Shodan los indexó) pero ya no tienen IP asociada —
justo el patrón de un CNAME que apuntaba a un recurso de hosting que se
liberó. Es la deuda técnica documentada en CLAUDE.md tras el escaneo de
`github.com` (~50 hosts en `no_answer`).

**Solo reconocimiento pasivo.** Este módulo resuelve el CNAME (una consulta
DNS) y lo compara contra una tabla de patrones. No hace ninguna petición
HTTP al recurso de terceros: comprobar si ese recurso responde "no existe"
cruzaría a verificar explotabilidad, que la restricción de seguridad #6 de
CLAUDE.md prohíbe explícitamente ("la herramienta señala patrones de riesgo,
no comprueba si son explotables"). Se prefiere un falso positivo señalado
por patrón a confirmar un takeover real.

Módulo independiente de `discovery/subdomains.py` (no se importa nada de
allí) para no introducir un import circular, mismo criterio que ya aplica
`discovery/shodan.py`.
"""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.resolver

from atalaya.config import settings
from atalaya.discovery.models import ResolutionStatus, SubdomainRecord, TakeoverCandidate

logger = logging.getLogger(__name__)

#: Estados de resolución que hacen de un host un candidato a inspeccionar.
#: Un host `ACTIVE` tiene IP real y queda fuera; `TIMEOUT`/`ERROR` no se
#: incluyen porque no sabemos si el host existe realmente en DNS (el fallo
#: pudo ser del resolver, no del nombre) -- mismo criterio conservador que
#: evita convertir una incidencia de red en un falso candidato.
_CANDIDATE_STATUSES = (
    ResolutionStatus.NO_ANSWER,
    ResolutionStatus.NXDOMAIN,
    ResolutionStatus.UNROUTABLE,
)

#: Sufijo de CNAME -> proveedor de hosting. Deliberadamente **no exhaustiva**
#: -- mismo criterio de honestidad que `COMMON_PORTS` en `discovery/ports.py`:
#: cubre los proveedores más citados en la práctica de subdomain takeover,
#: no pretende ser una lista cerrada. Ampliarla es deuda técnica documentada,
#: no silenciada.
TAKEOVER_PATTERNS: dict[str, str] = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "azurewebsites.net": "Azure App Service",
    "azure-api.net": "Azure API Management",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "myshopify.com": "Shopify",
    "webflow.io": "Webflow",
    "wordpress.com": "WordPress.com",
    "zendesk.com": "Zendesk",
    "ghost.io": "Ghost",
    "statuspage.io": "Statuspage",
    "wpengine.com": "WP Engine",
    "bitbucket.io": "Bitbucket",
    "tumblr.com": "Tumblr",
    "surge.sh": "Surge.sh",
    "unbouncepages.com": "Unbounce",
}


def match_takeover_pattern(cname: str) -> tuple[str, str] | None:
    """Compara *cname* contra `TAKEOVER_PATTERNS`.

    Coincide tanto con el propio sufijo (p. ej. ``s3.amazonaws.com``) como
    con cualquier subdominio suyo (p. ej. ``bucket.s3.amazonaws.com``), igual
    criterio de comparación por punto separador que `normalize_hostname` en
    `discovery/subdomains.py` -- evita falsos positivos de tipo
    ``evil-s3.amazonaws.com.attacker.net``.

    Returns:
        Tupla ``(proveedor, sufijo_que_hizo_match)``, o ``None`` si *cname*
        no coincide con ningún patrón conocido.
    """
    candidate = (cname or "").strip().lower().rstrip(".")
    if not candidate:
        return None
    for suffix, provider in TAKEOVER_PATTERNS.items():
        if candidate == suffix or candidate.endswith(f".{suffix}"):
            return provider, suffix
    return None


def build_resolver() -> dns.asyncresolver.Resolver:
    """Construye el resolver DNS asíncrono según la configuración.

    Mismo patrón que `discovery/subdomains.py::build_resolver`, duplicado a
    propósito en vez de importado: este módulo debe poder evolucionar (o
    fallar) sin acoplarse a `subdomains.py`, igual que `discovery/shodan.py`.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = settings.dns_timeout
    resolver.lifetime = settings.dns_timeout
    if settings.dns_servers:
        resolver.nameservers = settings.dns_servers
    return resolver


async def _resolve_cname(
    hostname: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
) -> str | None:
    """Resuelve el registro CNAME de *hostname*.

    Nunca lanza excepción: cualquier fallo (nombre inexistente, sin CNAME,
    timeout, error del resolver) se traduce en `None`, mismo criterio de
    degradación controlada que `resolve_hostname` en `discovery/subdomains.py`
    -- un host problemático no puede abortar el resto de la búsqueda.
    """
    async with semaphore:
        try:
            answer = await resolver.resolve(hostname, "CNAME")
            for rdata in answer:
                return str(rdata).rstrip(".")
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            logger.debug("Timeout resolviendo CNAME de %s", hostname)
            return None
        except Exception as exc:  # noqa: BLE001 - degradación controlada
            logger.debug("Fallo resolviendo CNAME de %s: %s", hostname, exc)
            return None


async def find_takeover_candidates(
    records: list[SubdomainRecord],
) -> list[TakeoverCandidate]:
    """Busca candidatos a subdomain takeover entre *records*.

    Filtra primero los hosts que no resuelven por A/AAAA (`_CANDIDATE_STATUSES`
    -- ver docstring del módulo para el porqué), resuelve su CNAME de forma
    concurrente y acotada (`settings.dns_concurrency`, mismo límite que
    `discovery/subdomains.py::resolve_hostname`, sin inventar una variable
    nueva) y compara cada uno contra `TAKEOVER_PATTERNS`.

    Recibe **todos** los registros de un `SubdomainScanResult` (no solo los
    activos): quien llama es responsable de pasar `result.records` completo,
    no `result.active_records` -- ver `discovery/enrichment.py::enrich_scan`.

    Nunca lanza excepción: un fallo de resolución de un host concreto se
    descarta silenciosamente (no genera candidato) y no afecta al resto.

    Returns:
        Candidatos detectados, en el mismo orden que *records*.
    """
    candidates = [r for r in records if r.status in _CANDIDATE_STATUSES]
    if not candidates:
        return []

    resolver = build_resolver()
    semaphore = asyncio.Semaphore(settings.dns_concurrency)
    cnames = await asyncio.gather(
        *(_resolve_cname(record.hostname, resolver, semaphore) for record in candidates)
    )

    found: list[TakeoverCandidate] = []
    for record, cname in zip(candidates, cnames):
        if cname is None:
            continue
        match = match_takeover_pattern(cname)
        if match is None:
            continue
        provider, pattern = match
        found.append(
            TakeoverCandidate(
                hostname=record.hostname,
                cname=cname,
                provider=provider,
                pattern_matched=pattern,
            )
        )

    if found:
        logger.info(
            "Detectados %d candidatos a subdomain takeover de %d hosts sin A/AAAA",
            len(found),
            len(candidates),
        )
    return found
