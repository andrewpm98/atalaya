"""Descubrimiento de subdominios vía Certificate Transparency (crt.sh),
Shodan y DNS.

Estrategia en tres fases:

1. **Recolección** — se consultan dos fuentes pasivas en paralelo: crt.sh,
   que indexa los registros de Certificate Transparency, y opcionalmente
   Shodan (`discovery/shodan.py`), que indexa DNS observado por su propio
   escaneo. Ninguna envía tráfico a la infraestructura objetivo. crt.sh es
   la fuente primaria y obligatoria; Shodan es una ampliación de cobertura
   que se omite sin más si no hay `SHODAN_API_KEY` configurada — revela
   hosts que nunca tuvieron un certificado TLS público, que crt.sh no puede
   ver por diseño.

2. **Normalización** — los datos de CT son ruidosos: comodines (`*.dominio`),
   mayúsculas, puntos finales, duplicados y entradas fuera de alcance. Se
   normaliza todo y se descarta lo que no pertenece al dominio analizado.

3. **Verificación** — un certificado emitido, o un registro DNS indexado, no
   implica un host activo *hoy*. Se resuelve cada candidato por DNS, de
   forma concurrente y acotada, para distinguir la superficie *histórica* de
   la *real*. Antes de esa resolución masiva, `detect_wildcard_dns()`
   comprueba si el dominio tiene DNS wildcard (un subdominio aleatorio que
   no puede existir, ¿resuelve igualmente?): si lo tiene, cualquier
   candidato "resolvería" sin ser un host real y distinto, e inflaría el
   recuento de activos sin generar ninguna incidencia — de ahí que sea un
   defecto de corrección, no solo una limitación documentada.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from uuid import uuid4

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from atalaya.config import settings
from atalaya.core.authorization import ensure_authorized, normalize_domain
from atalaya.core.exceptions import DiscoveryError, InvalidTargetError
from atalaya.core.netutils import partition_ips
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)
from atalaya.discovery.shodan import fetch_shodan_subdomains

logger = logging.getLogger(__name__)

#: Registros consultados para considerar activo un host.
_DNS_RECORD_TYPES = ("A", "AAAA")


# ─────────────────────────────────────────────────────────────────────────
# Fase 1 · Recolección desde Certificate Transparency
# ─────────────────────────────────────────────────────────────────────────


def normalize_hostname(raw: str, domain: str) -> str | None:
    """Normaliza un hostname de CT y verifica que pertenece a *domain*.

    Descarta entradas vacías, comodines sin host concreto, direcciones de
    correo (presentes ocasionalmente en los SAN) y nombres fuera de alcance.

    Returns:
        El hostname normalizado, o ``None`` si debe descartarse.
    """
    candidate = (raw or "").strip().lower().rstrip(".")
    if not candidate or "@" in candidate or " " in candidate:
        return None

    # "*.api.dominio.com" → "api.dominio.com"; "*.dominio.com" → "dominio.com"
    while candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate:
        return None

    # Solo lo que pertenece al dominio analizado.
    if candidate != domain and not candidate.endswith(f".{domain}"):
        return None

    try:
        return normalize_domain(candidate)
    except InvalidTargetError:
        return None


def parse_crtsh_payload(payload: list[dict], domain: str) -> set[str]:
    """Extrae hostnames normalizados de la respuesta JSON de crt.sh.

    crt.sh devuelve un objeto por certificado. El campo ``name_value`` puede
    contener varios nombres separados por saltos de línea (los SAN del
    certificado), y ``common_name`` un nombre adicional.

    Args:
        payload: Lista de objetos JSON devueltos por crt.sh.
        domain: Dominio raíz, usado para descartar entradas fuera de alcance.

    Returns:
        Conjunto de hostnames únicos y normalizados.
    """
    hostnames: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        raw_names: list[str] = []
        name_value = entry.get("name_value")
        if isinstance(name_value, str):
            raw_names.extend(name_value.splitlines())
        common_name = entry.get("common_name")
        if isinstance(common_name, str):
            raw_names.append(common_name)

        for raw in raw_names:
            normalized = normalize_hostname(raw, domain)
            if normalized:
                hostnames.add(normalized)
    return hostnames


async def fetch_crtsh(
    domain: str, client: httpx.AsyncClient | None = None
) -> tuple[set[str], list[str]]:
    """Consulta crt.sh y devuelve los subdominios encontrados.

    crt.sh es un servicio gratuito históricamente inestable: puede devolver
    502/504 o cortar la conexión bajo carga. Se aplican reintentos con backoff
    exponencial y, si aun así falla, se degrada de forma controlada devolviendo
    el error como incidencia en lugar de abortar el escaneo completo.

    Returns:
        Tupla ``(hostnames, errores_no_fatales)``.
    """
    url = f"{settings.crtsh_url}/"
    params = {"q": f"%.{domain}", "output": "json"}
    errors: list[str] = []

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": "Atalaya-ASM/0.1"},
        )

    try:
        for attempt in range(1, settings.crtsh_retries + 1):
            try:
                response = await client.get(url, params=params)
                if response.status_code != 200:
                    raise DiscoveryError(f"crt.sh respondió {response.status_code}")
                payload = response.json()
                if not isinstance(payload, list):
                    raise DiscoveryError("crt.sh devolvió un formato inesperado")
                hostnames = parse_crtsh_payload(payload, domain)
                logger.info(
                    "crt.sh devolvió %d certificados -> %d hostnames unicos",
                    len(payload),
                    len(hostnames),
                )
                return hostnames, errors

            except (httpx.HTTPError, ValueError, DiscoveryError) as exc:
                logger.warning(
                    "crt.sh intento %d/%d: %s", attempt, settings.crtsh_retries, exc
                )
                if attempt == settings.crtsh_retries:
                    errors.append(f"crt.sh no disponible tras {attempt} intentos: {exc}")
                    return set(), errors
                await asyncio.sleep(2 ** (attempt - 1))
    finally:
        if owns_client:
            await client.aclose()

    return set(), errors


# ─────────────────────────────────────────────────────────────────────────
# Fase 3 · Verificación por DNS
# ─────────────────────────────────────────────────────────────────────────


def build_resolver() -> dns.asyncresolver.Resolver:
    """Construye el resolver DNS asíncrono según la configuración."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = settings.dns_timeout
    resolver.lifetime = settings.dns_timeout
    if settings.dns_servers:
        resolver.nameservers = settings.dns_servers
    return resolver


async def detect_wildcard_dns(domain: str, resolver: dns.asyncresolver.Resolver) -> list[str]:
    """Comprueba si *domain* tiene DNS wildcard (`*.dominio` con una IP fija).

    Consulta un subdominio con un UUID: no puede existir de verdad, así que
    si resuelve, es porque el dominio responde a **cualquier** nombre bajo
    él, no porque ese nombre concreto esté dado de alta. Sin este filtro, un
    dominio con wildcard inflaría el recuento de activos con cualquier
    candidato de crt.sh/Shodan que nunca se dio de alta como servicio real.

    Nunca lanza excepción: un fallo de la consulta (timeout, servidor caído)
    se trata igual que "no hay wildcard" — mismo criterio de degradación
    controlada que `resolve_hostname`, y preferible a abortar el escaneo por
    una comprobación que es una mejora de precisión, no el objetivo del
    escaneo.

    Returns:
        Las IPs a las que resuelve el nombre aleatorio, o ``[]`` si no
        resuelve (sin wildcard, o la consulta falló).
    """
    probe = f"{uuid4().hex}.{domain}"
    ips: list[str] = []
    for record_type in _DNS_RECORD_TYPES:
        try:
            answer = await resolver.resolve(probe, record_type)
            ips.extend(str(rdata) for rdata in answer)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as exc:  # noqa: BLE001 - degradación controlada
            logger.info("Comprobación de wildcard DNS para %s: %s", domain, exc)
            continue
    return sorted(set(ips))


async def resolve_hostname(
    hostname: str,
    resolver: dns.asyncresolver.Resolver,
    sources: list[DiscoverySource],
    semaphore: asyncio.Semaphore,
) -> SubdomainRecord:
    """Resuelve un hostname a IPv4/IPv6 y devuelve su registro.

    Nunca lanza excepción: cualquier fallo se refleja en el estado del
    registro, de modo que un host problemático no aborta el escaneo.
    """
    async with semaphore:
        ips: list[str] = []
        status = ResolutionStatus.NXDOMAIN
        error: str | None = None

        for record_type in _DNS_RECORD_TYPES:
            try:
                answer = await resolver.resolve(hostname, record_type)
                ips.extend(str(rdata) for rdata in answer)
                status = ResolutionStatus.ACTIVE
            except dns.resolver.NXDOMAIN:
                if status is not ResolutionStatus.ACTIVE:
                    status = ResolutionStatus.NXDOMAIN
                break
            except dns.resolver.NoAnswer:
                if status is not ResolutionStatus.ACTIVE:
                    status = ResolutionStatus.NO_ANSWER
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                if status is not ResolutionStatus.ACTIVE:
                    status = ResolutionStatus.TIMEOUT
                    error = "timeout en la resolución DNS"
            except Exception as exc:  # noqa: BLE001 - degradación controlada
                if status is not ResolutionStatus.ACTIVE:
                    status = ResolutionStatus.ERROR
                    error = str(exc)

        unique_ips = sorted(set(ips))

        # Un nombre puede resolver sin ser alcanzable: 0.0.0.0 (registro
        # anulado), bucle local o direccionamiento privado. En ese caso el
        # host existe en DNS pero no constituye un activo escaneable.
        if status is ResolutionStatus.ACTIVE:
            routable, _ = partition_ips(unique_ips)
            if not routable:
                status = ResolutionStatus.UNROUTABLE

        return SubdomainRecord(
            hostname=hostname,
            status=status,
            ip_addresses=unique_ips,
            sources=list(sources),
            error=error,
        )


# ─────────────────────────────────────────────────────────────────────────
# Orquestación
# ─────────────────────────────────────────────────────────────────────────


async def enumerate_subdomains(
    domain: str,
    *,
    resolve: bool = True,
    client: httpx.AsyncClient | None = None,
) -> SubdomainScanResult:
    """Enumera los subdominios de *domain* y verifica cuáles están activos.

    Args:
        domain: Dominio raíz a analizar (p. ej. ``ejemplo.com``).
        resolve: Si es False, omite la verificación DNS y devuelve solo los
            candidatos de CT. Útil para inspección rápida y para pruebas.
        client: Cliente HTTP reutilizable. Si no se indica, se crea y cierra
            internamente.

    Returns:
        `SubdomainScanResult` con los registros, el resumen y las incidencias.

    Raises:
        InvalidTargetError: si el dominio está mal formado.
        UnauthorizedTargetError: si no está en `SCAN_ALLOWLIST`.
    """
    target = ensure_authorized(domain)
    result = SubdomainScanResult(domain=target)
    logger.info("Iniciando enumeración de subdominios para %s", target)

    # Fases 1-2 - recolección y normalización. Ambas fuentes son independientes
    # entre sí (hosts distintos, sin autenticación compartida), se consultan
    # concurrentemente en vez de una tras otra.
    (hostnames_crtsh, errors_crtsh), (hostnames_shodan, errors_shodan) = await asyncio.gather(
        fetch_crtsh(target, client=client),
        fetch_shodan_subdomains(target, client=client),
    )
    result.errors.extend(errors_crtsh)
    result.errors.extend(errors_shodan)

    # Un mismo host puede aparecer en ambas fuentes; se conserva de cuál (o
    # de cuáles) procede cada uno, para trazabilidad del hallazgo.
    sources_by_hostname: dict[str, set[DiscoverySource]] = {}
    for hostname in hostnames_crtsh:
        sources_by_hostname.setdefault(hostname, set()).add(DiscoverySource.CRTSH)
    for hostname in hostnames_shodan:
        sources_by_hostname.setdefault(hostname, set()).add(DiscoverySource.SHODAN)

    # El propio dominio raíz siempre forma parte de la superficie, aunque
    # ninguna fuente lo haya reportado explícitamente.
    sources_by_hostname.setdefault(target, set())

    if not resolve:
        result.records = [
            SubdomainRecord(
                hostname=h,
                status=ResolutionStatus.NO_ANSWER,
                sources=sorted(sources_by_hostname[h], key=lambda s: s.value),
            )
            for h in sorted(sources_by_hostname)
        ]
        result.finished_at = datetime.now(UTC)
        return result

    # Fase 3 - verificación DNS concurrente y acotada. La comprobación de
    # wildcard va antes: es la que decide si algún registro de la resolución
    # masiva de abajo hay que descartarlo como activo, no al revés.
    resolver = build_resolver()
    wildcard_ips = await detect_wildcard_dns(target, resolver)
    result.wildcard_ips = wildcard_ips
    if wildcard_ips:
        logger.warning(
            "DNS wildcard detectado en %s: cualquier subdominio resuelve a %s",
            target,
            wildcard_ips,
        )

    semaphore = asyncio.Semaphore(settings.dns_concurrency)
    tasks = [
        resolve_hostname(
            hostname,
            resolver,
            sorted(sources_by_hostname[hostname], key=lambda s: s.value),
            semaphore,
        )
        for hostname in sorted(sources_by_hostname)
    ]
    records = await asyncio.gather(*tasks)

    # Un registro cuyas IPs son un subconjunto de las del wildcard no es un
    # host distinto: el mismo nombre aleatorio de detect_wildcard_dns habría
    # resuelto igual. Se reclasifica antes de "confirmado por DNS" de abajo,
    # para que is_active (y por tanto esa confirmación) ya lo excluya.
    if wildcard_ips:
        wildcard_set = set(wildcard_ips)
        for record in records:
            if record.status is ResolutionStatus.ACTIVE and set(record.ip_addresses) <= (
                wildcard_set
            ):
                record.status = ResolutionStatus.WILDCARD

    # Un host que resuelve queda confirmado también por DNS.
    for record in records:
        if record.is_active and DiscoverySource.DNS not in record.sources:
            record.sources.append(DiscoverySource.DNS)

    result.records = sorted(records, key=lambda r: r.hostname)
    result.finished_at = datetime.now(UTC)

    logger.info(
        "Enumeración completada para %s: %d descubiertos, %d activos, "
        "%d no enrutables, %d con direccionamiento interno, %d descartados por wildcard",
        target,
        result.total_discovered,
        result.total_active,
        len(result.unroutable_records),
        len(result.leaking_records),
        len(result.wildcard_records),
    )
    return result
