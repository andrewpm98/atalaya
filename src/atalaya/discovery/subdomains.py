"""Descubrimiento de subdominios vía Certificate Transparency (crt.sh) y DNS.

Estrategia en tres fases:

1. **Recolección** — se consulta crt.sh, que indexa los registros de
   Certificate Transparency. Cada certificado TLS emitido públicamente queda
   registrado en logs auditables, por lo que consultarlos revela subdominios
   sin enviar un solo paquete a la infraestructura objetivo. Es la técnica de
   enumeración pasiva con mejor relación cobertura/intrusividad.

2. **Normalización** — los datos de CT son ruidosos: comodines (`*.dominio`),
   mayúsculas, puntos finales, duplicados y entradas fuera de alcance. Se
   normaliza todo y se descarta lo que no pertenece al dominio analizado.

3. **Verificación** — un certificado emitido no implica un host activo. Se
   resuelve cada candidato por DNS, de forma concurrente y acotada, para
   distinguir la superficie *histórica* de la *real*.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

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

    # Fases 1-2 - recolección y normalización
    hostnames, errors = await fetch_crtsh(target, client=client)
    result.errors.extend(errors)

    # El propio dominio raíz siempre forma parte de la superficie.
    hostnames.add(target)

    if not resolve:
        result.records = [
            SubdomainRecord(
                hostname=h,
                status=ResolutionStatus.NO_ANSWER,
                sources=[DiscoverySource.CRTSH],
            )
            for h in sorted(hostnames)
        ]
        result.finished_at = datetime.now(timezone.utc)
        return result

    # Fase 3 - verificación DNS concurrente y acotada
    resolver = build_resolver()
    semaphore = asyncio.Semaphore(settings.dns_concurrency)
    tasks = [
        resolve_hostname(hostname, resolver, [DiscoverySource.CRTSH], semaphore)
        for hostname in sorted(hostnames)
    ]
    records = await asyncio.gather(*tasks)

    # Un host que resuelve queda confirmado también por DNS.
    for record in records:
        if record.is_active and DiscoverySource.DNS not in record.sources:
            record.sources.append(DiscoverySource.DNS)

    result.records = sorted(records, key=lambda r: r.hostname)
    result.finished_at = datetime.now(timezone.utc)

    logger.info(
        "Enumeración completada para %s: %d descubiertos, %d activos, "
        "%d no enrutables, %d con direccionamiento interno",
        target,
        result.total_discovered,
        result.total_active,
        len(result.unroutable_records),
        len(result.leaking_records),
    )
    return result
