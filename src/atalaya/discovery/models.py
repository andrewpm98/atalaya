"""Modelos de resultado de las fases de descubrimiento.

Se definen con Pydantic por tres motivos:

1. **Validación**: los datos proceden de fuentes externas no confiables
   (crt.sh, DNS) y deben normalizarse antes de entrar en el sistema.
2. **Serialización directa a la API**: FastAPI usa estos modelos como
   esquemas de respuesta sin conversión intermedia (Paso 4).
3. **Mapeo a la base de datos**: los campos anticipan las columnas de las
   entidades `Asset` y `Finding` (Paso 3).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from atalaya.core.netutils import IpScope, classify_ip, partition_ips


class DiscoverySource(str, Enum):
    """Origen de un activo descubierto.

    Un mismo host puede confirmarse por varias fuentes; conservar el origen
    permite valorar la fiabilidad del hallazgo y auditar la procedencia.
    """

    CRTSH = "crt.sh"
    DNS = "dns"


class ResolutionStatus(str, Enum):
    """Resultado de la resolución DNS de un host."""

    ACTIVE = "active"            # resuelve a al menos una IP enrutable
    UNROUTABLE = "unroutable"    # resuelve, pero solo a IPs no alcanzables
    NXDOMAIN = "nxdomain"        # el nombre no existe
    NO_ANSWER = "no_answer"      # existe pero sin registros A/AAAA
    TIMEOUT = "timeout"          # el resolver no respondió a tiempo
    ERROR = "error"              # fallo inesperado


class SubdomainRecord(BaseModel):
    """Un subdominio descubierto y el resultado de su verificación DNS."""

    hostname: str = Field(description="Nombre completo del host, normalizado")
    status: ResolutionStatus = Field(description="Resultado de la resolución DNS")
    ip_addresses: list[str] = Field(
        default_factory=list, description="Todas las direcciones resueltas"
    )
    sources: list[DiscoverySource] = Field(
        default_factory=list, description="Fuentes que reportaron este host"
    )
    error: str | None = Field(
        default=None, description="Detalle del error si la resolución falló"
    )

    @property
    def routable_ips(self) -> list[str]:
        """Direcciones alcanzables desde Internet. Objetivos válidos de escaneo."""
        return partition_ips(self.ip_addresses)[0]

    @property
    def non_routable_ips(self) -> list[str]:
        """Direcciones que resuelven pero no son alcanzables."""
        return partition_ips(self.ip_addresses)[1]

    @property
    def ip_scopes(self) -> dict[str, IpScope]:
        """Clasificación de cada dirección, para trazabilidad del hallazgo."""
        return {ip: classify_ip(ip) for ip in self.ip_addresses}

    @property
    def is_active(self) -> bool:
        """True si el host resuelve a al menos una IP enrutable.

        Un nombre que resuelve exclusivamente a ``0.0.0.0``, a bucle local o
        a direccionamiento privado **no** es un activo alcanzable, aunque el
        registro DNS exista.
        """
        return self.status is ResolutionStatus.ACTIVE and bool(self.routable_ips)

    @property
    def leaks_internal_addressing(self) -> bool:
        """True si un nombre público resuelve a direccionamiento interno.

        No es un activo alcanzable, pero sí un hallazgo: revela estructura de
        red interna. La capa IA lo tratará como tal (Paso 5).
        """
        return any(
            scope in (IpScope.PRIVATE, IpScope.LOOPBACK, IpScope.CGNAT)
            for scope in self.ip_scopes.values()
        )


class SubdomainScanResult(BaseModel):
    """Resultado completo de una enumeración de subdominios."""

    domain: str = Field(description="Dominio raíz analizado")
    records: list[SubdomainRecord] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    errors: list[str] = Field(
        default_factory=list,
        description="Incidencias no fatales (p. ej. una fuente no disponible)",
    )

    @property
    def total_discovered(self) -> int:
        """Número de subdominios únicos encontrados."""
        return len(self.records)

    @property
    def active_records(self) -> list[SubdomainRecord]:
        """Subdominios que resuelven a una IP alcanzable."""
        return [r for r in self.records if r.is_active]

    @property
    def unroutable_records(self) -> list[SubdomainRecord]:
        """Subdominios que resuelven, pero solo a direcciones no alcanzables."""
        return [r for r in self.records if r.status is ResolutionStatus.UNROUTABLE]

    @property
    def leaking_records(self) -> list[SubdomainRecord]:
        """Subdominios que exponen direccionamiento interno."""
        return [r for r in self.records if r.leaks_internal_addressing]

    @property
    def total_active(self) -> int:
        """Número de subdominios activos y alcanzables."""
        return len(self.active_records)

    @property
    def duration_seconds(self) -> float | None:
        """Duración del escaneo en segundos, si ya ha finalizado."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def unique_ips(self) -> list[str]:
        """Todas las direcciones observadas, únicas y ordenadas."""
        return sorted({ip for record in self.records for ip in record.ip_addresses})

    def scan_targets(self) -> list[str]:
        """Direcciones enrutables únicas: objetivos válidos de escaneo.

        Es la entrada del módulo de puertos. Excluye deliberadamente las
        direcciones no alcanzables, que producirían intentos de conexión
        inútiles o, peor, dirigidos al propio equipo que ejecuta la herramienta.
        """
        return sorted({ip for record in self.records for ip in record.routable_ips})

    def summary(self) -> dict[str, object]:
        """Resumen compacto para logs, CLI y respuestas de la API."""
        return {
            "domain": self.domain,
            "discovered": self.total_discovered,
            "active": self.total_active,
            "unroutable": len(self.unroutable_records),
            "leaking_internal": len(self.leaking_records),
            "scan_targets": len(self.scan_targets()),
            "duration_seconds": self.duration_seconds,
            "errors": len(self.errors),
        }


class DiscoveryFinding(BaseModel):
    """Hallazgo producido por un módulo de descubrimiento (cabeceras, TLS...).

    Forma mínima y deliberadamente igual a los campos de escritura de
    `core.models.Finding` (`finding_type`, `evidence`): cualquier módulo que
    detecte un riesgo devuelve esto, no un `Finding` de SQLAlchemy — el
    descubrimiento no conoce la capa de persistencia, igual que
    `SubdomainRecord` tampoco la conoce. La severidad nace siempre `unknown`;
    la razona el triaje por IA (Paso 5), nunca el propio módulo de
    descubrimiento.
    """

    finding_type: str = Field(description="Categoría del hallazgo, p. ej. 'hsts_missing'")
    evidence: str = Field(description="Qué se observó exactamente, en lenguaje claro")


class HeaderScanResult(BaseModel):
    """Resultado del análisis de cabeceras de seguridad HTTP de un host."""

    hostname: str
    checked_url: str | None = Field(
        default=None, description="URL efectivamente consultada (esquema incluido)"
    )
    findings: list[DiscoveryFinding] = Field(default_factory=list)
    error: str | None = Field(
        default=None,
        description="Motivo por el que no se pudo completar el análisis, si aplica",
    )


class TlsScanResult(BaseModel):
    """Resultado de la inspección TLS de un host."""

    hostname: str
    port: int = 443
    protocol_version: str | None = Field(
        default=None, description="Versión de protocolo negociada, p. ej. 'TLSv1.2'"
    )
    issuer: str | None = None
    not_valid_before: datetime | None = None
    not_valid_after: datetime | None = None
    days_remaining: int | None = Field(
        default=None, description="Días hasta la caducidad; negativo si ya caducó"
    )
    findings: list[DiscoveryFinding] = Field(default_factory=list)
    error: str | None = Field(
        default=None,
        description="Motivo por el que no se pudo completar la inspección, si aplica",
    )


class EnrichmentResult(BaseModel):
    """Resultado combinado de puertos, cabeceras y TLS sobre los hosts
    activos de un `SubdomainScanResult` (Paso 2, resto).

    Producido por `discovery/enrichment.py::enrich_scan`, que orquesta los
    tres módulos concurrentemente. Vive en `discovery/models.py`, no en
    `enrichment.py`, por el mismo motivo que el resto de modelos de
    descubrimiento: es la forma de intercambio entre la capa de
    descubrimiento (sin estado, sin BD) y `core/persistence.py`.
    """

    ports_by_ip: dict[str, list[int]] = Field(default_factory=dict)
    header_results: list[HeaderScanResult] = Field(default_factory=list)
    tls_results: list[TlsScanResult] = Field(default_factory=list)

    def findings_by_hostname(self) -> dict[str, list[DiscoveryFinding]]:
        """Agrupa los hallazgos de cabeceras y TLS por host.

        Forma lista para `core/persistence.py::apply_discovery_findings`,
        que necesita saber a qué `Asset` (por hostname) añadir cada uno.
        """
        grouped: dict[str, list[DiscoveryFinding]] = {}
        for item in (*self.header_results, *self.tls_results):
            if item.findings:
                grouped.setdefault(item.hostname, []).extend(item.findings)
        return grouped
