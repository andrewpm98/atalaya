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
