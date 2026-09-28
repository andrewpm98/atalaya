"""Modelos ORM: Scan, Asset, Finding.

Relaciones: ``Scan 1─N Asset``, ``Asset 1─N Finding``. Los campos de `Asset`
reflejan los de `discovery.models.SubdomainRecord` para que persistir un
resultado de descubrimiento sea una copia directa de campos, no una
reinterpretación (ver `core/persistence.py`).

Los estados y fuentes se guardan como cadenas (`.value` de los enums de
`discovery.models`), no reutilizando esos mismos enums aquí: acopla la capa
de persistencia a la de descubrimiento lo mínimo posible, a costa de no
validar el valor a nivel de tipo Python. La restricción de valores válidos
vive en el enum de origen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import JSON, DateTime, ForeignKey, Text
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from atalaya.core.database import Base


class ScanStatus(str, Enum):
    """Estado del ciclo de vida de un escaneo."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingSeverity(str, Enum):
    """Severidad de un hallazgo.

    Sin la capa de IA (Paso 5), todo hallazgo nace en `UNKNOWN`: no se
    inventa una severidad antes de que el triaje la razone.
    """

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _values(enum_cls: type[Enum]) -> list[str]:
    """Fuerza a SQLAlchemy a guardar `.value` (minúsculas) y no `.name`."""
    return [member.value for member in enum_cls]


class UtcDateTime(TypeDecorator[datetime]):
    """Marca de tiempo guardada como UTC *naive* en `TIMESTAMP WITHOUT TIME ZONE`.

    El resto del código trabaja con `datetime` *aware* en UTC (lo correcto
    fuera de la BD), pero las columnas de la migración inicial no tienen zona
    horaria. SQLite acepta un valor *aware* ahí sin quejarse; asyncpg lo
    rechaza (``can't subtract offset-naive and offset-aware datetimes``), así
    que contra PostgreSQL ningún escaneo llegaba a guardarse — bug real, que
    la suite no veía porque corre sobre SQLite.

    Por qué convertir aquí y no pasar las columnas a `TIMESTAMP WITH TIME
    ZONE`: no exige migración, y la lectura sigue devolviendo lo mismo que
    hasta ahora en los dos motores (*naive*, en UTC), así que la API no cambia
    de formato según el motor. Se *convierte* a UTC antes de quitar la zona,
    no solo se descarta: un valor *aware* en otra zona se guarda correcto.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is not None:
            return value.astimezone(UTC).replace(tzinfo=None)
        return value


class Scan(Base):
    """Un escaneo concreto sobre un dominio objetivo."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(index=True)
    status: Mapped[ScanStatus] = mapped_column(
        SqlEnum(ScanStatus, values_callable=_values), default=ScanStatus.RUNNING
    )
    started_at: Mapped[datetime] = mapped_column(
        UtcDateTime(), default=lambda: datetime.now(UTC)
    )
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), default=None)
    #: Incidencias no fatales del escaneo (p. ej. una fuente externa caída).
    errors: Mapped[list[str]] = mapped_column(JSON, default=list)

    #: `order_by` explícito: sin él, el orden de carga no está garantizado, y en
    #: PostgreSQL cambia de verdad — un `UPDATE` (el triaje) reescribe la fila
    #: al final del heap. Ese orden llega a los prompts de la capa IA, al informe
    #: y al dashboard; con él, los tres son reproducibles entre motores y antes/
    #: después de triar (lo exige el proveedor `replay`, ver `ai/replay.py`).
    assets: Mapped[list[Asset]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Asset.id"
    )


class Asset(Base):
    """Un activo descubierto durante un escaneo: host, IPs y su alcance."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    hostname: Mapped[str] = mapped_column(index=True)
    #: `ResolutionStatus.value`: active/wildcard/unroutable/nxdomain/no_answer/timeout/error.
    status: Mapped[str] = mapped_column()
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: `DiscoverySource.value` de cada fuente que reportó el host.
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(default=False)
    leaks_internal_addressing: Mapped[bool] = mapped_column(default=False)
    #: Puertos abiertos detectados. Vacío hasta que `discovery/ports.py`
    #: (Paso 2) esté implementado; la columna ya existe para no requerir
    #: una migración adicional cuando llegue.
    open_ports: Mapped[list[int]] = mapped_column(JSON, default=list)

    scan: Mapped[Scan] = relationship(back_populates="assets")
    #: Mismo motivo que `Scan.assets`: orden estable independiente del motor.
    findings: Mapped[list[Finding]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", order_by="Finding.id"
    )


class Finding(Base):
    """Un hallazgo de riesgo asociado a un activo, pendiente de triaje IA."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    #: Categoría del hallazgo, p. ej. "internal_addressing_leak".
    finding_type: Mapped[str] = mapped_column(index=True)
    evidence: Mapped[str] = mapped_column(Text)
    severity: Mapped[FindingSeverity] = mapped_column(
        SqlEnum(FindingSeverity, values_callable=_values),
        default=FindingSeverity.UNKNOWN,
    )
    #: Explicación de impacto y remediación: las produce la capa IA (Paso 5).
    impact: Mapped[str | None] = mapped_column(Text, default=None)
    remediation: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime(), default=lambda: datetime.now(UTC)
    )

    asset: Mapped[Asset] = relationship(back_populates="findings")
