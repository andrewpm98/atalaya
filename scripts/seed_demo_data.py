"""Carga los datos de reserva de la demo en una BD limpia, con un solo comando.

    python scripts/seed_demo_data.py --reset

Siembra `demo/github.com.json`: dos escaneos reales de github.com (21/09 y
28/09/2026), con sus hallazgos triados por el modelo real salvo los que
aparecieron entre un escaneo y otro, que quedan pendientes para triarlos en
directo. Junto con `AI_PROVIDER=replay` (grabaciones en
`demo/ai_recordings.json`), la demo completa — escaneos, triaje, pregunta en
lenguaje natural, informe y diff — funciona sin red. Ver "Datos de reserva
para la demo" en CLAUDE.md.

Usa el `DATABASE_URL` configurado (SQLite local o el PostgreSQL de Docker) y
aplica antes las migraciones. **`--reset` borra todos los escaneos de esa
BD**: sin él, el script se niega a sembrar sobre una BD que ya tenga datos.
Reiniciar también las secuencias de ids no es cosmético: el prompt del diff
incluye los ids de ambos escaneos, así que las respuestas grabadas solo
coinciden si el seed produce siempre los mismos (#1 y #2).

Herramienta de demo, no parte del paquete `atalaya` (mismo criterio que
`_shot.py`): vive en `scripts/` y no se instala.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "demo" / "github.com.json"
FIXTURE_FORMAT = 1

#: Orden de borrado: hijos antes que padres. SQLite no aplica `ON DELETE
#: CASCADE` sin `PRAGMA foreign_keys=ON`, así que no se confía en la cascada.
_TABLES = ("findings", "assets", "scans")


class SeedError(Exception):
    """Condición que impide sembrar (fixture inválido o BD con datos)."""


def load_fixture(path: str | Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    """Lee y valida lo mínimo del fixture: formato y presencia de escaneos."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("meta", {}).get("format") != FIXTURE_FORMAT:
        raise SeedError(f"formato de fixture no soportado en {path}")
    if not data.get("scans"):
        raise SeedError(f"el fixture {path} no contiene escaneos")
    return data


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def build_scans(fixture: dict[str, Any]) -> list[Scan]:
    """Traduce el fixture a objetos ORM, en el orden en que deben recibir id."""
    scans: list[Scan] = []
    for raw_scan in fixture["scans"]:
        scan = Scan(
            domain=raw_scan["domain"],
            status=ScanStatus(raw_scan["status"]),
            started_at=_parse_dt(raw_scan["started_at"]),
            finished_at=_parse_dt(raw_scan["finished_at"]),
            errors=list(raw_scan["errors"]),
        )
        for raw_asset in raw_scan["assets"]:
            asset = Asset(
                hostname=raw_asset["hostname"],
                status=raw_asset["status"],
                ip_addresses=list(raw_asset["ip_addresses"]),
                sources=list(raw_asset["sources"]),
                is_active=raw_asset["is_active"],
                leaks_internal_addressing=raw_asset["leaks_internal_addressing"],
                open_ports=list(raw_asset["open_ports"]),
            )
            for raw_finding in raw_asset["findings"]:
                asset.findings.append(
                    Finding(
                        finding_type=raw_finding["finding_type"],
                        evidence=raw_finding["evidence"],
                        severity=FindingSeverity(raw_finding["severity"]),
                        impact=raw_finding["impact"],
                        remediation=raw_finding["remediation"],
                        created_at=_parse_dt(raw_finding["created_at"]),
                    )
                )
            scan.assets.append(asset)
        scans.append(scan)
    return scans


async def count_scans(session: AsyncSession) -> int:
    return int((await session.execute(select(func.count()).select_from(Scan))).scalar_one())


async def reset_database(session: AsyncSession) -> None:
    """Vacía las tablas y reinicia las secuencias de ids (ver docstring del módulo)."""
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text(f"TRUNCATE TABLE {', '.join(_TABLES)} RESTART IDENTITY"))
    else:
        for table in _TABLES:
            await session.execute(text(f"DELETE FROM {table}"))
        # Sin AUTOINCREMENT, SQLite reutiliza max(rowid)+1: con la tabla vacía
        # vuelve a 1. Si alguna tabla lo usara, su contador vive aquí.
        has_sequence = await session.execute(
            text("SELECT 1 FROM sqlite_master WHERE name = 'sqlite_sequence'")
        )
        if has_sequence.first() is not None:
            await session.execute(text("DELETE FROM sqlite_sequence"))
    await session.commit()


async def seed(session: AsyncSession, fixture: dict[str, Any], *, reset: bool) -> list[Scan]:
    """Siembra el fixture. Se niega si la BD tiene escaneos y `reset` es falso.

    Cada escaneo se vuelca (`flush`) antes de añadir el siguiente para que
    los ids sigan el orden del fixture: el previo recibe el id menor.
    """
    existing = await count_scans(session)
    if existing and not reset:
        raise SeedError(
            f"la BD ya tiene {existing} escaneo(s); usa --reset para borrarlos y sembrar la demo"
        )
    await reset_database(session)

    scans = build_scans(fixture)
    for scan in scans:
        session.add(scan)
        await session.flush()
    await session.commit()

    expected = list(range(1, len(scans) + 1))
    if [scan.id for scan in scans] != expected:
        raise SeedError(
            f"ids de escaneo inesperados {[s.id for s in scans]} (se esperaba {expected}): "
            "las respuestas grabadas del diff no coincidirían"
        )
    return scans


def _run_migrations() -> None:
    """`alembic upgrade head` sobre el `DATABASE_URL` configurado.

    Antes de abrir el bucle de eventos propio: `migrations/env.py` hace su
    propio `asyncio.run()`, que no puede anidarse.
    """
    from alembic import command
    from alembic.config import Config

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(config, "head")


def _summary(fixture: dict[str, Any], scan_ids: list[int]) -> str:
    """Resumen legible de lo sembrado, calculado desde el fixture.

    No desde los objetos ORM: tras cerrar la sesión, la colección `findings`
    de un activo sin hallazgos nunca se inicializó y leerla intentaría una
    carga perezosa sin sesión (`DetachedInstanceError`).
    """
    lines = []
    for scan_id, raw_scan in zip(scan_ids, fixture["scans"], strict=True):
        findings = [f for a in raw_scan["assets"] for f in a["findings"]]
        pending = sum(f["severity"] == FindingSeverity.UNKNOWN.value for f in findings)
        lines.append(
            f"  #{scan_id} {raw_scan['domain']} {raw_scan['started_at'][:16]} UTC — "
            f"{len(raw_scan['assets'])} activos, {len(findings)} hallazgos, {pending} sin triar"
        )
    lines.append("Preguntas grabadas para AI_PROVIDER=replay (dominio github.com):")
    lines.extend(f"  - {question}" for question in fixture["meta"]["questions"])
    return "\n".join(lines)


async def _main(fixture_path: Path, reset: bool) -> None:
    from atalaya.core.database import SessionLocal, engine

    fixture = load_fixture(fixture_path)
    try:
        async with SessionLocal() as session:
            scan_ids = [scan.id for scan in await seed(session, fixture, reset=reset)]
        print(f"Datos de demo sembrados desde {fixture_path.relative_to(ROOT)}:")
        print(_summary(fixture, scan_ids))
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--reset", action="store_true", help="borra TODOS los escaneos de la BD antes de sembrar"
    )
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args(argv)

    from atalaya.config import settings

    print(f"BD: {make_url(settings.database_url).render_as_string(hide_password=True)}")
    _run_migrations()
    try:
        asyncio.run(_main(args.fixture.resolve(), args.reset))
    except SeedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
