"""Construye los datos de reserva de la demo a partir de escaneos reales.

    python scripts/build_demo_data.py --previous 2 --current 7

Se ejecuta **una vez, con red y con clave del proveedor de IA**; lo que
produce se versiona y es lo que usa `scripts/seed_demo_data.py` el día de la
defensa, sin red. Se versiona también este script porque es la respuesta a
"¿de dónde salen estos datos?": nada está escrito a mano.

1. Exporta dos escaneos reales del mismo dominio de la BD configurada
   (`DATABASE_URL`), hechos con `POST /scans`.
2. Los tría **todos** con el modelo real (`AI_PROVIDER`), a través de
   `RecordingProvider`: cada respuesta queda grabada en una caché local
   (`demo/.ai_cache.json`, no versionada) para no pagar dos veces el mismo
   prompt si hay que regenerar.
3. Escribe el fixture `demo/<dominio>.json`: todo triado, salvo los
   hallazgos del escaneo actual que no existían en el previo (mismo hostname
   y tipo), que quedan `unknown` para triarlos en directo durante la demo.
4. Siembra el fixture en una BD temporal con el mismo código que el día de
   la defensa y recorre el guion por la API (`run_demo_flow`) antes y
   después de triar lo pendiente: así el orden en que se hagan los pasos en
   la defensa no importa. Graba `demo/ai_recordings.json` solo con lo que
   ese recorrido usó.
5. Verifica: siembra de nuevo y repite el recorrido con `AI_PROVIDER=replay`,
   sin tocar el modelo real. Si algo no está grabado, falla aquí.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import tempfile
from collections.abc import AsyncGenerator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from atalaya.ai.provider import LLMProvider, get_provider
from atalaya.ai.replay import RecordingProvider, RecordingStore
from atalaya.ai.triage import triage_findings
from atalaya.api import main as api_main
from atalaya.api.routes import findings as findings_routes
from atalaya.api.routes import scans as scans_routes
from atalaya.api.security import API_KEY_HEADER
from atalaya.config import settings
from atalaya.core import repository
from atalaya.core.database import Base, SessionLocal, get_session
from atalaya.core.models import FindingSeverity, Scan

sys.path.insert(0, str(Path(__file__).resolve().parent))
from seed_demo_data import FIXTURE_FORMAT, ROOT, load_fixture, seed

DEMO_DIR = ROOT / "demo"
RECORDINGS = DEMO_DIR / "ai_recordings.json"
CACHE = DEMO_DIR / ".ai_cache.json"

#: Guion de preguntas en lenguaje natural. La primera es el placeholder del
#: dashboard: quien pruebe sin guion probablemente empiece por ella.
QUESTIONS = [
    "¿Algún activo filtra direccionamiento interno?",
    "¿Qué debería arreglar primero y por qué?",
    "¿Qué subdominios parecen entornos de prueba o de uso interno?",
    "¿Hay riesgo de subdomain takeover en este dominio?",
]


class DemoFlowError(Exception):
    """Un paso del guion de la demo no respondió como debe."""


# --- Recorrido del guion --------------------------------------------------------


async def run_demo_flow(
    client: httpx.AsyncClient,
    *,
    domain: str,
    previous_id: int,
    current_id: int,
    questions: list[str],
    expected_pending: int,
) -> dict[str, Any]:
    """Recorre la demo por la API: preguntas, informe y diff; triaje; y otra vez.

    Solo comprueba lo que se ve desde fuera (códigos HTTP, recuentos), como lo
    vería el dashboard. Que el informe lleve resumen ejecutivo no se ve en el
    código HTTP — `GET /report` se degrada sin él a propósito — así que quien
    llama debe vigilar los fallos del proveedor (ver `_replay_misses`).
    """

    def check(response: httpx.Response, what: str) -> httpx.Response:
        if response.status_code != 200:
            raise DemoFlowError(f"{what}: HTTP {response.status_code} {response.text[:300]}")
        return response

    async def one_pass(label: str) -> dict[str, Any]:
        for question in questions:
            check(
                await client.post("/findings/ask", json={"domain": domain, "question": question}),
                f"[{label}] pregunta {question!r}",
            )
        report = check(await client.get(f"/scans/{current_id}/report"), f"[{label}] informe")
        if not report.content.startswith(b"%PDF"):
            raise DemoFlowError(f"[{label}] el informe no es un PDF")
        diff = check(
            await client.get(f"/scans/{current_id}/diff/{previous_id}"), f"[{label}] diff"
        ).json()
        if not diff["analysis"].strip():
            raise DemoFlowError(f"[{label}] diff sin análisis")
        return {k: len(diff[k]) for k in ("nuevos", "desaparecidos", "comunes", "cambiados")}

    await one_pass("antes del triaje")
    triage = check(await client.post(f"/scans/{current_id}/triage"), "triaje en directo").json()
    if triage["triaged"] != expected_pending or triage["errors"]:
        raise DemoFlowError(
            f"triaje en directo: {triage['triaged']} triados (se esperaban "
            f"{expected_pending}), errores {triage['errors']}"
        )
    diff_counts = await one_pass("después del triaje")
    check(await client.get(f"/scans/{previous_id}/report"), "informe del escaneo previo")
    return {"triaged": triage["triaged"], "diff": diff_counts}


# --- Infraestructura: BD temporal y API en proceso ------------------------------


@contextmanager
def _patched_provider(provider: LLMProvider | None) -> Iterator[None]:
    """Hace que las rutas usen `provider` en vez de instanciar el configurado.

    `None` deja el `get_provider()` real: es lo que se quiere al verificar
    con `AI_PROVIDER=replay`, para recorrer exactamente el camino de la demo.
    """
    originals = (scans_routes.get_provider, findings_routes.get_provider)
    if provider is not None:
        scans_routes.get_provider = lambda: provider  # type: ignore[assignment]
        findings_routes.get_provider = lambda: provider  # type: ignore[assignment]
    try:
        yield
    finally:
        scans_routes.get_provider, findings_routes.get_provider = originals


async def _with_seeded_api(
    fixture: dict[str, Any], workdir: Path, name: str, provider: LLMProvider | None
) -> dict[str, Any]:
    """Siembra `fixture` en una SQLite temporal y recorre el guion por la API."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{workdir / name}.sqlite3")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        await seed(session, fixture, reset=True)

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as session:
            yield session

    meta = fixture["meta"]
    api_main.app.dependency_overrides[get_session] = _override
    try:
        with _patched_provider(provider):
            transport = httpx.ASGITransport(app=api_main.app)
            # Con API_KEY en .env la API en proceso también la exige: sin la
            # cabecera, todo el guion respondería 401.
            headers = {API_KEY_HEADER: settings.api_key} if settings.api_key else None
            async with httpx.AsyncClient(
                transport=transport, base_url="http://demo", timeout=600, headers=headers
            ) as client:
                return await run_demo_flow(
                    client,
                    domain=meta["domain"],
                    previous_id=1,
                    current_id=2,
                    questions=meta["questions"],
                    expected_pending=meta["pending_triage"],
                )
    finally:
        api_main.app.dependency_overrides.clear()
        await engine.dispose()


@contextmanager
def _replay_misses() -> Iterator[list[str]]:
    """Recoge los avisos de `ReplayProvider` por peticiones no grabadas."""
    misses: list[str] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if "sin grabación" in record.getMessage():
                misses.append(record.getMessage())

    handler = _Handler(level=logging.WARNING)
    logger = logging.getLogger("atalaya.ai.replay")
    logger.addHandler(handler)
    try:
        yield misses
    finally:
        logger.removeHandler(handler)


# --- Exportación ------------------------------------------------------------


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _export_scan(scan: Scan, pending: set[tuple[str, str]] | None) -> dict[str, Any]:
    """Escaneo → dict del fixture. Los hallazgos en `pending` vuelven a `unknown`."""
    assets = []
    for asset in scan.assets:
        findings = []
        for finding in asset.findings:
            is_pending = pending is not None and (asset.hostname, finding.finding_type) in pending
            findings.append(
                {
                    "finding_type": finding.finding_type,
                    "evidence": finding.evidence,
                    "severity": (
                        FindingSeverity.UNKNOWN.value if is_pending else finding.severity.value
                    ),
                    "impact": None if is_pending else finding.impact,
                    "remediation": None if is_pending else finding.remediation,
                    "created_at": _dt(finding.created_at),
                }
            )
        assets.append(
            {
                "hostname": asset.hostname,
                "status": asset.status,
                "ip_addresses": asset.ip_addresses,
                "sources": asset.sources,
                "is_active": asset.is_active,
                "leaks_internal_addressing": asset.leaks_internal_addressing,
                "open_ports": asset.open_ports,
                "findings": findings,
            }
        )
    return {
        "domain": scan.domain,
        "status": scan.status.value,
        "started_at": _dt(scan.started_at),
        "finished_at": _dt(scan.finished_at),
        "errors": scan.errors,
        "assets": assets,
    }


def _finding_keys(scan: Scan) -> set[tuple[str, str]]:
    return {(a.hostname, f.finding_type) for a in scan.assets for f in a.findings}


async def _load_source(previous_id: int, current_id: int) -> tuple[Scan, Scan]:
    async with SessionLocal() as session:
        previous = await repository.get_scan(session, previous_id)
        current = await repository.get_scan(session, current_id)
    if previous is None or current is None:
        raise DemoFlowError(f"no existen los escaneos #{previous_id} y #{current_id}")
    if previous.domain != current.domain or previous.started_at >= current.started_at:
        raise DemoFlowError("los escaneos deben ser del mismo dominio y el previo, anterior")
    return previous, current


async def _triage_all(
    fixture: dict[str, Any], workdir: Path, recorder: RecordingProvider
) -> dict[str, Any]:
    """Tría todo el fixture en una BD temporal y devuelve el fixture triado."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{workdir / 'triage'}.sqlite3")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        async with factory() as session:
            ids = [scan.id for scan in await seed(session, fixture, reset=True)]
        triaged_scans = []
        async with factory() as session:
            for scan_id in ids:
                scan = await repository.get_scan(session, scan_id)
                assert scan is not None
                findings = [f for a in scan.assets for f in a.findings]
                result = await triage_findings(recorder, findings)
                if result.errors:
                    raise DemoFlowError(f"triaje del escaneo #{scan_id}: {result.errors[:3]}")
                await session.commit()
                triaged_scans.append(scan)
                print(f"  #{scan_id}: {result.triaged} hallazgos triados")
            return {"scans": triaged_scans}
    finally:
        await engine.dispose()


async def build(previous_id: int, current_id: int) -> None:
    previous, current = await _load_source(previous_id, current_id)
    pending = _finding_keys(current) - _finding_keys(previous)
    domain = current.domain
    real_provider = get_provider()
    model = settings.gemini_model if settings.ai_provider == "gemini" else settings.ai_model
    print(
        f"Fuente: #{previous.id} y #{current.id} de {domain}; modelo {settings.ai_provider}/{model}"
    )

    DEMO_DIR.mkdir(exist_ok=True)
    cache = RecordingStore.load(CACHE) if CACHE.exists() else RecordingStore()
    recorder = RecordingProvider(real_provider, cache)
    base_meta = {
        "format": FIXTURE_FORMAT,
        "domain": domain,
        "questions": QUESTIONS,
    }
    raw_fixture = {
        "meta": {**base_meta, "pending_triage": 0},
        "scans": [_export_scan(previous, None), _export_scan(current, None)],
    }

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        settings.reports_dir = str(workdir / "reports")
        Path(settings.reports_dir).mkdir()

        print("1/4 Triaje completo con el modelo real")
        try:
            triaged = await _triage_all(raw_fixture, workdir, recorder)
        finally:
            cache.save(CACHE)
        print(f"    llamadas reales al modelo: {recorder.calls}")

        prev_scan, cur_scan = triaged["scans"]
        pending_count = sum(
            (a.hostname, f.finding_type) in pending for a in cur_scan.assets for f in a.findings
        )
        fixture = {
            "meta": {
                **base_meta,
                "description": (
                    f"Dos escaneos reales de {domain} hechos con Atalaya (POST /scans). "
                    f"Triaje real con {settings.ai_provider}/{model}; los hallazgos del "
                    "escaneo actual que no existían en el previo quedan sin triar, para "
                    "triarlos en directo."
                ),
                "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "model": f"{settings.ai_provider}/{model}",
                "pending_triage": pending_count,
            },
            "scans": [_export_scan(prev_scan, None), _export_scan(cur_scan, pending)],
        }
        fixture_path = DEMO_DIR / f"{domain}.json"
        fixture_path.write_text(
            json.dumps(fixture, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )
        fixture = load_fixture(fixture_path)
        print(f"2/4 Fixture escrito: {fixture_path.relative_to(ROOT)} ({pending_count} pendientes)")

        print("3/4 Grabando el guion (antes y después del triaje en directo)")
        recorder.used.clear()
        calls_before = recorder.calls
        try:
            summary = await _with_seeded_api(fixture, workdir, "record", recorder)
        finally:
            cache.save(CACHE)
        print(
            f"    llamadas reales al modelo: {recorder.calls - calls_before}; diff {summary['diff']}"
        )

        recordings = RecordingStore(
            entries={k: cache.entries[k] for k in sorted(recorder.used)},
            meta={
                "recorded_at": datetime.now(UTC).date().isoformat(),
                "model": f"{settings.ai_provider}/{model}",
                "fixture": fixture_path.relative_to(ROOT).as_posix(),
            },
        )
        recordings.save(RECORDINGS)
        print(f"    {len(recordings.entries)} respuestas en {RECORDINGS.relative_to(ROOT)}")

        print("4/4 Verificación sin modelo real (AI_PROVIDER=replay)")
        settings.ai_provider = "replay"
        settings.ai_replay_file = str(RECORDINGS)
        with _replay_misses() as misses:
            await _with_seeded_api(fixture, workdir, "verify", None)
        if misses:
            raise DemoFlowError(f"{len(misses)} peticiones sin grabación: {misses[:3]}")
        print("    demo completa reproducida sin llamar al modelo")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--previous", type=int, required=True, help="id del escaneo previo")
    parser.add_argument("--current", type=int, required=True, help="id del escaneo actual")
    args = parser.parse_args(argv)
    try:
        asyncio.run(build(args.previous, args.current))
    except DemoFlowError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
