"""Pruebas de los datos de reserva de la demo (`scripts/`, `demo/`).

La central es `test_la_demo_completa_se_reproduce_sin_red`: siembra el fixture
versionado y recorre el guion entero por la API con `AI_PROVIDER=replay`. Las
grabaciones dependen del texto exacto de cada prompt, así que si alguien
cambia un prompt, el contexto que se le manda al modelo o el orden de los
datos, esta prueba falla *ahora* — no el día de la defensa, sin red para
regrabar. El remedio es volver a ejecutar `scripts/build_demo_data.py`.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.config import settings
from atalaya.core.models import Finding, FindingSeverity, Scan

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_demo_data
import seed_demo_data

FIXTURE = seed_demo_data.load_fixture()


def _findings(raw_scan: dict[str, object]) -> list[dict[str, object]]:
    return [f for a in raw_scan["assets"] for f in a["findings"]]  # type: ignore[attr-defined]


def test_fixture_previo_triado_y_actual_con_pendientes_declarados() -> None:
    previous, current = FIXTURE["scans"]
    assert previous["domain"] == current["domain"] == FIXTURE["meta"]["domain"]
    assert previous["started_at"] < current["started_at"]
    assert all(f["severity"] != "unknown" for f in _findings(previous))

    pending = [f for f in _findings(current) if f["severity"] == "unknown"]
    assert len(pending) == FIXTURE["meta"]["pending_triage"] > 0
    assert all(f["impact"] is None and f["remediation"] is None for f in pending)
    triaged = [f for f in _findings(current) if f["severity"] != "unknown"]
    assert all(f["impact"] and f["remediation"] for f in triaged)


async def test_seed_asigna_ids_desde_1_en_orden_cronologico(db_session: AsyncSession) -> None:
    scans = await seed_demo_data.seed(db_session, FIXTURE, reset=True)
    assert [s.id for s in scans] == [1, 2]
    assert scans[0].started_at < scans[1].started_at


async def test_seed_se_niega_a_pisar_una_bd_con_escaneos(db_session: AsyncSession) -> None:
    db_session.add(Scan(domain="ajeno.com"))
    await db_session.commit()
    with pytest.raises(seed_demo_data.SeedError, match="--reset"):
        await seed_demo_data.seed(db_session, FIXTURE, reset=False)
    assert await seed_demo_data.count_scans(db_session) == 1


async def test_seed_con_reset_sustituye_todo_y_reinicia_ids(db_session: AsyncSession) -> None:
    """Sin reiniciar la secuencia, el diff pediría otros ids y la grabación no coincidiría."""
    for _ in range(3):
        db_session.add(Scan(domain="ajeno.com"))
    await db_session.commit()

    scans = await seed_demo_data.seed(db_session, FIXTURE, reset=True)
    assert [s.id for s in scans] == [1, 2]
    assert await seed_demo_data.count_scans(db_session) == 2
    total = sum(len(_findings(s)) for s in FIXTURE["scans"])
    stored = (await db_session.execute(Finding.__table__.select())).all()
    assert len(stored) == total


async def test_la_demo_completa_se_reproduce_sin_red(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guion entero con `AI_PROVIDER=replay`: preguntas, informe, diff, triaje y otra vez."""
    monkeypatch.setattr(settings, "ai_provider", "replay")
    monkeypatch.setattr(settings, "ai_replay_file", str(ROOT / "demo" / "ai_recordings.json"))
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))

    with build_demo_data._replay_misses() as misses:
        summary = await build_demo_data._with_seeded_api(FIXTURE, tmp_path, "demo", None)

    # Un fallo aquí no se ve en los códigos HTTP (el informe se degrada sin
    # resumen a propósito): por eso se exige que no falte ninguna grabación.
    assert misses == []
    assert summary["triaged"] == FIXTURE["meta"]["pending_triage"]
    assert summary["diff"]["nuevos"] + summary["diff"]["comunes"] == len(
        FIXTURE["scans"][1]["assets"]
    )


def test_pendientes_del_fixture_son_los_que_no_existian_en_el_previo() -> None:
    """El criterio de qué se tría en directo: lo aparecido desde el escaneo anterior."""
    previous, current = FIXTURE["scans"]
    prev_keys = {
        (a["hostname"], f["finding_type"]) for a in previous["assets"] for f in a["findings"]
    }
    for asset in current["assets"]:
        for finding in asset["findings"]:
            is_new = (asset["hostname"], finding["finding_type"]) not in prev_keys
            assert (finding["severity"] == FindingSeverity.UNKNOWN.value) == is_new


def test_cli_de_siembra_de_extremo_a_extremo(tmp_path: Path) -> None:
    """El comando real de la defensa: migra, siembra, se niega a repetir sin
    `--reset` y resiembra con él. Ejecuta `main()` en un subproceso porque el
    engine de `core/database.py` se crea al importar, con el `DATABASE_URL`
    del entorno."""
    db = tmp_path / "demo.sqlite3"
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite+aiosqlite:///{db.as_posix()}",
        "PYTHONIOENCODING": "utf-8",
    }
    script = str(ROOT / "scripts" / "seed_demo_data.py")

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, script, *args],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )

    first = run()
    assert first.returncode == 0, first.stderr
    assert "#2 github.com" in first.stdout
    assert f"{FIXTURE['meta']['pending_triage']} sin triar" in first.stdout

    again = run()
    assert again.returncode == 1
    assert "--reset" in again.stderr

    reset = run("--reset")
    assert reset.returncode == 0, reset.stderr
    assert "#1 github.com" in reset.stdout
