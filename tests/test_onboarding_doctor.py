"""Pruebas de `atalaya doctor` de principio a fin, en un proyecto temporal.

`--offline` en todas: el diagnóstico de red ya se prueba con dobles en
`test_onboarding_checks.py`; aquí importa el conjunto (código de salida, que
un `.env` roto se diagnostique en vez de romper el comando) y, sobre todo,
que **ningún secreto del `.env` aparezca en la salida**.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from atalaya.cli import build_parser
from atalaya.onboarding import ui
from atalaya.onboarding.doctor import run_doctor

_SECRETOS = {
    "ANTHROPIC_API_KEY": "sk-ant-api03-SECRETO-ANTHROPIC-a1b2",
    "SHODAN_API_KEY": "SECRETO-SHODAN-9f3c",
    "API_KEY": "SECRETO-API-KEY",
    "GEMINI_API_KEY": "AIza-SECRETO-GEMINI",
}


@pytest.fixture
def proyecto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Directorio de trabajo vacío y sin variables de entorno que interfieran
    (las variables pesan más que el `.env` en pydantic-settings)."""
    monkeypatch.chdir(tmp_path)
    for name in (*_SECRETOS, "DATABASE_URL", "SCAN_ALLOWLIST", "AI_PROVIDER", "AI_MAX_TOKENS"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


async def _doctor(project: Path) -> tuple[int, str]:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    code = await run_doctor(ui.make_terminal(stream, width=120), project, offline=True)
    stream.flush()
    buffer = stream.buffer
    assert isinstance(buffer, io.BytesIO)
    return code, buffer.getvalue().decode("utf-8")


async def test_ningun_secreto_aparece_en_la_salida(proyecto: Path) -> None:
    lineas = [f"{k}={v}" for k, v in _SECRETOS.items()]
    lineas.append("DATABASE_URL=postgresql+asyncpg://atalaya:SECRETO-PG@127.0.0.1:1/atalaya")
    (proyecto / ".env").write_text("\n".join(lineas) + "\n", encoding="utf-8")

    code, salida = await _doctor(proyecto)

    for secreto in [*_SECRETOS.values(), "SECRETO-PG"]:
        assert secreto not in salida
    assert "no conecta con 127.0.0.1:1" in salida
    assert code == 1  # la base de datos inalcanzable es un error


async def test_un_valor_invalido_en_env_se_diagnostica_sin_romper(proyecto: Path) -> None:
    (proyecto / ".env").write_text("AI_MAX_TOKENS=mil\n", encoding="utf-8")

    code, salida = await _doctor(proyecto)

    assert code == 1
    assert "AI_MAX_TOKENS" in salida
    assert "Cómo resolverlo" in salida


async def test_solo_avisos_sale_con_codigo_cero(proyecto: Path) -> None:
    """Sin `.env` todo son valores por defecto: avisos, no errores."""
    (proyecto / ".env.example").write_text("", encoding="utf-8")

    code, salida = await _doctor(proyecto)

    assert code == 0
    assert "atalaya init" in salida
    assert "código de salida 0" in salida


def test_el_subcomando_doctor_acepta_offline() -> None:
    args = build_parser().parse_args(["doctor", "--offline"])
    assert args.offline is True
    assert args.func.__name__ == "_run_doctor"
