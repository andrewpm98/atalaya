"""Pruebas de `onboarding/envfile.py`: el `.env`, donde viven los secretos.

Lo que importa: no perder lo que ya había (comentarios, otros campos), que el
valor escrito se lea idéntico con el parser de la aplicación, que haya copia
antes de sobrescribir y que un fallo no deje un `.env` a medias.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from dotenv import dotenv_values

from atalaya.onboarding.envfile import (
    EnvWriteError,
    mask_secret,
    mask_url,
    read_env,
    render_env,
    write_env,
)

_BASE = """# ─── Capa IA ───
# Comentario que explica el campo.
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=
AI_MODEL=claude-sonnet-4-6

# Otro bloque
SCAN_ALLOWLIST=
"""


def test_render_reemplaza_valores_y_conserva_comentarios_y_orden() -> None:
    texto = render_env(_BASE, {"ANTHROPIC_API_KEY": "sk-ant-x", "SCAN_ALLOWLIST": "a.com,b.es"})

    assert "# Comentario que explica el campo." in texto
    assert texto.index("AI_PROVIDER") < texto.index("ANTHROPIC_API_KEY") < texto.index("SCAN_ALLOWLIST")
    valores = dotenv_values(stream=__import__("io").StringIO(texto))
    assert valores["ANTHROPIC_API_KEY"] == "sk-ant-x"
    assert valores["SCAN_ALLOWLIST"] == "a.com,b.es"
    assert valores["AI_MODEL"] == "claude-sonnet-4-6"  # lo no pedido, intacto


def test_render_anade_al_final_las_claves_que_no_estaban() -> None:
    texto = render_env("AI_PROVIDER=anthropic\n", {"API_KEY": "k"})
    assert texto.endswith("API_KEY=k\n")
    assert "atalaya init" in texto  # se dice de dónde sale


def test_render_actualiza_todas_las_apariciones_de_una_clave_repetida() -> None:
    texto = render_env("API_KEY=vieja\nAPI_KEY=otra\n", {"API_KEY": "nueva"})
    assert texto.count("API_KEY=nueva") == 2


def test_render_respeta_los_finales_de_linea_windows() -> None:
    texto = render_env("A=1\r\nB=2\r\n", {"B": "3"})
    assert texto == "A=1\r\nB=3\r\n"


@pytest.mark.parametrize(
    "valor",
    [
        "postgresql+asyncpg://u:p%40ss@localhost:5432/db",
        "con espacios y # almohadilla",
        "pa$$word",
        "it's",
        'comillas "dobles"',
        "",
    ],
)
def test_lo_escrito_se_lee_identico(tmp_path: Path, valor: str) -> None:
    env = tmp_path / ".env"
    write_env(env, {"DATABASE_URL": valor})
    assert read_env(env)["DATABASE_URL"] == valor


def test_un_valor_que_no_se_leeria_igual_no_se_escribe(tmp_path: Path) -> None:
    """`${...}` lo expande dotenv incluso entre comillas simples (comprobado):
    la aplicación leería otro valor. Se aborta sin tocar el `.env` existente."""
    env = tmp_path / ".env"
    env.write_text("API_KEY=antigua\n", encoding="utf-8")

    with pytest.raises(EnvWriteError, match="API_KEY"):
        write_env(env, {"API_KEY": "it's ${HOME}"})

    assert env.read_text(encoding="utf-8") == "API_KEY=antigua\n"
    assert list(tmp_path.iterdir()) == [env]  # ni copia ni temporales


def test_sin_env_previo_parte_de_la_plantilla(tmp_path: Path) -> None:
    plantilla = tmp_path / ".env.example"
    plantilla.write_text(_BASE, encoding="utf-8")
    env = tmp_path / ".env"

    resultado = write_env(env, {"SCAN_ALLOWLIST": "ejemplo.com"}, template=plantilla)

    assert resultado.backup is None
    assert "# Comentario que explica el campo." in env.read_text(encoding="utf-8")
    assert read_env(env)["SCAN_ALLOWLIST"] == "ejemplo.com"


def test_antes_de_sobrescribir_guarda_copia_del_anterior(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("API_KEY=antigua\n", encoding="utf-8")

    resultado = write_env(env, {"API_KEY": "nueva"}, now=datetime(2026, 10, 12, 11, 30, 5, tzinfo=UTC))

    assert resultado.backup == tmp_path / ".env.bak-20261012-113005"
    assert resultado.backup.read_text(encoding="utf-8") == "API_KEY=antigua\n"
    assert read_env(env)["API_KEY"] == "nueva"
    # Dos escrituras en el mismo segundo no pisan la primera copia.
    segundo = write_env(env, {"API_KEY": "otra"}, now=datetime(2026, 10, 12, 11, 30, 5, tzinfo=UTC))
    assert segundo.backup is not None and segundo.backup != resultado.backup
    assert not list(tmp_path.glob(".env.tmp-*"))


def test_read_env_de_un_fichero_que_no_existe_es_vacio(tmp_path: Path) -> None:
    assert read_env(tmp_path / ".env") == {}


def test_mask_secret_solo_deja_ver_el_proveedor_y_el_final() -> None:
    assert mask_secret("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ-a1b2") == "sk-ant-…a1b2"
    assert mask_secret("AIzaSyD-1234567890abcdefghij9f3c") == "AIza…9f3c"
    assert mask_secret("Zx8yQw2ErTy6UiOp1AsDfGhJkL3Z9f3c") == "••••…9f3c"
    assert mask_secret("corta") == "••••"
    assert mask_secret("") == ""


def test_mask_url_oculta_la_contrasena() -> None:
    oculta = mask_url("postgresql+asyncpg://atalaya:s3creta@db.interna:5432/atalaya")
    assert "s3creta" not in oculta
    assert "db.interna:5432" in oculta
