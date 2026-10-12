"""Lectura y escritura del `.env`: el único sitio donde viven los secretos.

Tres garantías, porque un `.env` a medio escribir deja la herramienta sin
arrancar y uno subido a git filtra todas las claves:

- **Se conserva lo que no se toca.** Se parte del `.env` existente (o de
  `.env.example`, la plantilla versionada) y solo se reemplazan los valores
  pedidos: comentarios, orden y el resto de campos quedan como estaban.
- **Escritura atómica con copia.** Fichero temporal en el mismo directorio y
  `os.replace`: o queda el `.env` nuevo entero o el anterior intacto. Antes,
  copia del anterior en `.env.bak-AAAAMMDD-HHMMSS` (ignorado por git y por
  Docker, ver `.gitignore`/`.dockerignore`: contiene secretos).
- **Verificado antes de escribir.** El texto generado se vuelve a leer con el
  mismo parser que usa la aplicación (`python-dotenv`, vía pydantic-settings);
  si algún valor no sale idéntico (comillas, `$`, `#`...), no se escribe.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dotenv import dotenv_values

#: Línea de asignación `CLAVE=valor` (con `export` opcional), no comentada.
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
#: Valores que se pueden escribir sin comillas: ni espacios, ni `#`, ni `$`,
#: ni comillas — lo que el parser de dotenv interpretaría.
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_\-.,:/@+=?&%~*\[\]]*")

#: Prefijos públicos que se pueden mostrar al enmascarar (identifican el
#: proveedor, no son secreto).
_PUBLIC_PREFIXES = ("sk-ant-", "AIza")


class EnvWriteError(Exception):
    """El `.env` generado no se puede escribir o no se leería igual."""


@dataclass(frozen=True)
class WriteResult:
    path: Path
    backup: Path | None


def read_env(path: Path) -> dict[str, str]:
    """Valores del `.env` tal como los leería la aplicación (vacío si no existe)."""
    if not path.exists():
        return {}
    return {key: value or "" for key, value in dotenv_values(path).items()}


def format_value(value: str) -> str:
    """Valor listo para `.env`, con comillas solo si hacen falta.

    Ojo: `python-dotenv` expande `${VAR}` **también entre comillas simples**
    (comprobado), así que un valor con `${` no se puede guardar tal cual; no
    hay escape. `write_env` lo detecta al verificar y se niega a escribirlo.
    """
    if _SAFE_VALUE.fullmatch(value):
        return value
    if "'" not in value:
        return f"'{value}'"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_env(base_text: str, updates: dict[str, str]) -> str:
    """Aplica *updates* sobre el texto de un `.env`, conservando el resto.

    Una clave repetida se actualiza en todas sus apariciones (dotenv se queda
    con la última, y dejar una antigua sería confuso). Las que no existen se
    añaden al final, bajo un comentario que dice de dónde salen.
    """
    newline = "\r\n" if "\r\n" in base_text else "\n"
    lines = base_text.splitlines()
    pending = dict(updates)
    for index, line in enumerate(lines):
        match = _ASSIGNMENT.match(line)
        if match and match.group(1) in updates:
            key = match.group(1)
            lines[index] = f"{key}={format_value(updates[key])}"
            pending.pop(key, None)
    if pending:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("# ─── Añadido por atalaya init ───────────────────────────────────")
        lines.extend(f"{key}={format_value(value)}" for key, value in pending.items())
    return newline.join(lines) + newline


def _verify(text: str, updates: dict[str, str]) -> None:
    parsed = dotenv_values(stream=io.StringIO(text))
    wrong = [key for key, value in updates.items() if (parsed.get(key) or "") != value]
    if wrong:
        raise EnvWriteError(
            "el .env generado no se leería igual en: " + ", ".join(sorted(wrong))
        )


def _backup_path(path: Path, now: datetime) -> Path:
    base = path.with_name(f"{path.name}.bak-{now:%Y%m%d-%H%M%S}")
    candidate, counter = base, 1
    while candidate.exists():
        candidate = base.with_name(f"{base.name}-{counter}")
        counter += 1
    return candidate


def write_env(
    path: Path,
    updates: dict[str, str],
    *,
    template: Path | None = None,
    now: datetime | None = None,
) -> WriteResult:
    """Escribe *updates* en el `.env` de *path* de forma atómica y verificada.

    Sin `.env` previo, parte de *template* (`.env.example`) si existe, para
    que el fichero nuevo lleve los comentarios que explican cada campo.
    """
    if path.exists():
        base = path.read_text(encoding="utf-8")
    elif template is not None and template.exists():
        base = template.read_text(encoding="utf-8")
    else:
        base = ""
    text = render_env(base, updates)
    _verify(text, updates)

    backup = None
    if path.exists():
        # Hora local: el nombre de la copia lo lee una persona.
        backup = _backup_path(path, now or datetime.now(UTC).astimezone())
        shutil.copy2(path, backup)

    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.tmp-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            tmp.chmod(0o600)
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise EnvWriteError(f"no se pudo escribir {path.name}: {exc}") from exc
    return WriteResult(path=path, backup=backup)


def mask_secret(value: str) -> str:
    """`sk-ant-…a1b2`: el prefijo público del proveedor y los 4 últimos caracteres."""
    if not value:
        return ""
    if len(value) <= 8:
        return "••••"
    prefix = next((p for p in _PUBLIC_PREFIXES if value.startswith(p)), "••••")
    return f"{prefix}…{value[-4:]}"


def mask_url(url: str) -> str:
    """URL de base de datos sin la contraseña."""
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ArgumentError

    try:
        return make_url(url).render_as_string(hide_password=True)
    except ArgumentError:
        return "(URL no válida)"
