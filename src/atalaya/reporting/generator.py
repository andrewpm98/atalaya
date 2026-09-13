"""Generador de informe con portada. Se implementa en el Paso 7."""

from __future__ import annotations

from pathlib import Path


async def generate_report(scan_id: int, fmt: str = "pdf") -> Path:
    """Genera el informe de un escaneo y devuelve la ruta del fichero."""
    raise NotImplementedError
