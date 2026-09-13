"""Interfaz de línea de comandos de Atalaya (arranque)."""

from __future__ import annotations

import argparse

from atalaya import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="atalaya", description="Atalaya ASM")
    parser.add_argument("--version", action="version", version=f"Atalaya {__version__}")
    parser.parse_args()
    print("Atalaya listo. Usa 'make api' para levantar la API.")


if __name__ == "__main__":
    main()
