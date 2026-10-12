"""Interfaz de línea de comandos de Atalaya.

Permite ejecutar fases de descubrimiento sin levantar la API, lo que resulta
práctico para pruebas rápidas y para la demostración del proyecto.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from atalaya import __version__
from atalaya.core.exceptions import AtalayaError


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # httpx registra en INFO la URL completa de cada petición, y Shodan solo
    # acepta la clave en la URL (`?key=...`): con `-v` acababa en claro en la
    # terminal. Sus avisos y errores se siguen viendo.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


async def _run_subdomains(args: argparse.Namespace) -> int:
    # Imports aquí y no arriba: cargan `atalaya.config`, y un `.env` con un
    # valor inválido impediría arrancar incluso `atalaya doctor`, que es el
    # comando que debe diagnosticarlo.
    from atalaya.core.database import SessionLocal
    from atalaya.core.persistence import (
        apply_discovery_findings,
        apply_port_scan,
        save_subdomain_scan,
    )
    from atalaya.discovery.enrichment import enrich_scan
    from atalaya.discovery.models import ResolutionStatus
    from atalaya.discovery.subdomains import enumerate_subdomains

    result = await enumerate_subdomains(args.domain, resolve=not args.no_resolve)

    if args.save:
        async with SessionLocal() as session:
            scan = await save_subdomain_scan(session, result)
            enrichment = await enrich_scan(result)
            apply_port_scan(scan, enrichment.ports_by_ip)
            apply_discovery_findings(scan, enrichment.findings_by_hostname())
            await session.commit()
            print(f"[BD] Escaneo #{scan.id} guardado ({len(scan.assets)} activos).")

    if args.json:
        print(result.model_dump_json(indent=2))
        return 0

    summary = result.summary()
    print(f"\nDominio analizado   : {summary['domain']}")
    print(f"Subdominios         : {summary['discovered']}")
    print(f"Activos (alcanzab.) : {summary['active']}")
    print(f"No enrutables       : {summary['unroutable']}")
    print(f"Objetivos de escaneo: {summary['scan_targets']} IPs")
    if summary["wildcard_dns"]:
        print(f"DNS wildcard        : sí ({summary['wildcard_filtered']} descartados)")
    if summary["duration_seconds"] is not None:
        print(f"Duración            : {summary['duration_seconds']:.2f} s")

    if result.errors:
        print("\nIncidencias:")
        for error in result.errors:
            print(f"  ! {error}")

    # Los nombres públicos que resuelven a direccionamiento interno son un
    # hallazgo en sí mismos: se destacan aunque no sean activos alcanzables.
    if result.leaking_records:
        print("\n[!] Direccionamiento interno expuesto:")
        for record in result.leaking_records:
            detalle = ", ".join(
                f"{ip} ({scope.value})" for ip, scope in record.ip_scopes.items()
            )
            print(f"  - {record.hostname}: {detalle}")

    records = result.active_records if args.only_active else result.records
    if records:
        print(f"\n{'HOSTNAME':<45} {'ESTADO':<12} IPs")
        print("-" * 82)
        for record in records:
            if record.status is ResolutionStatus.UNROUTABLE:
                ips = ", ".join(
                    f"{ip} [{scope.value}]" for ip, scope in record.ip_scopes.items()
                )
            else:
                ips = ", ".join(record.routable_ips or record.ip_addresses) or "-"
            print(f"{record.hostname:<45} {record.status.value:<12} {ips}")
    print()
    return 0


async def _run_doctor(args: argparse.Namespace) -> int:
    from atalaya.onboarding.doctor import run_doctor
    from atalaya.onboarding.ui import make_terminal

    return await run_doctor(make_terminal(), Path.cwd(), offline=args.offline)


async def _run_init(args: argparse.Namespace) -> int:
    import os

    import httpx

    from atalaya.onboarding import ui
    from atalaya.onboarding.wizard import (
        NonInteractiveOptions,
        RichPrompter,
        Wizard,
        run_non_interactive,
    )

    term = ui.make_terminal()
    root = Path.cwd()
    async with httpx.AsyncClient() as client:
        if args.non_interactive:
            options = NonInteractiveOptions(
                allowlist=args.allowlist,
                allow_any=args.allow_any,
                database=args.database,
                ai_provider=args.ai_provider,
                ai_model=args.ai_model,
                protect_api=args.protect_api,
                takeover_verify=args.takeover_verify,
                offline=args.offline,
            )
            return await run_non_interactive(term, root, client, options)
        if not sys.stdin.isatty():
            term.print(ui.status(term, "err", "atalaya init necesita una terminal interactiva"))
            if "MSYSTEM" in os.environ:
                # Git Bash (mintty) no ofrece a Python una consola de Windows.
                term.print(ui.note("En Git Bash: winpty atalaya init, o abre PowerShell."))
            term.print(ui.note("Para scripts y CI: atalaya init --non-interactive --allowlist ..."))
            return 2
        wizard = Wizard(term, RichPrompter(term), root, client, allow_any=args.allow_any)
        return await wizard.run()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atalaya", description="Atalaya ASM")
    parser.add_argument("--version", action="version", version=f"Atalaya {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log detallado")

    subparsers = parser.add_subparsers(dest="command")

    subdomains = subparsers.add_parser(
        "subdomains", help="Enumera los subdominios de un dominio"
    )
    subdomains.add_argument("domain", help="Dominio a analizar (p. ej. ejemplo.com)")
    subdomains.add_argument(
        "--no-resolve", action="store_true", help="Omite la verificación DNS"
    )
    subdomains.add_argument(
        "--only-active", action="store_true", help="Muestra solo los hosts que resuelven"
    )
    subdomains.add_argument("--json", action="store_true", help="Salida en formato JSON")
    subdomains.add_argument(
        "--save", action="store_true", help="Persiste el resultado en base de datos"
    )
    subdomains.set_defaults(func=_run_subdomains)

    doctor = subparsers.add_parser(
        "doctor", help="Comprueba la configuración: qué funciona y cómo arreglar lo que no"
    )
    doctor.add_argument(
        "--offline", action="store_true", help="No sale a la red (no valida claves ni crt.sh)"
    )
    doctor.set_defaults(func=_run_doctor)

    init = subparsers.add_parser(
        "init", help="Configura Atalaya paso a paso (alcance, base de datos, claves)"
    )
    init.add_argument(
        "--allow-any",
        action="store_true",
        help="Permite dejar el alcance sin restricción (no recomendado)",
    )
    init.add_argument(
        "--non-interactive",
        action="store_true",
        help="Sin preguntas: opciones y secretos desde variables de entorno",
    )
    init.add_argument("--allowlist", help="Dominios autorizados, separados por comas")
    init.add_argument(
        "--database",
        choices=["sqlite", "docker"],
        help="Base de datos predefinida (o DATABASE_URL en el entorno)",
    )
    init.add_argument(
        "--ai-provider",
        choices=["anthropic", "gemini", "replay", "keep"],
        default="keep",
        help="Proveedor de IA; la clave sale de ANTHROPIC_API_KEY o GEMINI_API_KEY",
    )
    init.add_argument("--ai-model", help="Modelo del proveedor de IA")
    init.add_argument(
        "--protect-api", action="store_true", help="Exige X-API-Key (la genera si no hay)"
    )
    init.add_argument(
        "--takeover-verify",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Verificación HTTP de takeover (opt-in)",
    )
    init.add_argument(
        "--offline", action="store_true", help="No valida las claves contra los proveedores"
    )
    init.set_defaults(func=_run_init)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _configure_logging(getattr(args, "verbose", False))

    if not getattr(args, "command", None):
        parser.print_help()
        return

    try:
        sys.exit(asyncio.run(args.func(args)))
    except AtalayaError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrumpido.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
