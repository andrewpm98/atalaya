"""Interfaz de línea de comandos de Atalaya.

Permite ejecutar fases de descubrimiento sin levantar la API, lo que resulta
práctico para pruebas rápidas y para la demostración del proyecto.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from atalaya import __version__
from atalaya.core.database import SessionLocal
from atalaya.core.exceptions import AtalayaError
from atalaya.core.persistence import apply_discovery_findings, apply_port_scan, save_subdomain_scan
from atalaya.discovery.enrichment import enrich_scan
from atalaya.discovery.models import ResolutionStatus
from atalaya.discovery.subdomains import enumerate_subdomains


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


async def _run_subdomains(args: argparse.Namespace) -> int:
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
