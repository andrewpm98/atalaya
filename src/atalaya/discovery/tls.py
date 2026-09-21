"""Inspección de certificados y configuración TLS (Paso 2).

Separa, a propósito, la obtención del certificado (`_fetch_certificate`, hace
red) de su evaluación (`parse_certificate`, `build_tls_findings`, puras):
igual criterio que `discovery/headers.py` y que `fetch_crtsh`/
`parse_crtsh_payload` en `subdomains.py`. Las pruebas generan certificados
reales en memoria con `cryptography` (ya dependencia del proyecto) para
cubrir `parse_certificate`/`build_tls_findings` sin ninguna conexión TLS
real.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import datetime, timezone

from cryptography import x509

from atalaya.config import settings
from atalaya.discovery.models import DiscoveryFinding, TlsScanResult

logger = logging.getLogger(__name__)

#: Por debajo de este margen, un certificado se marca como próximo a
#: caducar — el enunciado del Paso 2 fija este umbral explícitamente.
_EXPIRY_WARNING_DAYS = 30

#: Versiones de protocolo consideradas obsoletas: sin las mitigaciones de
#: TLS 1.2+ (cifrados AEAD, protección frente a downgrade) y ya retiradas
#: por los navegadores principales desde 2020.
_OBSOLETE_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def parse_certificate(der_bytes: bytes) -> dict[str, object]:
    """Extrae emisor y validez de un certificado en formato DER.

    Campos deliberadamente mínimos — lo que necesita un informe de ASM, no
    un volcado completo del certificado (que incluiría SANs, huella, clave
    pública... ruido para este propósito).
    """
    cert = x509.load_der_x509_certificate(der_bytes)
    not_valid_after = cert.not_valid_after_utc
    not_valid_before = cert.not_valid_before_utc
    days_remaining = (not_valid_after - datetime.now(timezone.utc)).days
    return {
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": not_valid_before,
        "not_valid_after": not_valid_after,
        "days_remaining": days_remaining,
    }


def build_tls_findings(
    protocol_version: str | None,
    not_valid_after: datetime | None,
    days_remaining: int | None,
) -> list[DiscoveryFinding]:
    """Evalúa versión de protocolo y caducidad; pura y síncrona.

    Marca como hallazgo los certificados caducados o a menos de
    `_EXPIRY_WARNING_DAYS` de caducar, y las versiones de protocolo
    obsoletas (TLS 1.0, 1.1 y anteriores) — exactamente lo que pide el
    enunciado del Paso 2, ni más ni menos: no se valida aquí la cadena de
    confianza ni el hostname del certificado (fuera de alcance).
    """
    findings: list[DiscoveryFinding] = []

    if protocol_version is not None and protocol_version in _OBSOLETE_VERSIONS:
        findings.append(
            DiscoveryFinding(
                finding_type="tls_version_obsoleta",
                evidence=f"El servidor negocia {protocol_version}, retirado por los navegadores principales.",
            )
        )

    if not_valid_after is not None and days_remaining is not None:
        if days_remaining < 0:
            findings.append(
                DiscoveryFinding(
                    finding_type="certificado_caducado",
                    evidence=(
                        f"El certificado caducó el {not_valid_after:%Y-%m-%d} "
                        f"({abs(days_remaining)} días atrás)."
                    ),
                )
            )
        elif days_remaining < _EXPIRY_WARNING_DAYS:
            findings.append(
                DiscoveryFinding(
                    finding_type="certificado_proximo_a_caducar",
                    evidence=(
                        f"El certificado caduca el {not_valid_after:%Y-%m-%d} "
                        f"(en {days_remaining} días)."
                    ),
                )
            )

    return findings


async def _fetch_certificate(host: str, port: int, timeout: float) -> tuple[bytes, str]:
    """Conecta por TLS y devuelve ``(certificado DER, versión negociada)``.

    `verify_mode=CERT_NONE` es deliberado: el objetivo es inspeccionar el
    certificado que presenta el servidor, no validar su cadena de confianza
    — un certificado autofirmado o caducado es precisamente uno de los
    casos que este módulo debe poder reportar, no rechazar antes de verlo.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=host),
        timeout=timeout,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der_bytes = ssl_object.getpeercert(binary_form=True)
        protocol_version = ssl_object.version()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if der_bytes is None:
        raise ssl.SSLError("el servidor no presentó certificado")
    return der_bytes, protocol_version


async def inspect_tls(
    host: str, port: int = 443, *, timeout: float | None = None
) -> TlsScanResult:
    """Inspecciona el certificado TLS de *host*:*port*.

    Nunca lanza: un host sin servicio TLS en ese puerto, un timeout o un
    fallo del handshake se reflejan en `TlsScanResult.error`, mismo criterio
    de degradación controlada que el resto del descubrimiento — muchos
    subdominios activos simplemente no sirven HTTPS, y eso no debe abortar
    la inspección de los demás.
    """
    to = timeout if timeout is not None else settings.tls_scan_timeout
    try:
        der_bytes, protocol_version = await _fetch_certificate(host, port, to)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        logger.info("Inspección TLS de %s:%d no disponible: %s", host, port, exc)
        return TlsScanResult(hostname=host, port=port, error=str(exc))

    try:
        cert = parse_certificate(der_bytes)
    except ValueError as exc:
        logger.warning("Certificado de %s:%d no se pudo parsear: %s", host, port, exc)
        return TlsScanResult(hostname=host, port=port, error=str(exc))

    findings = build_tls_findings(protocol_version, cert["not_valid_after"], cert["days_remaining"])
    return TlsScanResult(
        hostname=host,
        port=port,
        protocol_version=protocol_version,
        issuer=cert["issuer"],
        not_valid_before=cert["not_valid_before"],
        not_valid_after=cert["not_valid_after"],
        days_remaining=cert["days_remaining"],
        findings=findings,
    )
