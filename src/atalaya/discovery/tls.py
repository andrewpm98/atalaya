"""Inspección de certificados y configuración TLS (Paso 2).

Separa, a propósito, la obtención del certificado (`_fetch_certificate`, hace
red) de su evaluación (`parse_certificate`, `build_tls_findings`, puras):
igual criterio que `discovery/headers.py` y que `fetch_crtsh`/
`parse_crtsh_payload` en `subdomains.py`. Las pruebas generan certificados
reales en memoria con `cryptography` (ya dependencia del proyecto) para
cubrir `parse_certificate`/`build_tls_findings` sin ninguna conexión TLS
real.

Además de caducidad y versión, se valida el certificado como lo haría un
cliente: que cubra el hostname (`hostname_matches`, pura, sobre los SAN) y
que su cadena lleve a una CA de confianza (`_verify_chain`, una segunda
negociación TLS **con** verificación, en paralelo con la de inspección).
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import UTC, datetime
from typing import TypedDict

import certifi
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

#: Códigos de verificación de OpenSSL que no generan `tls_cadena_no_confiable`
#: porque ya los cubre otro hallazgo: la caducidad (`certificado_caducado`) y
#: el desajuste de hostname (`tls_hostname_no_coincide`, que se evalúa aparte
#: sobre los SAN y no depende de este código).
_X509_V_ERR_CERT_HAS_EXPIRED = 10
_X509_V_ERR_HOSTNAME_MISMATCH = 62
_VERIFY_CODES_CUBIERTOS = {_X509_V_ERR_CERT_HAS_EXPIRED, _X509_V_ERR_HOSTNAME_MISMATCH}

#: SAN que se citan como mucho en la evidencia (un certificado de CDN puede
#: llevar cientos).
_MAX_SAN_EN_EVIDENCIA = 6


class CertificateInfo(TypedDict):
    """Campos deliberadamente mínimos — lo que necesita un informe de ASM,
    no un volcado completo del certificado (que incluiría SANs, huella,
    clave pública... ruido para este propósito)."""

    issuer: str
    not_valid_before: datetime
    not_valid_after: datetime
    days_remaining: int
    dns_names: list[str]


def parse_certificate(der_bytes: bytes) -> CertificateInfo:
    """Extrae emisor y validez de un certificado en formato DER."""
    cert = x509.load_der_x509_certificate(der_bytes)
    not_valid_after = cert.not_valid_after_utc
    not_valid_before = cert.not_valid_before_utc
    days_remaining = (not_valid_after - datetime.now(UTC)).days
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []
    return {
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": not_valid_before,
        "not_valid_after": not_valid_after,
        "days_remaining": days_remaining,
        "dns_names": dns_names,
    }


def hostname_matches(hostname: str, dns_names: list[str]) -> bool:
    """¿Cubre alguno de los SAN (`dNSName`) del certificado a *hostname*?

    Mismas reglas que un navegador (RFC 6125): sin distinguir mayúsculas; el
    comodín solo vale como etiqueta completa más a la izquierda y cubre
    **exactamente una** etiqueta (`*.ejemplo.com` cubre `a.ejemplo.com`, no
    `ejemplo.com` ni `a.b.ejemplo.com`). No se recurre al CN del sujeto: los
    navegadores lo ignoran desde 2017, así que un certificado sin SAN no es
    válido para ningún nombre.
    """
    host = hostname.lower().rstrip(".")
    for name in dns_names:
        pattern = name.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*.") and "*" not in pattern[2:]:
            label, _, rest = host.partition(".")
            if label and rest == pattern[2:]:
                return True
    return False


def build_trust_findings(
    hostname: str, dns_names: list[str], chain_error: tuple[int, str] | None
) -> list[DiscoveryFinding]:
    """Hallazgos de validez del certificado para un cliente; pura.

    `chain_error` es `(código, mensaje)` de OpenSSL si la cadena no verificó,
    o `None` si verificó o no se pudo concluir (ver `_verify_chain`).
    """
    findings: list[DiscoveryFinding] = []
    if not hostname_matches(hostname, dns_names):
        shown = dns_names[:_MAX_SAN_EN_EVIDENCIA]
        rest = len(dns_names) - len(shown)
        sans = (", ".join(shown) + (f" y {rest} más" if rest else "")) if shown else "ninguno"
        findings.append(
            DiscoveryFinding(
                finding_type="tls_hostname_no_coincide",
                evidence=(
                    f"El certificado que presenta {hostname} no cubre ese nombre "
                    f"(SAN: {sans}): un navegador lo rechaza como posible suplantación."
                ),
            )
        )
    if chain_error is not None and chain_error[0] not in _VERIFY_CODES_CUBIERTOS:
        code, message = chain_error
        findings.append(
            DiscoveryFinding(
                finding_type="tls_cadena_no_confiable",
                evidence=(
                    f"La cadena del certificado de {hostname} no verifica contra las CA de "
                    f"confianza (almacén de Mozilla, certifi): {message} (código {code}). "
                    "Autofirmado, CA no reconocida o intermedio no enviado por el servidor."
                ),
            )
        )
    return findings


def build_tls_findings(
    protocol_version: str | None,
    not_valid_after: datetime | None,
    days_remaining: int | None,
) -> list[DiscoveryFinding]:
    """Evalúa versión de protocolo y caducidad; pura y síncrona.

    Marca como hallazgo los certificados caducados o a menos de
    `_EXPIRY_WARNING_DAYS` de caducar, y las versiones de protocolo
    obsoletas (TLS 1.0, 1.1 y anteriores) — lo que pide el enunciado del
    Paso 2. La validez para un cliente (hostname y cadena de confianza) va
    aparte, en `build_trust_findings`.
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


def _verification_context() -> ssl.SSLContext:
    """Contexto de verificación de cadena, igual en toda versión de Python.

    Python 3.13+ activa `VERIFY_X509_STRICT` en `create_default_context`, que
    rechaza certificados sin extensiones que los navegadores no exigen (p. ej.
    *Authority Key Identifier*). Se desactiva: sin ello, un mismo certificado
    saldría válido en el Docker (Python 3.11) y «no confiable» en desarrollo
    (3.13+), y la herramienta marcaría como problema algo que ningún navegador
    rechaza. El criterio es el del cliente real, no el más estricto posible.
    """
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


async def _verify_chain(host: str, port: int, timeout: float) -> tuple[int, str] | None:
    """Negociación TLS **con** verificación de cadena: `(código, mensaje)` de
    OpenSSL si el certificado no verifica, `None` si verifica.

    Almacén de CA explícito (`certifi`, el de Mozilla que ya usa httpx) y no
    el del sistema: el del sistema cambia entre Windows y Debian, y en un
    contenedor sin CA instaladas marcaría **todos** los hosts como no
    confiables. `check_hostname=False` porque el hostname se evalúa aparte
    sobre los SAN, y así un desajuste de nombre no oculta un fallo de cadena.

    Cualquier otro fallo (timeout, conexión cerrada) devuelve `None`: sin
    handshake completo no se puede concluir nada sobre la cadena, y la
    inspección principal ya refleja si el servicio TLS responde.
    """
    context = _verification_context()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_code, exc.verify_message
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        logger.info("Verificación de cadena de %s:%d no concluyente: %s", host, port, exc)
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return None


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
    # Inspección y verificación a la vez: la segunda no añade latencia al host.
    fetch_task = asyncio.ensure_future(_fetch_certificate(host, port, to))
    chain_error = await _verify_chain(host, port, to)
    try:
        der_bytes, protocol_version = await fetch_task
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        logger.info("Inspección TLS de %s:%d no disponible: %s", host, port, exc)
        return TlsScanResult(hostname=host, port=port, error=str(exc))

    try:
        cert = parse_certificate(der_bytes)
    except ValueError as exc:
        logger.warning("Certificado de %s:%d no se pudo parsear: %s", host, port, exc)
        return TlsScanResult(hostname=host, port=port, error=str(exc))

    findings = build_tls_findings(protocol_version, cert["not_valid_after"], cert["days_remaining"])
    findings += build_trust_findings(host, cert["dns_names"], chain_error)
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
