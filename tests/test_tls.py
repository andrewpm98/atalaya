"""Pruebas de `discovery/tls.py`: inspección de certificados y versión TLS.

`parse_certificate`/`build_tls_findings` son puras: se prueban contra
certificados X.509 reales generados en memoria con `cryptography` (ya
dependencia del proyecto), sin ninguna conexión TLS. `inspect_tls` se prueba
sustituyendo `_fetch_certificate` (la única función que hace red) por un
doble — mismo criterio que `fetch_crtsh`/`enumerate_subdomains` en
`test_subdomains.py`.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from atalaya.discovery.tls import build_tls_findings, inspect_tls, parse_certificate

_NOW = datetime.now(timezone.utc)


def _make_cert_der(*, not_valid_before: datetime, not_valid_after: datetime, cn: str = "Atalaya Test CA") -> bytes:
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    cert = builder.sign(key, algorithm=None)
    return cert.public_bytes(serialization.Encoding.DER)


# ─── parse_certificate ────────────────────────────────────────────────────


def test_parse_certificate_extrae_emisor_y_validez() -> None:
    der = _make_cert_der(
        not_valid_before=_NOW - timedelta(days=1),
        not_valid_after=_NOW + timedelta(days=365),
        cn="Atalaya Root",
    )

    datos = parse_certificate(der)

    assert datos["issuer"] == "CN=Atalaya Root"
    assert 360 <= datos["days_remaining"] <= 365


def test_parse_certificate_certificado_caducado_da_dias_negativos() -> None:
    der = _make_cert_der(
        not_valid_before=_NOW - timedelta(days=100),
        not_valid_after=_NOW - timedelta(days=5),
    )

    datos = parse_certificate(der)

    assert datos["days_remaining"] < 0


# ─── build_tls_findings ───────────────────────────────────────────────────


def test_build_tls_findings_certificado_sano_y_version_moderna_sin_hallazgos() -> None:
    findings = build_tls_findings("TLSv1.3", _NOW + timedelta(days=200), 200)
    assert findings == []


def test_build_tls_findings_version_obsoleta() -> None:
    findings = build_tls_findings("TLSv1.1", _NOW + timedelta(days=200), 200)
    assert {f.finding_type for f in findings} == {"tls_version_obsoleta"}


def test_build_tls_findings_certificado_caducado() -> None:
    findings = build_tls_findings("TLSv1.3", _NOW - timedelta(days=3), -3)
    assert {f.finding_type for f in findings} == {"certificado_caducado"}


def test_build_tls_findings_certificado_proximo_a_caducar() -> None:
    findings = build_tls_findings("TLSv1.3", _NOW + timedelta(days=10), 10)
    assert {f.finding_type for f in findings} == {"certificado_proximo_a_caducar"}


def test_build_tls_findings_version_obsoleta_y_caducado_a_la_vez() -> None:
    findings = build_tls_findings("TLSv1", _NOW - timedelta(days=1), -1)
    assert {f.finding_type for f in findings} == {"tls_version_obsoleta", "certificado_caducado"}


# ─── inspect_tls (orquestación) ────────────────────────────────────────────


async def test_inspect_tls_combina_certificado_y_version(monkeypatch) -> None:
    der = _make_cert_der(
        not_valid_before=_NOW - timedelta(days=1), not_valid_after=_NOW + timedelta(days=5)
    )

    async def fake_fetch(host: str, port: int, timeout: float) -> tuple[bytes, str]:
        assert host == "ejemplo.com"
        assert port == 443
        return der, "TLSv1.2"

    monkeypatch.setattr("atalaya.discovery.tls._fetch_certificate", fake_fetch)

    resultado = await inspect_tls("ejemplo.com")

    assert resultado.hostname == "ejemplo.com"
    assert resultado.protocol_version == "TLSv1.2"
    assert resultado.error is None
    assert {f.finding_type for f in resultado.findings} == {"certificado_proximo_a_caducar"}


async def test_inspect_tls_degrada_con_gracia_si_no_hay_servicio_tls(monkeypatch) -> None:
    async def fake_fetch(host: str, port: int, timeout: float) -> tuple[bytes, str]:
        raise OSError("Connection refused")

    monkeypatch.setattr("atalaya.discovery.tls._fetch_certificate", fake_fetch)

    resultado = await inspect_tls("sin-tls.ejemplo.com")

    assert resultado.findings == []
    assert resultado.error is not None


async def test_inspect_tls_degrada_con_gracia_ante_fallo_ssl(monkeypatch) -> None:
    async def fake_fetch(host: str, port: int, timeout: float) -> tuple[bytes, str]:
        raise ssl.SSLError("handshake failure")

    monkeypatch.setattr("atalaya.discovery.tls._fetch_certificate", fake_fetch)

    resultado = await inspect_tls("ejemplo.com")

    assert resultado.error is not None
