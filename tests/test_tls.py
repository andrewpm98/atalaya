"""Pruebas de `discovery/tls.py`: inspección de certificados y versión TLS.

`parse_certificate`/`build_tls_findings` son puras: se prueban contra
certificados X.509 reales generados en memoria con `cryptography` (ya
dependencia del proyecto), sin ninguna conexión TLS. `inspect_tls` se prueba
sustituyendo `_fetch_certificate` (la única función que hace red) por un
doble — mismo criterio que `fetch_crtsh`/`enumerate_subdomains` en
`test_subdomains.py`. `_verify_chain` (la segunda negociación, con
verificación) se sustituye en todas las pruebas por el fixture automático
`_sin_red`: salvo las marcadas `tls_local`, que levantan un servidor TLS en
`127.0.0.1` con certificados generados aquí — sin salir de la máquina.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from atalaya.discovery import tls as tls_module
from atalaya.discovery.tls import (
    build_tls_findings,
    build_trust_findings,
    hostname_matches,
    inspect_tls,
    parse_certificate,
)

_NOW = datetime.now(UTC)


def _make_cert_der(
    *,
    not_valid_before: datetime,
    not_valid_after: datetime,
    cn: str = "Atalaya Test CA",
    sans: list[str] | None = None,
) -> bytes:
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
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
    cert = builder.sign(key, algorithm=None)
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(autouse=True)
def _sin_red(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin esto, cada prueba de `inspect_tls` abriría una conexión real al
    host de prueba desde `_verify_chain`."""
    if request.node.get_closest_marker("tls_local"):
        return

    async def _cadena_valida(host: str, port: int, timeout: float) -> None:
        return None

    monkeypatch.setattr("atalaya.discovery.tls._verify_chain", _cadena_valida)


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

    der = _make_cert_der(
        not_valid_before=_NOW - timedelta(days=1),
        not_valid_after=_NOW + timedelta(days=5),
        sans=["ejemplo.com"],
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


# ─── hostname_matches (RFC 6125, como un navegador) ─────────────────────────


@pytest.mark.parametrize(
    ("hostname", "sans", "esperado"),
    [
        ("ejemplo.com", ["ejemplo.com"], True),
        ("EJEMPLO.com.", ["ejemplo.COM"], True),  # mayúsculas y punto final
        ("a.ejemplo.com", ["*.ejemplo.com"], True),
        ("ejemplo.com", ["*.ejemplo.com"], False),  # el comodín no cubre el ápex
        ("a.b.ejemplo.com", ["*.ejemplo.com"], False),  # ni más de una etiqueta
        ("a.ejemplo.com", ["a*.ejemplo.com"], False),  # comodín parcial: no
        ("a.ejemplo.com", ["*.*.com"], False),
        ("ejemplo.com.evil.net", ["ejemplo.com"], False),
        ("ejemplo.com", [], False),  # sin SAN no vale para ningún nombre
        ("b.ejemplo.com", ["a.ejemplo.com", "*.ejemplo.com"], True),
    ],
)
def test_hostname_matches(hostname: str, sans: list[str], esperado: bool) -> None:
    assert hostname_matches(hostname, sans) is esperado


def test_parse_certificate_extrae_los_san() -> None:
    der = _make_cert_der(
        not_valid_before=_NOW - timedelta(days=1),
        not_valid_after=_NOW + timedelta(days=90),
        sans=["ejemplo.com", "*.ejemplo.com"],
    )
    assert parse_certificate(der)["dns_names"] == ["ejemplo.com", "*.ejemplo.com"]


# ─── build_trust_findings ───────────────────────────────────────────────────


def test_certificado_valido_para_el_host_y_cadena_correcta_sin_hallazgos() -> None:
    assert build_trust_findings("a.ejemplo.com", ["*.ejemplo.com"], None) == []


def test_hostname_que_no_coincide_cita_los_san() -> None:
    [hallazgo] = build_trust_findings("api.ejemplo.com", ["otro.net", "www.otro.net"], None)
    assert hallazgo.finding_type == "tls_hostname_no_coincide"
    assert "api.ejemplo.com" in hallazgo.evidence and "otro.net, www.otro.net" in hallazgo.evidence


def test_cadena_no_confiable_incluye_el_motivo_de_openssl() -> None:
    [hallazgo] = build_trust_findings(
        "ejemplo.com", ["ejemplo.com"], (18, "self-signed certificate")
    )
    assert hallazgo.finding_type == "tls_cadena_no_confiable"
    assert "self-signed certificate" in hallazgo.evidence and "18" in hallazgo.evidence


def test_caducidad_no_se_duplica_como_cadena_no_confiable() -> None:
    """Un certificado caducado ya da `certificado_caducado`: OpenSSL lo
    reporta como error de verificación (código 10), y no se cuenta dos veces."""
    assert build_trust_findings("ejemplo.com", ["ejemplo.com"], (10, "certificate has expired")) == []


async def test_inspect_tls_suma_los_hallazgos_de_validez(monkeypatch) -> None:
    der = _make_cert_der(
        not_valid_before=_NOW - timedelta(days=1),
        not_valid_after=_NOW + timedelta(days=200),
        sans=["otro.net"],
    )

    async def fake_fetch(host: str, port: int, timeout: float) -> tuple[bytes, str]:
        return der, "TLSv1.3"

    async def fake_verify(host: str, port: int, timeout: float) -> tuple[int, str]:
        return 20, "unable to get local issuer certificate"

    monkeypatch.setattr("atalaya.discovery.tls._fetch_certificate", fake_fetch)
    monkeypatch.setattr("atalaya.discovery.tls._verify_chain", fake_verify)

    resultado = await inspect_tls("ejemplo.com")

    assert {f.finding_type for f in resultado.findings} == {
        "tls_hostname_no_coincide",
        "tls_cadena_no_confiable",
    }


# ─── Integración: servidor TLS real en 127.0.0.1 ────────────────────────────


def _clave() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _cert(
    subject_cn: str,
    key: ec.EllipticCurvePrivateKey,
    *,
    issuer: x509.Certificate | None = None,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
    sans: list[str] | None = None,
    ca: bool = False,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest_asyncio.fixture
async def servidor_tls(tmp_path: Path) -> AsyncIterator[object]:
    """Fábrica: `await servidor_tls(cert, key)` levanta un servidor TLS en
    127.0.0.1 con ese certificado y devuelve su puerto."""
    servidores: list[asyncio.Server] = []

    async def _levantar(cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> int:
        cert_file = tmp_path / f"cert{len(servidores)}.pem"
        key_file = tmp_path / f"key{len(servidores)}.pem"
        cert_file.write_bytes(_pem(cert))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexto.load_cert_chain(cert_file, key_file)

        async def _atender(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        servidor = await asyncio.start_server(_atender, "127.0.0.1", 0, ssl=contexto)
        servidores.append(servidor)
        puerto: int = servidor.sockets[0].getsockname()[1]
        # `localhost` puede resolver primero a ::1; sin nadie escuchando ahí,
        # Windows tarda ~2 s en rechazar la conexión antes de probar IPv4.
        try:
            servidores.append(await asyncio.start_server(_atender, "::1", puerto, ssl=contexto))
        except OSError:
            pass  # sin IPv6 en la máquina: se usa solo IPv4
        return puerto

    yield _levantar
    for servidor in servidores:
        servidor.close()
        await servidor.wait_closed()


def _tipos(resultado) -> set[str]:
    assert resultado.error is None, resultado.error
    return {f.finding_type for f in resultado.findings}


@pytest.mark.tls_local
async def test_real_autofirmado_da_cadena_no_confiable(servidor_tls) -> None:
    key = _clave()
    puerto = await servidor_tls(_cert("localhost", key, sans=["localhost"]), key)

    resultado = await inspect_tls("localhost", puerto, timeout=5)

    assert _tipos(resultado) == {"tls_cadena_no_confiable"}
    assert "self-signed" in resultado.findings[0].evidence


@pytest.mark.tls_local
async def test_real_certificado_de_otro_nombre_da_hostname_no_coincide(
    servidor_tls, tmp_path: Path, monkeypatch
) -> None:
    """Cadena válida (CA propia añadida como confiable) pero emitido para otro
    nombre: solo el hallazgo de hostname, no el de cadena."""
    ca_key = _clave()
    ca = _cert("Atalaya Test Root", ca_key, ca=True)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(_pem(ca))
    monkeypatch.setattr(tls_module.certifi, "where", lambda: str(ca_file))

    key = _clave()
    hoja = _cert("otro.test", key, issuer=ca, issuer_key=ca_key, sans=["otro.test"])
    puerto = await servidor_tls(hoja, key)

    assert _tipos(await inspect_tls("localhost", puerto, timeout=5)) == {"tls_hostname_no_coincide"}


@pytest.mark.tls_local
async def test_real_cadena_de_confianza_y_nombre_correctos_sin_hallazgos(
    servidor_tls, tmp_path: Path, monkeypatch
) -> None:
    ca_key = _clave()
    ca = _cert("Atalaya Test Root", ca_key, ca=True)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(_pem(ca))
    monkeypatch.setattr(tls_module.certifi, "where", lambda: str(ca_file))

    key = _clave()
    hoja = _cert("localhost", key, issuer=ca, issuer_key=ca_key, sans=["localhost"])
    puerto = await servidor_tls(hoja, key)

    assert _tipos(await inspect_tls("localhost", puerto, timeout=5)) == set()


def test_la_verificacion_no_usa_el_modo_estricto_de_python_313() -> None:
    """Python 3.13+ activa VERIFY_X509_STRICT por defecto: exige extensiones
    (p. ej. Authority Key Identifier) que los navegadores no piden. Con él, el
    mismo certificado sería válido en el Docker (3.11) y no confiable en
    desarrollo (3.13+). Se comprueba el contexto que construye el módulo."""
    contexto = tls_module._verification_context()
    assert not contexto.verify_flags & ssl.VERIFY_X509_STRICT
    assert contexto.verify_mode == ssl.CERT_REQUIRED
    assert contexto.check_hostname is False
