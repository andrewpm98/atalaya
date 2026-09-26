"""Pruebas de `discovery/takeover_verify.py`: verificación HTTP opt-in del
riesgo de subdomain takeover.

Deterministas y sin red, mismo criterio que el resto de la suite: el HTTP se
sustituye por `httpx.MockTransport`, y el opt-in y la allowlist se fijan con
`monkeypatch` sobre `settings`. Un fallo aquí indica un problema del código,
nunca una caída de un proveedor de terceros real.
"""

from __future__ import annotations

import logging

import httpx
import pytest

from atalaya.discovery.models import EnrichmentResult, TakeoverCandidate
from atalaya.discovery.takeover_verify import (
    TAKEOVER_FINGERPRINTS,
    match_fingerprint,
    verify_candidates,
)

_GITHUB_404 = "404: Not Found\nThere isn't a GitHub Pages site here."
_S3_404 = "<Error><Code>NoSuchBucket</Code></Error>"


def _candidate(
    hostname: str = "old.ejemplo.com",
    cname: str = "old.ejemplo.com.github.io",
    provider: str = "GitHub Pages",
    pattern: str = "github.io",
) -> TakeoverCandidate:
    return TakeoverCandidate(
        hostname=hostname, cname=cname, provider=provider, pattern_matched=pattern
    )


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _boobytrapped_client() -> httpx.AsyncClient:
    def _no_debe_llamarse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"no debería hacerse ninguna petición HTTP: {request.url}")

    return _client(_no_debe_llamarse)


# ─── match_fingerprint ─────────────────────────────────────────────────────


def test_match_fingerprint_reconoce_huella_github() -> None:
    marca = match_fingerprint("github.io", _GITHUB_404)
    assert marca == "There isn't a GitHub Pages site here."


def test_match_fingerprint_insensible_a_mayusculas() -> None:
    assert match_fingerprint("github.io", _GITHUB_404.upper()) is not None


def test_match_fingerprint_multiples_marcadores_s3() -> None:
    assert match_fingerprint("s3.amazonaws.com", _S3_404) == "NoSuchBucket"


def test_match_fingerprint_sin_huella_en_cuerpo() -> None:
    assert match_fingerprint("github.io", "<html>una página normal</html>") is None


def test_match_fingerprint_proveedor_sin_huella_en_tabla() -> None:
    """Un proveedor con patrón pero sin huella documentada no verifica."""
    assert "trafficmanager.net" not in TAKEOVER_FINGERPRINTS
    assert match_fingerprint("trafficmanager.net", "cualquier cosa") is None


# ─── verify_candidates: opt-in ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_off_por_defecto_devuelve_sin_tocar_y_sin_http(monkeypatch) -> None:
    """Sin TAKEOVER_VERIFY, no se hace ninguna petición y los candidatos
    vuelven intactos."""
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", False)

    candidatos = [_candidate()]
    async with _boobytrapped_client() as client:
        resultado = await verify_candidates(candidatos, client=client)

    assert resultado == candidatos
    assert resultado[0].verification_attempted is False
    assert resultado[0].unclaimed_indicator is None


@pytest.mark.asyncio
async def test_lista_vacia_no_hace_nada(monkeypatch) -> None:
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    async with _boobytrapped_client() as client:
        assert await verify_candidates([], client=client) == []


# ─── verify_candidates: detección de huella ────────────────────────────────


@pytest.mark.asyncio
async def test_detecta_recurso_no_reclamado(monkeypatch) -> None:
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "old.ejemplo.com.github.io"
        return httpx.Response(404, text=_GITHUB_404)

    async with _client(handler) as client:
        resultado = await verify_candidates([_candidate()], client=client)

    candidato = resultado[0]
    assert candidato.verification_attempted is True
    assert candidato.unclaimed_indicator is not None
    assert "There isn't a GitHub Pages site here." in candidato.unclaimed_indicator


@pytest.mark.asyncio
async def test_sin_huella_marca_intentado_sin_indicador(monkeypatch) -> None:
    """El destino responde, pero con una página normal: se intentó, no hay
    indicio. No es un falso positivo."""
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>sitio activo y reclamado</html>")

    async with _client(handler) as client:
        resultado = await verify_candidates([_candidate()], client=client)

    assert resultado[0].verification_attempted is True
    assert resultado[0].unclaimed_indicator is None


@pytest.mark.asyncio
async def test_fallback_a_http_si_https_no_conecta(monkeypatch) -> None:
    """Si HTTPS no conecta, se prueba HTTP: la página de error del proveedor
    puede servirse por cualquiera de los dos."""
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("no hay HTTPS aquí")
        return httpx.Response(404, text=_GITHUB_404)

    async with _client(handler) as client:
        resultado = await verify_candidates([_candidate()], client=client)

    assert resultado[0].unclaimed_indicator is not None


@pytest.mark.asyncio
async def test_error_de_conexion_degrada_sin_lanzar(monkeypatch) -> None:
    """Ni HTTPS ni HTTP conectan (destino del CNAME tampoco resuelve): el
    candidato se queda en patrón, sin indicio, sin excepción."""
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("destino inexistente")

    async with _client(handler) as client:
        resultado = await verify_candidates([_candidate()], client=client)

    assert resultado[0].verification_attempted is True
    assert resultado[0].unclaimed_indicator is None


# ─── verify_candidates: salvaguarda de allowlist ───────────────────────────


@pytest.mark.asyncio
async def test_gate_allowlist_omite_hostname_no_autorizado(monkeypatch) -> None:
    """Un candidato cuyo hostname no está en SCAN_ALLOWLIST no se sondea: no
    se hace ninguna petición a su destino de terceros."""
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "otrodominio.com")

    async with _boobytrapped_client() as client:
        resultado = await verify_candidates([_candidate()], client=client)

    assert resultado[0].verification_attempted is False
    assert resultado[0].unclaimed_indicator is None


# ─── verify_candidates: auditoría ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_audita_cada_peticion_a_terceros(monkeypatch, caplog) -> None:
    monkeypatch.setattr("atalaya.config.settings.takeover_verify", True)
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text=_GITHUB_404)

    with caplog.at_level(logging.INFO, logger="atalaya.discovery.takeover_verify"):
        async with _client(handler) as client:
            await verify_candidates([_candidate()], client=client)

    auditoria = [r.message for r in caplog.records if "auditoría" in r.message]
    assert len(auditoria) == 1
    assert "old.ejemplo.com" in auditoria[0]
    assert "old.ejemplo.com.github.io" in auditoria[0]


# ─── Evidencia del hallazgo: nunca "confirmado" ────────────────────────────


def test_evidencia_con_indicio_dice_alta_sospecha_no_confirmado() -> None:
    candidato = _candidate().model_copy(
        update={
            "verification_attempted": True,
            "unclaimed_indicator": "«There isn't a GitHub Pages site here.» en "
            "https://old.ejemplo.com.github.io/ (HTTP 404)",
        }
    )
    resultado = EnrichmentResult(takeover_candidates=[candidato])
    findings = resultado.findings_by_hostname()["old.ejemplo.com"]

    assert len(findings) == 1
    evidencia = findings[0].evidence
    assert "ALTA SOSPECHA" in evidencia
    assert "NO CONFIRMADO" in evidencia
    assert "indicio adicional" in evidencia
    # Nunca afirma explotabilidad confirmada: "confirmado" solo aparece negado.
    assert "NO CONFIRMADO" in evidencia and "confirmado como" not in evidencia.lower()


def test_evidencia_sin_indicio_es_solo_patron() -> None:
    """Sin verificación (o sin huella), la evidencia es la de patrón puro,
    idéntica al comportamiento previo a esta ampliación."""
    resultado = EnrichmentResult(takeover_candidates=[_candidate()])
    evidencia = resultado.findings_by_hostname()["old.ejemplo.com"][0].evidence

    assert "ALTA SOSPECHA" not in evidencia
    assert "no verificado" in evidencia
