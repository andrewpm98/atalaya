"""Pruebas de `ai/diff_analyst.py`: contexto y análisis de la comparación entre escaneos."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from atalaya.ai.diff_analyst import analyze_diff, build_diff_context
from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus
from atalaya.core.repository import ScanDiff, diff_scans


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete` devuelve una respuesta fija o falla."""

    def __init__(self, *, text: str | None = None, error: Exception | None = None) -> None:
        self._text = text
        self._error = error
        self.prompts: list[str] = []

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.prompts.append(prompt)
        if self._error is not None:
            raise self._error
        assert self._text is not None
        return self._text

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError("no usado en estas pruebas")


def _asset(hostname: str, *, critico: bool = False) -> Asset:
    asset = Asset(
        hostname=hostname,
        status="active",
        ip_addresses=["93.184.216.34"],
        sources=["crt.sh"],
        is_active=True,
        leaks_internal_addressing=False,
        open_ports=[],
    )
    if critico:
        asset.findings.append(
            Finding(
                finding_type="subdomain_takeover_risk",
                evidence="CNAME hacia proveedor de terceros",
                severity=FindingSeverity.CRITICAL,
            )
        )
    return asset


def _scans() -> tuple[Scan, Scan]:
    previous = Scan(
        id=1,
        domain="ejemplo.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        errors=[],
    )
    previous.assets.extend([_asset("viejo.ejemplo.com", critico=True), _asset("comun.ejemplo.com")])

    current = Scan(
        id=2,
        domain="ejemplo.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 2, 1, tzinfo=UTC),
        errors=[],
    )
    current.assets.extend([_asset("nuevo.ejemplo.com", critico=True), _asset("comun.ejemplo.com")])

    return previous, current


# ─── build_diff_context ─────────────────────────────────────────────────────


def test_build_diff_context_cruza_hostnames_con_hallazgos_graves() -> None:
    previous, current = _scans()
    diff = diff_scans(previous, current)

    context = build_diff_context(domain="ejemplo.com", diff=diff, previous_scan=previous, current_scan=current)

    assert context["nuevos"] == ["nuevo.ejemplo.com"]
    assert context["desaparecidos"] == ["viejo.ejemplo.com"]
    assert context["comunes_count"] == 1
    assert context["nuevos_con_hallazgos_graves"] == {"nuevo.ejemplo.com": ["subdomain_takeover_risk"]}
    assert context["desaparecidos_con_hallazgos_graves"] == {"viejo.ejemplo.com": ["subdomain_takeover_risk"]}


def test_build_diff_context_sin_hallazgos_graves_produce_diccionarios_vacios() -> None:
    diff = ScanDiff(nuevos=["a.ejemplo.com"], desaparecidos=[], comunes=[])
    previous = Scan(id=1, domain="ejemplo.com", status=ScanStatus.COMPLETED, errors=[])
    current = Scan(id=2, domain="ejemplo.com", status=ScanStatus.COMPLETED, errors=[])
    current.assets.append(_asset("a.ejemplo.com"))

    context = build_diff_context(domain="ejemplo.com", diff=diff, previous_scan=previous, current_scan=current)

    assert context["nuevos_con_hallazgos_graves"] == {}


# ─── analyze_diff ────────────────────────────────────────────────────────


async def test_analyze_diff_exitoso() -> None:
    provider = _FakeProvider(text="La superficie se ha expandido con un nuevo activo de riesgo.")
    previous, current = _scans()
    diff = diff_scans(previous, current)

    resultado = await analyze_diff(
        provider, domain="ejemplo.com", diff=diff, previous_scan=previous, current_scan=current
    )

    assert "expandido" in resultado
    datos = json.loads(provider.prompts[0].split("(JSON):\n", 1)[1])
    assert datos["nuevos"] == ["nuevo.ejemplo.com"]


async def test_analyze_diff_propaga_el_fallo_del_proveedor() -> None:
    provider = _FakeProvider(error=AIProviderError("proveedor caído"))
    previous, current = _scans()
    diff = diff_scans(previous, current)

    with pytest.raises(AIProviderError, match="proveedor caído"):
        await analyze_diff(provider, domain="ejemplo.com", diff=diff, previous_scan=previous, current_scan=current)


async def test_analyze_diff_respuesta_vacia_lanza_ai_provider_error() -> None:
    provider = _FakeProvider(text="")
    previous, current = _scans()
    diff = diff_scans(previous, current)

    with pytest.raises(AIProviderError):
        await analyze_diff(provider, domain="ejemplo.com", diff=diff, previous_scan=previous, current_scan=current)
