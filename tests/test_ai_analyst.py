"""Pruebas de `ai/analyst.py`: contexto de visión global y análisis del escaneo."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from atalaya.ai.analyst import AnalystResult, analyze_scan, build_scan_overview_context
from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete_tool` responde según `tool_output_fn`."""

    def __init__(self, tool_output_fn) -> None:
        self._tool_output_fn = tool_output_fn
        self.prompts: list[str] = []
        self.systems: list[str | None] = []

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise NotImplementedError("no usado en estas pruebas")

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        self.prompts.append(prompt)
        self.systems.append(system)
        outcome = self._tool_output_fn(prompt)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _scan() -> Scan:
    scan = Scan(
        id=3,
        domain="ejemplo.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        errors=[],
    )
    activo = Asset(
        hostname="admin.ejemplo.com",
        status="active",
        ip_addresses=["93.184.216.34"],
        sources=["crt.sh"],
        is_active=True,
        leaks_internal_addressing=False,
        open_ports=[22, 443],
    )
    critico = Finding(
        finding_type="hsts_missing",
        evidence="Sin cabecera HSTS",
        severity=FindingSeverity.CRITICAL,
        impact="Permite downgrade a HTTP",
    )
    bajo = Finding(
        finding_type="tls_weak_version",
        evidence="TLS 1.0",
        severity=FindingSeverity.LOW,
    )
    activo.findings.extend([critico, bajo])

    interno = Asset(
        hostname="interno.ejemplo.com",
        status="unroutable",
        ip_addresses=["10.0.0.5"],
        sources=["dns"],
        is_active=False,
        leaks_internal_addressing=True,
        open_ports=[],
    )
    scan.assets.extend([activo, interno])
    return scan


def _valid_tool_output() -> dict[str, Any]:
    return {
        "answer": "El activo admin.ejemplo.com es el más urgente.",
        "patterns": ["Concentración de hallazgos en admin.ejemplo.com"],
        "concerning_combinations": ["HSTS ausente + panel admin expuesto"],
        "priorities": ["Corregir HSTS en admin.ejemplo.com primero"],
    }


# ─── build_scan_overview_context ────────────────────────────────────────────


def test_build_scan_overview_context_solo_incluye_critical_high() -> None:
    context = build_scan_overview_context(_scan())

    assert context["domain"] == "ejemplo.com"
    assert context["total_assets"] == 2
    assert context["assets_with_internal_addressing"] == 1
    assert context["severity_distribution"]["critical"] == 1
    assert context["severity_distribution"]["low"] == 1
    # Solo el finding critical entra al detalle; el low queda fuera.
    assert len(context["critical_high_findings"]) == 1
    assert context["critical_high_findings"][0]["hostname"] == "admin.ejemplo.com"
    assert context["critical_high_findings"][0]["type"] == "hsts_missing"


# ─── analyze_scan ────────────────────────────────────────────────────────


async def test_analyze_scan_exitoso_con_pregunta() -> None:
    provider = _FakeProvider(lambda _prompt: _valid_tool_output())

    result = await analyze_scan(provider, _scan(), question="¿qué activo es más peligroso?")

    assert isinstance(result, AnalystResult)
    assert "admin.ejemplo.com" in result.answer
    assert result.patterns
    assert result.concerning_combinations
    assert result.priorities
    assert "¿qué activo es más peligroso?" in provider.prompts[0]


async def test_analyze_scan_sin_pregunta_pide_resumen() -> None:
    provider = _FakeProvider(lambda _prompt: _valid_tool_output())

    await analyze_scan(provider, _scan())

    assert "Sin pregunta" in provider.prompts[0]


async def test_analyze_scan_propaga_el_fallo_del_proveedor() -> None:
    provider = _FakeProvider(lambda _prompt: AIProviderError("rate limit"))

    with pytest.raises(AIProviderError, match="rate limit"):
        await analyze_scan(provider, _scan(), question="¿qué prioridad tiene esto?")


async def test_analyze_scan_respuesta_invalida_se_traduce_a_ai_provider_error() -> None:
    # "answer" vacío: no respeta la validación de `AnalystResult` (min_length=1).
    provider = _FakeProvider(
        lambda _prompt: {
            "answer": "",
            "patterns": [],
            "concerning_combinations": [],
            "priorities": [],
        }
    )

    with pytest.raises(AIProviderError):
        await analyze_scan(provider, _scan())


async def test_analyze_scan_envia_contexto_json_valido() -> None:
    provider = _FakeProvider(lambda _prompt: _valid_tool_output())

    await analyze_scan(provider, _scan())

    datos = json.loads(provider.prompts[0].split("Datos del escaneo (JSON):\n", 1)[1])
    assert datos["domain"] == "ejemplo.com"
    assert provider.systems[0] is not None
