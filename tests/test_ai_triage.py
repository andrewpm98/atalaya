"""Pruebas de `ai/triage.py`: construcción del contexto y triaje de hallazgos.

Sin red ni SDK real: `_FakeProvider` implementa `LLMProvider` con respuestas
programables por prompt, el mismo rol que cumple `httpx.MockTransport` para
las pruebas de descubrimiento.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from atalaya.ai.provider import LLMProvider
from atalaya.ai.triage import (
    TriageBatchResult,
    build_finding_context,
    triage_finding,
    triage_findings,
)
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete_tool` responde según `tool_output_fn`."""

    def __init__(
        self,
        tool_output_fn: Callable[[str], dict[str, Any] | Exception],
    ) -> None:
        self._tool_output_fn = tool_output_fn
        self.calls: list[str] = []

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise NotImplementedError("no usado en estas pruebas")

    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(prompt)
        outcome = self._tool_output_fn(prompt)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _asset(hostname: str = "www.ejemplo.com") -> Asset:
    return Asset(
        hostname=hostname,
        status="active",
        ip_addresses=["93.184.216.34"],
        sources=["crt.sh", "dns"],
        is_active=True,
        leaks_internal_addressing=False,
        open_ports=[],
    )


def _finding(evidence: str = "evidencia") -> Finding:
    # `severity` se fija explícitamente: el default de la columna
    # (`FindingSeverity.UNKNOWN`) solo se aplica al hacer flush contra la
    # BD, no al construir el objeto en memoria como hacen estas pruebas.
    return Finding(
        finding_type="internal_addressing_leak",
        evidence=evidence,
        severity=FindingSeverity.UNKNOWN,
    )


# ─── build_finding_context ──────────────────────────────────────────────────


def test_build_finding_context_solo_incluye_campos_seleccionados() -> None:
    asset = _asset()
    finding = _finding("10.0.0.5 es privado")

    context = build_finding_context(asset, finding)

    assert context == {
        "asset": {
            "hostname": "www.ejemplo.com",
            "ip_addresses": ["93.184.216.34"],
            "status": "active",
            "sources": ["crt.sh", "dns"],
            "is_active": True,
            "open_ports": [],
        },
        "finding": {
            "type": "internal_addressing_leak",
            "evidence": "10.0.0.5 es privado",
        },
    }
    # No se filtran columnas internas (id, scan_id) que no aportan al triaje.
    assert "id" not in context["asset"]
    assert "leaks_internal_addressing" not in context["asset"]


# ─── triage_finding ──────────────────────────────────────────────────────


async def test_triage_finding_exitoso_actualiza_el_finding() -> None:
    provider = _FakeProvider(
        lambda _prompt: {
            "severity": "high",
            "impact": "Expone estructura de red interna a cualquier cliente DNS.",
            "remediation": "Elimina el registro DNS o usa un CNAME público.",
        }
    )
    asset, finding = _asset(), _finding()

    error = await triage_finding(provider, asset, finding)

    assert error is None
    assert finding.severity is FindingSeverity.HIGH
    assert "estructura de red interna" in finding.impact
    assert "CNAME" in finding.remediation


async def test_triage_finding_fallo_del_proveedor_no_lanza_y_deja_finding_intacto() -> None:
    provider = _FakeProvider(lambda _prompt: AIProviderError("rate limit"))
    asset, finding = _asset(), _finding()

    error = await triage_finding(provider, asset, finding)

    assert error is not None
    assert "rate limit" in error
    assert finding.severity is FindingSeverity.UNKNOWN
    assert finding.impact is None


async def test_triage_finding_respuesta_invalida_no_lanza_y_deja_finding_intacto() -> None:
    # "severity" fuera del enum: el modelo no respetó el schema.
    provider = _FakeProvider(lambda _prompt: {"severity": "catastrofico", "impact": "x", "remediation": "y"})
    asset, finding = _asset(), _finding()

    error = await triage_finding(provider, asset, finding)

    assert error is not None
    assert finding.severity is FindingSeverity.UNKNOWN


async def test_triage_finding_impact_vacio_no_valida() -> None:
    provider = _FakeProvider(lambda _prompt: {"severity": "low", "impact": "", "remediation": "y"})
    asset, finding = _asset(), _finding()

    error = await triage_finding(provider, asset, finding)

    assert error is not None
    assert finding.severity is FindingSeverity.UNKNOWN


# ─── triage_findings (colección) ───────────────────────────────────────────


async def test_triage_findings_degrada_con_gracia_ante_un_fallo_puntual() -> None:
    def outcome(prompt: str) -> dict[str, Any] | Exception:
        if "malo.ejemplo.com" in prompt:
            return AIProviderError("timeout")
        return {"severity": "medium", "impact": "impacto", "remediation": "remediación"}

    provider = _FakeProvider(outcome)

    bueno_asset = _asset("bueno.ejemplo.com")
    malo_asset = _asset("malo.ejemplo.com")
    bueno = _finding()
    bueno.asset = bueno_asset
    malo = _finding()
    malo.asset = malo_asset

    result = await triage_findings(provider, [bueno, malo])

    assert isinstance(result, TriageBatchResult)
    assert result.triaged == 1
    assert len(result.errors) == 1
    assert "timeout" in result.errors[0]
    assert bueno.severity is FindingSeverity.MEDIUM
    assert malo.severity is FindingSeverity.UNKNOWN


async def test_triage_findings_respeta_la_concurrencia_configurada() -> None:
    en_vuelo = 0
    maximo_en_vuelo = 0

    async def outcome_lento(prompt: str) -> dict[str, Any]:
        nonlocal en_vuelo, maximo_en_vuelo
        en_vuelo += 1
        maximo_en_vuelo = max(maximo_en_vuelo, en_vuelo)
        await asyncio.sleep(0.01)  # punto de cesión real: permite que se solapen
        en_vuelo -= 1
        return {"severity": "low", "impact": "i", "remediation": "r"}

    class _SlowProvider(LLMProvider):
        async def complete(self, prompt: str, *, system: str | None = None) -> str:
            raise NotImplementedError

        async def complete_tool(
            self, prompt: str, *, tool_name: str, tool_schema: dict, system: str | None = None
        ) -> dict[str, Any]:
            return await outcome_lento(prompt)

    findings = []
    for i in range(6):
        f = _finding(f"evidencia-{i}")
        f.asset = _asset(f"host{i}.ejemplo.com")
        findings.append(f)

    await triage_findings(_SlowProvider(), findings, concurrency=2)

    assert maximo_en_vuelo == 2
