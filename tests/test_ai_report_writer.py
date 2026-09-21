"""Pruebas de `ai/report_writer.py`: contexto y redacción del resumen ejecutivo."""

from __future__ import annotations

import json
from typing import Any

import pytest

from atalaya.ai.provider import LLMProvider
from atalaya.ai.report_writer import build_summary_context, write_executive_summary
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete` devuelve una respuesta fija o falla."""

    def __init__(self, *, text: str | None = None, error: Exception | None = None) -> None:
        self._text = text
        self._error = error
        self.prompts: list[str] = []
        self.systems: list[str | None] = []

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.prompts.append(prompt)
        self.systems.append(system)
        if self._error is not None:
            raise self._error
        assert self._text is not None
        return self._text

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError("no usado en estas pruebas")


def _finding(hostname: str, tipo: str, impact: str | None) -> Finding:
    asset = Asset(
        hostname=hostname,
        status="active",
        ip_addresses=["93.184.216.34"],
        sources=["crt.sh"],
        is_active=True,
        leaks_internal_addressing=False,
        open_ports=[],
    )
    finding = Finding(
        finding_type=tipo,
        evidence="Sin cabecera HSTS",
        severity=FindingSeverity.CRITICAL,
        impact=impact,
    )
    finding.asset = asset
    return finding


# ─── build_summary_context ──────────────────────────────────────────────────


def test_build_summary_context_prefiere_impact_sobre_evidence() -> None:
    triado = _finding("admin.ejemplo.com", "hsts_missing", "Permite ataques de downgrade")
    sin_triar = _finding("beta.ejemplo.com", "hsts_missing", None)

    context = build_summary_context(
        domain="ejemplo.com", risk_score=80, critical_findings=[triado, sin_triar], high_findings=[]
    )

    assert context["domain"] == "ejemplo.com"
    assert context["risk_score"] == 80
    assert context["critical_count"] == 2
    assert context["critical_findings"][0]["description"] == "Permite ataques de downgrade"
    # Sin impact triado, cae a la evidencia cruda.
    assert context["critical_findings"][1]["description"] == "Sin cabecera HSTS"
    # No se manda `remediation`: no aporta a un resumen ejecutivo.
    assert "remediation" not in context["critical_findings"][0]


# ─── write_executive_summary ────────────────────────────────────────────────


async def test_write_executive_summary_exitoso() -> None:
    provider = _FakeProvider(text="El dominio presenta riesgos que requieren atención inmediata.")
    critico = _finding("admin.ejemplo.com", "hsts_missing", "Permite downgrade")

    resumen = await write_executive_summary(
        provider, domain="ejemplo.com", risk_score=75, critical_findings=[critico], high_findings=[]
    )

    assert "atención inmediata" in resumen
    datos = json.loads(provider.prompts[0].split("(JSON):\n", 1)[1])
    assert datos["risk_score"] == 75
    assert provider.systems[0] is not None
    assert "jerga" in provider.systems[0].lower()
    assert "no técnico" in provider.systems[0].lower()


async def test_write_executive_summary_propaga_el_fallo_del_proveedor() -> None:
    provider = _FakeProvider(error=AIProviderError("proveedor caído"))

    with pytest.raises(AIProviderError, match="proveedor caído"):
        await write_executive_summary(
            provider, domain="ejemplo.com", risk_score=50, critical_findings=[], high_findings=[]
        )


async def test_write_executive_summary_respuesta_vacia_lanza_ai_provider_error() -> None:
    provider = _FakeProvider(text="   ")

    with pytest.raises(AIProviderError):
        await write_executive_summary(
            provider, domain="ejemplo.com", risk_score=50, critical_findings=[], high_findings=[]
        )
