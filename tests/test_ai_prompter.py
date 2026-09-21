"""Pruebas de `ai/prompter.py`: enrutado de preguntas en lenguaje natural."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from atalaya.ai.analyst import AnalystResult
from atalaya.ai.prompter import build_routing_context, route_and_answer
from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete_tool` responde según `tool_name`.

    `responses` mapea `tool_name` -> resultado (dict) o excepción a lanzar.
    Permite programar, en una misma prueba, la respuesta del paso de
    enrutado y la del agente especializado al que se despache.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.tool_calls: list[str] = []

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise NotImplementedError("no usado en estas pruebas")

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        self.tool_calls.append(tool_name)
        outcome = self._responses[tool_name]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _scan(*, con_takeover: bool = False) -> Scan:
    scan = Scan(
        id=9,
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
        open_ports=[],
    )
    activo.findings.append(
        Finding(finding_type="hsts_missing", evidence="Sin HSTS", severity=FindingSeverity.CRITICAL)
    )
    scan.assets.append(activo)

    if con_takeover:
        tk_asset = Asset(
            hostname="old.ejemplo.com",
            status="no_answer",
            ip_addresses=[],
            sources=["crt.sh"],
            is_active=False,
            leaks_internal_addressing=False,
            open_ports=[],
        )
        tk_asset.findings.append(
            Finding(
                finding_type="subdomain_takeover_risk",
                evidence="old.ejemplo.com tiene un CNAME hacia old.github.io, patrón de GitHub Pages.",
                severity=FindingSeverity.UNKNOWN,
            )
        )
        scan.assets.append(tk_asset)

    return scan


_ANALYST_OUTPUT = {
    "answer": "El activo admin.ejemplo.com es el más urgente.",
    "patterns": [],
    "concerning_combinations": [],
    "priorities": ["Corregir HSTS"],
}

_TAKEOVER_BATCH_OUTPUT = {
    "assessments": [
        {
            "hostname": "old.ejemplo.com",
            "provider": "GitHub Pages",
            "priority": "alta",
            "reasoning": "Patrón muy característico.",
        }
    ]
}


# ─── build_routing_context ──────────────────────────────────────────────────


def test_build_routing_context_detecta_candidatos_de_takeover() -> None:
    context = build_routing_context(_scan(con_takeover=True))

    assert context["domain"] == "ejemplo.com"
    assert context["total_assets"] == 2
    assert context["has_takeover_candidates"] is True
    assert context["findings_by_severity"]["critical"] == 1


def test_build_routing_context_sin_candidatos() -> None:
    context = build_routing_context(_scan())

    assert context["has_takeover_candidates"] is False


# ─── route_and_answer: ruta 'analyst' ───────────────────────────────────────


async def test_route_and_answer_enruta_a_analyst() -> None:
    provider = _FakeProvider(
        {
            "route_query": {"agent": "analyst", "refined_question": "¿qué es más urgente?"},
            "record_analysis": _ANALYST_OUTPUT,
        }
    )

    result = await route_and_answer(provider, scan=_scan(), question="¿qué debo mirar primero?")

    assert isinstance(result, AnalystResult)
    assert "admin.ejemplo.com" in result.answer
    assert provider.tool_calls == ["route_query", "record_analysis"]


# ─── route_and_answer: ruta 'takeover' ──────────────────────────────────────


async def test_route_and_answer_enruta_a_takeover() -> None:
    provider = _FakeProvider(
        {
            "route_query": {"agent": "takeover", "refined_question": "evalúa los candidatos a takeover"},
            "record_takeover_assessment_batch": _TAKEOVER_BATCH_OUTPUT,
        }
    )

    result = await route_and_answer(
        provider, scan=_scan(con_takeover=True), question="¿hay riesgo de takeover?"
    )

    assert isinstance(result, AnalystResult)
    assert "1 candidato" in result.answer
    assert "old.ejemplo.com" in result.concerning_combinations[0]
    assert provider.tool_calls == ["route_query", "record_takeover_assessment_batch"]


async def test_route_and_answer_takeover_sin_candidatos_no_llama_de_nuevo_al_proveedor() -> None:
    provider = _FakeProvider(
        {"route_query": {"agent": "takeover", "refined_question": "¿hay takeover?"}}
    )

    result = await route_and_answer(provider, scan=_scan(), question="¿hay riesgo de takeover?")

    assert isinstance(result, AnalystResult)
    assert "No se han detectado" in result.answer
    assert provider.tool_calls == ["route_query"]  # no se llegó a llamar al segundo tool


# ─── route_and_answer: clasificación insegura → fallback a 'analyst' ───────


async def test_route_and_answer_agent_desconocido_usa_analyst_por_defecto() -> None:
    provider = _FakeProvider(
        {
            "route_query": {"agent": "otro-agente-inventado", "refined_question": "x"},
            "record_analysis": _ANALYST_OUTPUT,
        }
    )

    result = await route_and_answer(provider, scan=_scan(), question="¿qué hay expuesto?")

    assert isinstance(result, AnalystResult)
    assert provider.tool_calls == ["route_query", "record_analysis"]


async def test_route_and_answer_refined_question_vacia_usa_analyst_por_defecto() -> None:
    provider = _FakeProvider(
        {
            "route_query": {"agent": "analyst", "refined_question": "   "},
            "record_analysis": _ANALYST_OUTPUT,
        }
    )

    result = await route_and_answer(provider, scan=_scan(), question="¿qué hay expuesto?")

    assert isinstance(result, AnalystResult)


async def test_route_and_answer_agent_ausente_en_respuesta_usa_analyst_por_defecto() -> None:
    provider = _FakeProvider(
        {
            "route_query": {"refined_question": "x"},  # falta "agent"
            "record_analysis": _ANALYST_OUTPUT,
        }
    )

    result = await route_and_answer(provider, scan=_scan(), question="¿qué hay expuesto?")

    assert isinstance(result, AnalystResult)
    assert provider.tool_calls == ["route_query", "record_analysis"]


# ─── route_and_answer: fallo del paso de enrutado se propaga ──────────────


async def test_route_and_answer_propaga_fallo_del_paso_de_enrutado() -> None:
    provider = _FakeProvider({"route_query": AIProviderError("proveedor caído")})

    with pytest.raises(AIProviderError, match="proveedor caído"):
        await route_and_answer(provider, scan=_scan(), question="¿qué hay expuesto?")

    assert provider.tool_calls == ["route_query"]
