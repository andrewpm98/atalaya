"""Pruebas de `ai/takeover_detective.py`: contexto y evaluación de riesgo de takeover."""

from __future__ import annotations

from typing import Any

from atalaya.ai.provider import LLMProvider
from atalaya.ai.takeover_detective import (
    TakeoverAssessment,
    assess_takeover_risk,
    build_takeover_context,
)
from atalaya.core.exceptions import AIProviderError
from atalaya.discovery.models import TakeoverCandidate


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete_tool` responde según `tool_output_fn`."""

    def __init__(self, tool_output_fn) -> None:
        self._tool_output_fn = tool_output_fn
        self.calls = 0

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise NotImplementedError("no usado en estas pruebas")

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        self.calls += 1
        outcome = self._tool_output_fn(prompt)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _candidate(hostname: str = "old.ejemplo.com") -> TakeoverCandidate:
    return TakeoverCandidate(
        hostname=hostname,
        cname="old-ejemplo.github.io",
        provider="GitHub Pages",
        pattern_matched="github.io",
    )


# ─── build_takeover_context ─────────────────────────────────────────────────


def test_build_takeover_context_incluye_los_cuatro_campos() -> None:
    context = build_takeover_context([_candidate()])

    assert context == [
        {
            "hostname": "old.ejemplo.com",
            "cname": "old-ejemplo.github.io",
            "provider": "GitHub Pages",
            "pattern_matched": "github.io",
        }
    ]


# ─── assess_takeover_risk ───────────────────────────────────────────────────


async def test_assess_takeover_risk_lista_vacia_no_llama_al_proveedor() -> None:
    provider = _FakeProvider(lambda _prompt: {"assessments": []})

    result = await assess_takeover_risk(provider, [])

    assert result == []
    assert provider.calls == 0


async def test_assess_takeover_risk_exitoso_una_sola_llamada() -> None:
    def outcome(_prompt: str) -> dict[str, Any]:
        return {
            "assessments": [
                {
                    "hostname": "old.ejemplo.com",
                    "provider": "GitHub Pages",
                    "priority": "alta",
                    "reasoning": "Patrón muy característico y host sin IP propia.",
                },
                {
                    "hostname": "otro.ejemplo.com",
                    "provider": "Heroku",
                    "priority": "baja",
                    "reasoning": "Patrón menos determinante.",
                },
            ]
        }

    provider = _FakeProvider(outcome)
    candidates = [_candidate("old.ejemplo.com"), _candidate("otro.ejemplo.com")]

    result = await assess_takeover_risk(provider, candidates)

    assert provider.calls == 1  # una sola llamada para todos los candidatos
    assert len(result) == 2
    assert all(isinstance(item, TakeoverAssessment) for item in result)
    assert result[0].priority == "alta"
    assert "no confirmada" not in result[0].reasoning.lower()  # no afirma explotabilidad


async def test_assess_takeover_risk_fallo_del_proveedor_degrada_a_lista_vacia() -> None:
    provider = _FakeProvider(lambda _prompt: AIProviderError("timeout"))

    result = await assess_takeover_risk(provider, [_candidate()])

    assert result == []


async def test_assess_takeover_risk_respuesta_invalida_degrada_a_lista_vacia() -> None:
    # "priority" fuera del Literal permitido: el modelo no respetó el schema.
    provider = _FakeProvider(
        lambda _prompt: {
            "assessments": [
                {
                    "hostname": "old.ejemplo.com",
                    "provider": "GitHub Pages",
                    "priority": "urgentisimo",
                    "reasoning": "x",
                }
            ]
        }
    )

    result = await assess_takeover_risk(provider, [_candidate()])

    assert result == []


async def test_assess_takeover_risk_reasoning_vacio_no_valida() -> None:
    provider = _FakeProvider(
        lambda _prompt: {
            "assessments": [
                {"hostname": "old.ejemplo.com", "provider": "GitHub Pages", "priority": "alta", "reasoning": ""}
            ]
        }
    )

    result = await assess_takeover_risk(provider, [_candidate()])

    assert result == []
