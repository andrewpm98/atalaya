"""Pruebas de `ai/query.py`: contexto de un escaneo y consulta en lenguaje natural."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from atalaya.ai.provider import LLMProvider
from atalaya.ai.query import ask, build_scan_context
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus


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


def _scan() -> Scan:
    scan = Scan(
        id=7,
        domain="ejemplo.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        errors=[],
    )
    asset = Asset(
        hostname="interno.ejemplo.com",
        status="unroutable",
        ip_addresses=["10.0.0.5"],
        sources=["crt.sh"],
        is_active=False,
        leaks_internal_addressing=True,
        open_ports=[],
    )
    finding = Finding(
        finding_type="internal_addressing_leak",
        evidence="10.0.0.5 es privado",
        severity=FindingSeverity.HIGH,
        impact="Filtra estructura de red interna",
        remediation="Elimina el registro DNS obsoleto",
    )
    asset.findings.append(finding)
    scan.assets.append(asset)
    return scan


def test_build_scan_context_incluye_activos_y_hallazgos() -> None:
    context = build_scan_context(_scan())

    assert context["domain"] == "ejemplo.com"
    assert context["status"] == "completed"
    assert len(context["assets"]) == 1

    asset_ctx = context["assets"][0]
    assert asset_ctx["hostname"] == "interno.ejemplo.com"
    assert asset_ctx["leaks_internal_addressing"] is True
    assert len(asset_ctx["findings"]) == 1
    assert asset_ctx["findings"][0]["severity"] == "high"


async def test_ask_envia_la_pregunta_y_el_contexto_serializado() -> None:
    provider = _FakeProvider(text="Sí, interno.ejemplo.com filtra direccionamiento interno.")

    respuesta = await ask(provider, _scan(), "¿algún activo filtra red interna?")

    assert respuesta == "Sí, interno.ejemplo.com filtra direccionamiento interno."
    assert len(provider.prompts) == 1
    assert "¿algún activo filtra red interna?" in provider.prompts[0]
    # El contexto va como JSON válido dentro del prompt.
    datos = json.loads(provider.prompts[0].split("Datos del escaneo (JSON):\n", 1)[1])
    assert datos["domain"] == "ejemplo.com"
    assert provider.systems[0] is not None


async def test_ask_propaga_el_fallo_del_proveedor() -> None:
    provider = _FakeProvider(error=AIProviderError("proveedor caído"))

    with pytest.raises(AIProviderError, match="proveedor caído"):
        await ask(provider, _scan(), "¿qué hay expuesto?")
