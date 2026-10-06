"""Pruebas de `ai/triage_reuse.py`: reutilizar solo ante el mismo prompt exacto."""

from __future__ import annotations

from typing import Any

import pytest

from atalaya.ai.provider import LLMProvider
from atalaya.ai.triage import triage_finding
from atalaya.ai.triage_reuse import _context_key, reuse_previous_triage
from atalaya.core.models import Asset, Finding, FindingSeverity


class _PromptRecorder(LLMProvider):
    """Guarda el prompt que recibiría el modelo y responde un triaje fijo."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise NotImplementedError

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        self.prompts.append(prompt)
        return {"severity": "low", "impact": "i", "remediation": "r"}


_BASE: dict[str, Any] = {
    "hostname": "www.ejemplo.com",
    "ip_addresses": ["140.82.121.3"],
    "status": "active",
    "sources": ["crt.sh"],
    "is_active": True,
    "open_ports": [443],
    "finding_type": "clickjacking_sin_proteccion",
    "evidence": "Sin X-Frame-Options ni frame-ancestors en la CSP.",
}


def _finding(severity: FindingSeverity = FindingSeverity.UNKNOWN, **cambios: Any) -> Finding:
    datos = {**_BASE, **cambios}
    asset = Asset(
        hostname=datos["hostname"],
        ip_addresses=datos["ip_addresses"],
        status=datos["status"],
        sources=datos["sources"],
        is_active=datos["is_active"],
        open_ports=datos["open_ports"],
    )
    finding = Finding(
        finding_type=datos["finding_type"], evidence=datos["evidence"], severity=severity
    )
    asset.findings.append(finding)
    return finding


def _triado(**cambios: Any) -> Finding:
    finding = _finding(FindingSeverity.HIGH, **cambios)
    finding.impact, finding.remediation = "impacto", "remediación"
    return finding


async def _prompt_enviado(finding: Finding) -> str:
    recorder = _PromptRecorder()
    assert await triage_finding(recorder, finding.asset, finding) is None
    return recorder.prompts[0]


# ─── La clave equivale al prompt ────────────────────────────────────────────


async def test_mismo_contexto_misma_clave_y_mismo_prompt() -> None:
    a, b = _finding(), _finding()
    assert a is not b
    assert _context_key(a) == _context_key(b)
    assert await _prompt_enviado(a) == await _prompt_enviado(b)


@pytest.mark.parametrize(
    "cambio",
    [
        {"hostname": "api.ejemplo.com"},
        {"ip_addresses": ["140.82.121.4"]},
        {"status": "no_answer"},
        {"sources": ["crt.sh", "shodan"]},
        {"is_active": False},
        {"open_ports": [22, 443]},
        {"finding_type": "csp_missing"},
        {"evidence": "Sin X-Frame-Options."},
    ],
)
async def test_cualquier_cambio_del_contexto_cambia_clave_y_prompt(cambio: dict[str, Any]) -> None:
    """Si un campo llega al modelo, distinguirlo es obligatorio: con él, el
    modelo podría responder otra cosa."""
    a, b = _finding(), _finding(**cambio)
    assert _context_key(a) != _context_key(b)
    assert await _prompt_enviado(a) != await _prompt_enviado(b)


# ─── reuse_previous_triage ──────────────────────────────────────────────────


def test_copia_el_triaje_del_mismo_contexto_y_saca_el_hallazgo_de_pendientes() -> None:
    pendiente = _finding()

    restantes, reutilizados = reuse_previous_triage([pendiente], [_triado()])

    assert (restantes, reutilizados) == ([], 1)
    assert pendiente.severity is FindingSeverity.HIGH
    assert (pendiente.impact, pendiente.remediation) == ("impacto", "remediación")


def test_sin_equivalente_queda_pendiente_e_intacto() -> None:
    pendiente = _finding()

    restantes, reutilizados = reuse_previous_triage(
        [pendiente], [_triado(hostname="api.ejemplo.com")]
    )

    assert (restantes, reutilizados) == ([pendiente], 0)
    assert pendiente.severity is FindingSeverity.UNKNOWN
    assert pendiente.impact is None


def test_ante_varios_triajes_del_mismo_contexto_gana_el_primero() -> None:
    """El repositorio los da del más reciente al más antiguo."""
    reciente, antiguo = _triado(), _triado()
    reciente.severity, antiguo.severity = FindingSeverity.LOW, FindingSeverity.CRITICAL
    pendiente = _finding()

    reuse_previous_triage([pendiente], [reciente, antiguo])

    assert pendiente.severity is FindingSeverity.LOW


def test_mezcla_de_reutilizables_y_nuevos_conserva_el_orden() -> None:
    a, b, c = _finding(), _finding(hostname="b.ejemplo.com"), _finding(hostname="c.ejemplo.com")

    restantes, reutilizados = reuse_previous_triage(
        [a, b, c], [_triado(hostname="b.ejemplo.com")]
    )

    assert (restantes, reutilizados) == ([a, c], 1)


def test_sin_historial_no_reutiliza_nada() -> None:
    pendientes = [_finding(), _finding(hostname="b.ejemplo.com")]
    assert reuse_previous_triage(pendientes, []) == (pendientes, 0)
