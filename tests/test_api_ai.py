"""Pruebas de `POST /scans/{id}/triage` y `POST /findings/ask`.

`get_provider` se sustituye por un doble (`_FakeProvider`) en el módulo de
cada router: estas pruebas verifican el cableado HTTP -> repositorio -> capa
IA -> persistencia, no el proveedor real (ya cubierto en
`test_ai_provider.py`) ni la lógica de triaje/consulta (`test_ai_triage.py`,
`test_ai_query.py`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


class _FakeProvider(LLMProvider):
    def __init__(
        self,
        *,
        tool_output: dict[str, Any] | None = None,
        text: str | None = None,
        error: Exception | None = None,
    ) -> None:
        self._tool_output = tool_output
        self._text = text
        self._error = error

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        if self._error is not None:
            raise self._error
        assert self._text is not None
        return self._text

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        if self._error is not None:
            raise self._error
        assert self._tool_output is not None
        return self._tool_output


def _fake_result(domain: str) -> SubdomainScanResult:
    result = SubdomainScanResult(domain=domain)
    result.records = [
        SubdomainRecord(
            hostname=f"interno.{domain}",
            status=ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"],
            sources=[DiscoverySource.CRTSH],
        )
    ]
    result.finished_at = datetime.now(timezone.utc)
    return result


def _create_scan_con_finding(client: TestClient, monkeypatch, domain: str = "ejemplo.com") -> int:
    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", fake_enumerate)
    created = client.post("/scans", json={"domain": domain}).json()
    return created["id"]


# ─── POST /scans/{id}/triage ────────────────────────────────────────────────


async def test_triage_scan_actualiza_findings_y_persiste(
    client: TestClient, monkeypatch
) -> None:
    scan_id = _create_scan_con_finding(client, monkeypatch)

    fake_provider = _FakeProvider(
        tool_output={
            "severity": "high",
            "impact": "Expone direccionamiento interno a cualquier cliente DNS.",
            "remediation": "Elimina el registro DNS obsoleto.",
        }
    )
    monkeypatch.setattr(
        "atalaya.api.routes.scans.get_provider", lambda: fake_provider
    )

    resp = client.post(f"/scans/{scan_id}/triage")

    assert resp.status_code == 200
    assert resp.json() == {"scan_id": scan_id, "triaged": 1, "errors": []}

    findings = client.get("/findings", params={"scan_id": scan_id}).json()
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "direccionamiento interno" in findings[0]["impact"]


async def test_triage_scan_es_idempotente_con_findings_ya_triados(
    client: TestClient, monkeypatch
) -> None:
    scan_id = _create_scan_con_finding(client, monkeypatch)
    fake_provider = _FakeProvider(
        tool_output={"severity": "low", "impact": "i", "remediation": "r"}
    )
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    primera = client.post(f"/scans/{scan_id}/triage").json()
    assert primera["triaged"] == 1

    segunda = client.post(f"/scans/{scan_id}/triage").json()
    assert segunda == {"scan_id": scan_id, "triaged": 0, "errors": []}


async def test_triage_scan_degrada_con_gracia_si_falla_el_proveedor(
    client: TestClient, monkeypatch
) -> None:
    scan_id = _create_scan_con_finding(client, monkeypatch)
    fake_provider = _FakeProvider(error=AIProviderError("rate limit"))
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: fake_provider)

    resp = client.post(f"/scans/{scan_id}/triage")

    assert resp.status_code == 200
    body = resp.json()
    assert body["triaged"] == 0
    assert len(body["errors"]) == 1
    assert "rate limit" in body["errors"][0]


async def test_triage_scan_inexistente_da_404(client: TestClient) -> None:
    resp = client.post("/scans/999/triage")
    assert resp.status_code == 404


# ─── POST /findings/ask ─────────────────────────────────────────────────────


async def test_ask_responde_sobre_el_ultimo_escaneo_del_dominio(
    client: TestClient, monkeypatch
) -> None:
    scan_id = _create_scan_con_finding(client, monkeypatch, domain="ejemplo.com")

    fake_provider = _FakeProvider(text="Sí, interno.ejemplo.com filtra red interna.")
    monkeypatch.setattr("atalaya.api.routes.findings.get_provider", lambda: fake_provider)

    resp = client.post(
        "/findings/ask",
        json={"domain": "ejemplo.com", "question": "¿algo filtra red interna?"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["answer"] == "Sí, interno.ejemplo.com filtra red interna."


async def test_ask_sin_escaneo_previo_da_404(client: TestClient) -> None:
    resp = client.post(
        "/findings/ask", json={"domain": "sin-escanear.com", "question": "¿qué hay?"}
    )
    assert resp.status_code == 404


async def test_ask_proveedor_caido_da_502(client: TestClient, monkeypatch) -> None:
    _create_scan_con_finding(client, monkeypatch)
    fake_provider = _FakeProvider(error=AIProviderError("proveedor caído"))
    monkeypatch.setattr("atalaya.api.routes.findings.get_provider", lambda: fake_provider)

    resp = client.post(
        "/findings/ask", json={"domain": "ejemplo.com", "question": "¿qué hay expuesto?"}
    )

    assert resp.status_code == 502
