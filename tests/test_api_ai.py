"""Pruebas de `POST /scans/{id}/triage` y `POST /findings/ask`.

`get_provider` se sustituye por un doble (`_FakeProvider`) en el módulo de
cada router: estas pruebas verifican el cableado HTTP -> repositorio -> capa
IA -> persistencia, no el proveedor real (ya cubierto en
`test_ai_provider.py`) ni la lógica de triaje/consulta (`test_ai_triage.py`,
`test_ai_query.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime
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


class _FakeRoutingProvider(LLMProvider):
    """Doble de `LLMProvider` para `POST /findings/ask`, que desde que pasa
    por `ai/prompter.py::route_and_answer()` hace dos llamadas a
    `complete_tool` con nombres de herramienta distintos (`route_query` y,
    según el enrutado, `record_analysis` o
    `record_takeover_assessment_batch`) en vez de una sola a `complete()`.
    `responses` mapea `tool_name` -> resultado (dict), igual patrón que
    `tests/test_ai_prompter.py::_FakeProvider`.
    """

    def __init__(self, responses: dict[str, Any], *, error: Exception | None = None) -> None:
        self._responses = responses
        self._error = error

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise NotImplementedError("no usado por route_and_answer")

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        if self._error is not None:
            raise self._error
        return self._responses[tool_name]


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
    result.finished_at = datetime.now(UTC)
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
    assert resp.json() == {
        "scan_id": scan_id, "triaged": 1, "reused": 0, "model_calls": 1, "errors": []
    }

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
    assert segunda == {
        "scan_id": scan_id, "triaged": 0, "reused": 0, "model_calls": 0, "errors": []
    }


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


async def test_triage_scan_force_vuelve_a_triar_los_ya_triados(
    client: TestClient, monkeypatch
) -> None:
    """P. ej. tras cambiar de modelo: sin `force` no hay forma de re-triar."""
    scan_id = _create_scan_con_finding(client, monkeypatch)
    primero = _FakeProvider(tool_output={"severity": "low", "impact": "i1", "remediation": "r1"})
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: primero)
    assert client.post(f"/scans/{scan_id}/triage").json()["triaged"] == 1

    segundo = _FakeProvider(tool_output={"severity": "high", "impact": "i2", "remediation": "r2"})
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: segundo)
    assert client.post(f"/scans/{scan_id}/triage").json()["triaged"] == 0  # sin force: nada
    resp = client.post(f"/scans/{scan_id}/triage", params={"force": "true"})

    assert resp.json() == {
        "scan_id": scan_id, "triaged": 1, "reused": 0, "model_calls": 1, "errors": []
    }
    finding = client.get("/findings", params={"scan_id": scan_id}).json()[0]
    assert (finding["severity"], finding["impact"]) == ("high", "i2")


async def test_triage_scan_force_con_proveedor_caido_conserva_el_triaje_anterior(
    client: TestClient, monkeypatch
) -> None:
    """Un re-triaje fallido no devuelve el hallazgo a `unknown`: no se pierde
    el triaje bueno que ya había por un fallo puntual del proveedor."""
    scan_id = _create_scan_con_finding(client, monkeypatch)
    bueno = _FakeProvider(tool_output={"severity": "medium", "impact": "i", "remediation": "r"})
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: bueno)
    client.post(f"/scans/{scan_id}/triage")

    caido = _FakeProvider(error=AIProviderError("503"))
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: caido)
    body = client.post(f"/scans/{scan_id}/triage", params={"force": "true"}).json()

    assert body["triaged"] == 0 and len(body["errors"]) == 1
    finding = client.get("/findings", params={"scan_id": scan_id}).json()[0]
    assert (finding["severity"], finding["impact"]) == ("medium", "i")


class _CountingProvider(_FakeProvider):
    """`_FakeProvider` que cuenta las llamadas a `complete_tool`."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.calls = 0

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        self.calls += 1
        return await super().complete_tool(
            prompt, tool_name=tool_name, tool_schema=tool_schema, system=system
        )


def _sin_proveedor() -> LLMProvider:
    raise AssertionError("con todo reutilizado no debe instanciarse el proveedor")


def _escaneo_triado(client: TestClient, monkeypatch) -> int:
    """Primer escaneo de `ejemplo.com`, ya triado como `high`."""
    scan_id = _create_scan_con_finding(client, monkeypatch)
    previo = _FakeProvider(
        tool_output={"severity": "high", "impact": "impacto previo", "remediation": "r previa"}
    )
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: previo)
    assert client.post(f"/scans/{scan_id}/triage").json()["triaged"] == 1
    return scan_id


async def test_triage_reutiliza_el_triaje_de_otro_escaneo_con_el_mismo_contexto(
    client: TestClient, monkeypatch, caplog
) -> None:
    """Re-escaneo sin cambios: mismo prompt exacto, así que se copia el triaje
    sin llamar al modelo (ni instanciarlo: funciona sin clave)."""
    _escaneo_triado(client, monkeypatch)
    nuevo_id = _create_scan_con_finding(client, monkeypatch)
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", _sin_proveedor)

    with caplog.at_level("INFO", logger="atalaya.api.routes.scans"):
        resp = client.post(f"/scans/{nuevo_id}/triage")

    assert resp.json() == {
        "scan_id": nuevo_id, "triaged": 1, "reused": 1, "model_calls": 0, "errors": []
    }
    finding = client.get("/findings", params={"scan_id": nuevo_id}).json()[0]
    assert (finding["severity"], finding["impact"], finding["remediation"]) == (
        "high", "impacto previo", "r previa"
    )
    assert "1 hallazgos triados con 0 llamadas al modelo" in caplog.text
    assert "ahorro del 100%" in caplog.text


async def test_triage_no_reutiliza_si_cambia_el_contexto(
    client: TestClient, monkeypatch
) -> None:
    """Mismo host y mismo hallazgo, pero otra IP: el prompt ya no es el mismo
    y el modelo podría responder otra cosa, así que se le pregunta."""
    _escaneo_triado(client, monkeypatch)

    async def otra_ip(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        result = _fake_result(domain)
        result.records[0].ip_addresses = ["10.0.0.6"]
        return result

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", otra_ip)
    nuevo_id = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]
    actual = _CountingProvider(tool_output={"severity": "low", "impact": "i", "remediation": "r"})
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: actual)

    body = client.post(f"/scans/{nuevo_id}/triage").json()

    assert (body["triaged"], body["reused"], body["model_calls"], actual.calls) == (1, 0, 1, 1)
    assert client.get("/findings", params={"scan_id": nuevo_id}).json()[0]["severity"] == "low"


async def test_triage_force_no_reutiliza(client: TestClient, monkeypatch) -> None:
    """Forzar es volver a preguntar al modelo actual, no copiar a otro."""
    _escaneo_triado(client, monkeypatch)
    nuevo_id = _create_scan_con_finding(client, monkeypatch)
    actual = _CountingProvider(tool_output={"severity": "low", "impact": "i", "remediation": "r"})
    monkeypatch.setattr("atalaya.api.routes.scans.get_provider", lambda: actual)

    body = client.post(f"/scans/{nuevo_id}/triage", params={"force": "true"}).json()

    assert (body["reused"], body["model_calls"], actual.calls) == (0, 1, 1)
    assert client.get("/findings", params={"scan_id": nuevo_id}).json()[0]["severity"] == "low"


async def test_triage_reutiliza_aunque_el_proveedor_falle_para_el_resto(
    client: TestClient, monkeypatch
) -> None:
    """Lo reutilizado no depende del proveedor: si cae, solo quedan sin
    triar los hallazgos que de verdad necesitaban una llamada."""
    _escaneo_triado(client, monkeypatch)

    async def con_host_extra(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        result = _fake_result(domain)
        result.records.append(
            SubdomainRecord(
                hostname=f"dev.{domain}",
                status=ResolutionStatus.UNROUTABLE,
                ip_addresses=["10.0.0.9"],
                sources=[DiscoverySource.CRTSH],
            )
        )
        return result

    monkeypatch.setattr("atalaya.api.routes.scans.enumerate_subdomains", con_host_extra)
    nuevo_id = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]
    monkeypatch.setattr(
        "atalaya.api.routes.scans.get_provider",
        lambda: _FakeProvider(error=AIProviderError("503")),
    )

    body = client.post(f"/scans/{nuevo_id}/triage").json()

    assert (body["triaged"], body["reused"], body["model_calls"]) == (1, 1, 1)
    assert len(body["errors"]) == 1 and "503" in body["errors"][0]
    findings = client.get("/findings", params={"scan_id": nuevo_id}).json()
    assert sorted(f["severity"] for f in findings) == ["high", "unknown"]


async def test_triage_scan_inexistente_da_404(client: TestClient) -> None:
    resp = client.post("/scans/999/triage")
    assert resp.status_code == 404


# ─── POST /findings/ask ─────────────────────────────────────────────────────


async def test_ask_responde_sobre_el_ultimo_escaneo_del_dominio(
    client: TestClient, monkeypatch
) -> None:
    scan_id = _create_scan_con_finding(client, monkeypatch, domain="ejemplo.com")

    fake_provider = _FakeRoutingProvider(
        {
            "route_query": {
                "agent": "analyst",
                "refined_question": "¿algo filtra red interna?",
            },
            "record_analysis": {
                "answer": "Sí, interno.ejemplo.com filtra red interna.",
                "patterns": ["direccionamiento interno expuesto"],
                "concerning_combinations": [],
                "priorities": ["Eliminar el registro DNS obsoleto"],
            },
        }
    )
    monkeypatch.setattr("atalaya.api.routes.findings.get_provider", lambda: fake_provider)

    resp = client.post(
        "/findings/ask",
        json={"domain": "ejemplo.com", "question": "¿algo filtra red interna?"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["answer"] == "Sí, interno.ejemplo.com filtra red interna."
    assert body["patterns"] == ["direccionamiento interno expuesto"]
    assert body["priorities"] == ["Eliminar el registro DNS obsoleto"]


async def test_ask_sin_escaneo_previo_da_404(client: TestClient) -> None:
    resp = client.post(
        "/findings/ask", json={"domain": "sin-escanear.com", "question": "¿qué hay?"}
    )
    assert resp.status_code == 404


async def test_ask_proveedor_caido_da_502(client: TestClient, monkeypatch) -> None:
    _create_scan_con_finding(client, monkeypatch)
    fake_provider = _FakeRoutingProvider({}, error=AIProviderError("proveedor caído"))
    monkeypatch.setattr("atalaya.api.routes.findings.get_provider", lambda: fake_provider)

    resp = client.post(
        "/findings/ask", json={"domain": "ejemplo.com", "question": "¿qué hay expuesto?"}
    )

    assert resp.status_code == 502
