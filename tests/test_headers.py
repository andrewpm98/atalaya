"""Pruebas de `discovery/headers.py`: análisis de cabeceras de seguridad HTTP.

`evaluate_headers` se prueba de forma pura (sin red, un `httpx.Headers` ya
construido). `analyze_headers` se prueba con `httpx.MockTransport`, mismo
patrón que `fetch_crtsh` en `test_subdomains.py`.
"""

from __future__ import annotations

import httpx

from atalaya.discovery.headers import analyze_headers, evaluate_headers

_SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
}


def _headers(overrides: dict[str, str | None] | None = None) -> httpx.Headers:
    data = dict(_SECURE_HEADERS)
    for key, value in (overrides or {}).items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return httpx.Headers(data)


# ─── evaluate_headers: reglas individuales ───────────────────────────────


def test_todas_las_cabeceras_presentes_no_da_hallazgos() -> None:
    assert evaluate_headers(_headers()) == []


def test_hsts_ausente() -> None:
    findings = evaluate_headers(_headers({"strict-transport-security": None}))
    assert {f.finding_type for f in findings} == {"hsts_missing"}


def test_hsts_max_age_bajo() -> None:
    findings = evaluate_headers(_headers({"strict-transport-security": "max-age=3600"}))
    assert {f.finding_type for f in findings} == {"hsts_max_age_bajo"}


def test_csp_ausente() -> None:
    findings = evaluate_headers(_headers({"content-security-policy": None}))
    assert {f.finding_type for f in findings} == {"csp_missing"}


def test_clickjacking_sin_xfo_ni_frame_ancestors() -> None:
    findings = evaluate_headers(
        _headers({"x-frame-options": None, "content-security-policy": "default-src 'self'"})
    )
    assert {f.finding_type for f in findings} == {"clickjacking_sin_proteccion"}


def test_clickjacking_mitigado_por_frame_ancestors_en_csp() -> None:
    findings = evaluate_headers(
        _headers(
            {
                "x-frame-options": None,
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            }
        )
    )
    assert findings == []


def test_content_type_options_ausente_o_incorrecto() -> None:
    assert evaluate_headers(_headers({"x-content-type-options": None}))[
        0
    ].finding_type == "mime_sniffing_habilitado"
    assert evaluate_headers(_headers({"x-content-type-options": "sniff"}))[
        0
    ].finding_type == "mime_sniffing_habilitado"


def test_referrer_policy_ausente() -> None:
    findings = evaluate_headers(_headers({"referrer-policy": None}))
    assert {f.finding_type for f in findings} == {"referrer_policy_missing"}


def test_permissions_policy_ausente() -> None:
    findings = evaluate_headers(_headers({"permissions-policy": None}))
    assert {f.finding_type for f in findings} == {"permissions_policy_missing"}


# ─── analyze_headers: orquestación HTTP ──────────────────────────────────


def _client_con_respuesta(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_analyze_headers_https_ok_sin_hallazgos() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.scheme == "https"
        return httpx.Response(200, headers=_SECURE_HEADERS)

    async with _client_con_respuesta(handler) as client:
        resultado = await analyze_headers("https://ejemplo.com/", client=client)

    assert resultado.hostname == "ejemplo.com"
    assert resultado.checked_url == "https://ejemplo.com/"
    assert resultado.findings == []
    assert resultado.error is None


async def test_analyze_headers_recoge_hallazgos_de_cabeceras_debiles() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={})

    async with _client_con_respuesta(handler) as client:
        resultado = await analyze_headers("https://ejemplo.com/", client=client)

    tipos = {f.finding_type for f in resultado.findings}
    assert "hsts_missing" in tipos
    assert "csp_missing" in tipos


async def test_analyze_headers_sin_https_reintenta_por_http_y_marca_hallazgo() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("conexión rechazada", request=request)
        return httpx.Response(200, headers=_SECURE_HEADERS)

    async with _client_con_respuesta(handler) as client:
        resultado = await analyze_headers("https://ejemplo.com/", client=client)

    assert resultado.error is None
    assert resultado.checked_url == "http://ejemplo.com/"
    assert any(f.finding_type == "sin_https" for f in resultado.findings)


async def test_analyze_headers_host_totalmente_inalcanzable_degrada_con_gracia() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("conexión rechazada", request=request)

    async with _client_con_respuesta(handler) as client:
        resultado = await analyze_headers("https://ejemplo.com/", client=client)

    assert resultado.findings == []
    assert resultado.error is not None
