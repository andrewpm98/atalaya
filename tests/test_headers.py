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


def _redirige_http_a_https(request: httpx.Request) -> httpx.Response | None:
    """Comportamiento correcto de un servidor: HTTP → 301 a la misma ruta en HTTPS."""
    if request.url.scheme == "http":
        return httpx.Response(301, headers={"location": str(request.url.copy_with(scheme="https"))})
    return None


async def test_analyze_headers_https_ok_sin_hallazgos() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _redirige_http_a_https(request) or httpx.Response(200, headers=_SECURE_HEADERS)

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


# ─── Redirección HTTP → HTTPS ────────────────────────────────────────────


async def _analiza(handler) -> list[str]:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        resultado = await analyze_headers("https://ejemplo.com/", client=client)
    assert resultado.error is None
    return [f.finding_type for f in resultado.findings]


async def test_http_que_sirve_contenido_sin_redirigir_es_hallazgo() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=_SECURE_HEADERS)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        resultado = await analyze_headers("https://ejemplo.com/", client=client)

    assert [f.finding_type for f in resultado.findings] == ["http_sin_redireccion_https"]
    evidencia = resultado.findings[0].evidence
    assert "http://ejemplo.com/" in evidencia and "200" in evidencia
    # El resultado sigue siendo el del análisis por HTTPS, no el de la sonda.
    assert resultado.checked_url == "https://ejemplo.com/"


async def test_redireccion_en_cadena_que_acaba_en_https_no_es_hallazgo() -> None:
    """http://ejemplo.com → http://www.ejemplo.com → https://www.ejemplo.com."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http" and request.url.host == "ejemplo.com":
            return httpx.Response(302, headers={"location": "http://www.ejemplo.com/"})
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://www.ejemplo.com/"})
        return httpx.Response(200, headers=_SECURE_HEADERS)

    assert await _analiza(handler) == []


async def test_redireccion_a_https_de_otro_host_no_es_hallazgo() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://ejemplo.net/"})
        return httpx.Response(200, headers=_SECURE_HEADERS)

    assert await _analiza(handler) == []


async def test_http_que_no_responde_no_es_hallazgo() -> None:
    """Puerto 80 cerrado o filtrado: no se sirve nada en claro."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            raise httpx.ConnectError("conexión rechazada", request=request)
        return httpx.Response(200, headers=_SECURE_HEADERS)

    assert await _analiza(handler) == []


async def test_solo_http_da_sin_https_y_no_duplica_con_la_redireccion() -> None:
    """Si HTTPS no responde, el hallazgo es `sin_https`: que tampoco redirija
    es la misma causa y no se cuenta dos veces."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("conexión rechazada", request=request)
        return httpx.Response(200, headers=_SECURE_HEADERS)

    assert await _analiza(handler) == ["sin_https"]


async def test_https_y_http_se_piden_en_paralelo() -> None:
    """En serie, un puerto 80 filtrado sumaría un timeout entero por host: la
    sonda HTTP arranca sin esperar a que HTTPS termine."""
    import asyncio

    https_empezada = asyncio.Event()
    http_empezada = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            https_empezada.set()
            await asyncio.wait_for(http_empezada.wait(), timeout=2)
            return httpx.Response(200, headers=_SECURE_HEADERS)
        http_empezada.set()
        await asyncio.wait_for(https_empezada.wait(), timeout=2)
        return httpx.Response(301, headers={"location": "https://ejemplo.com/"})

    assert await _analiza(handler) == []
