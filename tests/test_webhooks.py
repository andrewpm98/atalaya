"""Pruebas de los avisos por webhook (`core/webhooks.py`): SSRF, firma y envío.

El resolvedor del sistema se sustituye por un diccionario (sin red): cada
prueba decide a qué direcciones resuelve cada host, que es justo lo que
controlaría un atacante con su propio DNS. El envío usa `httpx.MockTransport`
para ver la petición exacta que sale.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket

import httpx
import pytest

from atalaya.core.audit import AUDIT_LOGGER_NAME
from atalaya.core.exceptions import InvalidWebhookError, WebhookDeliveryError
from atalaya.core.webhooks import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    mask_webhook_url,
    send_webhook,
    sign_payload,
    validate_webhook_url,
)

PUBLICA = "93.184.216.34"
#: Ruta con un token, como la de un webhook de Slack: no debe salir nunca.
TOKEN = "T000/B000/xoxb-secreto-del-webhook"
URL = f"https://hooks.ejemplo.com/services/{TOKEN}"


@pytest.fixture
def dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Resolvedor falso: host → direcciones. Un host ausente no resuelve."""
    tabla: dict[str, list[str]] = {"hooks.ejemplo.com": [PUBLICA]}

    async def fake_getaddrinfo(host: str, port: int) -> list[str]:
        if host in tabla:
            return tabla[host]
        raise socket.gaierror(socket.EAI_NONAME, "no resuelve")

    monkeypatch.setattr("atalaya.core.webhooks._getaddrinfo", fake_getaddrinfo)
    return tabla


class _Collector(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def auditoria() -> object:
    """Mensajes del logger de auditoría (no propaga al raíz: `caplog` no los ve)."""
    collector = _Collector()
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    logger.addHandler(collector)
    yield collector
    logger.removeHandler(collector)


def _mensajes(collector: object) -> list[str]:
    assert isinstance(collector, _Collector)
    return [r.getMessage() for r in collector.records]


# --- Validación al crear el monitor -----------------------------------------


async def test_acepta_un_webhook_https_publico(dns: dict[str, list[str]]) -> None:
    assert await validate_webhook_url(f"  {URL} ") == URL


@pytest.mark.parametrize(
    ("url", "motivo"),
    [
        (f"http://hooks.ejemplo.com/services/{TOKEN}", "https"),
        ("ftp://hooks.ejemplo.com/", "https"),
        ("https://usuario:clave@hooks.ejemplo.com/", "usuario"),
        ("https:///sin-host", "host"),
        ("no es una url", "https"),
    ],
    ids=["http", "ftp", "credenciales", "sin_host", "texto"],
)
async def test_rechaza_urls_mal_formadas_o_sin_https(
    dns: dict[str, list[str]], url: str, motivo: str
) -> None:
    with pytest.raises(InvalidWebhookError, match=motivo):
        await validate_webhook_url(url)


@pytest.mark.parametrize(
    ("direccion", "alcance"),
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.5", "private"),
        ("192.168.1.10", "private"),
        ("169.254.169.254", "link_local"),  # metadatos de la nube
        ("0.0.0.0", "unspecified"),
        ("100.64.0.1", "cgnat"),
        ("::1", "loopback"),
        ("fc00::1", "private"),
    ],
)
async def test_rechaza_un_host_que_resuelve_a_una_direccion_no_enrutable(
    dns: dict[str, list[str]], auditoria: object, direccion: str, alcance: str
) -> None:
    """El SSRF clásico: un nombre público que apunta a la red interna."""
    dns["hooks.ejemplo.com"] = [direccion]

    with pytest.raises(InvalidWebhookError, match=alcance) as excinfo:
        await validate_webhook_url(URL)

    # El tipo de dirección sí, la dirección no: a quien use la API no hace
    # falta decirle a qué IP interna resuelve un nombre.
    assert direccion not in str(excinfo.value)
    assert any("SSRF" in m and "hooks.ejemplo.com" in m for m in _mensajes(auditoria))


async def test_rechaza_si_una_sola_direccion_es_interna(dns: dict[str, list[str]]) -> None:
    """Con una pública y una privada, la conexión podría acabar en cualquiera."""
    dns["hooks.ejemplo.com"] = [PUBLICA, "10.0.0.5"]

    with pytest.raises(InvalidWebhookError, match="private"):
        await validate_webhook_url(URL)


async def test_rechaza_una_ip_interna_escrita_en_la_url(dns: dict[str, list[str]]) -> None:
    dns["127.0.0.1"] = ["127.0.0.1"]

    with pytest.raises(InvalidWebhookError, match="loopback"):
        await validate_webhook_url("https://127.0.0.1:5432/")


async def test_rechaza_un_host_que_no_resuelve(dns: dict[str, list[str]]) -> None:
    with pytest.raises(InvalidWebhookError, match="resolver"):
        await validate_webhook_url("https://no-existe.ejemplo.com/hook")


# --- Enmascarado y firma ------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "esperado"),
    [
        (URL, "https://hooks.ejemplo.com/…"),
        ("https://hooks.ejemplo.com/", "https://hooks.ejemplo.com/"),
        ("https://hooks.ejemplo.com?token=x", "https://hooks.ejemplo.com/…"),
        ("https://hooks.ejemplo.com:8443/a", "https://hooks.ejemplo.com:8443/…"),
        ("https://[2001:db8::1]/a", "https://[2001:db8::1]/…"),
    ],
)
def test_enmascara_ruta_y_consulta(url: str, esperado: str) -> None:
    assert mask_webhook_url(url) == esperado


def test_la_firma_es_el_hmac_sha256_del_cuerpo() -> None:
    cuerpo = b'{"event": "cambios"}'
    esperado = hmac.new(b"secreto-de-16-caracteres", cuerpo, hashlib.sha256).hexdigest()

    assert sign_payload(cuerpo, "secreto-de-16-caracteres") == f"sha256={esperado}"
    assert sign_payload(cuerpo + b" ", "secreto-de-16-caracteres") != f"sha256={esperado}"


# --- Envío --------------------------------------------------------------------


def _transporte(
    respuesta: httpx.Response, enviadas: list[httpx.Request]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        enviadas.append(request)
        return respuesta

    return httpx.MockTransport(handler)


async def test_envia_a_la_ip_validada_con_el_nombre_en_host_y_sni(
    dns: dict[str, list[str]],
) -> None:
    """Contra el *DNS rebinding*: se conecta a la IP que se validó, no se
    vuelve a resolver el nombre. El nombre va en `Host` y en el SNI, con el
    que se verifica el certificado."""
    enviadas: list[httpx.Request] = []
    payload = {"event": "cambios", "nuevos": ["api.ejemplo.com"], "texto": "añadido"}

    await send_webhook(
        URL, payload, event="cambios", transport=_transporte(httpx.Response(204), enviadas)
    )

    [peticion] = enviadas
    assert peticion.method == "POST"
    assert peticion.url.host == PUBLICA
    assert peticion.url.path == f"/services/{TOKEN}"
    assert peticion.headers["host"] == "hooks.ejemplo.com"
    assert peticion.extensions["sni_hostname"] == "hooks.ejemplo.com"
    assert peticion.headers[EVENT_HEADER] == "cambios"
    assert peticion.headers["content-type"].startswith("application/json")
    assert json.loads(peticion.content) == payload
    assert SIGNATURE_HEADER not in peticion.headers  # sin secreto, sin firma


async def test_con_secreto_firma_el_cuerpo_exacto_que_envia(dns: dict[str, list[str]]) -> None:
    enviadas: list[httpx.Request] = []
    secreto = "un-secreto-compartido-largo"

    await send_webhook(
        URL,
        {"event": "cambios"},
        event="cambios",
        secret=secreto,
        transport=_transporte(httpx.Response(200), enviadas),
    )

    [peticion] = enviadas
    assert peticion.headers[SIGNATURE_HEADER] == sign_payload(peticion.content, secreto)


async def test_ipv6_publica_va_entre_corchetes_y_el_nombre_en_host(
    dns: dict[str, list[str]],
) -> None:
    dns["hooks.ejemplo.com"] = ["2606:2800:220:1:248:1893:25c8:1946"]
    enviadas: list[httpx.Request] = []

    await send_webhook(
        "https://hooks.ejemplo.com:8443/x",
        {},
        event="cambios",
        transport=_transporte(httpx.Response(200), enviadas),
    )

    [peticion] = enviadas
    assert peticion.url.host == "2606:2800:220:1:248:1893:25c8:1946"
    assert peticion.url.port == 8443
    assert peticion.headers["host"] == "hooks.ejemplo.com:8443"


async def test_revalida_al_enviar_y_no_envia_si_el_dns_cambio(
    dns: dict[str, list[str]],
) -> None:
    """El monitor se creó con una IP pública; días después el nombre apunta a
    `127.0.0.1`. No sale ninguna petición."""
    dns["hooks.ejemplo.com"] = ["127.0.0.1"]
    enviadas: list[httpx.Request] = []

    with pytest.raises(InvalidWebhookError):
        await send_webhook(
            URL, {}, event="cambios", transport=_transporte(httpx.Response(200), enviadas)
        )
    assert enviadas == []


async def test_no_sigue_redirecciones(dns: dict[str, list[str]]) -> None:
    """Un 302 hacia la red interna saltaría toda la validación."""
    enviadas: list[httpx.Request] = []
    redireccion = httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/scans"})

    with pytest.raises(WebhookDeliveryError, match="302"):
        await send_webhook(URL, {}, event="cambios", transport=_transporte(redireccion, enviadas))
    assert len(enviadas) == 1


async def test_respuesta_de_error_no_cuenta_como_entregado_y_no_expone_el_token(
    dns: dict[str, list[str]], auditoria: object
) -> None:
    enviadas: list[httpx.Request] = []

    with pytest.raises(WebhookDeliveryError, match="500") as excinfo:
        await send_webhook(
            URL, {}, event="cambios", transport=_transporte(httpx.Response(500), enviadas)
        )

    assert TOKEN not in str(excinfo.value)
    [mensaje] = _mensajes(auditoria)
    assert "NO entregado" in mensaje and "HTTP 500" in mensaje
    assert TOKEN not in mensaje


async def test_un_error_de_red_guarda_el_tipo_y_no_el_texto_con_la_url(
    dns: dict[str, list[str]], auditoria: object
) -> None:
    """El texto de un error de httpx lleva la URL completa, con su token."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"no se pudo conectar a {URL}", request=request)

    with pytest.raises(WebhookDeliveryError, match="ConnectError") as excinfo:
        await send_webhook(URL, {}, event="cambios", transport=httpx.MockTransport(handler))

    assert TOKEN not in str(excinfo.value)
    assert all(TOKEN not in m for m in _mensajes(auditoria))


async def test_si_una_direccion_no_conecta_prueba_la_siguiente(
    dns: dict[str, list[str]], auditoria: object
) -> None:
    """Sin salida IPv6, un host con IPv6 en primer lugar no recibiría nunca el
    aviso: fijar la IP desactiva el *happy eyeballs* de httpx."""
    dns["hooks.ejemplo.com"] = ["2606:2800:220:1:248:1893:25c8:1946", PUBLICA]
    intentos: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        intentos.append(request.url.host)
        if ":" in request.url.host:
            raise httpx.ConnectError("sin ruta IPv6", request=request)
        return httpx.Response(200)

    await send_webhook(URL, {}, event="cambios", transport=httpx.MockTransport(handler))

    assert intentos == ["2606:2800:220:1:248:1893:25c8:1946", PUBLICA]
    assert "sin conexión" in _mensajes(auditoria)[0]
    assert "entregado" in _mensajes(auditoria)[1]


async def test_tras_conectar_no_se_reintenta_con_otra_direccion(
    dns: dict[str, list[str]],
) -> None:
    """Un timeout de lectura llega con la petición ya enviada: repetirla en
    otra dirección duplicaría el aviso."""
    dns["hooks.ejemplo.com"] = [PUBLICA, "93.184.216.35"]
    intentos: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        intentos.append(request.url.host)
        raise httpx.ReadTimeout("sin respuesta", request=request)

    with pytest.raises(WebhookDeliveryError, match="ReadTimeout"):
        await send_webhook(URL, {}, event="cambios", transport=httpx.MockTransport(handler))
    assert intentos == [PUBLICA]


async def test_si_ninguna_direccion_conecta_no_se_entrega(dns: dict[str, list[str]]) -> None:
    dns["hooks.ejemplo.com"] = [PUBLICA, "93.184.216.35"]

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("sin respuesta", request=request)

    with pytest.raises(WebhookDeliveryError, match="ConnectTimeout"):
        await send_webhook(URL, {}, event="cambios", transport=httpx.MockTransport(handler))


async def test_audita_cada_aviso_entregado_sin_el_token(
    dns: dict[str, list[str]], auditoria: object
) -> None:
    await send_webhook(
        URL, {}, event="escaneo_fallido", transport=_transporte(httpx.Response(200), [])
    )

    [mensaje] = _mensajes(auditoria)
    assert "escaneo_fallido" in mensaje and "entregado" in mensaje
    assert "https://hooks.ejemplo.com/…" in mensaje
    assert TOKEN not in mensaje
