"""Avisos por webhook de la vigilancia programada, protegidos contra SSRF.

Un webhook es una URL que da quien crea el monitor y a la que la API hace un
`POST` desde la red donde corre. Sin control, es una petición del servidor a
donde el usuario diga (SSRF): `https://127.0.0.1:5432`, el servicio de
metadatos de la nube (`169.254.169.254`) o cualquier máquina de la red
interna. Mismo criterio que la restricción de seguridad #2 para los objetivos
de escaneo: solo direcciones enrutables (`core/netutils.py::classify_ip`).

Tres defensas, y por qué hace falta cada una:

- **Se valida al crear el monitor y otra vez al enviar.** Entre las dos pueden
  pasar días, y el DNS del host puede cambiar.
- **Al enviar, se conecta a la IP ya validada, no al nombre.** Si se validara
  resolviendo el nombre y httpx lo resolviera otra vez al conectar, un DNS con
  TTL 0 podría dar una dirección pública a la primera consulta y `127.0.0.1` a
  la segunda (*DNS rebinding*). El certificado se sigue verificando contra el
  nombre original (SNI): fijar la IP no rebaja TLS (comprobado contra un
  servidor real, ver `send_webhook`).
- **No se siguen redirecciones.** Un `302` hacia `http://127.0.0.1` saltaría
  todo lo anterior; una respuesta 3xx cuenta como aviso no entregado.

Solo `https`: el aviso es un mapa de la superficie de exposición del dominio
(qué hosts aparecen, qué puertos se abren) y no debe viajar en claro.

La URL se trata como un secreto: las de Slack o Discord llevan el token en la
ruta. Fuera de la base de datos solo sale enmascarada (`mask_webhook_url`), y
de un error de httpx solo se guarda el tipo, porque su texto lleva la URL.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import socket
from typing import Any

import httpx

from atalaya import __version__
from atalaya.config import settings
from atalaya.core.audit import get_audit_logger
from atalaya.core.exceptions import InvalidWebhookError, WebhookDeliveryError
from atalaya.core.netutils import classify_ip

#: Cabecera con la firma HMAC-SHA256 del cuerpo, si el monitor tiene secreto.
SIGNATURE_HEADER = "X-Atalaya-Signature"
#: Cabecera con el tipo de aviso (`cambios`, `escaneo_fallido`).
EVENT_HEADER = "X-Atalaya-Event"


def _parse(url: str) -> httpx.URL:
    """Comprueba la forma de la URL (sin red) y la devuelve analizada."""
    try:
        parsed = httpx.URL(url.strip())
    except (httpx.InvalidURL, TypeError) as exc:
        raise InvalidWebhookError("La URL del webhook no es válida.") from exc
    if parsed.scheme != "https":
        raise InvalidWebhookError(
            "El webhook debe usar https: el aviso describe la superficie de exposición "
            "del dominio y no debe viajar en claro."
        )
    if not parsed.host:
        raise InvalidWebhookError("La URL del webhook no tiene host.")
    if parsed.userinfo:
        raise InvalidWebhookError(
            "La URL del webhook no puede llevar usuario ni contraseña; para autenticar "
            "el aviso, usa el secreto del monitor (firma HMAC)."
        )
    return parsed


def _ascii_host(parsed: httpx.URL) -> str:
    """El host en ASCII (punycode si es internacionalizado): es la forma que
    van a ver el DNS, la cabecera `Host` y el SNI."""
    return parsed.raw_host.decode("ascii")


def _netloc(parsed: httpx.URL) -> str:
    host = _ascii_host(parsed)
    host = f"[{host}]" if ":" in host else host
    return f"{host}:{parsed.port}" if parsed.port else host


def mask_webhook_url(url: str) -> str:
    """La URL sin ruta ni consulta: `https://hooks.slack.com/…`.

    Es lo único que sale de la base de datos (respuestas de la API, log de
    auditoría, `last_error`): basta para saber a dónde avisa un monitor sin
    exponer el token que llevan en la ruta los webhooks de Slack o Discord.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        return "(URL no válida)"
    tiene_ruta = parsed.path not in ("", "/") or bool(parsed.query)
    return f"{parsed.scheme}://{_netloc(parsed)}/{'…' if tiene_ruta else ''}"


async def _getaddrinfo(host: str, port: int) -> list[str]:
    """Direcciones de `host` según el resolvedor del sistema.

    El del sistema y no `dnspython` a propósito: es el que usaría cualquier
    cliente HTTP, e incluye el fichero `hosts`, donde un nombre inocente puede
    apuntar a `127.0.0.1`. Separado para que los tests lo sustituyan.
    """
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


async def _resolve_public(parsed: httpx.URL) -> list[str]:
    """Direcciones del host del webhook, todas enrutables, o `InvalidWebhookError`.

    Basta con una no enrutable para rechazar: si el nombre resuelve a una
    pública y a una privada, la conexión podría acabar en cualquiera.
    """
    try:
        addresses = await _getaddrinfo(_ascii_host(parsed), parsed.port or 443)
    except (OSError, UnicodeError) as exc:  # `socket.gaierror` es un `OSError`
        raise InvalidWebhookError(
            f"No se pudo resolver el host del webhook ({_ascii_host(parsed)})."
        ) from exc
    addresses = list(dict.fromkeys(addresses))  # sin duplicados, en orden
    if not addresses:
        raise InvalidWebhookError(
            f"El host del webhook ({_ascii_host(parsed)}) no tiene direcciones."
        )
    for address in addresses:
        scope = classify_ip(address)
        if not scope.is_routable:
            # El tipo de dirección sí, la dirección no: a quien tenga acceso a
            # la API no hace falta decirle a qué IP interna resuelve un nombre.
            get_audit_logger().info(
                "Webhook rechazado (SSRF): %s resuelve a una dirección %s",
                _ascii_host(parsed),
                scope.value,
            )
            raise InvalidWebhookError(
                f"El webhook apunta a una dirección no enrutable ({scope.value}). Solo se "
                "avisa a direcciones públicas: una URL hacia la red interna convertiría a "
                "la API en un punto de entrada a ella (SSRF)."
            )
    return addresses


async def validate_webhook_url(url: str) -> str:
    """Valida un webhook antes de guardarlo: forma, `https` y destino público.

    Devuelve la URL normalizada. La validación se repite al enviar
    (`send_webhook`): esta solo evita guardar un monitor que nunca podrá avisar.
    """
    parsed = _parse(url)
    await _resolve_public(parsed)
    return str(parsed)


def sign_payload(body: bytes, secret: str) -> str:
    """Firma del cuerpo para `X-Atalaya-Signature`: `sha256=<HMAC en hex>`.

    Mismo esquema que los webhooks de GitHub: el receptor recalcula el HMAC
    con el secreto compartido y lo compara en tiempo constante. El cuerpo
    lleva `sent_at`, así que la firma también cubre la fecha y un receptor
    puede rechazar un aviso antiguo reenviado.
    """
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def send_webhook(
    url: str,
    payload: dict[str, Any],
    *,
    event: str,
    secret: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Envía un aviso al webhook, o lanza `WebhookDeliveryError`/`InvalidWebhookError`.

    Cada intento, entregado o no, queda en el log de auditoría con el destino
    enmascarado: es una petición a un tercero con datos del inventario.

    `transport` existe para los tests (`httpx.MockTransport`).
    """
    parsed = _parse(url)
    addresses = await _resolve_public(parsed)
    destino = mask_webhook_url(url)
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Host": _netloc(parsed),
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": f"Atalaya/{__version__}",
        EVENT_HEADER: event,
    }
    if secret:
        headers[SIGNATURE_HEADER] = sign_payload(body, secret)

    audit = get_audit_logger()
    response: httpx.Response | None = None
    sin_conexion: httpx.HTTPError | None = None
    # Las direcciones validadas, en el orden del resolvedor, hasta que una
    # conecte. Fijar la IP desactiva el *happy eyeballs* de httpx: sin esto,
    # un host con IPv6 en primer lugar no recibiría nunca el aviso desde una
    # máquina sin salida IPv6. Solo se pasa a la siguiente si no se llegó a
    # conectar: con la conexión hecha, el aviso pudo llegar y repetirlo lo
    # duplicaría.
    for ip in addresses:
        # Un cliente nuevo por intento, no uno compartido: el pool de
        # conexiones de httpx se indexa por origen (aquí, la IP) y reutilizaría
        # una conexión TLS abierta con otro SNI sin volver a verificar el
        # certificado (comprobado).
        async with httpx.AsyncClient(
            timeout=settings.webhook_timeout, follow_redirects=False, transport=transport
        ) as client:
            try:
                response = await client.post(
                    parsed.copy_with(host=ip),
                    content=body,
                    headers=headers,
                    # SNI y verificación del certificado contra el nombre, no la IP.
                    extensions={"sni_hostname": _ascii_host(parsed)},
                )
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                audit.info(
                    "Aviso «%s» sin conexión con %s (%s): %s",
                    event,
                    destino,
                    ip,
                    type(exc).__name__,
                )
                sin_conexion = exc
                continue
            except httpx.HTTPError as exc:
                audit.info(
                    "Aviso «%s» NO entregado a %s (%s): %s", event, destino, ip, type(exc).__name__
                )
                raise WebhookDeliveryError(
                    f"aviso no entregado a {destino}: {type(exc).__name__}"
                ) from exc
        break

    if response is None:
        raise WebhookDeliveryError(
            f"aviso no entregado a {destino}: {type(sin_conexion).__name__}"
        ) from sin_conexion
    if not response.is_success:
        audit.info(
            "Aviso «%s» NO entregado a %s (%s): HTTP %d", event, destino, ip, response.status_code
        )
        raise WebhookDeliveryError(
            f"aviso no entregado a {destino}: respondió HTTP {response.status_code}"
        )
    audit.info(
        "Aviso «%s» entregado a %s (%s): HTTP %d", event, destino, ip, response.status_code
    )
