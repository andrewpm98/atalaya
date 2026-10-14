"""Pruebas de la vigilancia programada: rutas `/monitors` y `core/monitor_runner.py`.

El descubrimiento se sustituye por una lista de hostnames que cada prueba
cambia entre ejecuciones (así se fabrica un «cambio»), y el envío del webhook
por una función que guarda los avisos (la seguridad del envío se prueba en
`test_webhooks.py`). El bucle se prueba directamente, con su propia base de
datos en fichero, como corre de verdad: con sesiones que no son las de una
petición.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from atalaya.config import settings
from atalaya.core import monitor_runner
from atalaya.core.audit import AUDIT_LOGGER_NAME
from atalaya.core.database import Base
from atalaya.core.exceptions import WebhookDeliveryError
from atalaya.core.models import Monitor, Scan, ScanStatus
from atalaya.core.monitor_runner import monitor_loop, run_due_monitors, run_monitor
from atalaya.core.scan_runner import run_scan
from atalaya.discovery.models import (
    DiscoverySource,
    EnrichmentResult,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)

TOKEN = "T000/B000/xoxb-secreto-del-webhook"
URL = f"https://hooks.ejemplo.com/services/{TOKEN}"
SECRETO = "secreto-compartido-de-prueba"


class _Descubrimiento:
    """Lo que encontrará el próximo escaneo."""

    def __init__(self) -> None:
        self.hosts: list[str] = ["www.ejemplo.com"]
        self.errors: list[str] = []
        self.falla: Exception | None = None


class _Webhook:
    """Avisos enviados, o fallo de entrega si `falla`."""

    def __init__(self) -> None:
        self.avisos: list[tuple[str, dict[str, Any]]] = []
        self.falla = False


@pytest.fixture
def descubrimiento(monkeypatch: pytest.MonkeyPatch) -> _Descubrimiento:
    estado = _Descubrimiento()

    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        if estado.falla is not None:
            raise estado.falla
        result = SubdomainScanResult(domain=domain)
        result.records = [
            SubdomainRecord(
                hostname=host,
                status=ResolutionStatus.ACTIVE,
                ip_addresses=["93.184.216.34"],
                sources=[DiscoverySource.CRTSH, DiscoverySource.DNS],
            )
            for host in estado.hosts
        ]
        result.errors = list(estado.errors)
        result.finished_at = datetime.now(UTC)
        return result

    async def fake_enrich(result: SubdomainScanResult) -> EnrichmentResult:
        return EnrichmentResult()

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", fake_enumerate)
    monkeypatch.setattr("atalaya.core.scan_runner.enrich_scan", fake_enrich)
    return estado


@pytest.fixture
def webhook(monkeypatch: pytest.MonkeyPatch) -> _Webhook:
    estado = _Webhook()

    async def fake_send(
        url: str, payload: dict[str, Any], *, event: str, secret: str | None = None
    ) -> None:
        if estado.falla:
            raise WebhookDeliveryError(
                "aviso no entregado a https://hooks.ejemplo.com/…: respondió HTTP 503"
            )
        estado.avisos.append((event, payload))

    monkeypatch.setattr("atalaya.core.monitor_runner.send_webhook", fake_send)
    return estado


@pytest.fixture
def dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Resolvedor del webhook sin red (ver `test_webhooks.py`)."""
    tabla: dict[str, list[str]] = {"hooks.ejemplo.com": ["93.184.216.34"]}

    async def fake_getaddrinfo(host: str, port: int) -> list[str]:
        if host in tabla:
            return tabla[host]
        raise socket.gaierror(socket.EAI_NONAME, "no resuelve")

    monkeypatch.setattr("atalaya.core.webhooks._getaddrinfo", fake_getaddrinfo)
    return tabla


@pytest_asyncio.fixture
async def factory(tmp_path: Path) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """Base de datos en fichero, como en `test_scan_background.py`: el bucle
    abre varias sesiones y cada una debe ver solo lo confirmado."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'mon.sqlite3').as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


async def _escaneo(factory: async_sessionmaker[AsyncSession], domain: str = "ejemplo.com") -> int:
    """Un escaneo completo con lo que diga `descubrimiento` (la línea base)."""
    async with factory() as session:
        scan = Scan(domain=domain, status=ScanStatus.RUNNING, assets=[])
        session.add(scan)
        await session.commit()
        scan_id = scan.id
    await run_scan(factory, scan_id)
    return scan_id


async def _monitor(
    factory: async_sessionmaker[AsyncSession],
    *,
    domain: str = "ejemplo.com",
    baseline: int | None = None,
    next_run_at: datetime | None = None,
    active: bool = True,
) -> int:
    async with factory() as session:
        monitor = Monitor(
            domain=domain,
            interval_hours=24,
            webhook_url=URL,
            webhook_secret=SECRETO,
            active=active,
            next_run_at=next_run_at or datetime.now(UTC),
            baseline_scan_id=baseline,
        )
        session.add(monitor)
        await session.commit()
        return monitor.id


async def _leer(factory: async_sessionmaker[AsyncSession], monitor_id: int) -> Monitor:
    async with factory() as session:
        monitor = await session.get(Monitor, monitor_id)
        assert monitor is not None
        return monitor


async def _num_escaneos(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        return (await session.execute(select(func.count(Scan.id)))).scalar_one()


# --- Una ejecución ----------------------------------------------------------


async def test_sin_historial_el_primer_escaneo_es_la_linea_base_y_no_avisa(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    monitor_id = await _monitor(factory)

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert webhook.avisos == []
    assert monitor.last_scan_id is not None
    assert monitor.baseline_scan_id == monitor.last_scan_id
    assert monitor.last_run_at is not None
    assert monitor.last_error is None


async def test_avisa_los_cambios_frente_a_la_linea_base_y_la_avanza(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    [(evento, payload)] = webhook.avisos
    assert evento == "cambios"
    assert payload["event"] == "cambios"
    assert payload["domain"] == "ejemplo.com"
    assert payload["monitor_id"] == monitor_id
    assert payload["previous_scan_id"] == base
    assert payload["current_scan_id"] == monitor.last_scan_id
    assert payload["nuevos"] == ["api.ejemplo.com"]
    assert payload["desaparecidos"] == []
    assert payload["cambiados"] == []
    assert "comunes" not in payload  # cientos de hostnames sin cambios en un dominio grande
    assert "1 activo nuevo, 0 desaparecidos y 0 con cambios" in payload["summary"]
    assert payload["sent_at"]
    assert monitor.baseline_scan_id == monitor.last_scan_id
    assert monitor.last_notified_at is not None
    assert monitor.last_error is None


async def test_sin_cambios_no_avisa_y_avanza_la_linea_base(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert webhook.avisos == []
    assert monitor.baseline_scan_id == monitor.last_scan_id != base
    assert monitor.last_notified_at is None


async def test_un_aviso_no_entregado_se_repite_en_la_siguiente_ejecucion(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Si la línea base avanzara con el aviso perdido, la siguiente ejecución
    compararía contra un escaneo que ya tiene el cambio y no saldría nunca."""
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    webhook.falla = True

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert monitor.baseline_scan_id == base
    assert monitor.last_error is not None and "HTTP 503" in monitor.last_error
    assert monitor.last_notified_at is None

    webhook.falla = False
    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    [(evento, payload)] = webhook.avisos
    assert evento == "cambios"
    assert payload["previous_scan_id"] == base
    assert payload["nuevos"] == ["api.ejemplo.com"]
    assert monitor.baseline_scan_id == monitor.last_scan_id
    assert monitor.last_error is None


async def test_un_escaneo_fallido_se_avisa_y_no_mueve_la_linea_base(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """En vigilancia, el peor fallo es el silencioso."""
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.falla = RuntimeError("fallo con https://api.shodan.io/?key=CLAVE-SECRETA")

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    [(evento, payload)] = webhook.avisos
    assert evento == "escaneo_fallido"
    assert payload["scan_id"] == monitor.last_scan_id
    assert "RuntimeError" in payload["reason"]
    assert "CLAVE-SECRETA" not in str(payload)  # `run_scan` solo guarda el tipo
    assert monitor.baseline_scan_id == base
    assert monitor.last_error == payload["reason"]


async def test_cero_subdominios_frente_a_una_base_con_activos_no_es_una_desaparicion(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """crt.sh caído deja un escaneo «completado» sin subdominios. Compararlo
    daría todo el dominio por desaparecido: una falsa alarma."""
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = []
    descubrimiento.errors = ["crt.sh no disponible tras 3 intentos: ReadTimeout"]

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    [(evento, payload)] = webhook.avisos
    assert evento == "escaneo_fallido"
    assert "fuente de subdominios" in payload["reason"]
    assert payload["errors"] == ["crt.sh no disponible tras 3 intentos: ReadTimeout"]
    assert monitor.baseline_scan_id == base


async def test_las_incidencias_no_bloquean_un_aviso_de_cambios(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Con clave de Shodan, su 403 sale en todo escaneo: no puede silenciar los avisos."""
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    descubrimiento.errors = ["Shodan rechazó la petición (HTTP 403)"]

    await run_monitor(factory, monitor_id)

    [(evento, payload)] = webhook.avisos
    assert evento == "cambios"
    assert payload["errors"] == ["Shodan rechazó la petición (HTTP 403)"]


async def test_un_dominio_fuera_de_la_allowlist_no_se_escanea_y_se_avisa(
    factory: async_sessionmaker[AsyncSession],
    descubrimiento: _Descubrimiento,
    webhook: _Webhook,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La allowlist cambió después de crear el monitor: gana la de ahora."""
    monitor_id = await _monitor(factory)
    monkeypatch.setattr(settings, "scan_allowlist", "otro.com")

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert await _num_escaneos(factory) == 0
    [(evento, payload)] = webhook.avisos
    assert evento == "escaneo_fallido"
    assert payload["scan_id"] is None
    assert "SCAN_ALLOWLIST" in payload["reason"]
    assert monitor.last_run_at is not None
    assert monitor.last_error == payload["reason"]


async def test_un_fallo_inesperado_queda_en_last_error_y_no_se_propaga(
    factory: async_sessionmaker[AsyncSession],
    descubrimiento: _Descubrimiento,
    webhook: _Webhook,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitor_id = await _monitor(factory)

    async def explota(*args: object) -> None:
        raise ValueError("inesperado")

    monkeypatch.setattr(monitor_runner, "_compare_and_notify", explota)

    await run_monitor(factory, monitor_id)  # no lanza

    assert (await _leer(factory, monitor_id)).last_error == "error inesperado (ValueError)"


# --- La planificación -------------------------------------------------------


async def test_ejecuta_solo_los_activos_vencidos_y_programa_el_siguiente_desde_ahora(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    ahora = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
    # Vencido hace un día: se ejecuta una vez, no 24 para «ponerse al día».
    vencido = await _monitor(factory, domain="a.ejemplo.com", next_run_at=ahora - timedelta(days=1))
    futuro = await _monitor(factory, domain="b.ejemplo.com", next_run_at=ahora + timedelta(hours=1))
    pausado = await _monitor(
        factory, domain="c.ejemplo.com", next_run_at=ahora - timedelta(hours=1), active=False
    )

    assert await run_due_monitors(factory, now=ahora) == 1

    # La base de datos devuelve UTC sin zona (`UtcDateTime`).
    siguiente = (ahora + timedelta(days=1)).replace(tzinfo=None)
    assert (await _leer(factory, vencido)).next_run_at == siguiente
    assert (await _leer(factory, vencido)).last_scan_id is not None
    assert (await _leer(factory, futuro)).last_run_at is None
    assert (await _leer(factory, pausado)).last_run_at is None
    assert await run_due_monitors(factory, now=ahora) == 0


async def test_dos_revisiones_simultaneas_ejecutan_el_monitor_una_sola_vez(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Como dos procesos de la API: el `UPDATE` condicional solo lo gana uno."""
    ahora = datetime.now(UTC)
    await _monitor(factory, next_run_at=ahora - timedelta(minutes=1))

    ejecutados = await asyncio.gather(
        run_due_monitors(factory, now=ahora), run_due_monitors(factory, now=ahora)
    )

    assert sorted(ejecutados) == [0, 1]
    assert await _num_escaneos(factory) == 1


async def test_el_bucle_sobrevive_a_un_fallo_de_una_vuelta(
    factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """La base de datos caída o sin migrar no detiene la vigilancia."""
    vueltas = 0
    segunda = asyncio.Event()

    async def fake_run_due(session_factory: object) -> int:
        nonlocal vueltas
        vueltas += 1
        if vueltas == 1:
            raise OSError("base de datos caída")
        segunda.set()
        return 0

    monkeypatch.setattr(monitor_runner, "run_due_monitors", fake_run_due)
    bucle = asyncio.create_task(monitor_loop(factory, tick_seconds=0))
    try:
        await asyncio.wait_for(segunda.wait(), timeout=5)
    finally:
        bucle.cancel()
        with pytest.raises(asyncio.CancelledError):
            await bucle
    assert vueltas >= 2


def test_el_lifespan_lanza_la_vigilancia_y_la_cancela_al_parar(
    factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from atalaya.api import main

    eventos: list[str] = []

    async def fake_loop(session_factory: object) -> None:
        eventos.append("lanzado")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            eventos.append("cancelado")
            raise

    monkeypatch.setattr(main, "monitor_loop", fake_loop)
    monkeypatch.setattr(main, "SessionLocal", factory)

    with TestClient(main.app) as api:
        assert api.get("/health").status_code == 200
        assert eventos == ["lanzado"]
    assert eventos == ["lanzado", "cancelado"]


# --- La API -----------------------------------------------------------------


def test_crear_un_monitor_no_devuelve_ni_la_url_completa_ni_el_secreto(
    client: TestClient, dns: dict[str, list[str]]
) -> None:
    resp = client.post(
        "/monitors", json={"domain": "Ejemplo.com.", "webhook_url": URL, "secret": SECRETO}
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["domain"] == "ejemplo.com"
    assert body["webhook"] == "https://hooks.ejemplo.com/…"
    assert body["signed"] is True
    assert body["interval_hours"] == 24
    assert body["active"] is True
    assert body["baseline_scan_id"] is None
    assert body["next_run_at"] and body["last_run_at"] is None
    assert TOKEN not in resp.text and SECRETO not in resp.text
    assert TOKEN not in client.get("/monitors").text
    assert client.get(f"/monitors/{body['id']}").json() == body


def test_la_linea_base_inicial_es_el_ultimo_escaneo_completado_del_dominio(
    client: TestClient, dns: dict[str, list[str]], descubrimiento: _Descubrimiento
) -> None:
    scan_id = client.post("/scans?wait=true", json={"domain": "ejemplo.com"}).json()["id"]

    resp = client.post("/monitors", json={"domain": "ejemplo.com", "webhook_url": URL})

    assert resp.json()["baseline_scan_id"] == scan_id
    assert resp.json()["signed"] is False


@pytest.mark.parametrize(
    ("webhook_url", "direccion"),
    [
        (URL, "127.0.0.1"),
        (URL, "169.254.169.254"),
        (f"http://hooks.ejemplo.com/services/{TOKEN}", "93.184.216.34"),
    ],
    ids=["loopback", "metadatos", "http"],
)
def test_un_webhook_inseguro_da_400_y_no_crea_el_monitor(
    client: TestClient, dns: dict[str, list[str]], webhook_url: str, direccion: str
) -> None:
    dns["hooks.ejemplo.com"] = [direccion]

    resp = client.post("/monitors", json={"domain": "ejemplo.com", "webhook_url": webhook_url})

    assert resp.status_code == 400
    assert client.get("/monitors").json() == []


def test_un_dominio_no_autorizado_da_403_y_no_crea_el_monitor(
    client: TestClient, dns: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "scan_allowlist", "ejemplo.com")

    resp = client.post("/monitors", json={"domain": "ajeno.com", "webhook_url": URL})

    assert resp.status_code == 403
    assert client.get("/monitors").json() == []


def test_un_dominio_ya_vigilado_da_409(client: TestClient, dns: dict[str, list[str]]) -> None:
    primero = client.post("/monitors", json={"domain": "ejemplo.com", "webhook_url": URL})
    assert primero.status_code == 201

    resp = client.post("/monitors", json={"domain": "EJEMPLO.COM", "webhook_url": URL})

    assert resp.status_code == 409
    assert len(client.get("/monitors").json()) == 1


@pytest.mark.parametrize(
    "extra",
    [{"interval_hours": 0}, {"interval_hours": 721}, {"secret": "corto"}],
    ids=["intervalo_0", "intervalo_721", "secreto_corto"],
)
def test_intervalo_o_secreto_fuera_de_rango_dan_422(
    client: TestClient, dns: dict[str, list[str]], extra: dict[str, Any]
) -> None:
    resp = client.post("/monitors", json={"domain": "ejemplo.com", "webhook_url": URL, **extra})

    assert resp.status_code == 422


def test_pausar_reanudar_y_borrar(client: TestClient, dns: dict[str, list[str]]) -> None:
    monitor_id = client.post(
        "/monitors", json={"domain": "ejemplo.com", "webhook_url": URL}
    ).json()["id"]

    assert client.patch(f"/monitors/{monitor_id}", json={"active": False}).json()["active"] is False
    assert client.get("/monitors").json()[0]["active"] is False
    assert client.patch(f"/monitors/{monitor_id}", json={"active": True}).json()["active"] is True

    assert client.delete(f"/monitors/{monitor_id}").status_code == 204
    assert client.get(f"/monitors/{monitor_id}").status_code == 404
    assert client.delete(f"/monitors/{monitor_id}").status_code == 404
    assert client.patch(f"/monitors/{monitor_id}", json={"active": False}).status_code == 404


def test_crear_y_borrar_quedan_en_la_auditoria_sin_el_token(
    client: TestClient, dns: dict[str, list[str]]
) -> None:
    mensajes: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            mensajes.append(record.getMessage())

    collector = _Collector()
    audit = logging.getLogger(AUDIT_LOGGER_NAME)
    audit.addHandler(collector)
    try:
        monitor_id = client.post(
            "/monitors", json={"domain": "ejemplo.com", "webhook_url": URL, "secret": SECRETO}
        ).json()["id"]
        client.delete(f"/monitors/{monitor_id}")
    finally:
        audit.removeHandler(collector)

    assert any("creado" in m and "https://hooks.ejemplo.com/…" in m for m in mensajes)
    assert any("borrado" in m for m in mensajes)
    assert all(TOKEN not in m and SECRETO not in m for m in mensajes)
