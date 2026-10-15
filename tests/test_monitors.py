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

from atalaya.api.schemas import MonitorOut
from atalaya.config import settings
from atalaya.core import monitor_runner, repository
from atalaya.core.audit import AUDIT_LOGGER_NAME
from atalaya.core.database import Base
from atalaya.core.exceptions import WebhookDeliveryError
from atalaya.core.models import Monitor, Scan, ScanStatus
from atalaya.core.monitor_runner import monitor_loop, run_due_monitors, run_monitor
from atalaya.core.scan_runner import run_scan
from atalaya.discovery.models import (
    DiscoveryFinding,
    DiscoverySource,
    EnrichmentResult,
    HeaderScanResult,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)

TOKEN = "T000/B000/xoxb-secreto-del-webhook"
URL = f"https://hooks.ejemplo.com/services/{TOKEN}"
SECRETO = "secreto-compartido-de-prueba"


class _Descubrimiento:
    """Lo que encontrará el próximo escaneo, por fuente.

    Como la enumeración real (`discovery/subdomains.py`), el dominio raíz entra
    siempre, aunque no responda ninguna fuente, y DNS se añade a todo host que
    resuelve. Una versión anterior de este doble devolvía cero registros con
    la fuente caída, algo que la enumeración real no hace nunca: el guardia de
    falsas alarmas pasaba aquí y fallaba en la prueba real.
    """

    def __init__(self) -> None:
        self.hosts: list[str] = ["www.ejemplo.com"]  # los que aporta crt.sh
        self.shodan: list[str] = []  # los que aporta Shodan
        self.caidas: set[DiscoverySource] = set()
        self.errors: list[str] = []
        self.falla: Exception | None = None
        # Puertos abiertos en la IP que comparten todos los hosts, y tipos de
        # hallazgo de cabeceras por host: lo que cambia cuando hay un timeout.
        self.puertos: list[int] = []
        self.cabeceras: dict[str, list[str]] = {}


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
        fuentes: dict[str, set[DiscoverySource]] = {domain: set()}
        for fuente, hosts in ((DiscoverySource.CRTSH, estado.hosts),
                              (DiscoverySource.SHODAN, estado.shodan)):
            if fuente not in estado.caidas:
                for host in hosts:
                    fuentes.setdefault(host, set()).add(fuente)
        result = SubdomainScanResult(domain=domain)
        result.records = [
            SubdomainRecord(
                hostname=host,
                status=ResolutionStatus.ACTIVE,
                ip_addresses=["93.184.216.34"],
                sources=[*sorted(fuentes[host], key=lambda s: s.value), DiscoverySource.DNS],
            )
            for host in sorted(fuentes)
        ]
        result.errors = list(estado.errors)
        result.finished_at = datetime.now(UTC)
        return result

    async def fake_enrich(result: SubdomainScanResult) -> EnrichmentResult:
        return EnrichmentResult(
            ports_by_ip={"93.184.216.34": list(estado.puertos)},
            header_results=[
                HeaderScanResult(
                    hostname=host,
                    findings=[DiscoveryFinding(finding_type=t, evidence=t) for t in tipos],
                )
                for host, tipos in estado.cabeceras.items()
            ],
        )

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


async def test_un_cambio_se_avisa_cuando_lo_confirma_la_ejecucion_siguiente(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]

    await run_monitor(factory, monitor_id)

    # Visto una vez: por confirmar, sin aviso. La base pasa a este escaneo.
    monitor = await _leer(factory, monitor_id)
    primero = monitor.last_scan_id
    assert webhook.avisos == []
    assert len(monitor.pending_changes) == 1
    assert monitor.baseline_scan_id == primero != base
    assert monitor.last_notified_at is None

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    [(evento, payload)] = webhook.avisos
    assert evento == "cambios"
    assert payload["event"] == "cambios"
    assert payload["domain"] == "ejemplo.com"
    assert payload["monitor_id"] == monitor_id
    assert payload["previous_scan_id"] == primero
    assert payload["current_scan_id"] == monitor.last_scan_id
    assert payload["nuevos"] == ["api.ejemplo.com"]
    assert payload["desaparecidos"] == []
    assert payload["cambiados"] == []
    assert payload["por_confirmar"] == 0
    assert payload["descartados"] == 0
    assert "comunes" not in payload  # cientos de hostnames sin cambios en un dominio grande
    assert "1 activo nuevo, 0 desaparecidos y 0 con cambios" in payload["summary"]
    assert f"confirmados en los escaneos #{primero} y #{monitor.last_scan_id}" in (
        payload["summary"]
    )
    assert payload["sent_at"]
    assert monitor.baseline_scan_id == monitor.last_scan_id
    assert monitor.pending_changes == []
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
    """La base pasa al escaneo nuevo, pero el cambio confirmado y no entregado
    se queda pendiente con su valor anterior: si se absorbiera en la base, no
    saldría nunca."""
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    await run_monitor(factory, monitor_id)  # visto una vez
    webhook.falla = True

    await run_monitor(factory, monitor_id)  # confirmado, pero el receptor da 503

    monitor = await _leer(factory, monitor_id)
    assert monitor.baseline_scan_id == monitor.last_scan_id
    assert len(monitor.pending_changes) == 1
    assert monitor.last_error is not None and "HTTP 503" in monitor.last_error
    assert monitor.last_notified_at is None

    webhook.falla = False
    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    [(evento, payload)] = webhook.avisos
    assert evento == "cambios"
    assert payload["nuevos"] == ["api.ejemplo.com"]
    assert monitor.pending_changes == []
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


async def test_crt_sh_caido_no_se_avisa_como_desaparicion_de_sus_hosts(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """crt.sh caído deja un escaneo «completado» con solo el dominio raíz.
    Compararlo daría sus subdominios por desaparecidos: una falsa alarma."""
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.caidas = {DiscoverySource.CRTSH}
    descubrimiento.errors = ["crt.sh no disponible tras 3 intentos: ReadTimeout"]

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    async with factory() as session:
        actual = await repository.get_scan(session, monitor.last_scan_id)
    # Lo que se vio en la prueba real: no sale con 0 activos, sale con la raíz.
    assert actual is not None
    assert [a.hostname for a in actual.assets] == ["ejemplo.com"]
    [(evento, payload)] = webhook.avisos
    assert evento == "escaneo_fallido"
    assert "crt.sh no aportó ningún subdominio" in payload["reason"]
    assert f"(#{base}) aportó 2" in payload["reason"]
    assert payload["errors"] == ["crt.sh no disponible tras 3 intentos: ReadTimeout"]
    assert monitor.baseline_scan_id == base


async def test_crt_sh_caido_en_un_dominio_al_que_nunca_aporto_no_es_un_fallo(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Como scanme.nmap.org: crt.sh no le aporta nada ni cuando funciona, así
    que su caída no cambia el escaneo y no hay nada que avisar."""
    descubrimiento.hosts = []
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.caidas = {DiscoverySource.CRTSH}

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert webhook.avisos == []
    assert monitor.baseline_scan_id == monitor.last_scan_id != base


async def test_caida_parcial_de_una_fuente_con_la_otra_respondiendo(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Shodan cae y crt.sh responde: los hosts que solo daba Shodan no han
    desaparecido. Se nombra la fuente caída, no la otra."""
    descubrimiento.shodan = ["vpn.ejemplo.com"]
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.caidas = {DiscoverySource.SHODAN}

    await run_monitor(factory, monitor_id)

    [(evento, payload)] = webhook.avisos
    assert evento == "escaneo_fallido"
    assert "shodan no aportó ningún subdominio" in payload["reason"]
    assert "crt.sh" not in payload["reason"]
    assert (await _leer(factory, monitor_id)).baseline_scan_id == base


async def test_las_incidencias_no_bloquean_un_aviso_de_cambios(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Con clave de Shodan, su 403 sale en todo escaneo: no puede silenciar los avisos."""
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    descubrimiento.errors = ["Shodan rechazó la petición (HTTP 403)"]

    await run_monitor(factory, monitor_id)
    await run_monitor(factory, monitor_id)

    [(evento, payload)] = webhook.avisos
    assert evento == "cambios"
    assert payload["errors"] == ["Shodan rechazó la petición (HTTP 403)"]


# --- La confirmación: un cambio se avisa al verse en dos ejecuciones --------


async def test_un_timeout_que_no_se_repite_se_descarta_como_ruido(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Lo que hace un timeout de verdad: el 443 no contesta (desaparece en los
    dos hosts, que comparten IP) y, con HTTPS mudo y HTTP respondiendo,
    *aparece* un `sin_https` que no existe. Ninguno de los tres se avisa."""
    descubrimiento.puertos = [80, 443]
    descubrimiento.cabeceras = {"www.ejemplo.com": ["hsts_missing"]}
    base = await _escaneo(factory)
    monitor_id = await _monitor(factory, baseline=base)
    descubrimiento.puertos = [80]
    descubrimiento.cabeceras = {"www.ejemplo.com": ["hsts_missing", "sin_https"]}

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert webhook.avisos == []
    assert MonitorOut.from_monitor(monitor).pending_changes == 3

    descubrimiento.puertos = [80, 443]
    descubrimiento.cabeceras = {"www.ejemplo.com": ["hsts_missing"]}
    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert webhook.avisos == []
    assert monitor.pending_changes == []
    assert MonitorOut.from_monitor(monitor).last_discarded == 3
    assert monitor.last_error is None


@pytest.mark.parametrize(
    ("antes", "despues", "campo"),
    [
        (["www.ejemplo.com"], ["www.ejemplo.com", "api.ejemplo.com"], "nuevos"),
        (["www.ejemplo.com", "api.ejemplo.com"], ["www.ejemplo.com"], "desaparecidos"),
    ],
    ids=["aparece", "desaparece"],
)
async def test_se_confirma_en_las_dos_direcciones(
    factory: async_sessionmaker[AsyncSession],
    descubrimiento: _Descubrimiento,
    webhook: _Webhook,
    antes: list[str],
    despues: list[str],
    campo: str,
) -> None:
    """El ruido también hace aparecer cosas: desconfiar solo de lo que
    desaparece no basta, y lo real se avisa igual en los dos sentidos."""
    descubrimiento.hosts = antes
    monitor_id = await _monitor(factory, baseline=await _escaneo(factory))
    descubrimiento.hosts = despues

    await run_monitor(factory, monitor_id)
    assert webhook.avisos == []
    await run_monitor(factory, monitor_id)

    [(_, payload)] = webhook.avisos
    assert payload[campo] == ["api.ejemplo.com"]


async def test_cada_cambio_se_confirma_por_separado(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Un cambio nuevo no retrasa el aviso de otro ya confirmado: sale el
    confirmado, y el aviso dice que hay otro en camino."""
    monitor_id = await _monitor(factory, baseline=await _escaneo(factory))
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]
    await run_monitor(factory, monitor_id)
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com", "vpn.ejemplo.com"]

    await run_monitor(factory, monitor_id)

    [(_, payload)] = webhook.avisos
    assert payload["nuevos"] == ["api.ejemplo.com"]
    assert payload["por_confirmar"] == 1
    assert len((await _leer(factory, monitor_id)).pending_changes) == 1

    await run_monitor(factory, monitor_id)

    assert [p["nuevos"] for _, p in webhook.avisos] == [["api.ejemplo.com"], ["vpn.ejemplo.com"]]


async def test_la_confirmacion_se_adelanta_a_una_hora_solo_si_no_habia_pendientes(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Sin adelantarla, un monitor diario avisaría de cada cambio un día tarde.
    Adelantándola siempre, un dominio que fluctúa sin parar se escanearía cada
    hora: solo se adelanta al pasar de nada pendiente a algo pendiente."""
    base = await _escaneo(factory)
    ahora = datetime.now(UTC)
    monitor_id = await _monitor(factory, baseline=base, next_run_at=ahora - timedelta(minutes=1))
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com"]

    assert await run_due_monitors(factory, now=ahora) == 1

    confirmacion = (await _leer(factory, monitor_id)).next_run_at.replace(tzinfo=UTC)
    assert timedelta(minutes=59) < confirmacion - ahora < timedelta(minutes=61)

    # En la confirmación aparece otro cambio: ya había algo pendiente, así
    # que no se adelanta otra vez y vuelve al turno normal.
    descubrimiento.hosts = ["www.ejemplo.com", "api.ejemplo.com", "vpn.ejemplo.com"]
    assert await run_due_monitors(factory, now=confirmacion) == 1

    [(_, payload)] = webhook.avisos
    assert payload["nuevos"] == ["api.ejemplo.com"]
    siguiente = (await _leer(factory, monitor_id)).next_run_at.replace(tzinfo=UTC)
    assert siguiente == confirmacion + timedelta(hours=24)


async def test_una_fuente_caida_no_confirma_ni_descarta_lo_pendiente(
    factory: async_sessionmaker[AsyncSession], descubrimiento: _Descubrimiento, webhook: _Webhook
) -> None:
    """Una ejecución que no compara (crt.sh caído) no es una observación: lo
    pendiente espera a la siguiente que sí compare."""
    monitor_id = await _monitor(factory, baseline=await _escaneo(factory))
    descubrimiento.hosts = ["www.ejemplo.com", "vpn.ejemplo.com"]
    await run_monitor(factory, monitor_id)
    observado = (await _leer(factory, monitor_id)).baseline_scan_id
    descubrimiento.caidas = {DiscoverySource.CRTSH}

    await run_monitor(factory, monitor_id)

    monitor = await _leer(factory, monitor_id)
    assert [evento for evento, _ in webhook.avisos] == ["escaneo_fallido"]
    assert monitor.baseline_scan_id == observado
    assert len(monitor.pending_changes) == 1

    descubrimiento.caidas = set()
    await run_monitor(factory, monitor_id)

    assert webhook.avisos[-1][1]["nuevos"] == ["vpn.ejemplo.com"]


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
    assert body["pending_changes"] == 0 and body["last_discarded"] == 0
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
