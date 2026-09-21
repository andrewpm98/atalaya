"""Pruebas de `discovery/ports.py`: escaneo asíncrono de puertos TCP.

Sin red: `asyncio.open_connection` se sustituye por un doble que decide
puerto abierto/cerrado/con retardo según una tabla — mismo criterio de
determinismo que el resto del proyecto (`httpx.MockTransport` para HTTP,
resolver doble para DNS en `test_subdomains.py`).
"""

from __future__ import annotations

import asyncio

from atalaya.discovery.ports import COMMON_PORTS, scan_ports


class _FakeWriter:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _fake_open_connection(open_ports: set[int], *, delay_ports: set[int] | None = None):
    """Doble de `asyncio.open_connection`: abre si el puerto está en
    *open_ports*, tarda más que cualquier timeout de prueba si está en
    *delay_ports*, y rechaza la conexión en cualquier otro caso."""
    delay_ports = delay_ports or set()

    async def _open(host: str, port: int):
        if port in delay_ports:
            await asyncio.sleep(10)
        if port in open_ports:
            return object(), _FakeWriter()
        raise ConnectionRefusedError(f"puerto {port} cerrado")

    return _open


async def test_scan_ports_devuelve_solo_los_abiertos_y_ordenados(monkeypatch) -> None:
    monkeypatch.setattr(
        "atalaya.discovery.ports.asyncio.open_connection",
        _fake_open_connection({443, 22, 80}),
    )

    abiertos = await scan_ports("192.0.2.10", ports=[8080, 443, 22, 80])

    assert abiertos == [22, 80, 443]


async def test_scan_ports_ninguno_abierto_devuelve_lista_vacia(monkeypatch) -> None:
    monkeypatch.setattr(
        "atalaya.discovery.ports.asyncio.open_connection", _fake_open_connection(set())
    )

    assert await scan_ports("192.0.2.10", ports=[80, 443]) == []


async def test_scan_ports_timeout_no_cuenta_como_abierto(monkeypatch) -> None:
    monkeypatch.setattr(
        "atalaya.discovery.ports.asyncio.open_connection",
        _fake_open_connection(set(), delay_ports={9999}),
    )

    abiertos = await scan_ports("192.0.2.10", ports=[9999], timeout=0.05)

    assert abiertos == []


async def test_scan_ports_sin_lista_prueba_common_ports(monkeypatch) -> None:
    solicitados: list[int] = []

    async def _open(host: str, port: int):
        solicitados.append(port)
        raise ConnectionRefusedError

    monkeypatch.setattr("atalaya.discovery.ports.asyncio.open_connection", _open)

    await scan_ports("192.0.2.10")

    assert set(solicitados) == set(COMMON_PORTS)


async def test_scan_ports_respeta_la_concurrencia(monkeypatch) -> None:
    """No debe haber más conexiones simultáneas en vuelo que `concurrency`."""
    en_vuelo = 0
    maximo_observado = 0

    async def _open(host: str, port: int):
        nonlocal en_vuelo, maximo_observado
        en_vuelo += 1
        maximo_observado = max(maximo_observado, en_vuelo)
        await asyncio.sleep(0.01)
        en_vuelo -= 1
        raise ConnectionRefusedError

    monkeypatch.setattr("atalaya.discovery.ports.asyncio.open_connection", _open)

    await scan_ports("192.0.2.10", ports=list(range(20)), concurrency=3)

    assert maximo_observado <= 3


async def test_scan_ports_un_puerto_con_error_no_aborta_el_resto(monkeypatch) -> None:
    async def _open(host: str, port: int):
        if port == 22:
            raise OSError("host unreachable")
        return object(), _FakeWriter()

    monkeypatch.setattr("atalaya.discovery.ports.asyncio.open_connection", _open)

    abiertos = await scan_ports("192.0.2.10", ports=[22, 80])

    assert abiertos == [80]
