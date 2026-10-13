"""Pruebas del escaneo en segundo plano (`POST /scans` → 202, `core/scan_runner.py`).

Con `TestClient`, las tareas en segundo plano terminan antes de que vuelva la
llamada: el 202 llega con el escaneo en `running` (la respuesta se construye
antes de lanzar la tarea) y un `GET` posterior ya lo ve terminado. Para ver
un escaneo que sigue en curso se sustituye `run_scan` en la ruta por una
función que no hace nada.

`run_scan` y `fail_interrupted_scans` se prueban también directamente, con su
propia base de datos en memoria: es como corren de verdad, con una sesión que
no es la de la petición.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from atalaya.config import settings
from atalaya.core.database import Base
from atalaya.core.exceptions import UnauthorizedTargetError
from atalaya.core.models import Scan, ScanStatus
from atalaya.core.scan_runner import INTERRUPTED_ERROR, fail_interrupted_scans, run_scan
from atalaya.discovery.models import (
    DiscoverySource,
    EnrichmentResult,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


def _fake_result(domain: str) -> SubdomainScanResult:
    result = SubdomainScanResult(domain=domain)
    result.records = [
        SubdomainRecord(
            hostname=f"www.{domain}",
            status=ResolutionStatus.ACTIVE,
            ip_addresses=["93.184.216.34"],
            sources=[DiscoverySource.CRTSH, DiscoverySource.DNS],
        )
    ]
    result.errors = ["crt.sh no disponible"]
    result.finished_at = datetime.now(UTC)
    return result


def _mock_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    async def fake_enrich(result: SubdomainScanResult) -> EnrichmentResult:
        return EnrichmentResult()

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", fake_enumerate)
    monkeypatch.setattr("atalaya.core.scan_runner.enrich_scan", fake_enrich)


def _scan_en_curso(monkeypatch: pytest.MonkeyPatch) -> None:
    """La ruta lanza una tarea que no hace nada: el escaneo se queda en `running`."""

    async def no_ejecutar(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr("atalaya.api.routes.scans.run_scan", no_ejecutar)


@pytest_asyncio.fixture
async def factory(tmp_path: Path) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """Base de datos en fichero, no en memoria: con `StaticPool` todas las
    sesiones comparten una conexión y cada una ve lo que la otra aún no ha
    confirmado, justo lo que hay que poder comprobar aquí."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'scans.sqlite3').as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


# --- La ruta ------------------------------------------------------------------


def test_responde_202_en_curso_y_el_escaneo_termina_en_segundo_plano(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_discovery(monkeypatch)

    resp = client.post("/scans", json={"domain": "ejemplo.com"})

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "running"
    assert body["assets"] == []
    assert body["finished_at"] is None
    assert resp.headers["location"] == f"/scans/{body['id']}"

    terminado = client.get(f"/scans/{body['id']}").json()
    assert terminado["status"] == "completed"
    assert terminado["finished_at"] is not None
    assert [a["hostname"] for a in terminado["assets"]] == ["www.ejemplo.com"]
    # La incidencia de la fuente caída se conserva: degradación, no fallo.
    assert terminado["errors"] == ["crt.sh no disponible"]


@pytest.mark.parametrize("ruta", ["/scans", "/scans?wait=true"])
def test_un_dominio_no_autorizado_da_403_sin_crear_el_escaneo(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, ruta: str
) -> None:
    """Al momento, y sin dejar un escaneo `failed` en la base de datos."""
    _mock_discovery(monkeypatch)
    monkeypatch.setattr(settings, "scan_allowlist", "ejemplo.com")

    resp = client.post(ruta, json={"domain": "ajeno.com"})

    assert resp.status_code == 403
    assert client.get("/scans").json() == []


def test_un_dominio_mal_formado_da_400_sin_crear_el_escaneo(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_discovery(monkeypatch)

    resp = client.post("/scans", json={"domain": "no es un dominio"})

    assert resp.status_code == 400
    assert client.get("/scans").json() == []


def test_un_fallo_deja_el_escaneo_fallido_con_el_motivo_y_sin_secretos(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El texto de una excepción inesperada puede llevar una URL con una clave
    (Shodan solo la acepta en la URL): a `errors` solo llega el tipo."""

    async def revienta(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        raise RuntimeError("GET https://api.shodan.io/dns?key=SECRETO-SHODAN")

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", revienta)

    scan_id = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]
    escaneo = client.get(f"/scans/{scan_id}").json()

    assert escaneo["status"] == "failed"
    assert escaneo["finished_at"] is not None
    assert escaneo["errors"] == ["el escaneo falló: error inesperado (RuntimeError)"]
    assert "SECRETO" not in str(escaneo)


def test_con_wait_un_fallo_tambien_se_devuelve_como_escaneo_fallido(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def revienta(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        raise RuntimeError("caída")

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", revienta)

    resp = client.post("/scans?wait=true", json={"domain": "ejemplo.com"})

    assert resp.status_code == 201
    assert resp.json()["status"] == "failed"


def test_si_la_allowlist_cambia_antes_de_ejecutar_gana_la_de_la_ejecucion(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run_scan` vuelve a autorizar (restricción #1): el motivo es el mensaje
    propio, pensado para el usuario."""

    async def ya_no_autorizado(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        raise UnauthorizedTargetError("'ejemplo.com' no está en SCAN_ALLOWLIST")

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", ya_no_autorizado)

    scan_id = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]

    assert client.get(f"/scans/{scan_id}").json()["errors"] == [
        "el escaneo falló: 'ejemplo.com' no está en SCAN_ALLOWLIST"
    ]


# --- Un escaneo en curso o fallido no se usa como si estuviera terminado -----


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/scans/{id}/triage"), ("GET", "/scans/{id}/report")],
    ids=["triaje", "informe"],
)
def test_triar_o_pedir_el_informe_de_un_escaneo_en_curso_da_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, method: str, path: str
) -> None:
    _scan_en_curso(monkeypatch)
    scan_id = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]

    resp = client.request(method, path.format(id=scan_id))

    assert resp.status_code == 409
    assert "en curso" in resp.json()["detail"]


def test_comparar_con_un_escaneo_en_curso_da_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sin activos todavía, todos los hostnames saldrían «desaparecidos»."""
    _mock_discovery(monkeypatch)
    terminado = client.post("/scans?wait=true", json={"domain": "ejemplo.com"}).json()["id"]
    _scan_en_curso(monkeypatch)
    en_curso = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]

    resp = client.get(f"/scans/{terminado}/diff/{en_curso}?analysis=false")

    assert resp.status_code == 409
    assert f"#{en_curso} está en curso" in resp.json()["detail"]


def test_comparar_con_un_escaneo_fallido_da_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_discovery(monkeypatch)
    terminado = client.post("/scans?wait=true", json={"domain": "ejemplo.com"}).json()["id"]

    async def revienta(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        raise RuntimeError("caída")

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", revienta)
    fallido = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]

    resp = client.get(f"/scans/{fallido}/diff/{terminado}?analysis=false")

    assert resp.status_code == 409
    assert f"#{fallido} está fallido" in resp.json()["detail"]


def test_preguntar_por_un_escaneo_en_curso_da_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scan_en_curso(monkeypatch)
    scan_id = client.post("/scans", json={"domain": "ejemplo.com"}).json()["id"]

    resp = client.post(
        "/findings/ask",
        json={"domain": "ejemplo.com", "question": "¿Qué arreglo primero?", "scan_id": scan_id},
    )

    assert resp.status_code == 409


# --- run_scan y fail_interrupted_scans, directamente --------------------------


async def _crear(factory: async_sessionmaker[AsyncSession], **campos: object) -> int:
    async with factory() as session:
        scan = Scan(domain="ejemplo.com", **campos)
        session.add(scan)
        await session.commit()
        return scan.id


async def test_mientras_corre_el_escaneo_no_se_ve_a_medias(
    factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Activos y hallazgos se guardan en una sola transacción al final: quien
    consulta durante el enriquecimiento (la fase larga) lo ve vacío y en curso."""
    scan_id = await _crear(factory, status=ScanStatus.RUNNING)
    vistos: list[tuple[ScanStatus, int]] = []

    async def fake_enumerate(domain: str, *, resolve: bool = True) -> SubdomainScanResult:
        return _fake_result(domain)

    async def fake_enrich(result: SubdomainScanResult) -> EnrichmentResult:
        from atalaya.core import repository

        async with factory() as otra:
            visto = await repository.get_scan(otra, scan_id)
            assert visto is not None
            vistos.append((visto.status, len(visto.assets)))
        return EnrichmentResult()

    monkeypatch.setattr("atalaya.core.scan_runner.enumerate_subdomains", fake_enumerate)
    monkeypatch.setattr("atalaya.core.scan_runner.enrich_scan", fake_enrich)

    await run_scan(factory, scan_id)

    assert vistos == [(ScanStatus.RUNNING, 0)]
    async with factory() as session:
        scan = await session.get(Scan, scan_id)
        assert scan is not None and scan.status is ScanStatus.COMPLETED


async def test_run_scan_de_un_escaneo_que_no_existe_no_falla(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await run_scan(factory, 999)


async def test_al_arrancar_se_cierran_los_escaneos_interrumpidos(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    en_curso = await _crear(factory, status=ScanStatus.RUNNING, errors=["previa"])
    terminado = await _crear(factory, status=ScanStatus.COMPLETED)

    async with factory() as session:
        assert await fail_interrupted_scans(session) == 1

    async with factory() as session:
        interrumpido = await session.get(Scan, en_curso)
        intacto = await session.get(Scan, terminado)
        assert interrumpido is not None and intacto is not None
        assert interrumpido.status is ScanStatus.FAILED
        assert interrumpido.finished_at is not None
        assert interrumpido.errors == ["previa", INTERRUPTED_ERROR]
        assert intacto.status is ScanStatus.COMPLETED
        assert intacto.errors == []


def test_la_api_cierra_los_interrumpidos_al_arrancar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """De extremo a extremo: el `lifespan` de la API, con su propia base de datos."""
    import asyncio

    from atalaya.api import main

    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'api.sqlite3').as_posix()}")
    fabrica = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def preparar() -> int:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return await _crear(fabrica, status=ScanStatus.RUNNING)

    async def leer(scan_id: int) -> Scan | None:
        async with fabrica() as session:
            return await session.get(Scan, scan_id)

    scan_id = asyncio.run(preparar())
    monkeypatch.setattr(main, "SessionLocal", fabrica)

    with TestClient(main.app) as api:
        assert api.get("/health").status_code == 200

    scan = asyncio.run(leer(scan_id))
    asyncio.run(engine.dispose())
    assert scan is not None and scan.status is ScanStatus.FAILED


def test_la_api_arranca_aunque_la_base_de_datos_no_este_lista(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sin migrar o caída: se registra y la API responde igual."""
    from atalaya.api import main

    def sin_base_de_datos() -> AsyncSession:
        raise ConnectionRefusedError("sin base de datos")

    monkeypatch.setattr(main, "SessionLocal", sin_base_de_datos)

    with TestClient(main.app) as api:
        assert api.get("/health").status_code == 200
