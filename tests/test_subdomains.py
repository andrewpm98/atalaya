"""Pruebas del módulo de enumeración de subdominios.

Todas las pruebas son deterministas: no dependen de crt.sh ni de DNS real.
Las fuentes externas se sustituyen por dobles, de modo que un fallo en la
suite indique siempre un problema en el código y nunca una caída de red.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from atalaya.core.authorization import ensure_authorized, is_authorized, normalize_domain
from atalaya.core.exceptions import InvalidTargetError, UnauthorizedTargetError
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)
from atalaya.discovery.subdomains import (
    enumerate_subdomains,
    fetch_crtsh,
    normalize_hostname,
    parse_crtsh_payload,
)

DOMAIN = "ejemplo.com"

#: Referencia al sleep original, para poder anularlo sin recursión.
_SLEEP_REAL = asyncio.sleep


def _sin_esperas(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anula el backoff entre reintentos para que las pruebas sean rápidas."""

    async def _noop(_seconds: float) -> None:
        await _SLEEP_REAL(0)

    monkeypatch.setattr("atalaya.discovery.subdomains.asyncio.sleep", _noop)


# ─── Normalización de hostnames ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "esperado"),
    [
        ("API.Ejemplo.com", "api.ejemplo.com"),      # mayúsculas
        ("api.ejemplo.com.", "api.ejemplo.com"),     # punto final
        ("  www.ejemplo.com  ", "www.ejemplo.com"),  # espacios
        ("*.ejemplo.com", "ejemplo.com"),            # comodín sobre la raíz
        ("*.api.ejemplo.com", "api.ejemplo.com"),    # comodín sobre subdominio
        ("ejemplo.com", "ejemplo.com"),              # dominio raíz
    ],
)
def test_normalize_hostname_valido(raw: str, esperado: str) -> None:
    assert normalize_hostname(raw, DOMAIN) == esperado


@pytest.mark.parametrize(
    "raw",
    [
        "",                        # vacío
        "   ",                     # solo espacios
        "otrodominio.com",         # fuera de alcance
        "ejemplo.com.evil.net",    # sufijo engañoso
        "admin@ejemplo.com",       # dirección de correo
        "*",                       # comodín sin host
        "host con espacios.ejemplo.com",
    ],
)
def test_normalize_hostname_descartado(raw: str) -> None:
    assert normalize_hostname(raw, DOMAIN) is None


# ─── Parseo de la respuesta de crt.sh ────────────────────────────────────


def test_parse_crtsh_extrae_san_multilinea() -> None:
    payload = [
        {"name_value": "www.ejemplo.com\napi.ejemplo.com", "common_name": "ejemplo.com"},
        {"name_value": "*.cdn.ejemplo.com"},
    ]
    assert parse_crtsh_payload(payload, DOMAIN) == {
        "www.ejemplo.com",
        "api.ejemplo.com",
        "ejemplo.com",
        "cdn.ejemplo.com",
    }


def test_parse_crtsh_elimina_duplicados() -> None:
    payload = [
        {"name_value": "www.ejemplo.com"},
        {"name_value": "WWW.ejemplo.com."},
        {"common_name": "www.ejemplo.com"},
    ]
    assert parse_crtsh_payload(payload, DOMAIN) == {"www.ejemplo.com"}


def test_parse_crtsh_ignora_entradas_malformadas() -> None:
    payload = [
        {"name_value": "www.ejemplo.com"},
        "esto no es un objeto",
        {"sin_campos_utiles": 1},
        {"name_value": None},
    ]
    assert parse_crtsh_payload(payload, DOMAIN) == {"www.ejemplo.com"}


# ─── Cliente HTTP contra crt.sh ──────────────────────────────────────────


def _client_con_respuesta(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_fetch_crtsh_ok() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=json.dumps([{"name_value": "api.ejemplo.com"}])
        )

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_crtsh(DOMAIN, client=client)

    assert hostnames == {"api.ejemplo.com"}
    assert errores == []


@pytest.mark.asyncio
async def test_fetch_crtsh_degrada_ante_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Si crt.sh falla, se reporta como incidencia sin abortar el escaneo."""
    _sin_esperas(monkeypatch)
    intentos = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        intentos["n"] += 1
        return httpx.Response(502)

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_crtsh(DOMAIN, client=client)

    assert hostnames == set()
    assert len(errores) == 1
    assert intentos["n"] > 1, "debe reintentar antes de rendirse"


@pytest.mark.asyncio
async def test_fetch_crtsh_json_invalido(monkeypatch: pytest.MonkeyPatch) -> None:
    _sin_esperas(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content="no soy json")

    async with _client_con_respuesta(handler) as client:
        hostnames, errores = await fetch_crtsh(DOMAIN, client=client)

    assert hostnames == set()
    assert errores


# ─── Orquestación completa ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enumerate_sin_resolucion() -> None:
    """Con resolve=False no se toca DNS y se devuelven los candidatos de CT."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=json.dumps([{"name_value": "www.ejemplo.com\napi.ejemplo.com"}]),
        )

    async with _client_con_respuesta(handler) as client:
        resultado = await enumerate_subdomains(DOMAIN, resolve=False, client=client)

    hostnames = {r.hostname for r in resultado.records}
    assert hostnames == {"ejemplo.com", "www.ejemplo.com", "api.ejemplo.com"}
    assert resultado.finished_at is not None
    assert resultado.duration_seconds is not None


@pytest.mark.asyncio
async def test_enumerate_incluye_siempre_el_dominio_raiz() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps([]))

    async with _client_con_respuesta(handler) as client:
        resultado = await enumerate_subdomains(DOMAIN, resolve=False, client=client)

    assert [r.hostname for r in resultado.records] == ["ejemplo.com"]


@pytest.mark.asyncio
async def test_enumerate_marca_activos(monkeypatch: pytest.MonkeyPatch) -> None:
    """Los hosts que resuelven quedan marcados como activos y con fuente DNS."""

    async def fake_resolve(hostname, resolver, sources, semaphore):
        activo = hostname == "www.ejemplo.com"
        return SubdomainRecord(
            hostname=hostname,
            status=ResolutionStatus.ACTIVE if activo else ResolutionStatus.NXDOMAIN,
            ip_addresses=["45.33.32.156"] if activo else [],
            sources=list(sources),
        )

    monkeypatch.setattr(
        "atalaya.discovery.subdomains.resolve_hostname", fake_resolve
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=json.dumps([{"name_value": "www.ejemplo.com\nold.ejemplo.com"}]),
        )

    async with _client_con_respuesta(handler) as client:
        resultado = await enumerate_subdomains(DOMAIN, client=client)

    assert resultado.total_discovered == 3
    assert resultado.total_active == 1
    activo = resultado.active_records[0]
    assert activo.hostname == "www.ejemplo.com"
    assert DiscoverySource.DNS in activo.sources
    assert resultado.scan_targets() == ["45.33.32.156"]


@pytest.mark.asyncio
async def test_enumerate_rechaza_dominio_invalido() -> None:
    with pytest.raises(InvalidTargetError):
        await enumerate_subdomains("no-es-un-dominio")


# ─── Salvaguarda de autorización ─────────────────────────────────────────


def test_allowlist_vacia_permite_todo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "")
    assert is_authorized("cualquier-dominio.com")


def test_allowlist_permite_dominio_y_subdominios(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")
    assert is_authorized("ejemplo.com")
    assert is_authorized("api.ejemplo.com")


def test_allowlist_bloquea_terceros(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")
    assert not is_authorized("otrodominio.com")
    with pytest.raises(UnauthorizedTargetError):
        ensure_authorized("otrodominio.com")


def test_allowlist_no_confunde_sufijos(monkeypatch: pytest.MonkeyPatch) -> None:
    """'ejemplo.com.evil.net' no debe considerarse parte de 'ejemplo.com'."""
    monkeypatch.setattr("atalaya.config.settings.scan_allowlist", "ejemplo.com")
    assert not is_authorized("ejemplo.com.evil.net")
    assert not is_authorized("noejemplo.com")


@pytest.mark.parametrize("valor", ["", "   ", "sinpunto", "-malo.com", "http://x.com"])
def test_normalize_domain_rechaza_invalidos(valor: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_domain(valor)


# ─── Modelos ─────────────────────────────────────────────────────────────


def test_modelo_calcula_resumen() -> None:
    resultado = SubdomainScanResult(
        domain=DOMAIN,
        records=[
            SubdomainRecord(
                hostname="a.ejemplo.com",
                status=ResolutionStatus.ACTIVE,
                ip_addresses=["45.33.32.156"],
            ),
            SubdomainRecord(
                hostname="b.ejemplo.com",
                status=ResolutionStatus.ACTIVE,
                ip_addresses=["45.33.32.156", "93.184.216.34"],
            ),
            SubdomainRecord(hostname="c.ejemplo.com", status=ResolutionStatus.NXDOMAIN),
        ],
    )
    assert resultado.total_discovered == 3
    assert resultado.total_active == 2
    assert resultado.unique_ips() == ["45.33.32.156", "93.184.216.34"]
    assert resultado.summary()["active"] == 2


def test_record_activo_requiere_ip() -> None:
    """Estado ACTIVE sin IPs no debe contar como activo."""
    record = SubdomainRecord(hostname="x.ejemplo.com", status=ResolutionStatus.ACTIVE)
    assert not record.is_active


def test_resultado_serializa_a_json() -> None:
    """El modelo debe serializar directamente para la API (Paso 4)."""
    resultado = SubdomainScanResult(
        domain=DOMAIN,
        records=[
            SubdomainRecord(
                hostname="a.ejemplo.com",
                status=ResolutionStatus.ACTIVE,
                ip_addresses=["45.33.32.156"],
                sources=[DiscoverySource.CRTSH, DiscoverySource.DNS],
            )
        ],
    )
    datos = json.loads(resultado.model_dump_json())
    assert datos["domain"] == DOMAIN
    assert datos["records"][0]["sources"] == ["crt.sh", "dns"]


# ─── Alcance de las direcciones resueltas ────────────────────────────────


def test_host_anulado_no_cuenta_como_activo() -> None:
    """Caso real: jobs.github.com resuelve a 0.0.0.0 tras su cierre."""
    record = SubdomainRecord(
        hostname="jobs.ejemplo.com",
        status=ResolutionStatus.UNROUTABLE,
        ip_addresses=["0.0.0.0"],
    )
    assert not record.is_active
    assert record.routable_ips == []
    assert record.non_routable_ips == ["0.0.0.0"]


def test_host_con_ip_privada_se_marca_como_fuga() -> None:
    """Un nombre público que resuelve a IP privada es un hallazgo."""
    record = SubdomainRecord(
        hostname="interno.ejemplo.com",
        status=ResolutionStatus.UNROUTABLE,
        ip_addresses=["10.20.30.40"],
    )
    assert not record.is_active
    assert record.leaks_internal_addressing


def test_host_publico_no_se_marca_como_fuga() -> None:
    record = SubdomainRecord(
        hostname="www.ejemplo.com",
        status=ResolutionStatus.ACTIVE,
        ip_addresses=["45.33.32.156"],
    )
    assert record.is_active
    assert not record.leaks_internal_addressing


def test_host_mixto_es_activo_y_fuga() -> None:
    """Con IP pública y privada: es alcanzable y además filtra direccionamiento."""
    record = SubdomainRecord(
        hostname="mixto.ejemplo.com",
        status=ResolutionStatus.ACTIVE,
        ip_addresses=["45.33.32.156", "192.168.1.10"],
    )
    assert record.is_active
    assert record.routable_ips == ["45.33.32.156"]
    assert record.leaks_internal_addressing


@pytest.mark.asyncio
async def test_resolucion_no_enrutable_cambia_el_estado(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si un host solo resuelve a 0.0.0.0, el estado pasa a UNROUTABLE."""
    import atalaya.discovery.subdomains as subs

    class FakeResolver:
        async def resolve(self, hostname: str, record_type: str):
            if record_type == "A":
                return ["0.0.0.0"]
            raise subs.dns.resolver.NoAnswer()

    record = await subs.resolve_hostname(
        "anulado.ejemplo.com",
        FakeResolver(),
        [DiscoverySource.CRTSH],
        asyncio.Semaphore(1),
    )
    assert record.status is ResolutionStatus.UNROUTABLE
    assert not record.is_active


def test_scan_targets_excluye_no_enrutables() -> None:
    """El escaneo de puertos solo debe recibir direcciones alcanzables."""
    resultado = SubdomainScanResult(
        domain=DOMAIN,
        records=[
            SubdomainRecord(
                hostname="a.ejemplo.com",
                status=ResolutionStatus.ACTIVE,
                ip_addresses=["45.33.32.156"],
            ),
            SubdomainRecord(
                hostname="b.ejemplo.com",
                status=ResolutionStatus.UNROUTABLE,
                ip_addresses=["0.0.0.0", "127.0.0.1", "10.0.0.5"],
            ),
        ],
    )
    assert resultado.scan_targets() == ["45.33.32.156"]
    assert len(resultado.unique_ips()) == 4  # unique_ips sí las conserva
    assert resultado.total_active == 1
    assert len(resultado.unroutable_records) == 1
    assert len(resultado.leaking_records) == 1
    assert resultado.summary()["scan_targets"] == 1
