"""Pruebas de `discovery/takeover.py`: detección de riesgo de subdomain
takeover por patrón de CNAME.

Mismo criterio de determinismo que `test_subdomains.py`: ninguna prueba toca
DNS real. El resolver se sustituye por un doble que implementa
`resolve(hostname, record_type)`, igual patrón que
`test_resolucion_no_enrutable_cambia_el_estado` en `test_subdomains.py`.
"""

from __future__ import annotations

import dns.exception
import dns.resolver
import pytest

from atalaya.discovery.models import DiscoverySource, ResolutionStatus, SubdomainRecord
from atalaya.discovery.takeover import (
    TAKEOVER_PATTERNS,
    find_takeover_candidates,
    match_takeover_pattern,
)

# ─── Tabla de patrones ────────────────────────────────────────────────────


def test_tabla_de_patrones_tiene_al_menos_veinte_entradas() -> None:
    assert len(TAKEOVER_PATTERNS) >= 15


# ─── match_takeover_pattern ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("cname", "proveedor_esperado", "sufijo_esperado"),
    [
        ("miapp.github.io", "GitHub Pages", "github.io"),
        ("MIAPP.GITHUB.IO.", "GitHub Pages", "github.io"),  # mayúsculas + punto final
        ("miapp.herokuapp.com", "Heroku", "herokuapp.com"),
        ("bucket.s3.amazonaws.com", "AWS S3", "s3.amazonaws.com"),
        ("miapp.azurewebsites.net", "Azure App Service", "azurewebsites.net"),
        ("cuenta.blob.core.windows.net", "Azure Blob Storage", "blob.core.windows.net"),
    ],
)
def test_match_takeover_pattern_reconoce_proveedores(
    cname: str, proveedor_esperado: str, sufijo_esperado: str
) -> None:
    resultado = match_takeover_pattern(cname)
    assert resultado == (proveedor_esperado, sufijo_esperado)


def test_match_takeover_pattern_no_reconoce_cname_ajeno() -> None:
    assert match_takeover_pattern("interno.ejemplo.com") is None


def test_match_takeover_pattern_no_se_deja_enganar_por_sufijo_falso() -> None:
    """'evil-github.io.attacker.net' no es GitHub Pages: mismo criterio de
    comparación por punto separador que `normalize_hostname`."""
    assert match_takeover_pattern("github.io.attacker.net") is None
    assert match_takeover_pattern("notgithub.io") is None


def test_match_takeover_pattern_vacio() -> None:
    assert match_takeover_pattern("") is None


# ─── find_takeover_candidates ─────────────────────────────────────────────


class _FakeResolver:
    """Doble mínimo de `dns.asyncresolver.Resolver`: mapea hostname -> CNAME
    o excepción, sin tocar la red."""

    def __init__(self, cnames: dict[str, str | Exception]) -> None:
        self._cnames = cnames

    async def resolve(self, hostname: str, record_type: str):
        assert record_type == "CNAME"
        valor = self._cnames.get(hostname)
        if valor is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(valor, Exception):
            raise valor
        return [valor]


def _record(hostname: str, status: ResolutionStatus, **kwargs) -> SubdomainRecord:
    return SubdomainRecord(
        hostname=hostname, status=status, sources=[DiscoverySource.CRTSH], **kwargs
    )


@pytest.mark.asyncio
async def test_host_no_answer_con_cname_conocido_genera_candidato(monkeypatch) -> None:
    resolver = _FakeResolver({"old.ejemplo.com": "old.ejemplo.com.github.io."})
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [_record("old.ejemplo.com", ResolutionStatus.NO_ANSWER)]
    candidatos = await find_takeover_candidates(records)

    assert len(candidatos) == 1
    candidato = candidatos[0]
    assert candidato.hostname == "old.ejemplo.com"
    assert candidato.cname == "old.ejemplo.com.github.io"
    assert candidato.provider == "GitHub Pages"
    assert candidato.pattern_matched == "github.io"


@pytest.mark.asyncio
async def test_host_nxdomain_con_cname_conocido_genera_candidato(monkeypatch) -> None:
    resolver = _FakeResolver({"legacy.ejemplo.com": "legacy.ejemplo.com.herokuapp.com."})
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [_record("legacy.ejemplo.com", ResolutionStatus.NXDOMAIN)]
    candidatos = await find_takeover_candidates(records)

    assert len(candidatos) == 1
    assert candidatos[0].provider == "Heroku"


@pytest.mark.asyncio
async def test_host_unroutable_con_cname_conocido_genera_candidato(monkeypatch) -> None:
    resolver = _FakeResolver({"stale.ejemplo.com": "stale.ejemplo.com.s3.amazonaws.com."})
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [
        _record(
            "stale.ejemplo.com", ResolutionStatus.UNROUTABLE, ip_addresses=["0.0.0.0"]
        )
    ]
    candidatos = await find_takeover_candidates(records)

    assert len(candidatos) == 1
    assert candidatos[0].provider == "AWS S3"


@pytest.mark.asyncio
async def test_host_active_no_genera_candidato_aunque_tenga_cname(monkeypatch) -> None:
    """Un host activo (con IP real) no es candidato -- ni siquiera se
    resuelve su CNAME: `find_takeover_candidates` lo filtra antes de tocar
    el resolver."""

    def _resolver_que_no_debe_llamarse():
        raise AssertionError("no debería construirse un resolver para hosts activos")

    monkeypatch.setattr(
        "atalaya.discovery.takeover.build_resolver", _resolver_que_no_debe_llamarse
    )

    records = [
        _record("www.ejemplo.com", ResolutionStatus.ACTIVE, ip_addresses=["93.184.216.34"])
    ]
    candidatos = await find_takeover_candidates(records)

    assert candidatos == []


@pytest.mark.asyncio
async def test_host_sin_cname_no_genera_candidato(monkeypatch) -> None:
    resolver = _FakeResolver({})  # NXDOMAIN al resolver el propio CNAME
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [_record("huerfano.ejemplo.com", ResolutionStatus.NO_ANSWER)]
    candidatos = await find_takeover_candidates(records)

    assert candidatos == []


@pytest.mark.asyncio
async def test_host_con_cname_desconocido_no_genera_candidato(monkeypatch) -> None:
    """El CNAME resuelve, pero no coincide con ningún proveedor de la tabla:
    no es un falso positivo, simplemente no está en la lista (deliberadamente
    no exhaustiva)."""
    resolver = _FakeResolver({"interno.ejemplo.com": "interno.ejemplo.com.otrodominio.net."})
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [_record("interno.ejemplo.com", ResolutionStatus.NO_ANSWER)]
    candidatos = await find_takeover_candidates(records)

    assert candidatos == []


@pytest.mark.asyncio
async def test_fallo_de_resolucion_no_aborta_el_resto(monkeypatch) -> None:
    """Degradación controlada: un host cuya resolución de CNAME falla no
    impide detectar los demás candidatos."""
    resolver = _FakeResolver(
        {
            "falla.ejemplo.com": dns.exception.Timeout(),
            "ok.ejemplo.com": "ok.ejemplo.com.github.io.",
        }
    )
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [
        _record("falla.ejemplo.com", ResolutionStatus.NO_ANSWER),
        _record("ok.ejemplo.com", ResolutionStatus.NO_ANSWER),
    ]
    candidatos = await find_takeover_candidates(records)

    assert len(candidatos) == 1
    assert candidatos[0].hostname == "ok.ejemplo.com"


@pytest.mark.asyncio
async def test_fallo_inesperado_del_resolver_no_lanza_excepcion(monkeypatch) -> None:
    resolver = _FakeResolver({"raro.ejemplo.com": RuntimeError("fallo inesperado")})
    monkeypatch.setattr("atalaya.discovery.takeover.build_resolver", lambda: resolver)

    records = [_record("raro.ejemplo.com", ResolutionStatus.NO_ANSWER)]
    # No debe lanzar, aunque el resolver falle de una forma no anticipada.
    candidatos = await find_takeover_candidates(records)

    assert candidatos == []


@pytest.mark.asyncio
async def test_lista_vacia_no_construye_resolver(monkeypatch) -> None:
    def _resolver_que_no_debe_llamarse():
        raise AssertionError("no debería construirse un resolver sin candidatos")

    monkeypatch.setattr(
        "atalaya.discovery.takeover.build_resolver", _resolver_que_no_debe_llamarse
    )

    assert await find_takeover_candidates([]) == []


@pytest.mark.asyncio
async def test_ningun_candidato_no_construye_resolver(monkeypatch) -> None:
    """Solo hosts activos: no hay nada que resolver, y no debe construirse
    ni siquiera el resolver."""

    def _resolver_que_no_debe_llamarse():
        raise AssertionError("no debería construirse un resolver sin candidatos")

    monkeypatch.setattr(
        "atalaya.discovery.takeover.build_resolver", _resolver_que_no_debe_llamarse
    )

    records = [
        _record("www.ejemplo.com", ResolutionStatus.ACTIVE, ip_addresses=["93.184.216.34"])
    ]
    assert await find_takeover_candidates(records) == []


def test_no_hace_peticion_http_al_recurso_de_terceros() -> None:
    """Verificación estática de la restricción de seguridad #6: el módulo no
    importa `httpx` ni ninguna librería de peticiones HTTP -- solo DNS."""
    import atalaya.discovery.takeover as mod

    with open(mod.__file__, encoding="utf-8") as archivo:
        codigo_fuente = archivo.read()
    assert "httpx" not in codigo_fuente
    assert "requests" not in codigo_fuente
