"""Pruebas de `core/repository.py`: consultas de lectura sobre escaneos,
activos y hallazgos ya persistidos.

Los datos se crean con `save_subdomain_scan` (ya probado en
`test_persistence.py`): esta suite prueba las consultas, no la escritura.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus
from atalaya.core.persistence import save_subdomain_scan
from atalaya.core.repository import (
    FindingRef,
    diff_scans,
    get_latest_scan,
    get_scan,
    list_assets,
    list_findings,
    list_scans,
)
from atalaya.discovery.models import (
    DiscoverySource,
    ResolutionStatus,
    SubdomainRecord,
    SubdomainScanResult,
)


def _result(domain: str = "ejemplo.com", hostnames: list[str] | None = None) -> SubdomainScanResult:
    hostnames = hostnames if hostnames is not None else ["www.ejemplo.com", "interno.ejemplo.com"]
    result = SubdomainScanResult(domain=domain)
    result.records = [
        SubdomainRecord(
            hostname=host,
            status=ResolutionStatus.ACTIVE if "interno" not in host else ResolutionStatus.UNROUTABLE,
            ip_addresses=["10.0.0.5"] if "interno" in host else ["140.82.121.3"],
            sources=[DiscoverySource.CRTSH],
        )
        for host in hostnames
    ]
    result.finished_at = datetime.now(UTC)
    return result


async def test_get_scan_devuelve_none_si_no_existe(db_session: AsyncSession) -> None:
    assert await get_scan(db_session, 999) is None


async def test_get_scan_precarga_assets_y_findings(db_session: AsyncSession) -> None:
    saved = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    scan = await get_scan(db_session, saved.id)

    assert scan is not None
    assert {a.hostname for a in scan.assets} == {"www.ejemplo.com", "interno.ejemplo.com"}
    interno = next(a for a in scan.assets if a.hostname == "interno.ejemplo.com")
    assert len(interno.findings) == 1


async def test_list_scans_ordena_por_mas_reciente_y_filtra_por_dominio(
    db_session: AsyncSession,
) -> None:
    primero = await save_subdomain_scan(db_session, _result(domain="uno.com"))
    await db_session.commit()
    segundo = await save_subdomain_scan(db_session, _result(domain="dos.com"))
    await db_session.commit()

    todos = await list_scans(db_session)
    assert [s.id for s in todos] == [segundo.id, primero.id]

    solo_uno = await list_scans(db_session, domain="uno.com")
    assert [s.id for s in solo_uno] == [primero.id]


async def test_get_latest_scan_ignora_escaneos_no_completados(db_session: AsyncSession) -> None:
    sin_terminar = SubdomainScanResult(domain="ejemplo.com")
    sin_terminar.records = [
        SubdomainRecord(hostname="a.ejemplo.com", status=ResolutionStatus.ACTIVE, ip_addresses=["1.2.3.4"])
    ]
    # finished_at no establecido -> Scan queda en RUNNING.
    await save_subdomain_scan(db_session, sin_terminar)
    await db_session.commit()

    assert await get_latest_scan(db_session, "ejemplo.com") is None

    completo = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    latest = await get_latest_scan(db_session, "ejemplo.com")
    assert latest is not None
    assert latest.id == completo.id
    assert latest.status is ScanStatus.COMPLETED


async def test_list_assets_filtra_por_scan(db_session: AsyncSession) -> None:
    uno = await save_subdomain_scan(db_session, _result(domain="uno.com"))
    await db_session.commit()
    await save_subdomain_scan(db_session, _result(domain="dos.com"))
    await db_session.commit()

    assets = await list_assets(db_session, scan_id=uno.id)
    assert {a.hostname for a in assets} == {"www.ejemplo.com", "interno.ejemplo.com"}


async def test_list_findings_filtra_por_asset_y_por_scan(db_session: AsyncSession) -> None:
    scan = await save_subdomain_scan(db_session, _result())
    await db_session.commit()

    interno = next(a for a in scan.assets if a.hostname == "interno.ejemplo.com")

    por_asset = await list_findings(db_session, asset_id=interno.id)
    assert len(por_asset) == 1

    por_scan = await list_findings(db_session, scan_id=scan.id)
    assert len(por_scan) == 1

    sin_filtro = await list_findings(db_session)
    assert len(sin_filtro) == 1


async def test_diff_scans_detecta_nuevos_y_desaparecidos(db_session: AsyncSession) -> None:
    anterior = await save_subdomain_scan(
        db_session, _result(hostnames=["a.ejemplo.com", "b.ejemplo.com"])
    )
    await db_session.commit()
    actual = await save_subdomain_scan(
        db_session, _result(hostnames=["b.ejemplo.com", "c.ejemplo.com"])
    )
    await db_session.commit()

    anterior_cargado = await get_scan(db_session, anterior.id)
    actual_cargado = await get_scan(db_session, actual.id)
    assert anterior_cargado is not None
    assert actual_cargado is not None

    diff = diff_scans(anterior_cargado, actual_cargado)

    assert diff.nuevos == ["c.ejemplo.com"]
    assert diff.desaparecidos == ["a.ejemplo.com"]
    assert diff.comunes == ["b.ejemplo.com"]


# ─── diff_scans: cambios en los activos comunes ─────────────────────────────
#
# Puro cálculo sobre objetos ORM en memoria, sin sesión: es lo que promete
# el docstring de `diff_scans`.


def _activo(
    hostname: str,
    *,
    status: str = "active",
    ips: list[str] | None = None,
    puertos: list[int] | None = None,
    hallazgos: list[tuple[str, str, FindingSeverity]] | None = None,
) -> Asset:
    asset = Asset(
        hostname=hostname,
        status=status,
        ip_addresses=ips or ["140.82.121.3"],
        sources=["crt.sh"],
        is_active=status == "active",
        leaks_internal_addressing=False,
        open_ports=puertos or [],
    )
    for finding_type, evidence, severity in hallazgos or []:
        asset.findings.append(
            Finding(finding_type=finding_type, evidence=evidence, severity=severity)
        )
    return asset


def _escaneo(*assets: Asset) -> Scan:
    scan = Scan(domain="ejemplo.com", status=ScanStatus.COMPLETED, errors=[])
    scan.assets.extend(assets)
    return scan


def test_diff_scans_detecta_puertos_nuevos_y_desaparecidos_en_un_activo_comun() -> None:
    diff = diff_scans(
        _escaneo(_activo("www.ejemplo.com", puertos=[80, 443, 8080])),
        _escaneo(_activo("www.ejemplo.com", puertos=[22, 80, 443])),
    )

    assert diff.comunes == ["www.ejemplo.com"]
    [cambio] = diff.cambiados
    assert cambio.puertos_nuevos == [22]
    assert cambio.puertos_desaparecidos == [8080]
    assert cambio.hallazgos_nuevos == cambio.hallazgos_desaparecidos == []


def test_diff_scans_hallazgos_con_la_severidad_del_escaneo_donde_estan() -> None:
    """Un hallazgo nuevo lleva la severidad del actual; uno desaparecido, la
    que tenía en el previo (lo grave que era, no lo que hay ahora)."""
    previo = _activo(
        "www.ejemplo.com", hallazgos=[("csp_missing", "sin CSP", FindingSeverity.MEDIUM)]
    )
    actual = _activo(
        "www.ejemplo.com", hallazgos=[("hsts_missing", "sin HSTS", FindingSeverity.UNKNOWN)]
    )

    [cambio] = diff_scans(_escaneo(previo), _escaneo(actual)).cambiados

    assert cambio.hallazgos_nuevos == [FindingRef("hsts_missing", "unknown")]
    assert cambio.hallazgos_desaparecidos == [FindingRef("csp_missing", "medium")]


def test_diff_scans_compara_hallazgos_por_tipo_no_por_evidencia() -> None:
    """La evidencia cambia sin que cambie el problema (días hasta la
    caducidad): si contara, todo certificado saldría «cambiado» cada semana."""
    previo = _activo(
        "vpn.ejemplo.com",
        hallazgos=[("certificado_proximo_a_caducar", "caduca en 27 días", FindingSeverity.LOW)],
    )
    actual = _activo(
        "vpn.ejemplo.com",
        hallazgos=[("certificado_proximo_a_caducar", "caduca en 20 días", FindingSeverity.LOW)],
    )

    diff = diff_scans(_escaneo(previo), _escaneo(actual))

    assert diff.comunes == ["vpn.ejemplo.com"]
    assert diff.cambiados == []


def test_diff_scans_ignora_el_cambio_de_ip() -> None:
    """Con CDN y balanceo la IP varía entre escaneos sin cambiar la exposición."""
    diff = diff_scans(
        _escaneo(_activo("www.ejemplo.com", ips=["140.82.121.3"])),
        _escaneo(_activo("www.ejemplo.com", ips=["140.82.121.4"])),
    )

    assert diff.cambiados == []


def test_diff_scans_detecta_el_cambio_de_estado() -> None:
    """Un activo que deja de resolver es justo donde vive la señal de takeover."""
    diff = diff_scans(
        _escaneo(_activo("blog.ejemplo.com", puertos=[443])),
        _escaneo(_activo("blog.ejemplo.com", status="nxdomain")),
    )

    [cambio] = diff.cambiados
    assert (cambio.estado_anterior, cambio.estado_actual) == ("active", "nxdomain")
    assert cambio.puertos_desaparecidos == [443]


def test_diff_scans_cambiados_solo_contiene_comunes_y_en_orden() -> None:
    """Un activo nuevo o desaparecido no se repite en `cambiados`, y los
    cambiados salen ordenados por hostname, como el resto de listas."""
    diff = diff_scans(
        _escaneo(
            _activo("z.ejemplo.com", puertos=[80]),
            _activo("a.ejemplo.com", puertos=[80]),
            _activo("viejo.ejemplo.com", puertos=[22]),
        ),
        _escaneo(
            _activo("a.ejemplo.com", puertos=[80, 443]),
            _activo("z.ejemplo.com", puertos=[443]),
            _activo("nuevo.ejemplo.com", puertos=[22]),
        ),
    )

    assert diff.nuevos == ["nuevo.ejemplo.com"]
    assert diff.desaparecidos == ["viejo.ejemplo.com"]
    assert [c.hostname for c in diff.cambiados] == ["a.ejemplo.com", "z.ejemplo.com"]
