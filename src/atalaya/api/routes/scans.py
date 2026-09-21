"""Router de escaneos: lanzar, consultar y triar escaneos de superficie de
exposición.

`create_scan` encadena las cuatro fases de descubrimiento sobre el mismo
escaneo: subdominios (Paso 2), puertos/cabeceras/TLS sobre los hosts activos
(`enrich_scan`, Paso 2 resto) y persistencia (Paso 3). `triage_scan`
(Paso 5) es la puerta de entrada REST al triaje por IA: sin ella,
`ai/triage.py` no sería alcanzable desde la API. `download_report`
(Paso 7) cumple el mismo papel para `reporting/generator.py`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.ai.provider import get_provider
from atalaya.ai.triage import triage_findings
from atalaya.api.schemas import ScanDetail, ScanRequest, ScanSummary, TriageResponse
from atalaya.core import repository
from atalaya.core.database import get_session
from atalaya.core.models import FindingSeverity, Scan
from atalaya.core.persistence import apply_discovery_findings, apply_port_scan, save_subdomain_scan
from atalaya.discovery.enrichment import enrich_scan
from atalaya.discovery.subdomains import enumerate_subdomains
from atalaya.reporting.generator import generate_report

router = APIRouter(prefix="/scans", tags=["escaneos"])


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ScanDetail)
async def create_scan(
    payload: ScanRequest, session: AsyncSession = Depends(get_session)
) -> Scan:
    """Lanza un escaneo completo sobre `payload.domain` y lo persiste.

    `enumerate_subdomains` valida y autoriza el dominio internamente (levanta
    `InvalidTargetError`/`UnauthorizedTargetError`, traducidas a HTTP por los
    manejadores de `api/main.py`): este endpoint no duplica esa comprobación.

    `enrich_scan` solo actúa sobre hosts activos (`result.active_records`):
    con `payload.resolve=False` esa lista está vacía y el enriquecimiento no
    hace ninguna llamada de red, sin necesidad de una rama explícita aquí.
    """
    result = await enumerate_subdomains(payload.domain, resolve=payload.resolve)
    scan = await save_subdomain_scan(session, result)

    enrichment = await enrich_scan(result)
    apply_port_scan(scan, enrichment.ports_by_ip)
    apply_discovery_findings(scan, enrichment.findings_by_hostname())

    await session.commit()
    # Se recarga con `selectinload`: `scan.assets` tiene todos los `Asset` (se
    # poblaron en memoria antes del flush), pero `asset.findings` solo está
    # cargado para los assets a los que `save_subdomain_scan` les añadió un
    # finding. Acceder a los demás dispararía un lazy-load fuera de contexto
    # async (`MissingGreenlet`) al serializar la respuesta.
    loaded = await repository.get_scan(session, scan.id)
    assert loaded is not None
    return loaded


@router.get("", response_model=list[ScanSummary])
async def list_scans(
    domain: str | None = Query(default=None, description="Filtra por dominio exacto"),
    session: AsyncSession = Depends(get_session),
) -> list[Scan]:
    """Lista los escaneos realizados, más recientes primero."""
    return await repository.list_scans(session, domain=domain)


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> Scan:
    """Devuelve el detalle de un escaneo, con sus activos y hallazgos."""
    scan = await repository.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {scan_id} no encontrado"
        )
    return scan


@router.post("/{scan_id}/triage", response_model=TriageResponse)
async def triage_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> TriageResponse:
    """Triaja con IA los hallazgos sin triar (`severity == unknown`) de un escaneo.

    No repite el triaje de hallazgos ya triados: es idempotente frente a
    llamadas repetidas y evita coste innecesario del proveedor de IA.
    """
    scan = await repository.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {scan_id} no encontrado"
        )

    pendientes = [
        finding
        for asset in scan.assets
        for finding in asset.findings
        if finding.severity is FindingSeverity.UNKNOWN
    ]
    if not pendientes:
        return TriageResponse(scan_id=scan.id, triaged=0, errors=[])

    provider = get_provider()
    result = await triage_findings(provider, pendientes)
    await session.commit()
    return TriageResponse(scan_id=scan.id, triaged=result.triaged, errors=result.errors)


@router.get("/{scan_id}/report")
async def download_report(
    scan_id: int, session: AsyncSession = Depends(get_session)
) -> FileResponse:
    """Genera (o regenera) el informe PDF de un escaneo y lo sirve para descarga.

    Regenerar en cada descarga, en vez de servir un fichero cacheado sin
    comprobar nada, evita servir un informe desactualizado si el escaneo se
    ha triado con IA después de la última descarga.
    """
    scan = await repository.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {scan_id} no encontrado"
        )
    path = await generate_report(scan)
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"atalaya_informe_{scan.domain}_{scan.id}.pdf",
    )
