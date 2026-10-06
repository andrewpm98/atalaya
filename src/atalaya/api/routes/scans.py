"""Router de escaneos: lanzar, consultar, comparar y triar escaneos de
superficie de exposición.

`create_scan` encadena las cuatro fases de descubrimiento sobre el mismo
escaneo: subdominios (Paso 2), puertos/cabeceras/TLS sobre los hosts activos
(`enrich_scan`, Paso 2 resto) y persistencia (Paso 3). `triage_scan`
(Paso 5) es la puerta de entrada REST al triaje por IA: sin ella,
`ai/triage.py` no sería alcanzable desde la API. `download_report`
(Paso 7) cumple el mismo papel para `reporting/generator.py`. `diff_scan`
cumple el mismo papel para `core/repository.py::diff_scans()` y
`ai/diff_analyst.py::analyze_diff()`: sin este endpoint, comparar dos
escaneos solo sería posible desde tests o desde el dashboard importando
`core/repository` directamente, rompiendo la regla de que la API es la
única puerta de entrada a la capa de negocio.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from atalaya.ai.diff_analyst import analyze_diff
from atalaya.ai.provider import get_provider
from atalaya.ai.triage import triage_findings
from atalaya.api.schemas import (
    AssetChangeOut,
    ScanDetail,
    ScanDiffOut,
    ScanRequest,
    ScanSummary,
    TriageResponse,
)
from atalaya.core import repository
from atalaya.core.database import get_session
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import FindingSeverity, Scan
from atalaya.core.persistence import apply_discovery_findings, apply_port_scan, save_subdomain_scan
from atalaya.core.repository import diff_scans
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


@router.get("/{scan_id}/diff/{other_scan_id}", response_model=ScanDiffOut)
async def diff_scan(
    scan_id: int,
    other_scan_id: int,
    analysis: bool = Query(
        default=True,
        description=(
            "false: solo nuevos/desaparecidos/comunes, sin llamar al modelo "
            "(`analysis` sale null). No depende de la IA ni puede dar 502."
        ),
    ),
    session: AsyncSession = Depends(get_session),
) -> ScanDiffOut:
    """Compara dos escaneos del mismo dominio y valora los cambios con IA.

    Compara hostnames (nuevos/desaparecidos/comunes) y, de los comunes,
    estado, puertos y hallazgos (`cambiados`); ver
    `core/repository.py::diff_scans`.

    Cuál de los dos ids es "previo" y cuál "actual" se decide por
    `started_at`, no por el orden en que se piden en la URL: pedir
    `/scans/5/diff/3` y `/scans/3/diff/5` debe dar la misma comparación
    (mismo `previous`/`current`, mismos `nuevos`/`desaparecidos`), no una
    invertida según qué id se escribió primero. Asumir que el primer
    segmento de la URL es siempre el "actual" sería frágil: nada en la ruta
    lo garantiza, y un cliente que compare "el escaneo de hoy contra el de
    ayer" podría escribirlos en cualquier orden.

    404 si cualquiera de los dos escaneos no existe. 400 si son de dominios
    distintos: a diferencia del 404 (ya usa `HTTPException` directamente en
    este router para "no encontrado"), no existe una excepción de dominio
    para "estos dos escaneos no se pueden comparar" — `InvalidTargetError`
    significa "el dominio pedido no es válido como objetivo de escaneo", no
    encaja aquí (ambos dominios son válidos, el problema es que no
    coinciden). Se usa `HTTPException(400)` directo, mismo patrón que ya
    usa este router para el 404.

    Propaga `AIProviderError` de `analyze_diff` (→ 502 vía el
    `exception_handler` de `api/main.py`): es una petición puntual bajo
    demanda, mismo criterio que `POST /findings/ask` — no como
    `GET /scans/{id}/report` (Tarea 3), donde el informe ya era una
    funcionalidad completa sin IA antes de que existiera esta capa; el diff
    nace con la IA como parte integral de la respuesta.

    `analysis=false` no cambia ese criterio por defecto: es una salida
    explícita para quien solo necesita el cálculo, que es puro y no depende
    del proveedor. Sin ella, un cliente sin IA disponible (el stack de Docker
    sin `.env`, o la demo en `replay` comparando una pareja no grabada) no
    podría ver ni siquiera qué hostnames aparecieron: el dashboard la usa
    como respaldo cuando la petición completa da 502.
    """
    scan_a = await repository.get_scan(session, scan_id)
    scan_b = await repository.get_scan(session, other_scan_id)
    if scan_a is None or scan_b is None:
        faltante = scan_id if scan_a is None else other_scan_id
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {faltante} no encontrado"
        )

    if scan_a.domain != scan_b.domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"No se pueden comparar escaneos de dominios distintos: "
                f"#{scan_a.id} ({scan_a.domain}) y #{scan_b.id} ({scan_b.domain})"
            ),
        )

    previous, current = (
        (scan_a, scan_b) if scan_a.started_at <= scan_b.started_at else (scan_b, scan_a)
    )
    diff = diff_scans(previous, current)

    valoracion: str | None = None
    if analysis:
        valoracion = await analyze_diff(
            get_provider(),
            domain=current.domain,
            diff=diff,
            previous_scan=previous,
            current_scan=current,
        )
    return ScanDiffOut(
        previous_scan_id=previous.id,
        current_scan_id=current.id,
        nuevos=diff.nuevos,
        desaparecidos=diff.desaparecidos,
        comunes=diff.comunes,
        cambiados=[AssetChangeOut.model_validate(change) for change in diff.cambiados],
        analysis=valoracion,
    )


@router.post("/{scan_id}/triage", response_model=TriageResponse)
async def triage_scan(
    scan_id: int,
    force: bool = Query(
        default=False,
        description=(
            "Vuelve a triar también los hallazgos ya triados (p. ej. tras cambiar de "
            "modelo). Una llamada al proveedor por hallazgo: en un escaneo grande, cientos."
        ),
    ),
    session: AsyncSession = Depends(get_session),
) -> TriageResponse:
    """Triaja con IA los hallazgos sin triar (`severity == unknown`) de un escaneo.

    Por defecto no repite el triaje de hallazgos ya triados: es idempotente
    frente a llamadas repetidas y evita coste innecesario del proveedor de IA.

    `force=true` los incluye todos. Es explícito y no el comportamiento por
    defecto por el coste (una llamada por hallazgo). Antes, re-triar exigía
    devolver `severity` a `unknown` a mano en la BD. Si el re-triaje de un
    hallazgo falla, conserva el triaje anterior en vez de quedar `unknown`:
    `ai/triage.py::triage_finding` no toca el hallazgo si el proveedor falla o
    la respuesta no valida, así que un proveedor caído a mitad no borra nada.
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
        if force or finding.severity is FindingSeverity.UNKNOWN
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

    A diferencia de `GET /scans/{id}/diff/{other_id}` y `POST /findings/ask`
    (que propagan `AIProviderError` → 502, ver docstring de `diff_scan`),
    aquí se captura: sin clave configurada, o si el proveedor falla, el
    informe debe seguir descargándose sin resumen ejecutivo, no fallar con
    un 502. La asimetría es intencional, no un descuido — mismo estilo de
    justificación que ya usa `ai/triage.py` para las suyas: el informe con
    portada era un requisito obligatorio de la práctica (ver CLAUDE.md)
    *antes* de que existiera la capa IA, así que no puede depender de ella
    para funcionar; el diff, en cambio, nace con la IA como parte integral
    de lo que devuelve — sin análisis no hay respuesta que dar, así que ahí
    sí tiene sentido que el fallo del proveedor se note como un 502.
    """
    scan = await repository.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {scan_id} no encontrado"
        )
    try:
        provider = get_provider()
    except AIProviderError:
        provider = None
    path = await generate_report(scan, provider=provider)
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"atalaya_informe_{scan.domain}_{scan.id}.pdf",
    )
