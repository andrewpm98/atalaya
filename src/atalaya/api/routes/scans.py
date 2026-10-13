"""Router de escaneos: lanzar, consultar, comparar y triar escaneos de
superficie de exposición.

`create_scan` valida el dominio, crea el escaneo en `running` y deja el
trabajo largo (subdominios, puertos/cabeceras/TLS y persistencia) a
`core/scan_runner.py::run_scan`, en segundo plano. `triage_scan`
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

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from atalaya.ai.diff_analyst import analyze_diff
from atalaya.ai.provider import get_provider
from atalaya.ai.triage import TriageBatchResult, triage_findings
from atalaya.ai.triage_reuse import reuse_previous_triage
from atalaya.api.schemas import (
    AssetChangeOut,
    ScanDetail,
    ScanDiffOut,
    ScanRequest,
    ScanSummary,
    TriageResponse,
)
from atalaya.core import repository
from atalaya.core.authorization import ensure_authorized
from atalaya.core.database import get_session, get_session_factory
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import FindingSeverity, Scan, ScanStatus
from atalaya.core.repository import diff_scans
from atalaya.core.scan_runner import run_scan
from atalaya.reporting.generator import generate_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["escaneos"])


def _ensure_not_running(scan: Scan) -> None:
    """409 si el escaneo aún está en curso.

    Mientras corre no tiene activos (se guardan todos al final), así que
    triarlo devolvería «0 triados» como si estuviera hecho, y su informe
    saldría vacío. 409 (conflicto con el estado del recurso) dice lo que pasa:
    el escaneo existe, pero todavía no se puede usar para eso.
    """
    if scan.status is ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"El escaneo #{scan.id} aún está en curso.",
        )


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanDetail,
    responses={201: {"description": "Con `wait=true`: el escaneo ya terminado, con sus activos."}},
)
async def create_scan(
    payload: ScanRequest,
    background: BackgroundTasks,
    response: Response,
    wait: bool = Query(
        default=False,
        description=(
            "true: espera a que termine y responde 201 con el escaneo completo, como antes "
            "de que el escaneo fuera en segundo plano. Puede tardar minutos."
        ),
    ),
    session: AsyncSession = Depends(get_session),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> Scan:
    """Lanza un escaneo de `payload.domain`: 202 al momento, y corre en segundo plano.

    Responde con el escaneo en `running`, sin activos, y la cabecera
    `Location` apunta a `GET /scans/{id}`, que se consulta hasta que el
    estado pase a `completed` o `failed`. Un escaneo tarda de segundos a
    minutos: dentro de la petición, la conexión quedaba abierta todo ese
    tiempo y un cliente con timeout lo daba por fallido aunque siguiera.

    La validación y la autorización van **antes** de crear nada: un dominio
    mal formado da 400 y uno fuera de `SCAN_ALLOWLIST` da 403 al momento (vía
    los manejadores de `api/main.py`), sin dejar un escaneo `failed` en la
    base de datos. `run_scan` vuelve a comprobarla al ejecutar.

    `wait=true` conserva el comportamiento anterior (201 con el detalle): lo
    usan los scripts y los ejemplos de `curl` que necesitan el resultado en
    la misma llamada. Es la misma función, esperada en línea.
    """
    domain = ensure_authorized(payload.domain)
    # `assets=[]` explícito: deja la relación cargada (vacía) para serializar
    # la respuesta sin una carga perezosa fuera del contexto async.
    scan = Scan(domain=domain, status=ScanStatus.RUNNING, assets=[])
    session.add(scan)
    await session.commit()
    scan_id = scan.id

    if not wait:
        background.add_task(run_scan, session_factory, scan_id, resolve=payload.resolve)
        response.headers["Location"] = f"/scans/{scan_id}"
        return scan

    await run_scan(session_factory, scan_id, resolve=payload.resolve)
    response.status_code = status.HTTP_201_CREATED
    # `run_scan` escribió con otra sesión: sin expirar, esta devolvería el
    # `Scan` que tiene en memoria, todavía en `running` y sin activos. Tras
    # expirarlo no se puede leer ni `scan.id` sin una carga perezosa fuera
    # del contexto async: por eso el id se guardó antes.
    session.expire_all()
    loaded = await repository.get_scan(session, scan_id)
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

    for escaneo in (scan_a, scan_b):
        if escaneo.status is not ScanStatus.COMPLETED:
            # Uno en curso no tiene activos todavía y uno fallido no los tendrá:
            # compararlos daría todos sus hostnames por «desaparecidos».
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Solo se comparan escaneos completados: el #{escaneo.id} "
                    f"está {'en curso' if escaneo.status is ScanStatus.RUNNING else 'fallido'}."
                ),
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

    Sin `force`, antes de llamar al modelo se reutiliza el triaje de los
    hallazgos de otros escaneos del dominio con el mismo contexto exacto
    (`ai/triage_reuse.py`): mismo prompt, misma respuesta, sin pagarla otra
    vez. Si todos se resuelven así, no se instancia el proveedor (funciona
    sin clave). Con `force` no se reutiliza nada: forzar significa volver a
    preguntar al modelo actual, no copiar lo que dijo otro.
    """
    scan = await repository.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Escaneo {scan_id} no encontrado"
        )
    _ensure_not_running(scan)

    pendientes = [
        finding
        for asset in scan.assets
        for finding in asset.findings
        if force or finding.severity is FindingSeverity.UNKNOWN
    ]
    if not pendientes:
        return TriageResponse(scan_id=scan.id, triaged=0, errors=[])

    total = len(pendientes)
    reutilizados = 0
    if not force:
        previos = await repository.list_triaged_findings(
            session, scan.domain, exclude_scan_id=scan.id
        )
        pendientes, reutilizados = reuse_previous_triage(pendientes, previos)

    result = TriageBatchResult()
    if pendientes:
        result = await triage_findings(get_provider(), pendientes)
    await session.commit()

    logger.info(
        "Triaje del escaneo #%s: %d hallazgos triados con %d llamadas al modelo "
        "(%d reutilizados de escaneos anteriores, ahorro del %.0f%%, %d fallos)",
        scan.id,
        result.triaged + reutilizados,
        len(pendientes),
        reutilizados,
        100 * reutilizados / total,
        len(result.errors),
    )
    return TriageResponse(
        scan_id=scan.id,
        triaged=result.triaged + reutilizados,
        reused=reutilizados,
        model_calls=len(pendientes),
        errors=result.errors,
    )


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
    _ensure_not_running(scan)
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
