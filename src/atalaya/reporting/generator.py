"""Generador de informe ejecutivo con portada (Paso 7).

Cierra el requisito de "reporte con portada" de la práctica: convierte un
escaneo ya persistido y triado en un PDF descargable, con portada
(dominio, fecha), resumen ejecutivo y el detalle de activos y hallazgos con
severidad, impacto y remediación.

**Desviación del stub original:** la firma prevista era
``generate_report(scan_id: int, fmt: str = "pdf") -> Path``. Se cambia
``scan_id: int`` por ``scan: Scan`` ya cargado, por el mismo motivo que
`ai/query.py::ask()` recibe un `Scan` y no un id + sesión: quien llama
(el endpoint) ya tiene el escaneo resuelto vía `repository.get_scan()`, con
sus activos y hallazgos precargados con `selectinload`. Si este módulo
aceptara `scan_id`, necesitaría su propia sesión de base de datos y
duplicaría esa consulta — acoplando la generación del informe a la capa de
persistencia sin necesidad.

El renderizado usa dos pasos separados y ambos probables de fallar por
motivos distintos: `render_html()` (Jinja2, puro y síncrono, fácil de
probar sin generar un PDF real) y la conversión a PDF (`xhtml2pdf`, que sí
hace trabajo de CPU no trivial). Se elige xhtml2pdf sobre WeasyPrint porque
es Python puro — no depende de Pango/Cairo/GTK, ausentes en un Windows
sin ese runtime instalado — y sobre reportlab con `platypus` porque
reutiliza la misma plantilla Jinja2 que ya usa `ai/` para todo lo que cruza
una frontera de presentación, en vez de construir el documento con una API
de bajo nivel.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

from atalaya.ai.provider import LLMProvider
from atalaya.ai.report_writer import write_executive_summary
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Finding, FindingSeverity, Scan

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
)

#: Orden de severidad de mayor a menor riesgo, para listar los hallazgos más
#: graves primero — igual criterio que un analista revisaría el informe.
_SEVERITY_ORDER = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.UNKNOWN,
]

_SEVERITY_LABEL = {
    FindingSeverity.CRITICAL: "Crítica",
    FindingSeverity.HIGH: "Alta",
    FindingSeverity.MEDIUM: "Media",
    FindingSeverity.LOW: "Baja",
    FindingSeverity.UNKNOWN: "Sin triar",
}


#: Peso de cada severidad en `risk_score` (0-100). La proporción entre pesos
#: (crítica ≈ 2.5x alta ≈ 2.5x media ≈ 4x baja) es deliberada, no arbitraria:
#: aproxima que un único hallazgo crítico ya debería acercar el informe a la
#: banda alta del índice (dos críticas superan 50/100 sin necesidad de nada
#: más), mientras que acumular hallazgos `low` por sí solos no debe empujar
#: el score hacia el mismo terreno que un puñado de críticas/altas — no son
#: comparables en impacto real. No hace falta más sofisticación (p. ej.
#: ponderar por activo o por tipo de hallazgo): el objetivo es un número que
#: sitúe el informe en una banda de un vistazo, no un score defendible como
#: CVSS.
_RISK_WEIGHTS: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 25,
    FindingSeverity.HIGH: 10,
    FindingSeverity.MEDIUM: 4,
    FindingSeverity.LOW: 1,
    FindingSeverity.UNKNOWN: 0,
}


def _compute_risk_score(counts: dict[FindingSeverity, int]) -> int:
    """Calcula el `risk_score` (0-100) a partir de los contadores por
    severidad. Acotado a 100: es un índice para el lector, no una suma sin
    límite que un escaneo con muchos hallazgos `low` pudiera desbordar.
    """
    total = sum(_RISK_WEIGHTS[sev] * count for sev, count in counts.items())
    return min(100, total)


def build_report_context(
    scan: Scan, executive_summary: str | None = None
) -> dict[str, object]:
    """Construye el contexto que consume la plantilla Jinja2 del informe.

    Igual principio que `ai/triage.py::build_finding_context`: selección
    deliberada de lo que necesita la plantilla, no las filas de BD tal cual.
    Aquí además se precalculan los contadores (por severidad, activos
    accesibles) para que la plantilla no lleve lógica de agregación.

    `executive_summary` es opcional y ajeno a este cálculo: quien llama
    (`generate_report`) ya decidió si hay resumen ejecutivo de IA disponible
    o no (`None` si no hay proveedor, o si `ai/report_writer.py` falló). Esta
    función solo lo coloca en el contexto junto al `risk_score`, que sí
    calcula aquí porque depende únicamente de `severity_counts` — ya
    calculado en esta misma función — sin necesitar IA.
    """
    findings: list[Finding] = [f for asset in scan.assets for f in asset.findings]
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1

    findings_ordenados = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))

    return {
        "domain": scan.domain,
        "scan_id": scan.id,
        "status": scan.status.value,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "generated_at": datetime.now(UTC),
        "errors": scan.errors,
        "assets": scan.assets,
        "assets_count": len(scan.assets),
        "assets_activos": sum(1 for a in scan.assets if a.is_active),
        "leaks_count": sum(1 for a in scan.assets if a.leaks_internal_addressing),
        "findings_count": len(findings),
        "severity_counts": [(_SEVERITY_LABEL[sev], counts[sev]) for sev in _SEVERITY_ORDER],
        "findings": findings_ordenados,
        "severity_label": _SEVERITY_LABEL,
        "risk_score": _compute_risk_score(counts),
        "executive_summary": executive_summary,
    }


def render_html(scan: Scan, executive_summary: str | None = None) -> str:
    """Renderiza el HTML del informe. Separado de la conversión a PDF para
    poder probarlo sin invocar xhtml2pdf (ver `tests/test_reporting.py`)."""
    template = _env.get_template("report.html")
    return template.render(**build_report_context(scan, executive_summary))


def _html_to_pdf_bytes(html: str) -> bytes:
    """Convierte HTML a PDF con xhtml2pdf. Función síncrona a propósito:
    `pisa.CreatePDF` bloquea en CPU, así que `generate_report` la ejecuta en
    un hilo aparte (`asyncio.to_thread`) para no bloquear el loop de eventos
    — coherente con "todo asíncrono" (CLAUDE.md), aunque aquí el coste sea
    de cómputo y no de red.
    """
    buffer = BytesIO()
    resultado = pisa.CreatePDF(html, dest=buffer)
    if resultado.err:
        raise RuntimeError(f"fallo generando el PDF: {resultado.err} error(es) de renderizado")
    return buffer.getvalue()


def _report_path(scan: Scan) -> Path:
    """Ruta determinista del informe de un escaneo: un informe por escaneo,
    no uno por descarga. Regenerarlo (p. ej. tras triar hallazgos nuevos)
    sobrescribe el fichero anterior en vez de acumular copias en disco cada
    vez que alguien pulsa "descargar" en el dashboard.
    """
    return Path(settings.reports_dir) / f"atalaya_informe_{scan.domain}_{scan.id}.pdf"


async def _build_executive_summary(provider: LLMProvider, scan: Scan) -> str | None:
    """Redacta el resumen ejecutivo con IA, o `None` si no se puede.

    Aísla la parte de `generate_report` que sí puede fallar (la llamada al
    proveedor) de la que no debe fallar nunca (generar el PDF): captura
    `AIProviderError` aquí mismo, no la deja propagar, para que el informe
    con portada — requisito obligatorio de la práctica antes de que
    existiera la capa IA (ver CLAUDE.md) — nunca dependa de que un
    proveedor externo esté disponible o configurado.
    """
    findings: list[Finding] = [f for asset in scan.assets for f in asset.findings]
    critical = [f for f in findings if f.severity is FindingSeverity.CRITICAL]
    high = [f for f in findings if f.severity is FindingSeverity.HIGH]
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    risk_score = _compute_risk_score(counts)

    try:
        return await write_executive_summary(
            provider,
            domain=scan.domain,
            risk_score=risk_score,
            critical_findings=critical,
            high_findings=high,
        )
    except AIProviderError as exc:
        logger.warning(
            "Resumen ejecutivo del escaneo #%s (%s) no disponible: %s", scan.id, scan.domain, exc
        )
        return None


async def generate_report(
    scan: Scan, fmt: str = "pdf", provider: LLMProvider | None = None
) -> Path:
    """Genera el informe de `scan` y devuelve la ruta del fichero escrito.

    Requiere que `scan.assets` y `asset.findings` ya estén cargados (p. ej.
    obtenidos con `repository.get_scan()`).

    `provider` es opcional: si se da, se usa `ai/report_writer.py::
    write_executive_summary()` para incluir un resumen ejecutivo en lenguaje
    natural. Si es `None`, o si el proveedor falla (`AIProviderError`), el
    informe se genera igual con `executive_summary = None` — ver
    `_build_executive_summary`. El informe con portada no puede depender de
    la capa IA: era un requisito obligatorio de la práctica antes de que
    esa capa existiera (ver CLAUDE.md, tabla de requisitos).

    Raises:
        ValueError: si `fmt` no es "pdf" — único formato implementado; el
            parámetro se conserva del stub original como punto de extensión
            explícito, no como código muerto.
    """
    if fmt != "pdf":
        raise ValueError(f"formato de informe no soportado: {fmt!r} (solo 'pdf')")

    executive_summary = await _build_executive_summary(provider, scan) if provider is not None else None

    html = render_html(scan, executive_summary)
    pdf_bytes = await asyncio.to_thread(_html_to_pdf_bytes, html)

    path = _report_path(scan)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pdf_bytes)
    logger.info("Informe del escaneo #%s (%s) generado en %s", scan.id, scan.domain, path)
    return path
