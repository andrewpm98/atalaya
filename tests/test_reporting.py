"""Pruebas de `reporting/generator.py`: informe ejecutivo con portada.

`render_html` se prueba por separado de `generate_report` a propósito: es
puro y síncrono (plantilla Jinja2, sin xhtml2pdf), así que cubre el
contenido del informe sin pagar el coste de generar un PDF real en cada
caso. `generate_report` cubre la conversión a PDF y la escritura a disco,
una vez, contra un directorio temporal.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime
from typing import Any

import pytest

from atalaya.ai.provider import LLMProvider
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError
from atalaya.core.models import Asset, Finding, FindingSeverity, Scan, ScanStatus
from atalaya.reporting.generator import build_report_context, generate_report, render_html


class _FakeProvider(LLMProvider):
    """Doble de `LLMProvider`: `complete` (usado por `write_executive_summary`)
    devuelve una respuesta fija o falla."""

    def __init__(self, *, text: str | None = None, error: Exception | None = None) -> None:
        self._text = text
        self._error = error

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        if self._error is not None:
            raise self._error
        assert self._text is not None
        return self._text

    async def complete_tool(
        self, prompt: str, *, tool_name: str, tool_schema: dict[str, Any], system: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError("no usado en estas pruebas")


def _scan(
    *,
    domain: str = "ejemplo.com",
    scan_id: int = 1,
    errors: list[str] | None = None,
) -> Scan:
    scan = Scan(
        id=scan_id,
        domain=domain,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 10, 5, tzinfo=UTC),
        errors=errors or [],
    )
    scan.assets = []
    return scan


def _asset_con_findings(scan: Scan, *findings_data: tuple[str, FindingSeverity]) -> Asset:
    asset = Asset(
        id=len(scan.assets) + 1,
        scan_id=scan.id,
        hostname=f"www{len(scan.assets) + 1}.{scan.domain}",
        status="active",
        ip_addresses=["93.184.216.34"],
        sources=["crtsh"],
        is_active=True,
        leaks_internal_addressing=False,
        open_ports=[443],
    )
    asset.findings = []
    for i, (finding_type, severity) in enumerate(findings_data):
        finding = Finding(
            id=100 + i,
            asset_id=asset.id,
            finding_type=finding_type,
            evidence="evidencia de prueba",
            severity=severity,
            impact="impacto de prueba" if severity is not FindingSeverity.UNKNOWN else None,
            remediation="remediación de prueba" if severity is not FindingSeverity.UNKNOWN else None,
        )
        finding.asset = asset  # `back_populates` añade `finding` a `asset.findings` solo
    scan.assets.append(asset)
    return asset


# ─── build_report_context / render_html ─────────────────────────────────────


def test_build_report_context_cuenta_por_severidad() -> None:
    scan = _scan()
    _asset_con_findings(scan, ("leak", FindingSeverity.CRITICAL), ("leak2", FindingSeverity.LOW))
    _asset_con_findings(scan, ("leak3", FindingSeverity.HIGH))

    ctx = build_report_context(scan)

    assert ctx["assets_count"] == 2
    assert ctx["findings_count"] == 3
    counts = dict(ctx["severity_counts"])
    assert counts["Crítica"] == 1
    assert counts["Alta"] == 1
    assert counts["Baja"] == 1
    assert counts["Media"] == 0


def test_build_report_context_ordena_hallazgos_por_severidad_descendente() -> None:
    scan = _scan()
    _asset_con_findings(
        scan,
        ("a", FindingSeverity.LOW),
        ("b", FindingSeverity.CRITICAL),
        ("c", FindingSeverity.MEDIUM),
    )

    ctx = build_report_context(scan)
    severidades = [f.severity for f in ctx["findings"]]

    assert severidades == [
        FindingSeverity.CRITICAL,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
    ]


def test_render_html_incluye_dominio_y_portada() -> None:
    scan = _scan(domain="miempresa.com")
    _asset_con_findings(scan, ("leak", FindingSeverity.HIGH))

    html = render_html(scan)

    assert "miempresa.com" in html
    assert "Informe de superficie de exposición" in html
    assert "remediación de prueba" in html


def test_render_html_escaneo_sin_activos_no_falla() -> None:
    html = render_html(_scan())
    assert "No se descubrió ningún activo" in html
    assert "No se detectó ningún hallazgo" in html


def test_render_html_hallazgo_sin_triar_indica_pendiente() -> None:
    scan = _scan()
    _asset_con_findings(scan, ("leak", FindingSeverity.UNKNOWN))

    html = render_html(scan)

    assert "Pendiente de triaje por IA" in html


def test_render_html_muestra_incidencias_del_escaneo() -> None:
    scan = _scan(errors=["crt.sh no disponible tras 3 intentos"])
    html = render_html(scan)
    assert "crt.sh no disponible tras 3 intentos" in html


# ─── risk_score ──────────────────────────────────────────────────────────────


def test_build_report_context_risk_score_sin_hallazgos_es_cero() -> None:
    ctx = build_report_context(_scan())
    assert ctx["risk_score"] == 0


def test_build_report_context_risk_score_sigue_la_severidad_maxima() -> None:
    """La fórmula en sí se prueba en `tests/test_scoring.py`; aquí, que el
    informe la usa: un crítico cae en la banda crítica y la banda se muestra."""
    scan = _scan()
    _asset_con_findings(scan, ("a", FindingSeverity.CRITICAL), ("b", FindingSeverity.LOW))

    ctx = build_report_context(scan)

    assert ctx["risk_score"] >= 75
    assert ctx["risk_band"] == "crítico"
    assert "crítico" in render_html(scan)


def test_build_report_context_muchos_leves_no_llegan_a_critico() -> None:
    """Regresión del defecto de la suma acotada: volumen de leves = 100/100."""
    scan = _scan()
    _asset_con_findings(scan, *[(f"tipo{i % 6}", FindingSeverity.LOW) for i in range(200)])

    assert build_report_context(scan)["risk_band"] == "bajo"


def test_risk_score_del_informe_y_de_la_api_coinciden() -> None:
    """El PDF y `GET /scans/{id}` (que es lo que pinta el dashboard) usan la
    misma función: el número de la pantalla y el del informe no pueden
    contradecirse. Se comprueba con el esquema real que serializa la API."""
    from atalaya.api.schemas import ScanDetail

    scan = _scan()
    _asset_con_findings(
        scan,
        ("a", FindingSeverity.HIGH),
        ("b", FindingSeverity.MEDIUM),
        ("b", FindingSeverity.MEDIUM),
        ("c", FindingSeverity.UNKNOWN),
    )
    for finding in scan.assets[0].findings:
        finding.created_at = datetime(2026, 1, 1, tzinfo=UTC)

    api = ScanDetail.model_validate(scan).model_dump()

    assert api["risk_score"] == build_report_context(scan)["risk_score"]


# ─── executive_summary (resumen ejecutivo con IA) ────────────────────────────


def test_build_report_context_sin_resumen_ejecutivo_por_defecto() -> None:
    assert build_report_context(_scan())["executive_summary"] is None


def test_render_html_con_resumen_ejecutivo_lo_incluye() -> None:
    scan = _scan()
    html = render_html(scan, executive_summary="El dominio presenta un riesgo moderado.")
    assert "El dominio presenta un riesgo moderado." in html


def test_render_html_sin_resumen_ejecutivo_muestra_texto_de_reserva() -> None:
    html = render_html(_scan(), executive_summary=None)
    assert "no disponible" in html.lower()


async def test_generate_report_con_provider_llama_a_write_executive_summary(
    tmp_path, monkeypatch
) -> None:
    """Con un proveedor de IA disponible, `generate_report` pasa el
    `risk_score` y los hallazgos `critical`/`high` a
    `ai/report_writer.py::write_executive_summary()`, y el PDF resultante es
    válido. El contenido exacto del texto dentro del PDF binario no se
    inspecciona aquí (ya lo cubre `test_render_html_con_resumen_ejecutivo_
    lo_incluye` sobre el HTML, previo a xhtml2pdf); esta prueba verifica el
    cableado: que se llama con los datos correctos."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    scan = _scan()
    _asset_con_findings(scan, ("leak", FindingSeverity.CRITICAL))
    provider = _FakeProvider(text="Resumen ejecutivo redactado por IA de prueba.")

    llamadas: list[dict[str, object]] = []

    async def fake_write_executive_summary(prov, *, domain, risk_score, critical_findings, high_findings):
        llamadas.append(
            {
                "domain": domain,
                "risk_score": risk_score,
                "critical_count": len(critical_findings),
                "high_count": len(high_findings),
            }
        )
        return "Resumen ejecutivo redactado por IA de prueba."

    monkeypatch.setattr(
        "atalaya.reporting.generator.write_executive_summary", fake_write_executive_summary
    )

    path = await generate_report(scan, provider=provider)

    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")
    # El mismo índice que muestra el informe (y la API), no uno propio.
    esperado = build_report_context(scan)["risk_score"]
    assert esperado >= 75
    assert llamadas == [
        {"domain": "ejemplo.com", "risk_score": esperado, "critical_count": 1, "high_count": 0}
    ]


async def test_generate_report_sin_provider_se_genera_igual_sin_resumen(
    tmp_path, monkeypatch
) -> None:
    """`provider=None` (sin clave configurada): el informe se genera igual,
    sin resumen ejecutivo — no es un fallo, es el comportamiento por defecto."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    scan = _scan()
    _asset_con_findings(scan, ("leak", FindingSeverity.HIGH))

    path = await generate_report(scan, provider=None)

    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")


async def test_generate_report_degrada_con_gracia_si_el_proveedor_falla(
    tmp_path, monkeypatch
) -> None:
    """El requisito de "reporte con portada" es obligatorio y anterior a la
    capa IA (ver CLAUDE.md): un proveedor caído (p. ej. sin clave, o un error
    de red) no debe impedir generar el PDF, solo omitir el resumen."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    scan = _scan()
    _asset_con_findings(scan, ("leak", FindingSeverity.CRITICAL))
    provider = _FakeProvider(error=AIProviderError("ANTHROPIC_API_KEY no configurada"))

    path = await generate_report(scan, provider=provider)

    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")


# ─── generate_report ─────────────────────────────────────────────────────────


async def test_generate_report_escribe_un_pdf_valido(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    scan = _scan()
    _asset_con_findings(scan, ("leak", FindingSeverity.HIGH))

    path = await generate_report(scan)

    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")


async def test_generate_report_es_determinista_por_escaneo(tmp_path, monkeypatch) -> None:
    """Descargar el informe dos veces del mismo escaneo sobrescribe el mismo
    fichero, en vez de acumular una copia nueva por descarga."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    scan = _scan()

    primera = await generate_report(scan)
    segunda = await generate_report(scan)

    assert primera == segunda
    assert len(list(tmp_path.glob("*.pdf"))) == 1


async def test_generate_report_formato_no_soportado_lanza_value_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    with pytest.raises(ValueError):
        await generate_report(_scan(), fmt="docx")


# ─── Maquetación de la tabla de activos ──────────────────────────────────────


def _runs_del_pdf(pdf: bytes) -> list[tuple[float, str, float, str]]:
    """(x, texto, tamaño, fuente) de cada línea de texto del PDF."""
    from io import BytesIO

    from pypdf import PdfReader

    runs: list[tuple[float, str, float, str]] = []

    def visitor(text, cm, tm, font_dict, font_size):  # type: ignore[no-untyped-def]
        if text.strip():
            font = (font_dict or {}).get("/BaseFont", "")
            runs.append((tm[4] + cm[4], text.strip(), font_size, str(font).lstrip("/")))

    for page in PdfReader(BytesIO(pdf)).pages:
        page.extract_text(visitor_text=visitor)
    return runs


def test_tabla_de_activos_sin_solapes_ni_ips_partidas() -> None:
    """Geometría real del PDF, no solo que se genere.

    Antes, las cinco columnas medían lo mismo y xhtml2pdf no parte una
    palabra sin espacios: un hostname largo invadía la columna «Estado». Y
    los primeros intentos de arreglo partían una IPv4 por la mitad (se leía
    como otra dirección) o pegaban las IPs sin separador. Se comprueba con
    el peor caso: la IPv6 más ancha posible y un hostname más largo que la
    columna (tiene que partirse sin invadir la siguiente)."""
    from reportlab.pdfbase.pdfmetrics import stringWidth

    from atalaya.reporting.generator import _html_to_pdf_bytes

    ipv6_peor = ":".join(["dddd"] * 8)  # 39 caracteres, los más anchos en Helvetica
    ips = ["185.199.108.153", "185.199.109.153", ipv6_peor, "2606:50c0:8000::153"]
    scan = _scan(domain="github.com")
    for hostname, status in (
        ("examregistration-uat-api.github.com", "active"),
        ("un-subdominio-extraordinariamente-largo-de-prueba.github.com", "unroutable"),
    ):
        asset = Asset(
            id=len(scan.assets) + 1, scan_id=scan.id, hostname=hostname, status=status,
            ip_addresses=ips, sources=["crtsh"], is_active=True,
            leaks_internal_addressing=False, open_ports=[80, 443, 8080, 8443],
        )  # fmt: skip
        asset.findings = []
        scan.assets.append(asset)

    runs = _runs_del_pdf(_html_to_pdf_bytes(render_html(scan)))
    # Solo la tabla de activos: otras tablas pueden empezar en la misma x.
    textos_doc = [t for _, t, _, _ in runs]
    runs = runs[textos_doc.index("Activos descubiertos") : textos_doc.index("Hallazgos detallados")]

    cabeceras = ["Host", "Estado", "IPs", "Puertos", "Hallazgos"]
    columnas = [next(x for x, t, _, f in runs if t == c and "Bold" in f) for c in cabeceras]
    assert columnas == sorted(columnas)

    for x, texto, tamano, fuente in runs:
        for inicio, siguiente in itertools.pairwise(columnas):
            if abs(x - inicio) < 1:
                fin = x + stringWidth(texto, fuente, tamano)
                assert fin <= siguiente, f"{texto!r} invade la columna siguiente"

    textos = [t for _, t, _, _ in runs]
    for ip in ips:
        assert textos.count(ip) == 2, f"{ip} no aparece entera y sola en su línea"
    assert "examregistration-uat-api.github.com" in textos  # los de la demo caben enteros
