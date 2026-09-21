"""Pruebas de `reporting/generator.py`: informe ejecutivo con portada.

`render_html` se prueba por separado de `generate_report` a propósito: es
puro y síncrono (plantilla Jinja2, sin xhtml2pdf), así que cubre el
contenido del informe sin pagar el coste de generar un PDF real en cada
caso. `generate_report` cubre la conversión a PDF y la escritura a disco,
una vez, contra un directorio temporal.
"""

from __future__ import annotations

from datetime import datetime, timezone
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
        started_at=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 10, 5, tzinfo=timezone.utc),
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


def test_build_report_context_risk_score_pondera_por_severidad() -> None:
    scan = _scan()
    _asset_con_findings(scan, ("a", FindingSeverity.CRITICAL), ("b", FindingSeverity.HIGH))

    ctx = build_report_context(scan)

    # 1 crítica (25) + 1 alta (10) = 35, ver `_RISK_WEIGHTS` en generator.py.
    assert ctx["risk_score"] == 35


def test_build_report_context_risk_score_se_acota_a_cien() -> None:
    scan = _scan()
    _asset_con_findings(scan, *[(f"c{i}", FindingSeverity.CRITICAL) for i in range(10)])

    ctx = build_report_context(scan)

    assert ctx["risk_score"] == 100


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
    assert llamadas == [
        {"domain": "ejemplo.com", "risk_score": 25, "critical_count": 1, "high_count": 0}
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
