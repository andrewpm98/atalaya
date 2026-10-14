"""Pruebas del dashboard Streamlit (`dashboard/app.py`).

Se usa `streamlit.testing.v1.AppTest`, que ejecuta el script en un entorno
controlado y permite inspeccionar los elementos renderizados sin un
navegador real. `httpx.Client` se sustituye por un doble (`_FakeClient`) que
responde según ruta y método, sin red — mismo criterio de determinismo que
el resto de la suite (`httpx.MockTransport` en `test_subdomains.py`,
`monkeypatch` de `enumerate_subdomains` en `test_api_scans.py`).

Un fallo aquí debe indicar siempre un problema en `dashboard/app.py`, nunca
que la API real esté caída: por eso ninguna prueba la levanta.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Self
from unittest.mock import patch

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from atalaya.core.models import FindingSeverity
from atalaya.core.scoring import compute_risk_score

#: Ruta absoluta: `AppTest.from_file` resuelve una ruta relativa contra el
#: fichero que llama, no contra el directorio de trabajo del proceso.
_APP_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"

#: Posición de las pestañas que se buscan por índice (`at.tabs[...]`).
_TAB_VIGILANCIA = 2
_TAB_PREGUNTAR = 3


class _Resp:
    """Doble de `httpx.Response`: solo lo que `dashboard/app.py` usa.

    `content` acepta bytes tal cual (respuesta binaria, p. ej. el PDF de
    `/scans/{id}/report`) o los codifica desde el payload — así el mismo
    doble sirve tanto para `api_get`/`api_post` (JSON) como para
    `api_get_bytes` (cuerpo crudo).
    """

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)
        self.content = payload if isinstance(payload, bytes) else str(payload).encode()

    def json(self) -> Any:
        return self._payload


def _fake_client(
    get_map: dict[str, _Resp | list[_Resp]],
    post_map: dict[str, _Resp] | None = None,
    send_map: dict[tuple[str, str], _Resp] | None = None,
    enviadas: list[tuple[str, str, object]] | None = None,
) -> type:
    """Doble de `httpx.Client`.

    `get_map` acepta una `_Resp` fija o una lista: con lista, cada llamada a
    esa ruta devuelve el siguiente elemento (se agota en el último), lo que
    permite simular que una ruta cambia de resultado entre una petición y la
    siguiente -- necesario para probar que el botón de triaje refresca los
    datos tras la llamada a la API (ver `test_triage_refresca_sin_rerun`).

    La pestaña «Vigilancia» pide `/monitors` en cada carga: sin un doble
    explícito responde «ningún monitor», como una instalación nueva, para que
    las pruebas de las otras pestañas no vean un error que no es suyo.

    `request` es lo que usa la vigilancia para POST/PATCH/DELETE; responde con
    `send_map[(método, ruta)]` (o `post_map` para un POST) y, si se pasa
    `enviadas`, anota cada llamada con su cuerpo.
    """
    post_map = post_map or {}
    send_map = send_map or {}

    def _get(path: str) -> _Resp:
        entry = get_map.get(path)
        if entry is None and path == "/monitors":
            return _Resp(200, [])
        if entry is None:
            return _Resp(404, {"detail": f"sin mock para GET {path}"})
        if isinstance(entry, list):
            return entry.pop(0) if len(entry) > 1 else entry[0]
        return entry

    class _Client:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
            return _get(path)

        def post(self, path: str, json: dict[str, object] | None = None) -> _Resp:
            return post_map.get(path, _Resp(404, {"detail": f"sin mock para POST {path}"}))

        def request(
            self, method: str, path: str, json: dict[str, object] | None = None
        ) -> _Resp:
            if enviadas is not None:
                enviadas.append((method, path, json))
            resp = send_map.get((method, path)) or (post_map.get(path) if method == "POST" else None)
            return resp or _Resp(404, {"detail": f"sin mock para {method} {path}"})

    return _Client


class _UnreachableClient:
    """Doble de `httpx.Client` que simula un servidor caído: toda llamada
    lanza `httpx.ConnectError`, igual que haría el cliente real si nada
    escucha en `API_URL`.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
        raise httpx.ConnectError("conexión rechazada")

    def post(self, path: str, json: dict[str, object] | None = None) -> _Resp:
        raise httpx.ConnectError("conexión rechazada")


def _finding(severity: str = "unknown") -> dict[str, Any]:
    triado = severity != "unknown"
    return {
        "id": 1,
        "finding_type": "internal_addressing_leak",
        "evidence": "interno.ejemplo.com resuelve a 10.0.0.5",
        "severity": severity,
        "impact": "Filtra estructura de red interna." if triado else None,
        "remediation": "Elimina el registro DNS obsoleto." if triado else None,
        "created_at": "2026-01-01T00:00:00",
    }


def _api_risk_score(findings: list[dict[str, Any]]) -> int:
    """El `risk_score` que calcularía la API para estos hallazgos. Una
    severidad fuera de la escala (ver el test de severidad desconocida) la
    API nunca la emitiría: aquí se ignora en vez de romper el doble."""
    validas = {sev.value for sev in FindingSeverity}
    return compute_risk_score(
        (f["severity"], f["finding_type"]) for f in findings if f["severity"] in validas
    )


def _scan_detail(scan_id: int = 1, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    findings = findings if findings is not None else [_finding()]
    return {
        "risk_score": _api_risk_score(findings),
        "id": scan_id,
        "domain": "ejemplo.com",
        "status": "completed",
        "started_at": "2026-01-01T00:00:00",
        "finished_at": "2026-01-01T00:00:05",
        "errors": [],
        "assets": [
            {
                "id": 1,
                "hostname": "interno.ejemplo.com",
                "status": "unroutable",
                "ip_addresses": ["10.0.0.5"],
                "sources": ["crt.sh"],
                "is_active": False,
                "leaks_internal_addressing": True,
                "open_ports": [],
                "findings": findings,
            }
        ],
    }


def _scan_summary(scan_id: int = 1) -> dict[str, Any]:
    return {
        "id": scan_id,
        "domain": "ejemplo.com",
        "status": "completed",
        "started_at": "2026-01-01T00:00:00",
        "finished_at": "2026-01-01T00:00:05",
        "errors": [],
    }


#: El score de riesgo se pinta con HTML propio (`render_risk_score`), no con
#: `st.metric`: es un número grande con banda de color, algo que `st.metric`
#: no permite. Para comprobarlo sin acoplarse al texto exacto del bloque, se
#: extrae el número de su marca.
_SCORE_RE = re.compile(r'class="atl-hero-num">(\d+)<')


def _score_mostrado(at: AppTest) -> int | None:
    """Score de riesgo renderizado en el detalle, o `None` si no hay."""
    for elemento in at.markdown:
        encontrado = _SCORE_RE.search(elemento.value)
        if encontrado:
            return int(encontrado.group(1))
    return None


def _run_app(get_map: dict[str, Any], post_map: dict[str, Any] | None = None) -> AppTest:
    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
    return at


# ─── Arranque y degradación ─────────────────────────────────────────────────


def test_arranca_sin_api_disponible() -> None:
    """Sin API que responda (conexión rechazada), la página no debe lanzar
    excepción: el estado se refleja en la barra lateral (`st.error`), no en
    un fallo del script.
    """
    with patch("httpx.Client", _UnreachableClient):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()

    assert not at.exception
    assert any("no disponible" in e.value for e in at.sidebar.error)


def test_lista_de_escaneos_vacia_muestra_aviso() -> None:
    at = _run_app(get_map={"/scans": _Resp(200, [])})
    assert not at.exception
    assert any("Todavía no hay escaneos" in i.value for i in at.tabs[1].info)


def test_error_de_la_api_se_muestra_sin_excepcion() -> None:
    """Un 400/403/etc. de la API se traduce a `st.error` con el detalle,
    nunca en una excepción de Python que tumbe la página.
    """
    get_map = {"/scans": _Resp(200, [])}
    post_map = {"/scans": _Resp(400, {"detail": "Dominio no válido: 'x'"})}

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[0].text_input[0].input("x").run()
        at.tabs[0].button[0].click().run()

    assert not at.exception
    assert any("Dominio no válido" in e.value for e in at.tabs[0].error)


# ─── Nuevo escaneo ──────────────────────────────────────────────────────────


def _en_curso(scan_id: int = 5) -> dict[str, Any]:
    """Lo que devuelve `POST /scans` (202) o el detalle mientras corre."""
    return {
        **_scan_detail(scan_id=scan_id),
        "status": "running",
        "finished_at": None,
        "assets": [],
        "risk_score": 0,
    }


def _fallido(scan_id: int = 5) -> dict[str, Any]:
    return {
        **_en_curso(scan_id),
        "status": "failed",
        "finished_at": "2026-01-01T00:00:03",
        "errors": ["interrumpido: la API se detuvo antes de que terminara"],
    }


def _lanzar_escaneo(get_map: dict[str, Any]) -> AppTest:
    """Pulsa «Escanear» con `POST /scans` respondiendo 202 en curso."""
    post_map = {"/scans": _Resp(202, _en_curso())}
    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[0].text_input[0].input("ejemplo.com").run()
        at.tabs[0].button[0].click().run()
    return at


def test_lanzar_un_escaneo_muestra_que_sigue_en_curso() -> None:
    """La API responde al momento (202): el panel no espera al escaneo, sino
    que lo sigue con un fragmento que se refresca solo."""
    at = _lanzar_escaneo({"/scans": _Resp(200, []), "/scans/5": _Resp(200, _en_curso())})

    assert not at.exception
    assert at.session_state["escaneo_en_curso"] == 5
    aviso = next((m.value for m in at.tabs[0].markdown if "atl-run" in m.value), "")
    assert "En curso" in aviso and "Escaneo #5" in aviso and "ejemplo.com" in aviso
    assert not at.tabs[0].success


def test_al_terminar_el_escaneo_muestra_el_resumen() -> None:
    at = _lanzar_escaneo({"/scans": _Resp(200, []), "/scans/5": _Resp(200, _scan_detail(5))})

    assert not at.exception
    assert "escaneo_en_curso" not in at.session_state
    mensajes = [s.value for s in at.tabs[0].success]
    assert any("Escaneo #5 completado" in m and "1 hallazgo(s)" in m for m in mensajes)


def test_si_el_escaneo_falla_muestra_el_motivo() -> None:
    at = _lanzar_escaneo({"/scans": _Resp(200, []), "/scans/5": _Resp(200, _fallido(5))})

    assert not at.exception
    assert any(
        "Escaneo #5" in e.value and "Interrumpido: la API se detuvo" in e.value
        for e in at.tabs[0].error
    )


def test_nuevo_escaneo_sin_dominio_no_llama_a_la_api() -> None:
    with patch("httpx.Client", _fake_client({"/scans": _Resp(200, [])})):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[0].button[0].click().run()

    assert not at.exception
    assert any("Introduce un dominio" in w.value for w in at.tabs[0].warning)


# ─── Escaneos: listado, detalle y triaje ────────────────────────────────────


def test_detalle_de_escaneo_muestra_metricas_y_activos() -> None:
    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail()),
        }
    )
    assert not at.exception
    tab = at.tabs[1]
    assert len(tab.dataframe) == 1
    assert [m.value for m in tab.metric] == ["1", "1", "1"]  # activos, hallazgos, sin triar


def test_triage_refresca_sin_rerun() -> None:
    """El botón de triaje debe: llamar a `POST /scans/{id}/triage`, mostrar
    el resultado, y releer el escaneo para mostrar la severidad actualizada
    -- todo en la misma ejecución, sin `st.rerun()` (que descartaría el
    mensaje de éxito antes de que el usuario lo vea).
    """
    sin_triar = _scan_detail()
    triado = _scan_detail(findings=[_finding(severity="high")])
    get_map = {
        "/scans": _Resp(200, [_scan_summary()]),
        # 1ª llamada (carga inicial de la pestaña), 2ª (recarga tras clic,
        # antes de triar) y 3ª (recarga tras el POST de triaje).
        "/scans/1": [_Resp(200, sin_triar), _Resp(200, sin_triar), _Resp(200, triado)],
    }
    post_map = {"/scans/1/triage": _Resp(200, {"scan_id": 1, "triaged": 1, "errors": []})}

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[1].button[0].click().run()

    assert not at.exception
    assert any("1 hallazgo(s) triado(s)" in s.value for s in at.success)
    assert [m.value for m in at.tabs[1].metric] == ["1", "1", "0"]


def test_triage_con_reutilizacion_lo_dice() -> None:
    """Si parte del triaje se copió de escaneos anteriores, el mensaje lo dice:
    que un clic no llame al modelo no debe parecer un fallo silencioso."""
    detalle = _scan_detail()
    get_map = {
        "/scans": _Resp(200, [_scan_summary()]),
        "/scans/1": [_Resp(200, detalle), _Resp(200, detalle), _Resp(200, detalle)],
    }
    respuesta = {"scan_id": 1, "triaged": 3, "reused": 2, "model_calls": 1, "errors": []}
    post_map = {"/scans/1/triage": _Resp(200, respuesta)}

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[1].button[0].click().run()

    assert not at.exception
    [exito] = [s.value for s in at.success]
    assert "3 hallazgo(s) triado(s)" in exito
    assert "2 reutilizado(s)" in exito and "1 llamada(s) al modelo" in exito


def test_triage_con_fallos_muestra_los_errores() -> None:
    detalle = _scan_detail()
    get_map = {
        "/scans": _Resp(200, [_scan_summary()]),
        "/scans/1": [_Resp(200, detalle), _Resp(200, detalle), _Resp(200, detalle)],
    }
    post_map = {
        "/scans/1/triage": _Resp(
            200, {"scan_id": 1, "triaged": 0, "errors": ["finding #1: rate limit"]}
        )
    }

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[1].button[0].click().run()

    assert not at.exception
    assert any("rate limit" in w.value for w in at.warning)


# ─── Score de riesgo ────────────────────────────────────────────────────────


def test_score_de_riesgo_es_el_de_la_api_sin_recalcular() -> None:
    """El dashboard pinta el `risk_score` que devuelve `GET /scans/{id}`
    (`core/scoring.py`, la misma función que usa el PDF), no uno propio. Se
    comprueba devolviendo a propósito un número que no se deduce de los
    hallazgos: si el dashboard recalculara, no saldría 42."""
    detalle = _scan_detail(findings=[_finding("critical")])
    detalle["risk_score"] = 42

    at = _run_app(
        get_map={"/scans": _Resp(200, [_scan_summary()]), "/scans/1": _Resp(200, detalle)}
    )

    assert not at.exception
    assert _score_mostrado(at) == 42
    assert any("RIESGO MEDIO" in m.value for m in at.tabs[1].markdown)


def test_banda_del_score_sigue_a_la_severidad_maxima() -> None:
    """Muchos hallazgos leves y uno medio: banda media, nunca crítica (el
    defecto de la suma acotada, que ponía github.com en 100/100)."""
    findings = [_finding("low")] * 40 + [_finding("medium")]
    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail(findings=findings)),
        }
    )

    assert not at.exception
    assert 25 <= (_score_mostrado(at) or 0) <= 49
    assert any("RIESGO MEDIO" in m.value for m in at.tabs[1].markdown)


def test_score_ignora_los_hallazgos_sin_triar_pero_lo_advierte() -> None:
    """Un hallazgo sin triar pesa 0: el score mide riesgo confirmado, no
    trabajo pendiente. Como eso puede leerse mal (score bajo ≠ superficie
    segura), la tarjeta tiene que decir cuántos quedan sin triar.
    """
    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail(findings=[_finding()] * 3)),
        }
    )

    assert not at.exception
    assert _score_mostrado(at) == 0
    assert any("3 hallazgo(s) sin triar no puntúan" in m.value for m in at.tabs[1].markdown)


def test_severidad_desconocida_para_el_cliente_no_rompe_el_detalle() -> None:
    """Una severidad que este cliente no conoce (porque la API la añadiera
    después) tiene que degradar a `unknown`, no tumbar la página.

    No es hipotético: el detalle colorea cada activo por su peor severidad y
    esa severidad se usa como índice sobre `_SEVERITY_ORDER`; sin acotar el
    rango, un valor ajeno a la escala se salía del índice y reventaba el
    render del escaneo entero. Mismo criterio de degradación controlada que
    `api_get`.
    """
    ajeno = _finding(severity="high")
    ajeno["severity"] = "catastrophic"

    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail(findings=[ajeno])),
        }
    )

    assert not at.exception
    assert _score_mostrado(at) == 0  # no puntúa: cuenta como sin triar
    assert len(at.tabs[1].expander) == 1  # el activo se sigue pintando


def test_marcas_de_tiempo_se_muestran_legibles() -> None:
    """Las fechas se pintan como `2026-01-01 00:00:05`, no en ISO crudo.

    La API devuelve `datetime.isoformat()`, con la `T` separadora y hasta seis
    decimales de segundo. Esa precisión no ayuda a situar un escaneo y ensancha
    todas las columnas que la muestran, así que el dashboard la recorta al
    segundo antes de enseñarla.
    """
    detalle = _scan_detail()
    detalle["started_at"] = "2026-01-01T00:00:05.123456"

    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, detalle),
        }
    )

    assert not at.exception
    textos = [m.value for m in at.tabs[1].markdown]
    assert any("2026-01-01 00:00:05" in t for t in textos)
    assert not any("00:00:05.123456" in t for t in textos)


def test_score_se_muestra_antes_que_los_activos() -> None:
    """Jerarquía del detalle: el score es la métrica principal y va arriba,
    antes de la lista de activos — aunque en el código se rellene después
    del botón de triaje (que puede releer el escaneo y cambiar el número).
    """
    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail(findings=[_finding("high")])),
        }
    )

    assert not at.exception
    textos = [m.value for m in at.tabs[1].markdown]
    posicion_score = next(i for i, t in enumerate(textos) if _SCORE_RE.search(t))
    posicion_activos = next(i for i, t in enumerate(textos) if "atl-sec" in t and "Activos" in t)
    assert posicion_score < posicion_activos


# ─── Informe ────────────────────────────────────────────────────────────────


def test_boton_informe_pide_el_pdf_y_habilita_la_descarga() -> None:
    """El botón "Generar informe PDF" pide `GET /scans/{id}/report` y, con la
    respuesta en mano, aparece el botón de descarga -- `st.download_button`
    necesita los bytes ya disponibles al renderizarse, no puede pedirlos en
    su propio clic (ver comentario en `dashboard/app.py`)."""
    detalle = _scan_detail(findings=[_finding(severity="high")])  # ya triado: sin botón de triaje
    pdf_bytes = b"%PDF-1.4 contenido de prueba"
    get_map = {
        "/scans": _Resp(200, [_scan_summary()]),
        "/scans/1": _Resp(200, detalle),
        "/scans/1/report": _Resp(200, pdf_bytes),
    }

    with patch("httpx.Client", _fake_client(get_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[1].button[0].click().run()

    assert not at.exception
    assert len(at.tabs[1].download_button) == 1
    assert "Descargar informe PDF" in at.tabs[1].download_button[0].label


def test_informe_con_fallo_de_la_api_no_muestra_boton_de_descarga() -> None:
    detalle = _scan_detail(findings=[_finding(severity="high")])
    get_map = {
        "/scans": _Resp(200, [_scan_summary()]),
        "/scans/1": _Resp(200, detalle),
        "/scans/1/report": _Resp(502, {"detail": "fallo generando el PDF"}),
    }

    with patch("httpx.Client", _fake_client(get_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[1].button[0].click().run()

    assert not at.exception
    assert len(at.tabs[1].download_button) == 0
    assert any("fallo generando el PDF" in e.value for e in at.tabs[1].error)


# ─── Preguntar ──────────────────────────────────────────────────────────────


def test_pregunta_muestra_la_respuesta() -> None:
    respuesta = {
        "scan_id": 1,
        "domain": "ejemplo.com",
        "question": "¿algo filtra red interna?",
        "answer": "Sí, interno.ejemplo.com filtra direccionamiento interno.",
    }
    get_map = {"/scans": _Resp(200, [])}
    post_map = {"/findings/ask": _Resp(200, respuesta)}

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[_TAB_PREGUNTAR].text_input[0].input("ejemplo.com").run()
        at.tabs[_TAB_PREGUNTAR].text_area[0].input("¿algo filtra red interna?").run()
        at.tabs[_TAB_PREGUNTAR].button[0].click().run()

    assert not at.exception
    textos = [m.value for m in at.tabs[_TAB_PREGUNTAR].markdown]
    assert any("Escaneo #1" in t for t in textos)
    assert any("filtra direccionamiento interno" in t for t in textos)


def test_pregunta_sin_escaneo_previo_muestra_error() -> None:
    get_map = {"/scans": _Resp(200, [])}
    post_map = {
        "/findings/ask": _Resp(404, {"detail": "No hay un escaneo completado para ese dominio."})
    }

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[_TAB_PREGUNTAR].text_input[0].input("sin-escanear.com").run()
        at.tabs[_TAB_PREGUNTAR].text_area[0].input("¿qué hay?").run()
        at.tabs[_TAB_PREGUNTAR].button[0].click().run()

    assert not at.exception
    assert any("No hay un escaneo completado" in e.value for e in at.tabs[_TAB_PREGUNTAR].error)


# ─── Autenticación (X-API-Key) ──────────────────────────────────────────────


def _cabeceras_enviadas(get_map: dict[str, Any]) -> list[object]:
    """Ejecuta el dashboard y devuelve las cabeceras con que se construyó cada
    cliente de la API. La sonda de `/health` de la barra lateral no cuenta: es
    pública y no se construye con `base_url`."""
    capturadas: list[object] = []
    base = _fake_client(get_map)

    class _Capturador(base):  # type: ignore[misc, valid-type]
        def __init__(self, *args: object, **kwargs: object) -> None:
            if "base_url" in kwargs:
                capturadas.append(kwargs.get("headers"))

    with patch("httpx.Client", _Capturador):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
    assert not at.exception
    assert capturadas, "el dashboard no llegó a llamar a la API"
    return capturadas


def test_envia_la_clave_si_esta_configurada(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATALAYA_API_KEY", "clave-del-dashboard")
    cabeceras = _cabeceras_enviadas({"/scans": _Resp(200, [])})
    assert cabeceras == [{"X-API-Key": "clave-del-dashboard"}] * len(cabeceras)


def test_sin_clave_no_envia_la_cabecera(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ni siquiera vacía: contra una API con clave, una vacía sería una clave
    incorrecta más, y el 401 no explicaría que falta configurarla."""
    monkeypatch.setenv("ATALAYA_API_KEY", "")
    cabeceras = _cabeceras_enviadas({"/scans": _Resp(200, [])})
    assert cabeceras == [None] * len(cabeceras)


def test_sin_variable_de_entorno_lee_api_key_del_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """En local basta con `API_KEY` en `.env`, el mismo sitio que la activa en
    la API: sin esto, el dashboard recibiría 401 en todo."""
    monkeypatch.delenv("ATALAYA_API_KEY", raising=False)
    (tmp_path / ".env").write_text("API_KEY=desde-el-env\nOTRA=1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cabeceras = _cabeceras_enviadas({"/scans": _Resp(200, [])})
    assert cabeceras == [{"X-API-Key": "desde-el-env"}] * len(cabeceras)


def test_un_401_de_la_api_se_muestra_como_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATALAYA_API_KEY", "")
    at = _run_app(
        get_map={"/scans": _Resp(401, {"detail": "Falta la cabecera X-API-Key o no es válida."})}
    )
    assert not at.exception
    assert any("401" in e.value and "X-API-Key" in e.value for e in at.tabs[1].error)


# ─── Comparar con otro escaneo (diff) ───────────────────────────────────────


def _resumen(scan_id: int, domain: str, started_at: str) -> dict[str, Any]:
    return {**_scan_summary(scan_id), "domain": domain, "started_at": started_at}


#: Tres escaneos, del más reciente al más antiguo (como los da `GET /scans`):
#: dos de `ejemplo.com` y uno de otro dominio, que nunca debe ofrecerse.
_ESCANEOS = [
    _resumen(3, "otro.com", "2026-01-03T00:00:00"),
    _resumen(2, "ejemplo.com", "2026-01-02T00:00:00"),
    _resumen(1, "ejemplo.com", "2026-01-01T00:00:00"),
]

_DIFF = {
    "previous_scan_id": 1,
    "current_scan_id": 2,
    "nuevos": ["nuevo.ejemplo.com"],
    "desaparecidos": [],
    "comunes": ["interno.ejemplo.com"],
    "analysis": "Aparece **un** activo nuevo sin hallazgos graves.",
}


def _app_con_registro(
    get_map: dict[str, Any], llamadas: list[str], elegir: int = 2
) -> AppTest:
    """Arranca el dashboard, elige el escaneo `#elegir` en «Ver detalle de» y
    anota en `llamadas` cada GET que hace. Devuelve el `AppTest` abierto dentro
    del parche para poder seguir interactuando."""
    base = _fake_client(get_map)

    class _Registrador(base):  # type: ignore[misc, valid-type]
        def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
            llamadas.append(path)
            return super().get(path, params)

    at = AppTest.from_file(_APP_PATH, default_timeout=15)
    with patch("httpx.Client", _Registrador):
        at.run()
        detalle = at.tabs[1].selectbox[0]
        detalle.select(next(o for o in detalle.options if o.startswith(f"#{elegir} "))).run()
    return at


def _boton(at: AppTest, etiqueta: str) -> Any:
    return next(b for b in at.button if b.label == etiqueta)


def _get_map_diff(diff: _Resp | list[_Resp]) -> dict[str, Any]:
    return {
        "/scans": _Resp(200, _ESCANEOS),
        "/scans/1": _Resp(200, _scan_detail(scan_id=1)),
        "/scans/2": _Resp(200, _scan_detail(scan_id=2)),
        "/scans/3": _Resp(200, {**_scan_detail(scan_id=3), "domain": "otro.com"}),
        "/scans/2/diff/1": diff,
    }


def test_sin_otro_escaneo_del_dominio_no_se_ofrece_comparar() -> None:
    llamadas: list[str] = []
    at = _app_con_registro(_get_map_diff(_Resp(200, _DIFF)), llamadas, elegir=3)

    assert not at.exception
    assert [s.label for s in at.tabs[1].selectbox] == ["Ver detalle de"]
    assert not any(b.label == "Comparar" for b in at.button)


def test_selector_ofrece_solo_el_mismo_dominio_y_no_llama_hasta_pulsar() -> None:
    """El diff llama al modelo de IA: no se pide al renderizar, solo al pulsar."""
    llamadas: list[str] = []
    at = _app_con_registro(_get_map_diff(_Resp(200, _DIFF)), llamadas)

    assert not at.exception
    selector = at.tabs[1].selectbox[1]
    assert selector.label == "Comparar con"
    assert [o.split(" ")[0] for o in selector.options] == ["#1"]
    assert not any("/diff/" in path for path in llamadas)


def test_por_defecto_compara_con_el_anterior_mas_reciente() -> None:
    escaneos = [
        _resumen(4, "ejemplo.com", "2026-01-04T00:00:00"),
        _resumen(3, "ejemplo.com", "2026-01-03T00:00:00"),
        _resumen(2, "ejemplo.com", "2026-01-02T00:00:00"),
        _resumen(1, "ejemplo.com", "2026-01-01T00:00:00"),
    ]
    # El detalle lleva la misma fecha que su resumen: es la del escaneo que se
    # está viendo la que decide cuáles son «anteriores».
    get_map = {"/scans": _Resp(200, escaneos)} | {
        f"/scans/{r['id']}": _Resp(200, {**_scan_detail(scan_id=r["id"]), **r})
        for r in escaneos
    }
    at = _app_con_registro(get_map, [], elegir=3)

    assert at.tabs[1].selectbox[1].value.startswith("#2 ")


def test_comparar_muestra_nuevos_desaparecidos_y_sin_cambios() -> None:
    llamadas: list[str] = []
    get_map = _get_map_diff(_Resp(200, _DIFF))
    at = _app_con_registro(get_map, llamadas)
    with patch("httpx.Client", _fake_client(get_map)):
        _boton(at, "Comparar").click().run()

    assert not at.exception
    metricas = {m.label: m.value for m in at.tabs[1].metric}
    assert metricas["Nuevos"] == "1"
    assert metricas["Desaparecidos"] == "0"
    assert metricas["Sin cambios"] == "1"
    textos = " ".join(m.value for m in at.tabs[1].markdown)
    assert "atl-chip-new" in textos and "nuevo.ejemplo.com" in textos
    assert "#1</b> → <b>#2" in textos
    assert "Aparece **un** activo nuevo" in textos  # la valoración del modelo
    assert any(e.label.startswith("Sin cambios · 1") for e in at.tabs[1].expander)


#: Dos comunes, uno de ellos con cambios: puerto abierto y cerrado, un
#: hallazgo crítico nuevo, uno desaparecido y una severidad fuera de la escala.
_DIFF_CAMBIOS = {
    **_DIFF,
    "comunes": ["interno.ejemplo.com", "www.ejemplo.com"],
    "cambiados": [
        {
            "hostname": "www.ejemplo.com",
            "estado_anterior": "active",
            "estado_actual": "active",
            "puertos_nuevos": [22],
            "puertos_desaparecidos": [8080],
            "hallazgos_nuevos": [
                {"finding_type": "hsts_missing", "severity": "critical"},
                {"finding_type": "csp_missing", "severity": "inventada"},
            ],
            "hallazgos_desaparecidos": [{"finding_type": "cookie_sin_secure", "severity": "low"}],
        }
    ],
}


def test_comparar_separa_cambiados_de_sin_cambios() -> None:
    get_map = _get_map_diff(_Resp(200, _DIFF_CAMBIOS))
    at = _app_con_registro(get_map, [])
    with patch("httpx.Client", _fake_client(get_map)):
        _boton(at, "Comparar").click().run()

    assert not at.exception
    metricas = {m.label: m.value for m in at.tabs[1].metric}
    assert (metricas["Cambiados"], metricas["Sin cambios"]) == ("1", "1")
    assert any(e.label.startswith("Sin cambios · 1") for e in at.tabs[1].expander)
    textos = " ".join(m.value for m in at.tabs[1].markdown)
    assert "Cambiados · 1" in textos
    assert "+ 22/tcp" in textos and "− 8080/tcp" in textos
    assert "atl-sev-critical" in textos and "+ hsts_missing" in textos
    assert "− cookie_sin_secure" in textos
    # Una severidad que el dashboard no conoce se pinta como sin triar, sin romper.
    assert "atl-sev-unknown" in textos
    # El estado no se repite cuando no cambió.
    assert "active →" not in textos


def test_cambiados_escapa_lo_que_viene_de_la_api() -> None:
    """El hostname sale del DNS/crt.sh: lo controla el objetivo, no nosotros."""
    malicioso = {
        **_DIFF_CAMBIOS,
        "cambiados": [{**_DIFF_CAMBIOS["cambiados"][0], "hostname": "<img src=x>.ejemplo.com"}],
    }
    get_map = _get_map_diff(_Resp(200, malicioso))
    at = _app_con_registro(get_map, [])
    with patch("httpx.Client", _fake_client(get_map)):
        _boton(at, "Comparar").click().run()

    textos = " ".join(m.value for m in at.tabs[1].markdown)
    assert "<img src=x>" not in textos and "&lt;img src=x&gt;" in textos


def test_si_la_ia_falla_muestra_los_cambios_sin_valoracion() -> None:
    """502 del proveedor: se repite con `analysis=false` y se ven igual los
    hostnames (puro cálculo), con el motivo de que falte la valoración."""
    peticiones: list[tuple[str, object]] = []
    sin_ia = {**_DIFF, "analysis": None}
    get_map = _get_map_diff(
        [_Resp(502, {"detail": "no hay respuesta grabada"}), _Resp(200, sin_ia)]
    )
    at = _app_con_registro(get_map, [])
    base = _fake_client(get_map)

    class _Registrador(base):  # type: ignore[misc, valid-type]
        def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
            peticiones.append((path, params))
            return super().get(path, params)

    with patch("httpx.Client", _Registrador):
        _boton(at, "Comparar").click().run()

    assert not at.exception
    diffs = [(path, params) for path, params in peticiones if "/diff/" in path]
    assert diffs == [("/scans/2/diff/1", None), ("/scans/2/diff/1", {"analysis": "false"})]
    assert any("no hay respuesta grabada" in w.value for w in at.tabs[1].warning)
    assert not at.error
    metricas = {m.label: m.value for m in at.tabs[1].metric}
    assert (metricas["Nuevos"], metricas["Sin cambios"]) == ("1", "1")
    assert _score_mostrado(at) is not None


def test_un_error_que_no_es_de_la_ia_no_reintenta() -> None:
    """Un 404 fallaría igual sin IA: se muestra una vez y no se repite."""
    peticiones: list[str] = []
    get_map = _get_map_diff(_Resp(404, {"detail": "Escaneo 1 no encontrado"}))
    at = _app_con_registro(get_map, [])
    base = _fake_client(get_map)

    class _Registrador(base):  # type: ignore[misc, valid-type]
        def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
            peticiones.append(path)
            return super().get(path, params)

    with patch("httpx.Client", _Registrador):
        _boton(at, "Comparar").click().run()

    assert not at.exception
    assert peticiones.count("/scans/2/diff/1") == 1
    assert [e.value for e in at.error if "no encontrado" in e.value] == [
        "/scans/2/diff/1 → 404: Escaneo 1 no encontrado"
    ]
    assert not any(m.label == "Nuevos" for m in at.tabs[1].metric)


def test_el_diff_se_conserva_sin_volver_a_pedirlo() -> None:
    """Otra interacción (aquí, pedir el informe) reejecuta el script entero:
    el diff ya pedido se sigue viendo y no se vuelve a llamar al modelo."""
    llamadas: list[str] = []
    get_map = _get_map_diff(_Resp(200, _DIFF))
    at = _app_con_registro(get_map, llamadas)
    base = _fake_client(get_map | {"/scans/2/report": _Resp(200, b"%PDF-1.4")})

    class _Registrador(base):  # type: ignore[misc, valid-type]
        def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
            llamadas.append(path)
            return super().get(path, params)

    with patch("httpx.Client", _Registrador):
        _boton(at, "Comparar").click().run()
        _boton(at, "Generar informe PDF").click().run()

    assert not at.exception
    assert llamadas.count("/scans/2/diff/1") == 1
    assert any(m.label == "Nuevos" for m in at.tabs[1].metric)


# ─── Puesta en marcha: bienvenida y estado de la configuración ─────────────


def _check(key: str, name: str, status: str, detail: str, hint: str | None = None) -> dict[str, Any]:
    return {"key": key, "name": name, "status": status, "detail": detail, "hint": hint,
            "elapsed_ms": None}


def _config_status(**overrides: dict[str, Any]) -> dict[str, Any]:
    """Respuesta de `GET /config/status` con todo correcto, salvo *overrides*."""
    checks = {
        "config": _check("config", "Configuración", "ok", ".env cargado · 6 campos válidos"),
        "scope": _check("scope", "Alcance", "ok", "1 dominio autorizado"),
        "database": _check("database", "Base de datos", "ok", "SQLite 3.50.4 · migraciones al día"),
        "ai": _check("ai", "IA", "info", "Anthropic · clave configurada, sin validar"),
        "shodan": _check("shodan", "Shodan", "off", "no configurado (opcional)"),
        "api": _check("api", "API", "ok", "protegida con X-API-Key"),
        "secrets": _check("secrets", "Secretos", "ok", ".env ignorado por git"),
    }
    checks.update(overrides)
    return {"checks": list(checks.values()), "errors": 0, "warnings": 0}


_SIN_ALCANCE = _check(
    "scope", "Alcance", "warn", "sin restricción: se puede escanear cualquier dominio",
    "Limítalo a los dominios autorizados con atalaya init (SCAN_ALLOWLIST).",
)
_PASO_ACTIVO_RE = re.compile(r'atl-step--now"><div class="atl-step-n">(\d)<')


def _bienvenida(at: AppTest) -> str | None:
    """Marcado de la bienvenida, o `None` si no se pintó."""
    return next((m.value for m in at.main.markdown if "atl-welcome" in m.value), None)


def _paso_activo(at: AppTest) -> int | None:
    marcado = _bienvenida(at) or ""
    encontrado = _PASO_ACTIVO_RE.search(marcado)
    return int(encontrado.group(1)) if encontrado else None


def _barra_lateral(at: AppTest) -> str:
    return "".join(m.value for m in at.sidebar.markdown)


def test_la_cabecera_lleva_la_torre() -> None:
    at = _run_app(get_map={"/scans": _Resp(200, [])})
    assert any('class="atl-tower"' in m.value and "ATALAYA" in m.value for m in at.main.markdown)


def test_sin_escaneos_da_la_bienvenida_con_el_estado() -> None:
    at = _run_app(
        get_map={"/scans": _Resp(200, []), "/config/status": _Resp(200, _config_status())}
    )
    assert not at.exception
    marcado = _bienvenida(at)
    assert marcado is not None
    assert "1 dominio autorizado" in marcado
    assert "Anthropic · clave configurada, sin validar" in marcado


def test_con_escaneos_no_hay_bienvenida() -> None:
    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail()),
            "/config/status": _Resp(200, _config_status()),
        }
    )
    assert not at.exception
    assert _bienvenida(at) is None


def test_configurado_el_paso_activo_es_el_primer_escaneo() -> None:
    at = _run_app(
        get_map={"/scans": _Resp(200, []), "/config/status": _Resp(200, _config_status())}
    )
    assert _paso_activo(at) == 2
    # Con alcance restringido no se sugiere un dominio ajeno a la allowlist.
    assert "scanme.nmap.org" not in (_bienvenida(at) or "")


@pytest.mark.parametrize(
    "override",
    [
        {"scope": _SIN_ALCANCE},
        {"ai": _check("ai", "IA", "warn", "Anthropic sin clave: triaje, consultas y "
                      "resúmenes no disponibles", "Añade la clave con atalaya init.")},
        {"config": _check("config", "Configuración", "warn",
                          "sin .env: se usan los valores por defecto")},
        {"database": _check("database", "Base de datos", "err",
                            "no conecta con 127.0.0.1:5432: connection refused")},
    ],
    ids=["sin-alcance", "ia-sin-clave", "sin-env", "bd-caida"],
)
def test_sin_configurar_el_paso_activo_es_init(override: dict[str, Any]) -> None:
    at = _run_app(
        get_map={"/scans": _Resp(200, []), "/config/status": _Resp(200, _config_status(**override))}
    )
    assert _paso_activo(at) == 1
    assert "atalaya init" in (_bienvenida(at) or "")


def test_sin_alcance_sugiere_scanme_y_muestra_la_pista() -> None:
    at = _run_app(
        get_map={
            "/scans": _Resp(200, []),
            "/config/status": _Resp(200, _config_status(scope=_SIN_ALCANCE)),
        }
    )
    marcado = _bienvenida(at) or ""
    assert "scanme.nmap.org" in marcado
    assert "Limítalo a los dominios autorizados" in marcado


def test_sin_estado_de_la_configuracion_la_bienvenida_no_falla() -> None:
    """Una API anterior a `/config/status` (404) o una clave rechazada: la
    bienvenida sale igual, sin el estado y sin un error más en la página."""
    at = _run_app(get_map={"/scans": _Resp(200, [])})
    assert not at.exception
    marcado = _bienvenida(at) or ""
    assert "No disponible" in marcado
    assert _paso_activo(at) == 1
    assert not any("/config/status" in e.value for e in at.error)
    assert "Configuración</div>" not in _barra_lateral(at)


def test_con_la_api_caida_no_hay_bienvenida_y_se_sugiere_init() -> None:
    """Sin respuesta de `/scans` no se sabe si hay escaneos: decir «primer
    arranque» o «todavía no hay escaneos» sería afirmar algo no comprobado."""
    with patch("httpx.Client", _UnreachableClient):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()

    assert not at.exception
    assert _bienvenida(at) is None
    assert not any("Todavía no hay escaneos" in i.value for i in at.info)
    assert "atalaya init" in _barra_lateral(at)


def test_la_barra_lateral_muestra_la_configuracion() -> None:
    at = _run_app(
        get_map={
            "/scans": _Resp(200, [_scan_summary()]),
            "/scans/1": _Resp(200, _scan_detail()),
            "/config/status": _Resp(200, _config_status(scope=_SIN_ALCANCE)),
        }
    )
    lateral = _barra_lateral(at)
    assert "Configuración</div>" in lateral
    assert "atl-dot--warn" in lateral and "sin restricción" in lateral
    assert "atl-dot--off" in lateral  # Shodan no configurado


def test_el_texto_del_estado_se_escapa() -> None:
    """El detalle viene de la API: se pinta como texto, nunca como HTML."""
    malicioso = _check("ai", "IA", "warn", "<img src=x onerror=alert(1)>", "<script>x</script>")
    at = _run_app(
        get_map={"/scans": _Resp(200, []), "/config/status": _Resp(200, _config_status(ai=malicioso))}
    )
    todo = (_bienvenida(at) or "") + _barra_lateral(at)
    assert "<img src=x" not in todo and "<script>" not in todo
    assert "&lt;img src=x onerror=alert(1)&gt;" in todo


def test_el_estado_no_se_pide_en_cada_reejecucion() -> None:
    """Cada clic reejecuta el script entero; el estado se reutiliza 60 s."""
    peticiones: list[str] = []
    base = _fake_client(
        {"/scans": _Resp(200, []), "/config/status": _Resp(200, _config_status())}
    )

    class _Registrador(base):  # type: ignore[misc, valid-type]
        def get(self, path: str, params: dict[str, object] | None = None) -> _Resp:
            peticiones.append(path)
            return super().get(path, params)

    with patch("httpx.Client", _Registrador):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.run()

    assert not at.exception
    assert peticiones.count("/scans") == 2
    assert peticiones.count("/config/status") == 1


def _reglas_css() -> list[tuple[str, str]]:
    """(selector, cuerpo) de cada regla de `_CSS`, leídas del fuente."""
    fuente = _APP_PATH.read_text(encoding="utf-8")
    inicio = fuente.index('_CSS = """')
    css = fuente[inicio : fuente.index('"""', inicio + 10)]
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    return [(s.strip(), c) for s, c in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


def test_la_barra_lateral_plegada_se_puede_volver_a_abrir() -> None:
    """Con la barra lateral plegada, el botón que la reabre vive dentro de
    `stToolbar` (Streamlit 1.64): ocultarla con `display: none` dejaba la
    barra lateral plegada sin forma de recuperarla. Y un ancho forzado sin
    condición la mantenía ocupando su hueco plegada. `AppTest` no pinta CSS
    (lo visual se comprobó en Chromium): esta guarda lee las reglas."""
    reglas = _reglas_css()
    for selector, cuerpo in reglas:
        if "stToolbar" in selector:
            assert "display" not in cuerpo, selector
        if "268px" in cuerpo:
            assert 'aria-expanded="true"' in selector, selector
    assert any(
        "stExpandSidebarButton" in s and "visibility: visible" in c for s, c in reglas
    )


# ─── Escaneos en curso y fallidos en el detalle ────────────────────────────


def _detalle_de(scan: dict[str, Any]) -> AppTest:
    resumen = {k: scan[k] for k in ("id", "domain", "status", "started_at", "finished_at", "errors")}
    return _run_app(
        get_map={"/scans": _Resp(200, [resumen]), f"/scans/{scan['id']}": _Resp(200, scan)}
    )


def test_el_detalle_de_un_escaneo_en_curso_no_muestra_indice_ni_acciones() -> None:
    """Sin activos todavía, el índice saldría 0 «riesgo bajo», y triar o pedir
    el informe daría 409: solo el estado, que se refresca solo."""
    at = _detalle_de(_en_curso(5))

    assert not at.exception
    assert any("En curso desde hace" in i.value for i in at.tabs[1].info)
    assert _score_mostrado(at) is None
    assert not [b for b in at.tabs[1].button if "Triar" in b.label or "informe" in b.label]


def test_el_detalle_de_un_escaneo_fallido_muestra_el_motivo() -> None:
    at = _detalle_de(_fallido(5))

    assert not at.exception
    assert [e.value for e in at.tabs[1].error] == [
        "Interrumpido: la API se detuvo antes de que terminara"
    ]
    assert _score_mostrado(at) is None


def test_comparar_solo_ofrece_escaneos_completados() -> None:
    """La API no compara uno en curso o fallido (409): no se ofrecen."""
    escaneos = [
        {**_resumen(4, "ejemplo.com", "2026-01-04T00:00:00"), "status": "running"},
        {**_resumen(3, "ejemplo.com", "2026-01-03T00:00:00"), "status": "failed"},
        _resumen(2, "ejemplo.com", "2026-01-02T00:00:00"),
        _resumen(1, "ejemplo.com", "2026-01-01T00:00:00"),
    ]
    get_map = {
        "/scans": _Resp(200, escaneos),
        "/scans/4": _Resp(200, _en_curso(4)),
        "/scans/2": _Resp(200, _scan_detail(2)),
    }
    at = _app_con_registro(get_map, [], elegir=2)

    assert not at.exception
    selector = at.tabs[1].selectbox[1]
    assert selector.label == "Comparar con"
    assert [o.split(" ")[0] for o in selector.options] == ["#1"]


# ─── Vigilancia ─────────────────────────────────────────────────────────────

_WEBHOOK = "https://hooks.ejemplo.com/…"


def _monitor(monitor_id: int = 1, **campos: object) -> dict[str, Any]:
    """Un monitor tal como lo devuelve `GET /monitors`, recién creado."""
    base: dict[str, Any] = {
        "id": monitor_id,
        "domain": f"m{monitor_id}.ejemplo.com",
        "interval_hours": 24,
        "webhook": _WEBHOOK,
        "signed": True,
        "active": True,
        "created_at": "2026-10-14T10:00:00",
        "next_run_at": "2099-01-01T00:00:00",
        "last_run_at": None,
        "last_scan_id": None,
        "baseline_scan_id": None,
        "last_notified_at": None,
        "last_error": None,
    }
    return {**base, **campos}


def _vigilancia(
    monitores: list[dict[str, Any]],
    escaneos: list[dict[str, Any]] | None = None,
    send_map: dict[tuple[str, str], _Resp] | None = None,
    enviadas: list[tuple[str, str, object]] | None = None,
) -> tuple[AppTest, Any]:
    """Arranca el dashboard con esos monitores. Devuelve el `AppTest` y el
    doble del cliente, para seguir interactuando dentro del mismo parche."""
    get_map = {"/monitors": _Resp(200, monitores), "/scans": _Resp(200, escaneos or [])}
    cliente = _fake_client(get_map, send_map=send_map, enviadas=enviadas)
    with patch("httpx.Client", cliente):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
    return at, cliente


def _tabla(at: AppTest) -> str:
    return next(
        (m.value for m in at.tabs[_TAB_VIGILANCIA].markdown if "atl-mon-wrap" in m.value), ""
    )


def test_vigilancia_sin_monitores_invita_a_crear_el_primero() -> None:
    at, _ = _vigilancia([])

    assert not at.exception
    assert any("Ningún dominio vigilado" in i.value for i in at.tabs[_TAB_VIGILANCIA].info)
    assert _tabla(at) == ""
    assert [b.label for b in at.tabs[_TAB_VIGILANCIA].button] == ["Vigilar"]


def test_el_resultado_de_cada_monitor_se_deduce_de_sus_campos() -> None:
    """Pendiente, escaneando, atención, avisado y sin cambios. Escaneando va
    antes que el error (que aún es el de la ejecución anterior) y el error
    antes que «avisado» (un aviso de fallo también deja `last_notified_at`)."""
    hace = "2026-10-14T10:00:00"
    despues = "2026-10-14T10:00:05"
    monitores = [
        _monitor(1),
        _monitor(2, last_run_at=hace, last_scan_id=7, last_error="viejo"),
        _monitor(3, last_run_at=hace, last_scan_id=8, last_notified_at=despues,
                 last_error="aviso no entregado a https://hooks.ejemplo.com/…: HTTP 503"),
        _monitor(4, last_run_at=hace, last_scan_id=9, baseline_scan_id=9, last_notified_at=despues),
        _monitor(5, last_run_at=hace, last_scan_id=10, baseline_scan_id=10,
                 last_notified_at="2026-10-13T10:00:00"),
    ]
    escaneos = [{**_scan_summary(7), "status": "running"}]
    at, _ = _vigilancia(monitores, escaneos)

    assert not at.exception
    filas = _tabla(at).split("<tr")[2:]  # sin la cabecera
    clases = [re.search(r"atl-mon-(pend|run|warn|ok|quiet)\b", f).group(1) for f in filas]
    assert clases == ["pend", "run", "warn", "ok", "quiet"]
    assert "Escaneo #7 en curso" in filas[1]
    assert "HTTP 503" in filas[2]
    assert "compara con el escaneo #9" in filas[3]
    assert "el primero será la referencia" in filas[0]


def test_un_monitor_en_pausa_lo_dice_y_ofrece_reanudar() -> None:
    at, _ = _vigilancia([_monitor(1, active=False)])

    assert "en pausa" in _tabla(at)
    assert "atl-mon-paused" in _tabla(at)
    assert "Reanudar" in [b.label for b in at.tabs[_TAB_VIGILANCIA].button]


def test_la_tabla_escapa_lo_que_viene_de_la_api() -> None:
    """El motivo de un fallo puede llevar texto del receptor o del DNS."""
    malicioso = "<img src=x onerror=alert(1)>"
    at, _ = _vigilancia(
        [_monitor(1, domain=f"{malicioso}.ejemplo.com", last_run_at="2026-10-14T10:00:00",
                  last_error=malicioso)]
    )

    assert malicioso not in _tabla(at)
    assert "&lt;img src=x onerror=alert(1)&gt;" in _tabla(at)


def _rellenar_alta(at: AppTest, dominio: str, webhook: str, secreto: str = "") -> None:
    tab = at.tabs[_TAB_VIGILANCIA]
    tab.text_input[0].input(dominio)
    tab.text_input[1].input(webhook)
    if secreto:
        tab.text_input[2].input(secreto)


def test_crear_un_monitor_genera_el_secreto_y_lo_ensena_una_vez() -> None:
    enviadas: list[tuple[str, str, object]] = []
    creado = _monitor(1, domain="ejemplo.com", baseline_scan_id=4)
    at, cliente = _vigilancia(
        [], send_map={("POST", "/monitors"): _Resp(201, creado)}, enviadas=enviadas
    )
    with patch("httpx.Client", cliente):
        _rellenar_alta(at, " ejemplo.com ", "https://hooks.ejemplo.com/x")
        _boton(at, "Vigilar").click().run()

    assert not at.exception
    [(metodo, ruta, cuerpo)] = enviadas
    assert (metodo, ruta) == ("POST", "/monitors")
    assert isinstance(cuerpo, dict)
    assert cuerpo["domain"] == "ejemplo.com"
    assert cuerpo["interval_hours"] == 24
    assert len(cuerpo["secret"]) >= 16
    tab = at.tabs[_TAB_VIGILANCIA]
    assert any("Vigilando ejemplo.com" in s.value and "escaneo #4" in s.value for s in tab.success)
    assert [c.value for c in tab.code] == [cuerpo["secret"]]
    # El formulario vuelve vacío.
    assert [w.value for w in tab.text_input] == ["", "", ""]


def test_con_secreto_propio_no_se_vuelve_a_ensenar() -> None:
    enviadas: list[tuple[str, str, object]] = []
    at, cliente = _vigilancia(
        [], send_map={("POST", "/monitors"): _Resp(201, _monitor(1))}, enviadas=enviadas
    )
    with patch("httpx.Client", cliente):
        _rellenar_alta(at, "ejemplo.com", "https://hooks.ejemplo.com/x", "mi-secreto-de-dieciseis")
        _boton(at, "Vigilar").click().run()

    assert enviadas[0][2]["secret"] == "mi-secreto-de-dieciseis"  # type: ignore[index]
    assert not at.tabs[_TAB_VIGILANCIA].code


def test_sin_firma_no_se_envia_secreto() -> None:
    enviadas: list[tuple[str, str, object]] = []
    at, cliente = _vigilancia(
        [], send_map={("POST", "/monitors"): _Resp(201, _monitor(1))}, enviadas=enviadas
    )
    with patch("httpx.Client", cliente):
        _rellenar_alta(at, "ejemplo.com", "https://hooks.ejemplo.com/x")
        at.tabs[_TAB_VIGILANCIA].checkbox[0].uncheck()
        _boton(at, "Vigilar").click().run()

    assert "secret" not in enviadas[0][2]  # type: ignore[operator]
    assert not at.tabs[_TAB_VIGILANCIA].code


def test_un_secreto_propio_corto_se_avisa_sin_llamar_a_la_api() -> None:
    enviadas: list[tuple[str, str, object]] = []
    at, cliente = _vigilancia([], enviadas=enviadas)
    with patch("httpx.Client", cliente):
        _rellenar_alta(at, "ejemplo.com", "https://hooks.ejemplo.com/x", "corto")
        _boton(at, "Vigilar").click().run()

    assert enviadas == []
    assert any("16 caracteres" in w.value for w in at.tabs[_TAB_VIGILANCIA].warning)


def test_el_rechazo_de_la_api_se_muestra_y_el_formulario_se_conserva() -> None:
    """Un webhook hacia la red interna: el motivo es el de la API, y lo
    escrito sigue ahí para corregirlo."""
    motivo = "El webhook apunta a una dirección no enrutable (loopback)."
    at, cliente = _vigilancia(
        [], send_map={("POST", "/monitors"): _Resp(400, {"detail": motivo})}
    )
    with patch("httpx.Client", cliente):
        _rellenar_alta(at, "ejemplo.com", "https://localhost/x")
        _boton(at, "Vigilar").click().run()

    tab = at.tabs[_TAB_VIGILANCIA]
    assert [e.value for e in tab.error] == [motivo]
    assert not tab.success
    assert tab.text_input[1].value == "https://localhost/x"


def test_pausar_envia_el_cambio_a_la_api() -> None:
    enviadas: list[tuple[str, str, object]] = []
    at, cliente = _vigilancia(
        [_monitor(3)],
        send_map={("PATCH", "/monitors/3"): _Resp(200, _monitor(3, active=False))},
        enviadas=enviadas,
    )
    with patch("httpx.Client", cliente):
        _boton(at, "Pausar").click().run()

    assert enviadas == [("PATCH", "/monitors/3", {"active": False})]


def test_borrar_pide_confirmacion_antes_de_llamar_a_la_api() -> None:
    enviadas: list[tuple[str, str, object]] = []
    at, cliente = _vigilancia(
        [_monitor(3)],
        send_map={("DELETE", "/monitors/3"): _Resp(204, None)},
        enviadas=enviadas,
    )
    with patch("httpx.Client", cliente):
        _boton(at, "Borrar…").click().run()
        assert enviadas == []
        assert any("Se dejará de vigilar" in w.value for w in at.tabs[_TAB_VIGILANCIA].warning)
        _boton(at, "Borrar monitor").click().run()

    assert enviadas == [("DELETE", "/monitors/3", None)]


def test_cancelar_el_borrado_no_llama_a_la_api() -> None:
    enviadas: list[tuple[str, str, object]] = []
    at, cliente = _vigilancia([_monitor(3)], enviadas=enviadas)
    with patch("httpx.Client", cliente):
        _boton(at, "Borrar…").click().run()
        _boton(at, "Cancelar").click().run()

    assert enviadas == []
    assert not at.tabs[_TAB_VIGILANCIA].warning
