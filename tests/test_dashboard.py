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

from pathlib import Path
from typing import Any, Self
from unittest.mock import patch

import httpx
from streamlit.testing.v1 import AppTest

#: Ruta absoluta: `AppTest.from_file` resuelve una ruta relativa contra el
#: fichero que llama, no contra el directorio de trabajo del proceso.
_APP_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


class _Resp:
    """Doble de `httpx.Response`: solo lo que `dashboard/app.py` usa."""

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self) -> Any:
        return self._payload


def _fake_client(
    get_map: dict[str, _Resp | list[_Resp]],
    post_map: dict[str, _Resp] | None = None,
) -> type:
    """Doble de `httpx.Client`.

    `get_map` acepta una `_Resp` fija o una lista: con lista, cada llamada a
    esa ruta devuelve el siguiente elemento (se agota en el último), lo que
    permite simular que una ruta cambia de resultado entre una petición y la
    siguiente -- necesario para probar que el botón de triaje refresca los
    datos tras la llamada a la API (ver `test_triage_refresca_sin_rerun`).
    """
    post_map = post_map or {}

    def _get(path: str) -> _Resp:
        entry = get_map.get(path)
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


def _scan_detail(scan_id: int = 1, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
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
                "findings": findings if findings is not None else [_finding()],
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


def test_nuevo_escaneo_exitoso_muestra_resumen() -> None:
    nuevo = _scan_detail(scan_id=5)
    get_map = {"/scans": _Resp(200, [])}
    post_map = {"/scans": _Resp(201, nuevo)}

    with patch("httpx.Client", _fake_client(get_map, post_map)):
        at = AppTest.from_file(_APP_PATH, default_timeout=15)
        at.run()
        at.tabs[0].text_input[0].input("ejemplo.com").run()
        at.tabs[0].button[0].click().run()

    assert not at.exception
    mensajes = [s.value for s in at.tabs[0].success]
    assert any("Escaneo #5 completado" in m and "1 hallazgo(s)" in m for m in mensajes)


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
        at.tabs[2].text_input[0].input("ejemplo.com").run()
        at.tabs[2].text_area[0].input("¿algo filtra red interna?").run()
        at.tabs[2].button[0].click().run()

    assert not at.exception
    textos = [m.value for m in at.tabs[2].markdown]
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
        at.tabs[2].text_input[0].input("sin-escanear.com").run()
        at.tabs[2].text_area[0].input("¿qué hay?").run()
        at.tabs[2].button[0].click().run()

    assert not at.exception
    assert any("No hay un escaneo completado" in e.value for e in at.tabs[2].error)
