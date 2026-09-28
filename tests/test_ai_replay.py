"""Pruebas del proveedor de reserva (`ai/replay.py`): grabar, reproducir, fallar honesto."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from atalaya.ai.provider import LLMProvider, get_provider
from atalaya.ai.replay import (
    FORMAT_VERSION,
    RecordingProvider,
    RecordingStore,
    ReplayProvider,
    request_key,
)
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError

_SCHEMA = {"type": "object", "properties": {"severity": {"type": "string"}}}


class _FakeProvider(LLMProvider):
    """Proveedor real simulado: cuenta llamadas y puede fallar a demanda."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.calls += 1
        if self.fail:
            raise AIProviderError("caído")
        return f"respuesta a {prompt}"

    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        self.calls += 1
        if self.fail:
            raise AIProviderError("caído")
        return {"severity": "high", "nested": {"prompt": prompt}}


async def test_lo_grabado_se_reproduce_sin_el_proveedor_real() -> None:
    store = RecordingStore()
    recorder = RecordingProvider(_FakeProvider(), store)
    text = await recorder.complete("hola", system="sys")
    tool = await recorder.complete_tool("hallazgo", tool_name="t", tool_schema=_SCHEMA)

    replay = ReplayProvider(store)
    assert await replay.complete("hola", system="sys") == text
    assert await replay.complete_tool("hallazgo", tool_name="t", tool_schema=_SCHEMA) == tool


async def test_peticion_no_grabada_falla_con_error_de_proveedor() -> None:
    """Nunca se inventa una respuesta: sin grabación, el mismo 502 que un proveedor caído."""
    replay = ReplayProvider(RecordingStore())
    with pytest.raises(AIProviderError, match="no hay respuesta grabada"):
        await replay.complete("pregunta fuera del guion")
    with pytest.raises(AIProviderError, match="no hay respuesta grabada"):
        await replay.complete_tool("x", tool_name="t", tool_schema=_SCHEMA)


async def test_una_grabacion_de_texto_no_responde_a_una_de_herramienta() -> None:
    store = RecordingStore()
    await RecordingProvider(_FakeProvider(), store).complete("mismo prompt")
    with pytest.raises(AIProviderError):
        await ReplayProvider(store).complete_tool("mismo prompt", tool_name="t", tool_schema=_SCHEMA)


def test_la_clave_tolera_espacios_y_mayusculas_pero_no_cambios_de_contenido() -> None:
    base = request_key("text", "¿Qué  debo arreglar\nprimero?", system="S")
    assert base == request_key("text", "  ¿qué debo ARREGLAR primero? ", system="S")
    assert base != request_key("text", "¿Qué debo arreglar después?", system="S")
    assert base != request_key("text", "¿Qué debo arreglar primero?", system="otro sistema")


def test_la_clave_depende_de_la_herramienta_y_su_schema() -> None:
    """Si cambia el contrato de la respuesta, la grabación antigua ya no vale."""
    base = request_key("tool", "p", system=None, tool_name="t", tool_schema=_SCHEMA)
    assert base != request_key("tool", "p", system=None, tool_name="otra", tool_schema=_SCHEMA)
    assert base != request_key("tool", "p", system=None, tool_name="t", tool_schema={})


async def test_recording_reutiliza_prompts_identicos_sin_pagar_dos_veces() -> None:
    inner = _FakeProvider()
    recorder = RecordingProvider(inner, RecordingStore())
    await recorder.complete_tool("mismo hallazgo", tool_name="t", tool_schema=_SCHEMA)
    await recorder.complete_tool("mismo hallazgo", tool_name="t", tool_schema=_SCHEMA)
    assert inner.calls == 1
    assert recorder.calls == 1
    assert len(recorder.used) == 1


async def test_recording_no_graba_los_fallos_del_proveedor_real() -> None:
    store = RecordingStore()
    with pytest.raises(AIProviderError):
        await RecordingProvider(_FakeProvider(fail=True), store).complete("p")
    assert store.entries == {}


async def test_replay_devuelve_copias_y_no_se_corrompe_al_mutarlas() -> None:
    store = RecordingStore()
    await RecordingProvider(_FakeProvider(), store).complete_tool(
        "p", tool_name="t", tool_schema=_SCHEMA
    )
    replay = ReplayProvider(store)
    first = await replay.complete_tool("p", tool_name="t", tool_schema=_SCHEMA)
    first["nested"]["prompt"] = "mutado"
    second = await replay.complete_tool("p", tool_name="t", tool_schema=_SCHEMA)
    assert second["nested"]["prompt"] == "p"


async def test_guardar_y_cargar_conserva_las_grabaciones(tmp_path: Path) -> None:
    store = RecordingStore(meta={"model": "m"})
    await RecordingProvider(_FakeProvider(), store).complete("p")
    path = tmp_path / "rec.json"
    store.save(path)

    loaded = RecordingStore.load(path)
    assert loaded.meta["format"] == FORMAT_VERSION
    assert await ReplayProvider(loaded).complete("p") == "respuesta a p"


def test_fichero_ausente_o_de_otra_version_es_error_de_proveedor(tmp_path: Path) -> None:
    with pytest.raises(AIProviderError, match="no existe"):
        RecordingStore.load(tmp_path / "no-existe.json")

    old = tmp_path / "old.json"
    old.write_text(json.dumps({"meta": {"format": 0}, "entries": {}}), encoding="utf-8")
    with pytest.raises(AIProviderError, match="no soportado"):
        RecordingStore.load(old)

    broken = tmp_path / "broken.json"
    broken.write_text("{no es json", encoding="utf-8")
    with pytest.raises(AIProviderError, match="ilegible"):
        RecordingStore.load(broken)


def test_get_provider_replay_carga_las_grabaciones_configuradas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "rec.json"
    RecordingStore().save(path)
    monkeypatch.setattr(settings, "ai_provider", "replay")
    monkeypatch.setattr(settings, "ai_replay_file", str(path))
    assert isinstance(get_provider(), ReplayProvider)


def test_get_provider_replay_sin_fichero_falla_como_proveedor_mal_configurado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ai_provider", "replay")
    monkeypatch.setattr(settings, "ai_replay_file", str(tmp_path / "no-existe.json"))
    with pytest.raises(AIProviderError):
        get_provider()
