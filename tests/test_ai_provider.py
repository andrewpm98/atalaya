"""Pruebas de `ai/provider.py`: `AnthropicProvider`, `GeminiProvider` y la
fábrica `get_provider`.

Sin red: se inyecta un cliente doble por proveedor (`_FakeAnthropicClient`/
`_FakeGeminiClient`) que implementa solo lo que cada `*Provider` usa
(`.messages.create` / `.aio.models.generate_content`), devolviendo objetos
con la misma forma que el SDK real correspondiente. Las formas de Gemini
(`FunctionCallingConfigMode`, campos de `GenerateContentConfig`/
`FunctionDeclaration`/`Tool`/`ToolConfig`/`FunctionCall`) se verificaron
contra el paquete `google-genai` instalado, no solo contra documentación.
Un fallo en esta suite indica un problema en nuestro código de traducción,
nunca una caída de un servicio externo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import anthropic
import pytest
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from atalaya.ai.provider import (
    _GEMINI_THINKING_BUDGET,
    AnthropicProvider,
    GeminiProvider,
    get_provider,
)
from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError


@dataclass
class _FakeMessages:
    """Doble de `client.messages`: registra las llamadas y devuelve lo programado."""

    response: Any = None
    error: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

    async def create(self, **kwargs: object) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


def _client(response: Any = None, error: Exception | None = None) -> SimpleNamespace:
    return SimpleNamespace(messages=_FakeMessages(response=response, error=error))


def _text_message(text: str) -> SimpleNamespace:
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


def _tool_message(tool_name: str, tool_input: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        content=[SimpleNamespace(type="tool_use", name=tool_name, input=tool_input)]
    )


# ─── complete() ────────────────────────────────────────────────────────────


async def test_complete_extrae_texto_de_la_respuesta() -> None:
    client = _client(response=_text_message("hola"))
    provider = AnthropicProvider(client=client)

    respuesta = await provider.complete("pregunta", system="instrucciones")

    assert respuesta == "hola"
    llamada = client.messages.calls[0]
    assert llamada["messages"] == [{"role": "user", "content": "pregunta"}]
    assert llamada["system"] == "instrucciones"


async def test_complete_sin_system_no_lo_envia() -> None:
    client = _client(response=_text_message("hola"))
    provider = AnthropicProvider(client=client)

    await provider.complete("pregunta")

    assert "system" not in client.messages.calls[0]


async def test_complete_sin_bloques_de_texto_lanza_ai_provider_error() -> None:
    client = _client(response=SimpleNamespace(content=[]))
    provider = AnthropicProvider(client=client)

    with pytest.raises(AIProviderError):
        await provider.complete("pregunta")


async def test_complete_envuelve_fallo_del_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(error=anthropic.AnthropicError("servicio no disponible"))
    provider = AnthropicProvider(client=client)

    with pytest.raises(AIProviderError, match="servicio no disponible"):
        await provider.complete("pregunta")


# ─── complete_tool() ────────────────────────────────────────────────────────


async def test_complete_tool_devuelve_el_input_de_la_herramienta() -> None:
    client = _client(response=_tool_message("record_triage", {"severity": "high"}))
    provider = AnthropicProvider(client=client)

    resultado = await provider.complete_tool(
        "prompt", tool_name="record_triage", tool_schema={"type": "object"}
    )

    assert resultado == {"severity": "high"}
    llamada = client.messages.calls[0]
    assert llamada["tool_choice"] == {"type": "tool", "name": "record_triage"}
    assert llamada["tools"][0]["name"] == "record_triage"


async def test_complete_tool_sin_llamada_a_la_herramienta_lanza_error() -> None:
    client = _client(response=_text_message("no llamo a ninguna herramienta"))
    provider = AnthropicProvider(client=client)

    with pytest.raises(AIProviderError, match="record_triage"):
        await provider.complete_tool(
            "prompt", tool_name="record_triage", tool_schema={"type": "object"}
        )


# ─── GeminiProvider ─────────────────────────────────────────────────────────
#
# Doble de `google.genai.Client`: solo implementa `.aio.models.generate_content`,
# que es lo único que `GeminiProvider` usa. Las respuestas imitan la forma de
# `GenerateContentResponse` (`.text`, `.candidates[i].content.parts[j]` con
# `.function_call.name`/`.args`), verificada contra el SDK real instalado.


@dataclass
class _FakeGenerateContent:
    response: Any = None
    error: Exception | None = None
    #: Respuestas sucesivas, para los casos con reintento (`mode="ANY"` que
    #: falla y se reintenta en `AUTO`). Si está vacío se devuelve siempre
    #: `response`, como antes.
    responses: list[Any] = field(default_factory=list)
    calls: list[dict[str, object]] = field(default_factory=list)

    async def generate_content(self, **kwargs: object) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        if self.responses:
            return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        return self.response


def _gemini_client(
    response: Any = None,
    error: Exception | None = None,
    responses: list[Any] | None = None,
) -> SimpleNamespace:
    models = _FakeGenerateContent(response=response, error=error, responses=responses or [])
    return SimpleNamespace(aio=SimpleNamespace(models=models))


def _gemini_text_response(text: str | None) -> SimpleNamespace:
    return SimpleNamespace(text=text, candidates=[])


def _gemini_tool_response(tool_name: str, args: dict[str, object]) -> SimpleNamespace:
    call = SimpleNamespace(name=tool_name, args=args)
    part = SimpleNamespace(function_call=call)
    content = SimpleNamespace(parts=[part])
    candidate = SimpleNamespace(content=content)
    return SimpleNamespace(text=None, candidates=[candidate])


def _gemini_no_call_response(text: str) -> SimpleNamespace:
    part = SimpleNamespace(function_call=None)
    content = SimpleNamespace(parts=[part])
    candidate = SimpleNamespace(content=content)
    return SimpleNamespace(text=text, candidates=[candidate])


def _gemini_empty_content_response() -> SimpleNamespace:
    """Candidato con `content=None`: observado en vivo contra la API real
    bajo presión de cuota del free tier (respuesta cortada sin contenido).
    """
    candidate = SimpleNamespace(content=None)
    return SimpleNamespace(text=None, candidates=[candidate])


def _gemini_cut_response(reason: genai_types.FinishReason) -> SimpleNamespace:
    """Candidato sin contenido y con `finish_reason`, tal como devuelve la API
    real cuando la generación se corta (`MAX_TOKENS`) o la decodificación
    restringida de `mode="ANY"` se rompe (`MALFORMED_FUNCTION_CALL`).
    """
    candidate = SimpleNamespace(content=None, finish_reason=reason)
    return SimpleNamespace(text=None, candidates=[candidate])


async def test_gemini_complete_extrae_texto_de_la_respuesta() -> None:
    client = _gemini_client(response=_gemini_text_response("hola"))
    provider = GeminiProvider(client=client)

    respuesta = await provider.complete("pregunta", system="instrucciones")

    assert respuesta == "hola"
    llamada = client.aio.models.calls[0]
    assert llamada["contents"] == "pregunta"
    assert llamada["config"].system_instruction == "instrucciones"


async def test_gemini_complete_sin_texto_lanza_ai_provider_error() -> None:
    client = _gemini_client(response=_gemini_text_response(None))
    provider = GeminiProvider(client=client)

    with pytest.raises(AIProviderError):
        await provider.complete("pregunta")


async def test_gemini_complete_envuelve_fallo_del_sdk() -> None:
    error = genai_errors.APIError(
        code=503, response_json={"error": {"message": "servicio no disponible"}}
    )
    client = _gemini_client(error=error)
    provider = GeminiProvider(client=client)

    with pytest.raises(AIProviderError, match="servicio no disponible"):
        await provider.complete("pregunta")


async def test_gemini_complete_tool_devuelve_los_args_de_la_llamada() -> None:
    client = _gemini_client(response=_gemini_tool_response("record_triage", {"severity": "high"}))
    provider = GeminiProvider(client=client)

    resultado = await provider.complete_tool(
        "prompt", tool_name="record_triage", tool_schema={"type": "object"}
    )

    assert resultado == {"severity": "high"}
    llamada = client.aio.models.calls[0]
    config = llamada["config"]
    assert config.tool_config.function_calling_config.mode.value == "ANY"
    assert config.tool_config.function_calling_config.allowed_function_names == [
        "record_triage"
    ]
    assert config.tools[0].function_declarations[0].name == "record_triage"


async def test_gemini_complete_tool_sin_llamada_a_la_herramienta_lanza_error() -> None:
    client = _gemini_client(response=_gemini_no_call_response("no llamo a ninguna herramienta"))
    provider = GeminiProvider(client=client)

    with pytest.raises(AIProviderError, match="record_triage"):
        await provider.complete_tool(
            "prompt", tool_name="record_triage", tool_schema={"type": "object"}
        )


async def test_gemini_complete_tool_candidato_sin_content_no_lanza_attributeerror() -> None:
    """Reproduce un fallo real observado contra la API en vivo: un candidato
    con `content=None` (respuesta cortada bajo presión de cuota) debía
    degradar a `AIProviderError`, no a un `AttributeError` sin controlar."""
    client = _gemini_client(response=_gemini_empty_content_response())
    provider = GeminiProvider(client=client)

    with pytest.raises(AIProviderError, match="record_triage"):
        await provider.complete_tool(
            "prompt", tool_name="record_triage", tool_schema={"type": "object"}
        )


async def test_gemini_complete_tool_reserva_presupuesto_de_razonamiento() -> None:
    """`max_output_tokens` de Gemini incluye los tokens de razonamiento, a
    diferencia del `max_tokens` de Anthropic. Mapear `ai_max_tokens` a secas
    dejaba que el razonamiento se comiera el límite y la respuesta se cortara
    antes de emitir la llamada (reproducido en vivo, ver `_GEMINI_THINKING_
    BUDGET`): el presupuesto de razonamiento va acotado y **sumado** aparte.
    """
    client = _gemini_client(response=_gemini_tool_response("record_triage", {"severity": "high"}))
    provider = GeminiProvider(client=client)

    await provider.complete_tool(
        "prompt", tool_name="record_triage", tool_schema={"type": "object"}
    )

    config = client.aio.models.calls[0]["config"]
    assert config.thinking_config.thinking_budget == _GEMINI_THINKING_BUDGET
    assert config.max_output_tokens == settings.ai_max_tokens + _GEMINI_THINKING_BUDGET


async def test_gemini_complete_tool_reintenta_en_auto_si_la_llamada_sale_malformada() -> None:
    """`MALFORMED_FUNCTION_CALL`: la decodificación restringida de
    `mode="ANY"` se rompe sobre prompts grandes (reproducido en vivo con un
    escaneo de 117 activos). El mismo prompt sí se responde con `AUTO`, así
    que se reintenta una vez en vez de devolver un 502.
    """
    client = _gemini_client(
        responses=[
            _gemini_cut_response(genai_types.FinishReason.MALFORMED_FUNCTION_CALL),
            _gemini_tool_response("record_analysis", {"answer": "ok"}),
        ]
    )
    provider = GeminiProvider(client=client)

    resultado = await provider.complete_tool(
        "prompt", tool_name="record_analysis", tool_schema={"type": "object"}
    )

    assert resultado == {"answer": "ok"}
    modos = [
        llamada["config"].tool_config.function_calling_config.mode.value
        for llamada in client.aio.models.calls
    ]
    assert modos == ["ANY", "AUTO"]
    # En `AUTO` no se restringe el nombre: es lo que evita la decodificación
    # restringida que falló en el primer intento.
    assert client.aio.models.calls[1][
        "config"
    ].tool_config.function_calling_config.allowed_function_names is None


async def test_gemini_complete_tool_malformada_dos_veces_lanza_error_con_el_motivo() -> None:
    client = _gemini_client(
        response=_gemini_cut_response(genai_types.FinishReason.MALFORMED_FUNCTION_CALL)
    )
    provider = GeminiProvider(client=client)

    with pytest.raises(AIProviderError, match="MALFORMED_FUNCTION_CALL"):
        await provider.complete_tool(
            "prompt", tool_name="record_analysis", tool_schema={"type": "object"}
        )

    assert len(client.aio.models.calls) == 2


async def test_gemini_complete_tool_truncada_no_reintenta_y_dice_el_motivo() -> None:
    """`MAX_TOKENS` no se reintenta: repetir la misma petición daría el mismo
    corte. Lo que sí cambia es que el motivo va en el mensaje — sin él, este
    fallo y "el modelo contestó con texto" eran indistinguibles, y el fallo
    real llegó a atribuirse a la cuota del free tier.
    """
    client = _gemini_client(response=_gemini_cut_response(genai_types.FinishReason.MAX_TOKENS))
    provider = GeminiProvider(client=client)

    with pytest.raises(AIProviderError, match="MAX_TOKENS"):
        await provider.complete_tool(
            "prompt", tool_name="record_analysis", tool_schema={"type": "object"}
        )

    assert len(client.aio.models.calls) == 1


def test_gemini_sin_api_key_lanza_ai_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.ai.provider.settings.gemini_api_key", "")

    with pytest.raises(AIProviderError, match="GEMINI_API_KEY"):
        GeminiProvider()


# ─── Construcción y fábrica ─────────────────────────────────────────────────


def test_sin_api_key_lanza_ai_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.ai.provider.settings.anthropic_api_key", "")

    with pytest.raises(AIProviderError, match="ANTHROPIC_API_KEY"):
        AnthropicProvider()


def test_get_provider_anthropic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.ai.provider.settings.anthropic_api_key", "clave-de-prueba")
    monkeypatch.setattr("atalaya.ai.provider.settings.ai_provider", "anthropic")

    assert isinstance(get_provider(), AnthropicProvider)


def test_get_provider_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.ai.provider.settings.gemini_api_key", "clave-de-prueba")
    monkeypatch.setattr("atalaya.ai.provider.settings.ai_provider", "gemini")

    assert isinstance(get_provider(), GeminiProvider)


def test_get_provider_desconocido_lanza_ai_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("atalaya.ai.provider.settings.ai_provider", "otro-llm")

    with pytest.raises(AIProviderError, match="otro-llm"):
        get_provider()
