"""Abstracción del proveedor de LLM.

`LLMProvider` es una interfaz, no una clase concreta: el resto de la capa IA
(`triage.py`, `query.py`) depende de ella, nunca del SDK de Anthropic
directamente. Cambiar de proveedor es escribir una nueva subclase sin tocar
lógica de negocio — la decisión de diseño que ya anticipaba CLAUDE.md
("Capa IA tras interfaz `LLMProvider`: el modelo es configuración, no
dependencia rígida"). `GeminiProvider` es la prueba de que la interfaz
cumple esa promesa: ninguna línea de `triage.py`, `query.py` ni de los
agentes de `ai/` cambió para incorporarlo.

**Desviación del stub original:** el contrato inicial solo tenía
`complete(prompt, system) -> str`. Se añade `complete_tool()`: el triaje
necesita una respuesta con forma garantizada (severidad/impacto/
remediación), y pedirle al modelo "responde en JSON" sobre texto libre es
frágil — basta con que anteponga una frase de cortesía al JSON para que el
parseo falle. Forzar una llamada a herramienta (`tool_choice` fijo) hace que
el propio proveedor valide la respuesta contra un JSON Schema antes de
devolverla; no hay texto que parsear. `complete()` se conserva para la
consulta en lenguaje natural, donde sí se quiere prosa libre.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import anthropic
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from atalaya.config import settings
from atalaya.core.exceptions import AIProviderError


class LLMProvider(ABC):
    """Cliente de LLM: respuesta libre o respuesta con forma garantizada."""

    @abstractmethod
    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        """Respuesta libre en texto. La usa la consulta en lenguaje natural.

        Raises:
            AIProviderError: si el proveedor falla o no devuelve texto.
        """

    @abstractmethod
    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        """Fuerza al modelo a responder llamando a una única herramienta.

        Args:
            tool_name: Nombre de la herramienta a la que se obliga a llamar.
            tool_schema: JSON Schema del `input` esperado.

        Returns:
            El `input` de la llamada a la herramienta, ya conforme a
            `tool_schema` (lo valida el proveedor antes de devolverlo).

        Raises:
            AIProviderError: si el proveedor falla o no llama a la herramienta.
        """


class AnthropicProvider(LLMProvider):
    """Implementación sobre el SDK oficial de Anthropic (Claude)."""

    def __init__(self, client: anthropic.AsyncAnthropic | None = None) -> None:
        self.model = settings.ai_model
        if client is not None:
            # Punto de inyección para tests: un doble que implemente
            # `.messages.create(...)` sin tocar la red.
            self._client = client
            return
        if not settings.anthropic_api_key:
            raise AIProviderError(
                "ANTHROPIC_API_KEY no configurada. Defínela en .env para usar la capa IA."
            )
        self._client = anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            timeout=settings.ai_timeout,
            max_retries=settings.ai_max_retries,
        )

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": settings.ai_max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system is not None:
            kwargs["system"] = system

        message = await self._create(**kwargs)
        text = "".join(block.text for block in message.content if block.type == "text")
        if not text:
            raise AIProviderError("el modelo no devolvió texto en la respuesta")
        return text

    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": settings.ai_max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [
                {
                    "name": tool_name,
                    "description": f"Registra el resultado como {tool_name}.",
                    "input_schema": tool_schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": tool_name},
        }
        if system is not None:
            kwargs["system"] = system

        message = await self._create(**kwargs)
        for block in message.content:
            if block.type == "tool_use" and block.name == tool_name:
                return block.input
        raise AIProviderError(f"el modelo no llamó a la herramienta {tool_name!r}")

    async def _create(self, **kwargs: Any) -> Any:
        """Envuelve `messages.create`: cualquier fallo del SDK se traduce a
        `AIProviderError`, para que el resto de la capa IA no dependa de las
        excepciones internas de `anthropic`.
        """
        try:
            return await self._client.messages.create(**kwargs)
        except anthropic.AnthropicError as exc:
            raise AIProviderError(f"fallo del proveedor Anthropic: {exc}") from exc


#: Presupuesto de razonamiento que se le reserva a Gemini 2.5 **además** de
#: `settings.ai_max_tokens`, al forzar una llamada a herramienta.
#:
#: `max_output_tokens` de Gemini y `max_tokens` de Anthropic NO significan lo
#: mismo: en los modelos 2.5 (que razonan siempre, con presupuesto dinámico)
#: los tokens de razonamiento se descuentan de `max_output_tokens`, mientras
#: que en Anthropic `max_tokens` solo acota la respuesta. Mapear
#: `ai_max_tokens` directamente sobre `max_output_tokens` dejaba que el
#: razonamiento se comiera el límite y la generación se cortara **antes** de
#: emitir la llamada a herramienta: `finish_reason=MAX_TOKENS` y
#: `candidate.content=None`, es decir, el error "el modelo no llamó a la
#: herramienta". Reproducido en vivo contra la API real (no era la cuota).
#: Acotándolo explícitamente, `ai_max_tokens` vuelve a significar lo mismo en
#: los dos proveedores: tokens disponibles para la respuesta.
_GEMINI_THINKING_BUDGET = 512

#: `finish_reason` ante el que se reintenta con `mode="AUTO"`. Con
#: `mode="ANY"` Gemini usa decodificación restringida para garantizar la
#: llamada, y sobre prompts grandes esa decodificación se rompe: devuelve
#: `MALFORMED_FUNCTION_CALL`, sin contenido y sin consumir tokens de salida.
#: Verificado en vivo: el mismo prompt (un escaneo de 117 activos y 204
#: hallazgos) falla con `ANY` y se responde correctamente con `AUTO`.
_GEMINI_MALFORMED_CALL = "MALFORMED_FUNCTION_CALL"


def _finish_reason(response: Any) -> str | None:
    """Nombre del `finish_reason` del primer candidato, si lo hay.

    Se normaliza a `str` porque el SDK devuelve un enum: se usa tanto para
    decidir el reintento como para el mensaje de error, y comparar enums del
    SDK acoplaría los dobles de test a su importación.
    """
    for candidate in getattr(response, "candidates", None) or []:
        reason = getattr(candidate, "finish_reason", None)
        if reason is None:
            return None
        return str(getattr(reason, "name", reason))
    return None


class GeminiProvider(LLMProvider):
    """Implementación sobre el SDK oficial de Google (`google-genai`, Gemini).

    Usa `client.aio.models.generate_content` (cliente asíncrono del SDK
    consolidado), coherente con "todo asíncrono" (CLAUDE.md) — no hay una
    variante sync que envolver en un hilo, el SDK ya expone la async
    directamente.
    """

    def __init__(self, client: genai.Client | None = None) -> None:
        self.model = settings.gemini_model
        if client is not None:
            # Punto de inyección para tests: un doble que implemente
            # `.aio.models.generate_content(...)` sin tocar la red.
            self._client = client
            return
        if not settings.gemini_api_key:
            raise AIProviderError(
                "GEMINI_API_KEY no configurada. Defínela en .env para usar la capa IA."
            )
        self._client = genai.Client(api_key=settings.gemini_api_key)

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        config = genai_types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=settings.ai_max_tokens,
        )
        response = await self._generate(model=self.model, contents=prompt, config=config)
        text = response.text
        if not text:
            raise AIProviderError("el modelo no devolvió texto en la respuesta")
        return text

    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        response = await self._tool_call(
            prompt, tool_name=tool_name, tool_schema=tool_schema, system=system, mode="ANY"
        )
        args = self._extract_tool_args(response, tool_name)
        if args is not None:
            return args

        reason = _finish_reason(response)
        if reason == _GEMINI_MALFORMED_CALL:
            # La decodificación restringida de `mode="ANY"` se rompió; el
            # modelo sí sabe llamar a la herramienta con decodificación
            # normal. Se pierde la *garantía* de la llamada (por eso no es el
            # modo por defecto), pero el `if args is not None` de abajo sigue
            # cubriendo el caso de que responda con texto: se degrada a
            # `AIProviderError`, nunca a una respuesta sin forma.
            response = await self._tool_call(
                prompt, tool_name=tool_name, tool_schema=tool_schema, system=system, mode="AUTO"
            )
            args = self._extract_tool_args(response, tool_name)
            if args is not None:
                return args
            reason = _finish_reason(response)

        # El `finish_reason` va en el mensaje a propósito: sin él, MAX_TOKENS
        # (respuesta cortada), MALFORMED_FUNCTION_CALL y "el modelo contestó
        # con texto" producían el mismo error opaco, y el fallo real se
        # atribuyó durante un tiempo a la cuota del free tier.
        detail = f" (finish_reason={reason})" if reason else ""
        raise AIProviderError(f"el modelo no llamó a la herramienta {tool_name!r}{detail}")

    async def _tool_call(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None,
        mode: str,
    ) -> Any:
        """Una petición con la herramienta declarada, en el modo indicado.

        `mode="ANY"` + `allowed_function_names=[tool_name]` es el equivalente
        en Gemini del `tool_choice={"type": "tool", "name": ...}` fijo de
        Anthropic: fuerza la llamada a exactamente esta herramienta, no
        "alguna de las disponibles". `mode="AUTO"` es el reintento de
        `complete_tool` (ver `_GEMINI_MALFORMED_CALL`).
        """
        function = genai_types.FunctionDeclaration(
            name=tool_name,
            description=f"Registra el resultado como {tool_name}.",
            parameters_json_schema=tool_schema,
        )
        config = genai_types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=settings.ai_max_tokens + _GEMINI_THINKING_BUDGET,
            thinking_config=genai_types.ThinkingConfig(
                thinking_budget=_GEMINI_THINKING_BUDGET
            ),
            tools=[genai_types.Tool(function_declarations=[function])],
            tool_config=genai_types.ToolConfig(
                function_calling_config=genai_types.FunctionCallingConfig(
                    mode=mode,
                    allowed_function_names=[tool_name] if mode == "ANY" else None,
                )
            ),
        )
        return await self._generate(model=self.model, contents=prompt, config=config)

    @staticmethod
    def _extract_tool_args(response: Any, tool_name: str) -> dict[str, Any] | None:
        """Los argumentos de la llamada a `tool_name`, o `None` si no la hay."""
        for candidate in response.candidates or []:
            # `candidate.content` puede ser `None` -- observado en vivo cuando
            # la respuesta se corta sin contenido (`finish_reason` MAX_TOKENS
            # o MALFORMED_FUNCTION_CALL). Sin este guard, `.parts` sobre
            # `None` lanza `AttributeError` en vez de degradar a
            # `AIProviderError` como el resto de fallos de esta función.
            if candidate.content is None:
                continue
            for part in candidate.content.parts or []:
                call = part.function_call
                if call is not None and call.name == tool_name:
                    return dict(call.args)
        return None

    async def _generate(self, **kwargs: Any) -> Any:
        """Envuelve `models.generate_content`: cualquier fallo del SDK se
        traduce a `AIProviderError`, mismo criterio que
        `AnthropicProvider._create`.
        """
        try:
            return await self._client.aio.models.generate_content(**kwargs)
        except genai_errors.APIError as exc:
            raise AIProviderError(f"fallo del proveedor Gemini: {exc}") from exc


def get_provider() -> LLMProvider:
    """Instancia el proveedor configurado en `settings.ai_provider`.

    `anthropic` y `gemini` están implementados. La interfaz existe para que
    sumar otro proveedor sea una nueva subclase + una rama aquí, no un
    cambio en `triage.py` ni en `query.py`.
    """
    if settings.ai_provider == "anthropic":
        return AnthropicProvider()
    if settings.ai_provider == "gemini":
        return GeminiProvider()
    raise AIProviderError(f"proveedor de IA no soportado: {settings.ai_provider!r}")
