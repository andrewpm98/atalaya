"""Abstracción del proveedor de LLM.

`LLMProvider` es una interfaz, no una clase concreta: el resto de la capa IA
(`triage.py`, `query.py`) depende de ella, nunca del SDK de Anthropic
directamente. Cambiar de proveedor es escribir una nueva subclase sin tocar
lógica de negocio — la decisión de diseño que ya anticipaba CLAUDE.md
("Capa IA tras interfaz `LLMProvider`: el modelo es configuración, no
dependencia rígida").

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


def get_provider() -> LLMProvider:
    """Instancia el proveedor configurado en `settings.ai_provider`.

    Solo `anthropic` está implementado. La interfaz existe para que sumar
    otro proveedor sea una nueva subclase + una rama aquí, no un cambio en
    `triage.py` ni en `query.py`.
    """
    if settings.ai_provider == "anthropic":
        return AnthropicProvider()
    raise AIProviderError(f"proveedor de IA no soportado: {settings.ai_provider!r}")
