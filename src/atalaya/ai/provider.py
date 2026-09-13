"""Abstracción del proveedor de LLM.

Permite cambiar de proveedor sin tocar la lógica de negocio. Por defecto
Anthropic (Claude), configurable vía `.env`.
"""

from __future__ import annotations

from atalaya.config import settings


class LLMProvider:
    """Cliente fino sobre el LLM configurado. Se implementa en el Paso 5."""

    def __init__(self) -> None:
        self.provider = settings.ai_provider
        self.model = settings.ai_model

    async def complete(self, prompt: str, system: str | None = None) -> str:
        """Envía un prompt al LLM y devuelve la respuesta en texto."""
        raise NotImplementedError
