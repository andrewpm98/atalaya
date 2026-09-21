"""Excepciones propias de Atalaya.

Disponer de una jerarquía propia permite que la capa API traduzca cada
error de dominio al código HTTP adecuado sin inspeccionar mensajes de texto.
"""

from __future__ import annotations


class AtalayaError(Exception):
    """Error base de la aplicación."""


class UnauthorizedTargetError(AtalayaError):
    """El objetivo solicitado no está en la lista de dominios autorizados."""


class InvalidTargetError(AtalayaError):
    """El objetivo solicitado no es un nombre de dominio válido."""


class DiscoveryError(AtalayaError):
    """Fallo irrecuperable durante una fase de descubrimiento."""


class AIProviderError(AtalayaError):
    """Fallo irrecuperable de la capa IA: proveedor no disponible o mal
    configurado (API key ausente, error de red, respuesta sin la forma
    esperada).

    Se levanta en operaciones puntuales (`ask_natural_language`) donde no
    hay una colección sobre la que degradar con gracia. El triaje de
    hallazgos, que sí procesa una colección, la captura por elemento en vez
    de dejarla propagar (ver `ai/triage.py`).
    """
