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
