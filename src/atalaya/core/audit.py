"""Traza de auditoría: acciones que deben quedar registradas siempre.

La restricción de seguridad #6 (CLAUDE.md) exige que cada petición HTTP a un
tercero de la verificación de takeover deje traza. Esa traza no puede depender
de cómo esté configurado el logging de quien ejecuta la herramienta: bajo
uvicorn solo se configuran los loggers de uvicorn, y en la CLI el nivel es
WARNING salvo con `-v`; en ambos casos un `logger.info` de `atalaya.*` se
descartaba en silencio (comprobado), y la auditoría obligatoria no se veía
nunca.

Por eso el logger de auditoría es independiente: nivel INFO fijo, su propio
handler (stderr) y sin propagar al logger raíz — así no se duplica cuando la
CLI configura el raíz con `basicConfig`, y ni `LOG_LEVEL` ni `-v` pueden
silenciarlo.
"""

from __future__ import annotations

import logging

AUDIT_LOGGER_NAME = "atalaya.audit"


def get_audit_logger() -> logging.Logger:
    """Devuelve el logger de auditoría, configurándolo la primera vez."""
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s AUDITORÍA %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
