"""`GET /config/status`: qué está configurado, para la bienvenida del dashboard.

Reutiliza las comprobaciones de `atalaya doctor` (`onboarding/checks.py`),
pero solo las que no salen a la red (`run_local_checks`): el dashboard lo pide
al cargar, y validar las claves contra Anthropic, Google o Shodan en cada
carga serían llamadas externas por mirar una pantalla. Validarlas es cosa de
`atalaya doctor`.

Solo lectura, a propósito: la configuración se escribe con `atalaya init`, en
la máquina del operador. Un endpoint que recibiera claves, con `API_KEY`
vacía (el valor por defecto), dejaría cambiar el proveedor de IA o la
allowlist a cualquiera que llegue a la API. Devuelve estado y texto, nunca
valores: ni claves ni la contraseña de la base de datos (`CheckResult` no
lleva secretos por construcción, y `tests/test_api_config.py` lo comprueba
sobre la respuesta completa).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from atalaya.api.schemas import ConfigStatusOut
from atalaya.config import settings
from atalaya.onboarding.checks import inputs_from_settings, run_local_checks

router = APIRouter(prefix="/config", tags=["sistema"])


@router.get("/status", response_model=ConfigStatusOut)
async def config_status() -> ConfigStatusOut:
    """Estado de la configuración con la que corre la API, sin salir a la red.

    Describe `settings`, cargado al arrancar el proceso, y no el `.env` de
    ahora: si alguien lo edita sin reiniciar la API, lo que cuenta es lo que
    la API está usando. El directorio de trabajo es la raíz del proyecto, la
    misma base desde la que se leen `.env`, `ai_replay_file` y `alembic.ini`.
    """
    inputs = inputs_from_settings(settings, Path.cwd(), offline=True)
    return ConfigStatusOut(checks=await run_local_checks(inputs))
