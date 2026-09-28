"""Proveedor de reserva: respuestas reales del modelo, grabadas y reproducidas.

Existe para la demo sin red (`AI_PROVIDER=replay`): el día de la defensa,
crt.sh o el proveedor de IA pueden no responder, y tres de los cinco pasos
de la demo (pregunta en lenguaje natural, valoración del diff, resumen
ejecutivo del informe) llaman al LLM en directo. Con datos precargados en la
BD no basta: `POST /findings/ask` y el diff propagarían el fallo como 502.

Dos implementaciones más de `LLMProvider`, sin tocar ningún agente:

- `RecordingProvider` envuelve a un proveedor real y guarda cada respuesta.
  La usa `scripts/build_demo_data.py`, una vez y con red, recorriendo el
  guion de la demo sobre los mismos datos que siembra
  `scripts/seed_demo_data.py`.
- `ReplayProvider` sirve esas respuestas sin red. **No inventa nada:** si la
  petición no se grabó (una pregunta fuera del guion, o datos distintos de
  los sembrados), falla con `AIProviderError` — el mismo 502 que daría el
  proveedor real caído. Degradar a una respuesta "parecida" sería presentar
  como análisis del modelo algo que el modelo nunca dijo sobre esos datos.

La clave de cada grabación es un hash de la petición completa (tipo, prompt
de sistema, prompt, herramienta y su schema), no solo de la pregunta: la
misma pregunta sobre un escaneo antes y después de triarlo son peticiones
distintas, con respuestas distintas. El prompt se normaliza (espacios y
mayúsculas) solo para que una pregunta tecleada en el dashboard no falle por
un espacio de más; cualquier cambio de contenido cambia la clave. Por eso
`tests/test_demo_data.py` reproduce la demo completa en la suite: si alguien
cambia un prompt, la suite avisa de que la grabación está obsoleta antes de
la defensa, no durante.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from atalaya.ai.provider import LLMProvider
from atalaya.core.exceptions import AIProviderError

logger = logging.getLogger(__name__)

#: Versión del formato del fichero de grabaciones. Si cambia la forma de la
#: clave o de las entradas, se sube y los ficheros antiguos dejan de cargarse
#: con un error explícito en vez de fallar petición a petición.
FORMAT_VERSION = 1

_TEXT = "text"
_TOOL = "tool"


def _normalize(text: str) -> str:
    """Colapsa espacios y mayúsculas: tolera cómo se teclea, no qué se pide."""
    return " ".join(text.split()).casefold()


def request_key(
    kind: str,
    prompt: str,
    *,
    system: str | None,
    tool_name: str | None = None,
    tool_schema: dict[str, Any] | None = None,
) -> str:
    """Huella de una petición al proveedor (ver docstring del módulo)."""
    payload = {
        "kind": kind,
        "system": _normalize(system) if system is not None else None,
        "prompt": _normalize(prompt),
        "tool_name": tool_name,
        "tool_schema": tool_schema,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _label(prompt: str, tool_name: str | None) -> str:
    """Descripción legible de una entrada, para poder auditar el fichero a mano."""
    first_line = prompt.strip().splitlines()[0] if prompt.strip() else ""
    return f"{tool_name or 'texto libre'} · {first_line[:120]}"


class RecordingStore:
    """Grabaciones en memoria, con carga y guardado en JSON."""

    def __init__(
        self,
        entries: dict[str, dict[str, Any]] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.entries: dict[str, dict[str, Any]] = entries or {}
        self.meta: dict[str, Any] = meta or {}

    @classmethod
    def load(cls, path: str | Path) -> RecordingStore:
        """Carga un fichero de grabaciones.

        Raises:
            AIProviderError: si no existe, no es JSON o es de otra versión.
                Es un fallo de configuración del proveedor, no de una
                petición concreta: mismo tratamiento que una clave ausente.
        """
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise AIProviderError(f"replay: no existe el fichero de grabaciones {path}") from exc
        except (OSError, ValueError) as exc:
            raise AIProviderError(f"replay: fichero de grabaciones ilegible {path}: {exc}") from exc

        meta = data.get("meta", {}) if isinstance(data, dict) else {}
        if meta.get("format") != FORMAT_VERSION:
            raise AIProviderError(
                f"replay: formato de grabaciones {meta.get('format')!r} no soportado "
                f"(se espera {FORMAT_VERSION}); regenerar con scripts/build_demo_data.py"
            )
        return cls(entries=dict(data.get("entries", {})), meta=meta)

    def save(self, path: str | Path) -> None:
        """Guarda con claves ordenadas: diffs de git legibles entre regrabaciones."""
        data = {"meta": {**self.meta, "format": FORMAT_VERSION}, "entries": self.entries}
        Path(path).write_text(
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


class ReplayProvider(LLMProvider):
    """Sirve respuestas grabadas; falla si la petición no está grabada."""

    def __init__(self, store: RecordingStore) -> None:
        self._store = store

    def _lookup(self, key: str, kind: str, prompt: str, tool_name: str | None) -> Any:
        entry = self._store.entries.get(key)
        if entry is None or entry.get("kind") != kind:
            logger.warning("replay: sin grabación para %s", _label(prompt, tool_name))
            raise AIProviderError(
                "replay: no hay respuesta grabada para esta petición "
                "(pregunta fuera del guion de la demo, o datos distintos de los sembrados)"
            )
        return copy.deepcopy(entry["response"])

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        key = request_key(_TEXT, prompt, system=system)
        return str(self._lookup(key, _TEXT, prompt, None))

    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        key = request_key(
            _TOOL, prompt, system=system, tool_name=tool_name, tool_schema=tool_schema
        )
        response = self._lookup(key, _TOOL, prompt, tool_name)
        if not isinstance(response, dict):
            raise AIProviderError(f"replay: la grabación de {tool_name!r} no es un objeto")
        return response


class RecordingProvider(LLMProvider):
    """Envuelve a un proveedor real y graba cada respuesta en `store`.

    Con `reuse=True`, una petición ya grabada se sirve de `store` sin volver a
    llamar al modelo: el mismo hallazgo en dos escaneos produce el mismo
    prompt, y pagarlo dos veces no aporta nada. `used` acumula las claves
    tocadas, para que quien graba pueda descartar las que la demo ya no usa.
    Los fallos del proveedor real se propagan y **no** se graban: una
    grabación solo contiene respuestas que el modelo dio de verdad.
    """

    def __init__(self, inner: LLMProvider, store: RecordingStore, *, reuse: bool = True) -> None:
        self._inner = inner
        self._store = store
        self._reuse = reuse
        self.used: set[str] = set()
        self.calls = 0

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        key = request_key(_TEXT, prompt, system=system)
        self.used.add(key)
        if self._reuse and key in self._store.entries:
            return str(self._store.entries[key]["response"])
        self.calls += 1
        text = await self._inner.complete(prompt, system=system)
        self._store.entries[key] = {
            "kind": _TEXT,
            "label": _label(prompt, None),
            "response": text,
        }
        return text

    async def complete_tool(
        self,
        prompt: str,
        *,
        tool_name: str,
        tool_schema: dict[str, Any],
        system: str | None = None,
    ) -> dict[str, Any]:
        key = request_key(
            _TOOL, prompt, system=system, tool_name=tool_name, tool_schema=tool_schema
        )
        self.used.add(key)
        if self._reuse and key in self._store.entries:
            return copy.deepcopy(self._store.entries[key]["response"])
        self.calls += 1
        response = await self._inner.complete_tool(
            prompt, tool_name=tool_name, tool_schema=tool_schema, system=system
        )
        self._store.entries[key] = {
            "kind": _TOOL,
            "label": _label(prompt, tool_name),
            "response": copy.deepcopy(response),
        }
        return response


def load_replay_provider(path: str | Path) -> ReplayProvider:
    """Instancia el proveedor de reserva y deja constancia de que no es un modelo en vivo.

    El aviso es `WARNING` a propósito: quien mire los logs de la API durante
    la demo debe ver que las respuestas son grabadas, con fecha y modelo.
    """
    store = RecordingStore.load(path)
    logger.warning(
        "AI_PROVIDER=replay: respuestas GRABADAS (%s, %s, %d entradas), no un modelo en vivo",
        store.meta.get("recorded_at", "fecha desconocida"),
        store.meta.get("model", "modelo desconocido"),
        len(store.entries),
    )
    return ReplayProvider(store)
