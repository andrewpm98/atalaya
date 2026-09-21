# Memoria técnica — Paso 5: Capa de IA (triaje y consulta en lenguaje natural)

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 5 de 7 — `LLMProvider`, triaje de hallazgos, consulta en lenguaje natural
**Estado:** Completado y verificado (triaje con dobles deterministas; capa de
transporte con Anthropic verificada en vivo — sin clave real, ver sección 6)

---

## 1. Resumen ejecutivo

El Paso 5 implementa **el componente diferencial del proyecto**: la capa que
convierte un hallazgo de reconocimiento crudo en una decisión priorizada y
explicada. Es la pieza que distingue a Atalaya de un escáner que solo lista.

Resultados tangibles:

- `ai/provider.py`: interfaz `LLMProvider` (ABC) y su implementación
  `AnthropicProvider`, con dos formas de pedir una respuesta al modelo —
  texto libre y respuesta con forma garantizada vía herramienta forzada.
- `ai/triage.py`: `triage_finding`/`triage_findings`, que reciben un `Asset`
  y un `Finding` y devuelven severidad razonada, impacto explicado y
  remediación concreta — con **contexto estructurado**, nunca un volcado de
  la fila de base de datos. Degradación controlada: un fallo en un hallazgo
  no aborta el resto.
- `ai/query.py` (módulo nuevo, no anticipado en el diseño original):
  `ask()`, consulta en lenguaje natural sobre un escaneo completo.
- Dos endpoints activados: `POST /scans/{id}/triage` y `POST /findings/ask`
  — el segundo es el que pedía explícitamente el enunciado del Paso 5; el
  primero se añadió porque, sin él, el triaje sería inalcanzable desde la API.
- **26 pruebas automatizadas nuevas** (114 en total: 88 + 26), todas
  deterministas y sin llamadas reales al proveedor de IA.
- Verificación en vivo contra la API real, incluyendo el camino de fallo
  (`502` cuando no hay `ANTHROPIC_API_KEY` configurada).
- Cinco commits, hasta 27 en el repositorio.

---

## 2. Qué se ha construido

### 2.1 Componentes

| Fichero | Responsabilidad | Estado |
|---|---|---|
| `src/atalaya/ai/provider.py` | `LLMProvider` (ABC) + `AnthropicProvider` | Nuevo (152 líneas) |
| `src/atalaya/ai/triage.py` | Triaje de hallazgos con contexto estructurado | Nuevo (187 líneas) |
| `src/atalaya/ai/query.py` | Consulta NL sobre un escaneo completo | Nuevo (83 líneas) |
| `src/atalaya/core/exceptions.py` | `AIProviderError` | Ampliado |
| `src/atalaya/config.py` | `ai_max_tokens`, `ai_timeout`, `ai_max_retries`, `ai_concurrency` | Ampliado |
| `src/atalaya/api/routes/scans.py` | `POST /scans/{id}/triage` | Ampliado |
| `src/atalaya/api/routes/findings.py` | `POST /findings/ask` (activa el stub del Paso 1) | Ampliado |
| `src/atalaya/api/main.py` | `exception_handler` de `AIProviderError` → 502 | Ampliado |
| `tests/test_ai_provider.py` | 9 pruebas de `AnthropicProvider` | Nuevo |
| `tests/test_ai_triage.py` | 7 pruebas de triaje | Nuevo |
| `tests/test_ai_query.py` | 3 pruebas de consulta NL | Nuevo |
| `tests/test_api_ai.py` | 7 pruebas de los dos endpoints | Nuevo |

### 2.2 Flujo del triaje

```
POST /scans/{id}/triage
   │
   ▼
[repository.get_scan]      escaneo + activos + findings, precargados
   │
   ▼
findings con severity == unknown   (los ya triados se omiten: idempotente)
   │
   ▼
[build_finding_context]    selecciona hostname, IPs, estado, fuentes,
   │                       tipo de hallazgo, evidencia — nada más
   ▼
[complete_tool]             fuerza una llamada a la herramienta "record_triage"
   │  {"severity": ..., "impact": ..., "remediation": ...}
   ▼
[_TriageOutput.model_validate]   valida contra el enum de severidad y
   │                             longitudes mínimas
   ▼
finding.severity/impact/remediation actualizados in-memory
   │
   ▼
session.commit()            TriageResponse {scan_id, triaged, errors}
```

Un fallo en cualquier punto de ese camino para **un** hallazgo concreto
—el proveedor no responde, la respuesta no valida— no interrumpe el resto:
se registra en `errors` y se sigue con el siguiente, con concurrencia
acotada por `ai_concurrency` (por defecto 5, mismo patrón que
`DNS_CONCURRENCY` en el Paso 2).

### 2.3 Flujo de la consulta en lenguaje natural

```
POST /findings/ask  {"domain": "ejemplo.com", "question": "..."}
   │
   ▼
[repository.get_latest_scan]   (o get_scan si se indica scan_id)
   │  404 si no hay escaneo completado
   ▼
[build_scan_context]           TODO el escaneo: todos los activos,
   │                           todos sus hallazgos ya triados
   ▼
[complete]                     texto libre, con instrucción de no
   │                           inventar fuera de los datos dados
   ▼
AskResponse {scan_id, domain, question, answer}
```

A diferencia del triaje, un fallo aquí **sí** se propaga como error HTTP
(502): es una petición puntual bajo demanda directa del usuario, no un
elemento de una colección sobre la que tenga sentido degradar en silencio.

---

## 3. Bloque de entendimiento: los conceptos

### 3.1 Por qué una interfaz `LLMProvider` y no llamar al SDK directamente

`LLMProvider` es una clase abstracta (`abc.ABC`) con dos métodos
(`complete`, `complete_tool`) sin implementación. `AnthropicProvider` es la
**única** clase concreta que la implementa hoy. El resto de la capa IA
(`triage.py`, `query.py`) solo conoce `LLMProvider`, nunca `anthropic.*`.

La razón no es especulativa ("por si un día cambiamos de proveedor"): es
que **permite probar la lógica de triaje sin red y sin credenciales**. Un
doble de pruebas (`_FakeProvider`) que implemente la misma interfaz sustituye
a Anthropic en toda la suite (sección 6), del mismo modo que
`httpx.MockTransport` sustituye a crt.sh en el Paso 2. Sin esta interfaz,
probar `triage_finding()` habría exigido mockear los detalles internos del
SDK de Anthropic —su cliente HTTP, sus tipos de respuesta— acoplando las
pruebas a una librería externa que puede cambiar su forma interna entre
versiones.

### 3.2 `complete()` frente a `complete_tool()`: dos formas de pedir una respuesta

Un LLM puede responder de dos maneras útiles aquí:

- **Texto libre** (`complete`): apropiado para la consulta en lenguaje
  natural, donde la respuesta es prosa dirigida a una persona.
- **Con forma garantizada** (`complete_tool`): el triaje necesita
  exactamente tres campos (`severity`, `impact`, `remediation`), no un
  párrafo que haya que interpretar.

La forma ingenua de conseguir lo segundo es pedir "responde en formato
JSON" dentro del texto libre y luego hacer `json.loads()` sobre la
respuesta. Es frágil: basta con que el modelo anteponga una frase de
cortesía ("Claro, aquí tienes:") para que el `json.loads()` falle. La
alternativa que usa este proyecto es el **uso de herramientas** (*tool
use*) del SDK de Anthropic: se declara una "herramienta" con un JSON Schema
de entrada, y se fuerza al modelo a invocarla (`tool_choice={"type": "tool",
"name": "record_triage"}`). El propio proveedor valida la respuesta contra
el schema antes de devolverla — no hay texto que parsear, hay un `dict` ya
conforme.

```python
tools=[{"name": "record_triage", "input_schema": {...}}],
tool_choice={"type": "tool", "name": "record_triage"},
```

### 3.3 Contexto estructurado: la decisión de diseño central

`build_finding_context()` no serializa el objeto `Asset` ni el objeto
`Finding` completos. Selecciona seis campos concretos del activo (hostname,
IPs, estado, fuentes, si está activo, puertos abiertos) y dos del hallazgo
(tipo, evidencia):

```python
{
    "asset": {"hostname": ..., "ip_addresses": [...], "status": ...,
              "sources": [...], "is_active": ..., "open_ports": [...]},
    "finding": {"type": ..., "evidence": ...},
}
```

Quedan fuera deliberadamente: `id`, `scan_id`, timestamps, y cualquier
columna interna de la tabla. Dos razones. La primera, de calidad de salida:
un modelo de lenguaje razona sobre lo que se le da, y una columna irrelevante
(`id=47`) no aporta señal, solo ruido que compite por atención con los datos
que sí importan. La segunda, de estabilidad: el prompt no cambia si mañana
se añade una columna a `Asset` que no tiene que ver con la decisión de
severidad — desacopla el contrato del LLM de la evolución del esquema de
base de datos, el mismo principio que ya aplicó `core/persistence.py` en el
Paso 3 al no reutilizar los enums de `discovery` directamente.

### 3.4 Degradación controlada aplicada a una llamada de red no determinista

El principio ya establecido en el Paso 2 (`resolve_hostname` nunca lanza
excepción) se traslada aquí con una diferencia importante: un fallo de DNS
es binario (responde o no), pero un LLM puede fallar de **tres** formas
distintas, y cada una se trata de forma distinta:

1. **El proveedor no responde** (red, rate limit, autenticación) →
   `AIProviderError`, capturada en `triage_finding`.
2. **El proveedor responde, pero no llama a la herramienta esperada** →
   `AnthropicProvider.complete_tool()` ya lo convierte en `AIProviderError`
   antes de que `triage_finding` lo vea.
3. **El proveedor llama a la herramienta, pero con datos que no cumplen
   las reglas de negocio** (por ejemplo, `impact` vacío, que el JSON Schema
   no prohíbe pero `_TriageOutput` sí, con `Field(min_length=1)`) →
   `pydantic.ValidationError`.

Los tres casos dejan el `Finding` intacto (`severity` sigue en `unknown`) y
se reportan como un mensaje de error, nunca como una excepción que se
propague. `triage_findings()` aplica esto sobre una colección con
concurrencia acotada por un `asyncio.Semaphore`, exactamente el patrón de
`resolve_hostname` en el Paso 2.

### 3.5 Idempotencia de `POST /scans/{id}/triage`

El endpoint filtra los hallazgos antes de triarlos: solo los que tienen
`severity == unknown`. Triar dos veces el mismo escaneo no vuelve a llamar
al proveedor de IA para los hallazgos ya triados — el segundo `POST`
devuelve `{"triaged": 0, "errors": []}` sin coste. Es relevante porque una
llamada a un LLM tiene coste económico y de tiempo; un endpoint no
idempotente invitaría a triar el mismo escaneo por accidente cada vez que
alguien recargue el dashboard (Paso 6).

### 3.6 Por qué `ai/query.py` es un módulo aparte

El diseño original (`CLAUDE.md`, Paso 1) solo preveía `provider.py` y
`triage.py`. Al implementar la consulta NL apareció una diferencia de fondo
con el triaje: `triage_finding` necesita el contexto **mínimo** de un
hallazgo aislado; `ask()` necesita el escaneo **completo** (todos los
activos, todos sus hallazgos) para poder responder una pregunta agregada
como "¿qué activos exponen direccionamiento interno?". Meter ambos casos en
`triage.py` habría significado un único fichero con dos prompts de tamaño y
propósito muy distintos, y una función `build_context` ambigua sobre qué
nivel de detalle maneja. Separarlo seguía el mismo criterio que ya distingue
`core/persistence.py` (escritura) de `core/repository.py` (lectura, Paso 4):
una responsabilidad, un fichero.

### 3.7 Por qué `ask()` propaga el error y `triage_finding()` no

Es una asimetría deliberada, no una inconsistencia. `triage_findings`
procesa una **colección**: el valor de degradar con gracia es que 49
hallazgos triados con éxito no se pierden porque el 50 falló. `ask()`
atiende una **petición puntual**: no hay nada que "degradar", solo una
pregunta que no se pudo responder. Propagar `AIProviderError` hasta el
`exception_handler` de `main.py` (→ 502) le da a quien preguntó una señal
clara e inmediata, en vez de una respuesta vacía o un mensaje genérico
enterrado en un campo `error` que tendría que interpretar.

---

## 4. Decisiones de diseño

| Decisión | Justificación |
|---|---|
| `LLMProvider` como `ABC`, no una clase concreta con métodos que lanzan `NotImplementedError` | Permite dobles de prueba que implementan la interfaz sin depender del SDK de Anthropic (sección 3.1) |
| `complete_tool()` añadido sobre el contrato original (`complete()` solo) | El triaje necesita una respuesta con forma garantizada; parsear JSON de texto libre es frágil (sección 3.2) |
| Cliente de Anthropic inyectable en `AnthropicProvider(client=...)` | Punto de prueba: un doble que implemente `.messages.create()` evita red real en `test_ai_provider.py` |
| `ai/query.py` separado de `ai/triage.py` | Contexto de tamaño y propósito distintos (sección 3.6); desviación documentada del diseño original |
| `ask()` propaga `AIProviderError`; `triage_finding()` la captura | Uno es una petición puntual, el otro procesa una colección (sección 3.7) |
| `POST /scans/{id}/triage` filtra por `severity == unknown` | Idempotencia: no repetir trabajo (ni coste) sobre hallazgos ya triados |
| `AIProviderError` → 502, no 500 | El fallo es de un servicio *upstream* (el proveedor de IA), no de la propia API ni de la petición del cliente — la semántica correcta de un 502 |
| Ajustes `ai_max_tokens`/`ai_timeout`/`ai_max_retries`/`ai_concurrency` configurables | Mismo criterio que `DNS_CONCURRENCY`/`CRTSH_RETRIES` en el Paso 2: los límites de una fuente externa no deben quedar fijos en el código |
| Sin verificación de explotabilidad en el prompt de triaje | Restricción no negociable del proyecto (`CLAUDE.md`): reconocimiento señala patrones de riesgo, no confirma que sean explotables; el `system prompt` lo indica explícitamente al modelo |

---

## 5. Endpoint no previsto: `POST /scans/{id}/triage`

El diseño original de la API (Paso 1) fijaba seis endpoints; `/scans/{id}/
triage` no era uno de ellos. Se añadió al implementar este paso por una
razón concreta: sin una ruta que lo invoque, `ai/triage.py` habría quedado
implementado y probado, pero **inalcanzable desde fuera de la suite de
tests** — exactamente lo que `CLAUDE.md` pide evitar de forma explícita
("los stubs no son código muerto"). La alternativa habría sido triar
automáticamente cada escaneo al crearlo (dentro de `POST /scans`), pero eso
acopla dos operaciones de coste y fiabilidad muy distintas —una enumeración
DNS determinista y una llamada a un LLM externo— en una sola petición, y le
quita al usuario la posibilidad de decidir cuándo gastar una llamada al
proveedor de IA. Un endpoint propio, invocado explícitamente, separa ambas
decisiones sin perder la posibilidad de automatizarlo después (por ejemplo,
desde el dashboard, tras revisar el escaneo).

---

## 6. Validación

### 6.1 Pruebas automatizadas

**26 pruebas nuevas, 114 en total (88 + 26), todas en verde:**

| Fichero | Nº | Qué cubre |
|---|---|---|
| `tests/test_ai_provider.py` | 9 | Extracción de texto/herramienta de la respuesta, error sin bloques válidos, envoltura de fallos del SDK en `AIProviderError`, construcción sin clave, fábrica `get_provider()` |
| `tests/test_ai_triage.py` | 7 | Contexto estructurado (campos incluidos/excluidos), triaje exitoso, fallo del proveedor, respuesta inválida (severidad fuera de enum, `impact` vacío), degradación en colección, límite de concurrencia real (con `asyncio.sleep`) |
| `tests/test_ai_query.py` | 3 | Contexto de escaneo completo, pregunta + contexto serializados en el prompt, propagación del fallo |
| `tests/test_api_ai.py` | 7 | Triaje vía API (éxito, idempotencia, degradación, 404), consulta NL vía API (éxito, 404 sin escaneo previo, 502 con proveedor caído) |

Ninguna prueba llama al SDK de Anthropic de verdad ni requiere
`ANTHROPIC_API_KEY`: `AnthropicProvider` se prueba con un cliente inyectado
que implementa solo `.messages.create()` con respuestas programadas; el
resto de la capa IA se prueba con un `_FakeProvider` que implementa
`LLMProvider` directamente. Es el mismo criterio de determinismo que el
resto del proyecto: un fallo en la suite debe indicar siempre un problema
en el código, nunca una caída del servicio de Anthropic o un límite de
cuota agotado.

Durante la escritura de `test_ai_triage.py` apareció una discrepancia menor,
no un defecto de producción: los `Finding` construidos a mano en las
pruebas (sin pasar por una sesión de base de datos) tenían `severity=None`
en vez de `FindingSeverity.UNKNOWN`, porque el valor por defecto de la
columna solo se aplica al hacer `flush()` contra la BD, no al construir el
objeto en memoria. Se corrigió fijando `severity=FindingSeverity.UNKNOWN`
explícitamente en el helper de prueba `_finding()` — un recordatorio de que
un objeto ORM transitorio y uno recién leído de la base de datos no son
exactamente equivalentes, algo a tener en cuenta si se escriben más pruebas
sobre objetos construidos a mano en vez de persistidos.

### 6.2 Verificación en vivo contra la API real

Se levantó `uvicorn atalaya.api.main:app` como proceso real (continuación
directa de la verificación del Paso 4, misma sesión), **sin**
`ANTHROPIC_API_KEY` configurada — el estado real de este entorno de
desarrollo, sin clave de Anthropic disponible:

```
POST /scans/1/triage   -> 200 OK   {"scan_id":1,"triaged":0,"errors":[]}
POST /findings/ask     -> 502 Bad Gateway
  {"detail":"ANTHROPIC_API_KEY no configurada. Defínela en .env
             para usar la capa IA."}
```

El primer resultado no es un falso positivo: el escaneo de `scanme.nmap.org`
usado en la verificación del Paso 4 no generó ningún `Finding` (resuelve a
una IP pública, sin `leaks_internal_addressing`), así que `triage_scan` no
tenía nada que triar y **nunca llegó a invocar** `get_provider()` — de ahí
que devuelva `200` en vez de `502` pese a no haber clave configurada. Es el
comportamiento correcto de la idempotencia descrita en 3.5: no gastar una
llamada al proveedor cuando no hace falta.

El segundo resultado sí ejercita el camino de fallo real: `get_provider()`
intenta construir `AnthropicProvider`, no encuentra la clave, lanza
`AIProviderError`, y `main.py` la traduce a `502` con el mensaje exacto
que ve quien hace la petición — confirmando en un proceso HTTP real, no
solo en un test, que la cadena `get_provider() → AIProviderError →
exception_handler → 502` funciona de extremo a extremo.

El camino de **éxito** del triaje (un `Finding` real triado por el modelo)
y el de fallo del proveedor **con hallazgos pendientes** no se han
verificado contra el servicio real de Anthropic en esta sesión, al no
disponer de una clave de API: quedan cubiertos por
`test_api_ai.py::test_triage_scan_actualiza_findings_y_persiste` y
`test_triage_scan_degrada_con_gracia_si_falla_el_proveedor`, con un doble
de proveedor determinista. Queda como verificación pendiente para cuando se
disponga de `ANTHROPIC_API_KEY`: repetir el escaneo de un dominio con
`leaks_internal_addressing=true` (por ejemplo, un caso de laboratorio
construido a propósito) y confirmar en vivo la severidad, el impacto y la
remediación que devuelve el modelo real.

---

## 7. Consideraciones legales y éticas

El `system prompt` de `ai/triage.py` instruye explícitamente al modelo:
*"No confirmes ni describas cómo explotar el hallazgo: reconocimiento señala
patrones de riesgo, no verifica explotabilidad"*. No es una formalidad: es
la traducción directa a un prompt de la restricción no negociable número 6
de `CLAUDE.md`. Un LLM sin esa instrucción, ante un hallazgo de
direccionamiento interno expuesto, podría razonablemente ofrecerse a
explicar cómo aprovecharlo — es exactamente el tipo de contenido que este
proyecto se compromete a no generar.

`ai/query.py` aplica el mismo criterio en su propio `system prompt`, y
añade una segunda restricción: responder **solo** con los datos del escaneo
que se le entregan, declarando explícitamente cuando la pregunta no se
puede responder con esos datos. Esto evita que el modelo complete con
conocimiento general sobre el dominio preguntado (que podría no ser exacto,
o filtrar una expectativa incorrecta sobre lo que la herramienta
"sabe"), y mantiene cada afirmación de la respuesta trazable a un dato
concreto del escaneo persistido.

---

## 8. Limitaciones actuales

- **Un único proveedor implementado.** `get_provider()` solo reconoce
  `"anthropic"`; la interfaz está lista para más, pero no hay una segunda
  implementación que lo demuestre.
- **Sin verificación en vivo contra el servicio real de Anthropic** en esta
  sesión, por falta de `ANTHROPIC_API_KEY` (sección 6.2) — cubierto con
  dobles deterministas, pendiente de repetir con clave real antes de la
  defensa si es posible.
- **`POST /scans/{id}/triage` no es paralelo entre escaneos.** Si se lanza
  sobre varios escaneos a la vez, cada petición HTTP abre su propia
  concurrencia acotada (`ai_concurrency`); no hay un límite global sobre
  cuántas llamadas simultáneas recibe el proveedor de IA en todo el sistema.
- **Sin caché de respuestas.** Si se quisiera volver a triar (por ejemplo,
  tras cambiar el modelo configurado), no hay forma de forzarlo sin
  modificar directamente `severity` en la base de datos a `unknown`.
- **El triaje no ve el histórico del dominio.** Cada hallazgo se evalúa de
  forma aislada; no se le informa al modelo si el mismo tipo de hallazgo ya
  apareció en escaneos anteriores del mismo dominio (lo que sí permitiría
  `core/repository.py::diff_scans`, Paso 4, si se incorporara al contexto).

---

## 9. Bloque de defensa: preguntas previsibles

### Sobre la interfaz `LLMProvider`

**¿Qué aporta la interfaz frente a llamar directamente al SDK de Anthropic?**
Dos cosas concretas: permite sustituir el proveedor sin tocar `triage.py` ni
`query.py` (solo escribir una nueva subclase y una rama en `get_provider()`),
y permite probar toda la lógica de negocio con un doble que no hace red ni
necesita credenciales — que es, en la práctica, lo que ha permitido escribir
26 pruebas deterministas sin gastar una sola llamada real al modelo.

**¿Por qué `complete_tool()` y no simplemente pedir JSON en el prompt?**
Porque pedir "responde en JSON" sobre texto libre es frágil: basta con que
el modelo anteponga una frase antes del JSON para que el `json.loads()`
falle. `complete_tool()` fuerza al modelo a invocar una herramienta con un
JSON Schema definido (`tool_choice` fijo); el propio proveedor valida la
respuesta contra ese schema antes de devolverla.

**¿Qué pasa si el proveedor de IA cambia su forma de responder o su SDK?**
Solo se vería afectado `ai/provider.py`. El resto de la capa IA depende de
`LLMProvider`, no de los tipos internos de `anthropic`.

### Sobre el triaje

**¿Cómo se evita que el modelo invente severidad sin base?**
Recibe únicamente los campos verificados de un `Asset` y un `Finding` ya
persistidos (hostname, IPs, estado, fuentes, tipo y evidencia del
hallazgo) — nunca genera el hallazgo, solo lo clasifica y explica. Es el
mismo principio que ya fijó `CLAUDE.md` desde el Paso 1: "el triaje se sitúa
después de la persistencia, no antes".

**¿Qué pasa si el modelo devuelve una severidad que no existe, o un
`impact` vacío?**
`_TriageOutput` (un modelo Pydantic) valida la respuesta antes de aplicarla
al `Finding`: la severidad debe ser uno de los valores del enum
`FindingSeverity`, e `impact`/`remediation` no pueden estar vacíos. Si no
valida, el `Finding` se deja intacto (`unknown`) y el fallo se reporta en
`errors`, sin lanzar excepción.

**¿Por qué `POST /scans/{id}/triage` es idempotente?**
Porque filtra los hallazgos por `severity == unknown` antes de procesarlos.
Una llamada al proveedor de IA tiene coste; repetir el triaje de un hallazgo
ya clasificado sin motivo sería desperdiciarlo. Se verificó explícitamente
con `test_triage_scan_es_idempotente_con_findings_ya_triados`.

**¿Por qué la concurrencia está acotada?**
Mismo motivo que `DNS_CONCURRENCY` en el Paso 2: lanzar todas las llamadas
al proveedor de IA a la vez puede disparar límites de *rate limiting* del
proveedor y degradar los resultados, además de tener un coste económico
directo (cada llamada a un LLM se paga). `ai_concurrency` (por defecto 5)
lo acota, con el mismo patrón de `asyncio.Semaphore` que ya usa
`resolve_hostname`.

### Sobre la consulta en lenguaje natural

**¿Por qué `ask()` no está en `triage.py`?**
Porque necesita un contexto de tamaño distinto: el triaje ve un hallazgo
aislado, la consulta NL necesita el escaneo completo para responder
preguntas agregadas. Meterlos en el mismo fichero habría significado dos
prompts con necesidades muy distintas compitiendo por la misma función de
construcción de contexto.

**¿Cómo se evita que el modelo responda con información que no está en el
escaneo?**
El `system prompt` se lo prohíbe explícitamente: debe responder solo con
los datos proporcionados, y decir cuando la pregunta no se puede contestar
con ellos. No hay una verificación automática de que lo respete — es una
instrucción al modelo, no una garantía técnica —, algo que se podría
reforzar en el futuro pidiendo también una respuesta estructurada con citas
a los hallazgos concretos que la sustentan.

**¿Por qué `ask()` sí propaga el error y el triaje no?**
El triaje procesa una colección donde degradar con gracia conserva el valor
de los hallazgos que sí se triaron. `ask()` es una pregunta puntual: no hay
nada parcial que conservar si falla, así que propagar el error da una señal
inmediata a quien preguntó, en vez de una respuesta vacía difícil de
diagnosticar.

### Sobre la validación

**¿Se ha probado esto contra el modelo real de Anthropic?**
La capa de transporte (`AnthropicProvider` construyendo la petición,
extrayendo texto o el resultado de una herramienta, envolviendo errores del
SDK) se probó con un cliente doble que reproduce la forma exacta de las
respuestas del SDK. El camino completo `HTTP → get_provider() →
AIProviderError → 502` se verificó en vivo contra un proceso real. Lo que
no se ha verificado en esta sesión es una llamada real al modelo de Claude,
por no disponer de `ANTHROPIC_API_KEY` en este entorno — es la verificación
pendiente más importante antes de la defensa (sección 6.2, 8).

**¿Por qué no se generó una clave de prueba para completar esa
verificación?**
Es una decisión pendiente de quien lleva el proyecto, no técnica: usar una
clave real implica coste económico por cada llamada. La cobertura con
dobles deterministas prueba que el código hace lo correcto con cualquier
respuesta bien formada o cualquier fallo del proveedor; falta la
confirmación de que las respuestas *reales* de Claude son razonables para
este dominio, que es una pregunta de calidad del prompt, no de corrección
del código.

### Preguntas de comprensión

**¿Qué es el uso de herramientas (*tool use*) en un LLM?**
Un mecanismo por el que se le declara al modelo un conjunto de funciones
disponibles, cada una con un esquema de entrada (JSON Schema). El modelo
puede "llamar" a una de ellas en vez de responder en texto libre, y el
proveedor garantiza que los argumentos de esa llamada cumplen el esquema
declarado. Aquí se usa para forzar una respuesta con exactamente los tres
campos que el triaje necesita.

**¿Qué diferencia hay entre `AIProviderError` y una excepción del SDK de
Anthropic?**
`AIProviderError` es la excepción propia del proyecto (`core/exceptions.py`);
las excepciones de `anthropic` (`AnthropicError` y sus subclases) son
internas del SDK y se capturan y traducen dentro de `AnthropicProvider`, sin
que lleguen nunca a `triage.py`, `query.py` ni a las rutas de la API. Es el
mismo principio que ya aplica `discovery/subdomains.py` con las excepciones
de `httpx` y `dnspython`.

---

## 10. Estado de los requisitos de la práctica

| Requisito | Estado tras el Paso 5 |
|---|---|
| **API o webhook** | ✅ Sin cambios de fondo; `/findings/ask` deja de estar en 501 |
| **GitHub con historial** | ✅ 27 commits publicados (5 de esta fase) |
| **Base de datos** | 🔨 Sin cambios en esta fase |
| **Aplicación web** | 🔨 Sin cambios en esta fase |
| **Reporte con portada** | ⬜ Paso 7 |

El requisito diferencial del proyecto —el triaje por IA, descrito en
`CLAUDE.md` como "el componente diferencial"— no aparece en la tabla de
los cinco obligatorios porque no es uno de ellos, pero es la pieza que
distingue a Atalaya de un enumerador de subdominios con base de datos.

---

## 11. Próximos pasos

| Fase | Contenido |
|---|---|
| **Paso 6** | Dashboard completo: lanzar escaneos, ver activos/hallazgos triados, preguntar en NL — consumiendo esta API |
| **Paso 7** | Informe ejecutivo con portada, incorporando el triaje de cada hallazgo |
| **Paso 2 (resto)** | Puertos, cabeceras HTTP y TLS — ampliarían el vocabulario de `finding_type` que el triaje puede clasificar, hoy limitado a `internal_addressing_leak` |
| Pendiente transversal | Verificar en vivo contra el servicio real de Anthropic en cuanto se disponga de `ANTHROPIC_API_KEY` (sección 6.2) |

---

## 12. Conclusión del Paso 5

El Paso 5 entrega el componente diferencial del proyecto: una capa de IA
aislada tras una interfaz, que recibe hallazgos ya verificados y
persistidos —nunca datos en bruto— y devuelve una clasificación razonada,
con degradación controlada ante cualquier fallo del proveedor y sin
necesidad de una sola línea de parseo de texto libre para el triaje, gracias
al uso de herramientas forzadas.

Dos aportaciones más allá del código merecen subrayarse. La primera, una
asimetría de diseño deliberada —el triaje degrada con gracia, la consulta
NL propaga el error— que refleja una distinción real entre procesar una
colección y atender una petición puntual, no una inconsistencia. La
segunda, la honestidad de la sección 6: la capa de transporte con Anthropic
y el camino de fallo completo se verificaron en vivo contra la API real; la
calidad de una respuesta real del modelo sobre un hallazgo real queda como
verificación pendiente, declarada como tal en vez de darse por supuesta.
