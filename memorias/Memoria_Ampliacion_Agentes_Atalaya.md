# Memoria técnica — Ampliación: sistema de agentes de IA

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación posterior a los 7 pasos de la hoja de ruta original
(todos cerrados, ver `Memoria_Paso1` a `Memoria_Paso7`) — no es un requisito
obligatorio de la entrega, profundiza el componente diferencial (capa IA) y
la calidad percibida de cara a la defensa oral.
**Estado:** Shodan, subdomain takeover, sistema de agentes de IA, `GeminiProvider`
y cableado a la API — completados y verificados. Rediseño visual del
dashboard — en curso al cierre de esta memoria (ver sección 8).

---

## 1. Resumen ejecutivo

Con los cinco requisitos obligatorios y los siete pasos de la hoja de ruta
ya cerrados (`Memoria_Paso7`), esta fase amplía dos ejes del proyecto que
quedaban como deuda técnica explícitamente documentada desde el Paso 2:
**fuente única de enumeración** y **sin consulta de CNAME** — y añade el
componente que más peso tiene en la defensa oral: un **sistema de agentes
de IA especializados**, en vez de un único prompt genérico, más un segundo
proveedor de IA (Gemini) que demuestra que la interfaz `LLMProvider` cumple
lo que promete desde el Paso 5.

Resultados tangibles:

- **Shodan** (`discovery/shodan.py`) como segunda fuente de enumeración de
  subdominios, opcional, consultada concurrentemente con crt.sh.
- **Detección de riesgo de subdomain takeover** (`discovery/takeover.py`)
  vía patrón de CNAME, sobre los hosts que no resuelven por A/AAAA —
  resolviendo exactamente la deuda técnica anotada en el Paso 2.
- **Cinco agentes de IA nuevos** (`ai/prompter.py`, `ai/analyst.py`,
  `ai/takeover_detective.py`, `ai/report_writer.py`, `ai/diff_analyst.py`),
  cada uno con contexto y responsabilidad propia, sobre la misma interfaz
  `LLMProvider` que ya usaba `ai/triage.py` — **sin tocar `ai/triage.py`**,
  por decisión explícita.
- **`GeminiProvider`**, segunda implementación de `LLMProvider` (Google AI
  Studio), verificada en vivo contra el modelo real.
- **Endpoint de diff** (`GET /scans/{id}/diff/{other_id}`), exponiendo
  `core/repository.py::diff_scans()`, que existía sin usar desde el Paso 4.
- **Resumen ejecutivo con IA en el informe PDF**, con un `risk_score`
  calculado de forma determinista (sin IA) y compartido entre el PDF y el
  dashboard.
- **260 tests en verde** (170 al cierre del Paso 7), sin contar el trabajo
  final del rediseño del dashboard (sección 8).
- **Un sistema de subagentes de Claude Code** (`.claude/agents/`) para
  dividir el trabajo de esta ampliación en piezas independientes,
  verificadas una a una antes de pasar a la siguiente.

---

## 2. Por qué esta ampliación y no otra

El margen tras cerrar el Paso 7 se podía invertir en robustecer cualquiera
de las piezas de deuda técnica documentada (comodines DNS, banner grabbing
de puertos, validación de cadena TLS...). Se priorizaron Shodan y
takeover porque ambas estaban señaladas desde el Paso 2 con una
justificación concreta de por qué importan (Shodan amplía cobertura más
allá de lo certificado; takeover es la interpretación de seguridad de un
dato que el proyecto ya observaba y descartaba — el 48% de hosts que no
resuelven en el caso real de `github.com`).

El sistema de agentes de IA se priorizó porque es, literalmente, **el
componente diferencial del proyecto** según el propio `CLAUDE.md` desde el
Paso 1: la parte que distingue a Atalaya de un enumerador de subdominios
con base de datos. Un único prompt genérico para "todo lo relacionado con
IA" no demuestra tanto criterio de diseño como una arquitectura de agentes
especializados, cada uno con el contexto mínimo necesario para su tarea —
el mismo principio de "contexto estructurado, no un dump de la fila de BD"
que ya regía `ai/triage.py`, aplicado ahora a cinco tareas distintas.

`GeminiProvider` se añadió, más allá de ampliar opciones, como **prueba
verificable** de una decisión de diseño que el proyecto lleva defendiendo
desde el Paso 1 ("Capa IA tras interfaz `LLMProvider`: el modelo es
configuración, no dependencia rígida") pero que hasta ahora solo tenía una
implementación concreta. Con dos proveedores intercambiables sin tocar
ninguna lógica de negocio, la afirmación deja de ser una intención de
diseño y pasa a ser un hecho demostrado.

---

## 3. Shodan: segunda fuente de enumeración

### 3.1 Diseño

`discovery/subdomains.py::enumerate_subdomains()` consulta crt.sh
(`fetch_crtsh`) y `discovery/shodan.py::fetch_shodan_subdomains()`
**concurrentemente** (`asyncio.gather`), fusionando los hostnames
resultantes en un `dict[str, set[DiscoverySource]]` que conserva de qué
fuente(s) procede cada uno — un host puede aparecer en ambas, y esa
información tiene valor de trazabilidad.

`discovery/shodan.py` sigue el mismo criterio de degradación controlada
que `fetch_crtsh`, con matices propios de una fuente **opcional**:

- Sin `SHODAN_API_KEY`, se omite de inmediato, sin tocar la red ni generar
  ninguna incidencia — es ampliación de cobertura, no un requisito.
- `404` (Shodan sin datos indexados para el dominio) no es un fallo.
- `401`/`403` (clave rechazada o sin permiso) **no reintenta**: un fallo de
  autorización no se arregla insistiendo, a diferencia de un `5xx`
  transitorio, que sí se reintenta con backoff exponencial (mismo patrón
  que crt.sh).

### 3.2 Hallazgo real: el plan gratuito no tiene acceso a `/dns/domain`

Al verificar en vivo contra la API real de Shodan con la clave disponible,
`/dns/domain/{domain}` devolvió `403` con el cuerpo
`{"error": "Requires membership or higher to access"}`. Comprobado con
`GET /api-info`: la clave es del plan `oss` (gratuito, para proyectos de
código abierto), y ese endpoint concreto requiere un plan de pago.

La primera implementación reintentaba un `403` igual que un `5xx` — 3
intentos con backoff, ~3 segundos perdidos por escaneo sin ninguna
posibilidad de éxito. Se corrigió para que `401`/`403` no reintenten,
igual criterio que ya aplicaba `401` antes de encontrar este caso real. Es
el mismo patrón de trabajo que ya dejaron los Pasos 2 y 4: un defecto
detectado sobre datos reales, no solo con dobles de prueba, y corregido
antes de darse por bueno.

**Consecuencia práctica:** con esta clave, Shodan está completamente
implementado y probado, pero no aporta subdominios reales — solo con un
plan de pago llegaría a hacerlo. Documentado como deuda técnica conocida
en CLAUDE.md, no ocultado.

---

## 4. Detección de riesgo de subdomain takeover

### 4.1 El razonamiento central

Un *subdomain takeover* ocurre cuando un CNAME sigue apuntando a un
servicio de hosting de terceros (GitHub Pages, Heroku, S3, Azure...) cuyo
recurso ya no está reclamado: cualquiera puede darlo de alta en ese
proveedor y servir contenido bajo el dominio de la víctima — indistinguible,
para quien lo visite, del sitio legítimo.

La pregunta de diseño central fue: **¿sobre qué hosts hay que mirar el
CNAME?** La respuesta, ya insinuada por la deuda técnica del Paso 2: no
sobre los `active` (tienen IP real, un servicio propio detrás), sino sobre
los que **no** resuelven por A/AAAA (`no_answer`, `nxdomain`,
`unroutable`) — ahí es donde un CNAME hacia un recurso liberado deja de
tener a qué apuntar por la vía normal, y el propio registro CNAME es la
única pista que queda. Mirar solo `active_records` (como hacían puertos,
cabeceras y TLS) habría dejado fuera exactamente los casos que importan.

### 4.2 Qué se construyó

- `discovery/models.py::TakeoverCandidate` — `hostname`, `cname`,
  `provider`, `pattern_matched`. Documentado explícitamente como
  **candidato por patrón, no confirmación**.
- `discovery/takeover.py::find_takeover_candidates()` — filtra por estado,
  resuelve el CNAME de cada candidato (concurrente, acotado por
  `settings.dns_concurrency`, reutilizado sin inventar una variable nueva),
  y lo compara contra `TAKEOVER_PATTERNS`: ~20 proveedores citados
  habitualmente en la práctica de takeover (GitHub Pages, Heroku ×2, S3,
  Azure ×4, Fastly, Pantheon, Shopify, Webflow, WordPress.com, Zendesk,
  Ghost, Statuspage, WP Engine, Bitbucket, Tumblr, Surge.sh, Unbounce),
  documentada explícitamente como no exhaustiva — mismo criterio de
  honestidad que `COMMON_PORTS`.
- Módulo **independiente** de `discovery/subdomains.py` (no importa nada de
  allí, para no introducir un import circular con `discovery/enrichment.py`
  importando ambos) — mismo criterio ya aplicado por `discovery/shodan.py`.
- **Ninguna petición HTTP al recurso de terceros.** Resolver el CNAME y
  compararlo contra la tabla es reconocimiento pasivo (una consulta DNS);
  comprobar si el recurso de terceros responde "no existe" cruzaría a
  verificar explotabilidad, prohibido explícitamente por la restricción de
  seguridad #6 de `CLAUDE.md`. Se prefiere un falso positivo señalado por
  patrón a confirmar un takeover real.

### 4.3 Integración sin tocar la capa de persistencia

`discovery/enrichment.py::enrich_scan()` incorpora la búsqueda de takeover
como cuarta rama del `asyncio.gather`, pero sobre `result.records`
completo (no `result.active_records`, a diferencia de puertos/cabeceras/
TLS) — y ya no hace `return` anticipado cuando no hay hosts activos, porque
la búsqueda de takeover sigue siendo relevante en ese caso.

Cada `TakeoverCandidate` se traduce a un `DiscoveryFinding`
(`finding_type="subdomain_takeover_risk"`) dentro de
`EnrichmentResult.findings_by_hostname()`, el mismo mecanismo genérico que
ya agrupaba hallazgos de cabeceras y TLS. **`core/persistence.py` no
necesitó ningún cambio**: `apply_discovery_findings()` ya itera
genéricamente sobre `finding_type`/`evidence` sin mirar el tipo concreto —
verificado leyendo el código antes de darlo por hecho, no asumido. Y
`save_subdomain_scan()` crea un `Asset` para **todo** `record` del
escaneo, sin filtrar por estado, así que los hosts `no_answer`/`nxdomain`
(donde vive el candidato) sí tienen una fila donde enganchar el hallazgo —
el punto donde más fácilmente se habría perdido el dato en silencio, y se
verificó explícitamente que no ocurre.

---

## 5. Sistema de agentes de IA

### 5.1 Por qué agentes especializados y no un único prompt

El encargo original pedía explícitamente que la herramienta "no dependa de
un único prompt genérico al modelo, sino que cada tarea tenga un agente
especializado con su propio contexto, instrucciones y criterio". Es la
extensión natural del principio que ya regía `ai/triage.py` desde el Paso
5 — contexto estructurado, seleccionado a propósito para la tarea concreta
— aplicado ahora a cinco tareas con necesidades de contexto muy distintas
entre sí: un hallazgo aislado (triaje) no necesita el mismo contexto que
un escaneo completo (analista), que una lista de candidatos de takeover
(detective), que un par de escaneos a comparar (diff). Mezclarlas en un
único prompt habría significado competir por atención con datos
irrelevantes para cada pregunta concreta — el mismo argumento que ya
motivó separar `ai/query.py` de `ai/triage.py` en el Paso 5.

### 5.2 Los seis agentes (triaje + cinco nuevos)

| Agente | Fichero | Categoría de fallo | Qué recibe | Qué devuelve |
|---|---|---|---|---|
| Triaje (sin tocar) | `triage.py` | Colección — degrada | `Asset` + `Finding` | severidad, impacto, remediación |
| Prompter | `prompter.py` | Puntual — propaga | Resumen ligero del escaneo + pregunta | `AnalystResult` (reutilizado) |
| Analista | `analyst.py` | Puntual — propaga | Severidades, hallazgos crítical/high | `AnalystResult`: respuesta, patrones, combinaciones, prioridades |
| Detective de takeover | `takeover_detective.py` | Colección — degrada | `TakeoverCandidate`(s) | `TakeoverAssessment`(s): prioridad + razonamiento |
| Redactor de informes | `report_writer.py` | Puntual — propaga* | `risk_score` + hallazgos crítical/high | 2-3 párrafos en prosa |
| Comparador de escaneos | `diff_analyst.py` | Puntual — propaga | `ScanDiff` + los dos `Scan` | Valoración en prosa |

\* `report_writer` propaga como función, pero quien lo integra
(`reporting/generator.py`) la captura — ver sección 7.

La distinción **colección vs. puntual** es la misma que ya estableció el
Paso 5 para justificar por qué `triage_findings()` degrada y `ask()`
propagaba: una colección conserva valor parcial si un elemento falla (49
hallazgos triados con éxito no se pierden porque el 50 falló); una
petición puntual no tiene nada parcial que conservar.

### 5.3 El Prompter: enrutado con reformulación, no solo clasificación

`ai/prompter.py::route_and_answer()` es el reemplazo de
`ai/query.py::ask()` para `POST /findings/ask`. No es un simple
`if`/`else` de clasificación: usa `complete_tool()` con una herramienta
`route_query` que el modelo debe llamar siempre, devolviendo tanto el
agente elegido (`"analyst"` o `"takeover"`) como la pregunta **reformulada
con el contexto del escaneo ya incorporado** — p. ej., "¿qué activos son
más peligrosos?" se convierte en una pregunta que ya sabe que hay tres
hallazgos `critical` sin triar en un host concreto, así que el agente
especializado no tiene que volver a pedir ese contexto.

Dos decisiones de robustez:

1. **Clasificación insegura → `"analyst"` por defecto**, no una excepción.
   Si el modelo no devuelve un `agent` reconocido o una `refined_question`
   vacía, la pregunta nunca se queda sin responder por un fallo de
   enrutado — solo se responde con el agente genérico en vez del
   especializado.
2. **La rama "takeover" no vuelve a invocar `discovery/takeover.py`.** Los
   candidatos ya están persistidos como `Finding(finding_type=
   "subdomain_takeover_risk")` si el escaneo pasó por el enriquecimiento;
   recalcularlos sería repetir trabajo de red ya hecho. Se reconstruye el
   contexto a partir de `{hostname, evidence}` de esos hallazgos — los
   mismos dos campos que ya usa `ai/triage.py::build_finding_context` para
   un `Finding`, en vez de intentar reconstruir el `TakeoverCandidate`
   original (`cname`/`pattern_matched`) parseando el texto de `evidence`,
   que acoplaría este módulo al formato exacto que genera
   `EnrichmentResult.findings_by_hostname()`.

Ambos agentes (`analyst`/`takeover` vía prompter) devuelven el mismo tipo
`AnalystResult` — reutilizado, no duplicado — para que `route_and_answer()`
tenga una única forma de respuesta sin importar a cuál se enrutó, y
`api/routes/findings.py` no tenga que manejar dos formas distintas.

### 5.4 `ai/query.py` se retiró

Con el prompter cubriendo `POST /findings/ask`, `ai/query.py::ask()` quedó
sin ningún llamador (verificado con `grep -rn "ai\.query" src tests` antes
de borrarlo, no asumido) y se eliminó junto con `tests/test_ai_query.py`.
No es una pérdida de funcionalidad: `ai/analyst.py::analyze_scan()` cubre
el mismo caso de uso (pregunta sobre un escaneo completo) con más señal
estructurada, no solo prosa libre.

---

## 6. `GeminiProvider`: segundo proveedor de IA

### 6.1 Por qué demuestra algo, no solo añade una opción

`LLMProvider` (Paso 5) se presentó desde el principio como una interfaz
que desacopla el modelo de la lógica de negocio. Hasta esta ampliación,
esa afirmación tenía una sola implementación concreta (`AnthropicProvider`)
que la respaldara — no había manera de comprobar, sin escribir una
segunda, si la abstracción realmente aislaba lo que decía aislar.
`GeminiProvider` es esa comprobación: **ninguna línea de `ai/triage.py`,
`ai/prompter.py`, `ai/analyst.py`, `ai/takeover_detective.py`,
`ai/report_writer.py` ni `ai/diff_analyst.py` cambió** para incorporarlo.

### 6.2 Implementación

Sobre el SDK oficial `google-genai` (el consolidado, no el
`google-generativeai` anterior), con el cliente **asíncrono**
(`client.aio.models.generate_content`) — coherente con "todo asíncrono"
(CLAUDE.md); el SDK ya expone la variante async directamente, sin
necesidad de envolver una llamada síncrona en un hilo.

`complete_tool()` fuerza la llamada a herramienta con
`FunctionCallingConfig(mode="ANY", allowed_function_names=[tool_name])` —
el equivalente Gemini del `tool_choice={"type": "tool", "name": ...}` fijo
de Anthropic: fuerza la llamada a exactamente esa herramienta, no
"alguna de las disponibles". Todos los nombres de campo (`system_instruction`,
`max_output_tokens`, `tools`, `tool_config`, `parameters_json_schema`,
`function_declarations`, `allowed_function_names`) se verificaron contra
el paquete `google-genai` instalado (introspección de
`model_fields`/`inspect.signature`), no solo contra documentación —
incluido confirmar que `FunctionCallingConfigMode` es un `str, Enum` y
acepta la cadena `"ANY"` directamente sin necesitar el símbolo del enum.

### 6.3 Bug real encontrado y corregido: `content=None`

Al cablear los agentes a la API y probarlos en vivo contra Gemini bajo
presión de cuota (free tier), `GeminiProvider.complete_tool()` lanzó
`AttributeError: 'NoneType' object has no attribute 'parts'` en vez de un
`AIProviderError` controlado: un `candidate` de la respuesta puede traer
`content=None` (respuesta cortada sin contenido), y el código no lo
contemplaba antes de iterar `.parts`. Se corrigió con un guard explícito
(`if candidate.content is None: continue`) y se cubrió con un test que
reproduce exactamente ese caso — mismo patrón de trabajo que el resto del
proyecto: un defecto real, no solo teórico, detectado sobre uso real y
corregido antes de darse por bueno.

### 6.4 Verificación en vivo

A diferencia de Anthropic (sin clave disponible en este entorno; ver
sección 9), sí hay `GEMINI_API_KEY` funcional. Se verificó en vivo, no
solo con dobles:

- `complete()` — respuesta libre correcta.
- `complete_tool()` — severidad `critical` razonada sobre un caso de RDP
  expuesto a Internet sin VPN.
- `triage_finding()` **real, sin modificar** — `severity=MEDIUM`, impacto
  y remediación coherentes sobre un hallazgo real de direccionamiento
  interno filtrado.
- `POST /findings/ask` (vía prompter) sobre un escaneo real.
- `GET /scans/{id}/diff/{other_id}` — comparación real de dos escaneos con
  análisis en prosa de Gemini.
- `GET /scans/{id}/report` — PDF con resumen ejecutivo real (6070 bytes,
  frente a 5631 bytes sin resumen — diferencia coherente con la ausencia
  del texto).

---

## 7. Cableado a la API

### 7.1 `POST /findings/ask`

Sustituida la llamada directa a `ai/query.py::ask()` por
`ai/prompter.py::route_and_answer()`. `AskResponse` se amplió con
`patterns`/`concerning_combinations`/`priorities`, no solo `answer` —
decisión: es señal real ya razonada por el modelo, y descartarla
obligaría a una segunda llamada para recuperarla. `default_factory=list`
cubre el caso del agente de takeover, que deja `patterns` vacío. El
dashboard, verificado, solo lee `answer`/`scan_id`/`domain` — compatible
con el esquema ampliado sin necesitar ningún cambio.

### 7.2 `GET /scans/{id}/diff/{other_id}`

Expone `core/repository.py::diff_scans()`, que existía desde el Paso 4 sin
ningún endpoint que lo invocara. `previous`/`current` se deciden por
`started_at`, **no** por el orden de los ids en la URL — pedir
`/scans/5/diff/3` y `/scans/3/diff/5` da la misma comparación, verificado
explícitamente con un test. 400 si los dos escaneos son de dominios
distintos (comparar dominios distintos no tiene sentido); 404 si falta
alguno; propaga `AIProviderError` → 502 (petición puntual, mismo criterio
que `/findings/ask`).

### 7.3 Resumen ejecutivo del informe: la asimetría deliberada

`reporting/generator.py::generate_report()` ganó un parámetro
`provider: LLMProvider | None`. Con proveedor, incluye el resumen de
`ai/report_writer.py`; sin él, o si falla (`AIProviderError`), **el
informe se genera igual**, sin resumen. Es una asimetría deliberada
respecto al endpoint de diff (que sí propaga el 502): el informe con
portada era un requisito obligatorio de la práctica *antes* de que
existiera la capa IA, así que no puede depender de que un proveedor
externo esté disponible; el diff, en cambio, nace con la IA como parte
integral de lo que devuelve — sin análisis no hay respuesta que dar.
`api/routes/scans.py::download_report` captura `AIProviderError` en dos
puntos distintos (construcción del proveedor y llamada al modelo), no uno
solo, para que ningún fallo de la capa IA llegue a bloquear la descarga.

`risk_score` (0-100) se calcula con pesos por severidad
(`critical=25, high=10, medium=4, low=1`, acotado a 100,
`reporting/generator.py::_RISK_WEIGHTS`) — sin IA, puro cálculo
determinista sobre `severity_counts`. El dashboard replica exactamente
estos mismos pesos (ver sección 8) para que el número que ve el usuario en
pantalla no contradiga al que aparece en el PDF del mismo escaneo.

---

## 8. Dashboard: diseño visual profesional

*(Sección a completar al cierre de esta fase — en curso al escribir esta
memoria.)*

### 8.1 Contexto y encargo

Rediseño completo de `dashboard/app.py` con criterio estético de
herramienta comercial de seguridad ofensiva (referentes: Shodan,
VirusTotal, Maltego, Burp Suite), no una demo académica ni el aspecto por
defecto de Streamlit: paleta oscura, tipografía monoespaciada para datos
técnicos, `risk_score` como métrica principal del detalle de un escaneo.
Criterio de validación literal: si alguien externo al proyecto ve el
dashboard sin contexto, debe asumir que es un producto comercial, no un
proyecto de máster.

### 8.2 Bug real encontrado y corregido durante el proceso

Un primer intento de rediseño (interrumpido por límite de cuota de sesión
de un subagente y retomado por otro) dejó `dashboard/app.py` con ~1086
líneas de CSS sofisticado (paleta de tres niveles de elevación, JetBrains
Mono + Inter, severidad con rojo reservado a crítico, masthead con
wordmark, tabs como control segmentado, chips de puertos...) pero **con un
bug de renderizado real**: `st.markdown(_CSS, unsafe_allow_html=True)`,
con el contenido real (~20KB, muchas líneas en blanco dentro del bloque
`<style>`), dejaba de tratarse como HTML crudo a partir de cierto punto y
el CSS se mostraba como texto literal en pantalla.

Diagnosticado por bisección binaria del contenido (no adivinado): un caso
mínimo de 6 líneas funcionaba correctamente con
`st.markdown(..., unsafe_allow_html=True)`; el contenido real, no. Bisecar
por longitud aisló el problema al contenido extenso del bloque `<style>`
en sí, no al preámbulo de `<link>` de fuentes. La corrección: `st.html(_CSS)`
— la API dedicada de Streamlit (1.63) para insertar HTML/CSS, que evita el
parser de Markdown por completo. Verificado que resuelve el problema con
una captura de pantalla real tras el cambio: el CSS se aplica
correctamente (masthead, paleta, tipografía, tabla de escaneos, leyenda de
severidad y bandas de `risk_score` en el sidebar, todo visible y
correctamente estilizado).

### 8.3 Estado al cierre de esta memoria

*(Completar con el resultado final del subagente `atalaya-dashboard`:
cambios de pulido aplicados, verificación visual final con capturas reales
que alguien haya mirado, decisión sobre el commit "WIP" que quedó de un
intento anterior, y conteo de tests final.)*

---

## 9. El sistema de agentes de Claude Code (tooling de desarrollo)

Distinto de los agentes de IA de Atalaya (sección 5), esta ampliación se
construyó coordinando **cuatro subagentes de Claude Code**
(`.claude/agents/`), cada uno con responsabilidad exclusiva y sin solape,
despachados en orden con verificación independiente entre cada uno:

1. **`atalaya-discovery`** — Shodan y subdomain takeover (secciones 3-4).
2. **`atalaya-ai-agents`** — los cinco agentes de IA (sección 5).
3. **`atalaya-api`** — cableado a la API (sección 7).
4. **`atalaya-dashboard`** — rediseño visual (sección 8).

Cada uno se verificó contra tres criterios antes de pasar al siguiente:
(1) tests en verde, (2) integración real comprobada (no solo el resumen
del propio subagente), (3) un caso de prueba manual real. En dos casos
concretos esa verificación independiente encontró defectos que el
subagente no había visto: el problema de `content=None` en `GeminiProvider`
(sección 6.3, encontrado por `atalaya-api` al probar en vivo) y el bug de
`st.markdown`/CSS del dashboard (sección 8.2, encontrado por el
coordinador antes de continuar). Ninguno de los dos se dio por bueno sin
corregirlo primero.

**Nota sobre el mecanismo:** los `.claude/agents/*.md` no se recargan
dentro de una sesión ya iniciada — solo están disponibles como
`subagent_type` con nombre propio en sesiones que arrancan *después* de
que existan. Durante esta sesión, se despacharon como agentes
`general-purpose` con el contenido completo del `.md` pegado como
instrucciones; el resultado práctico es idéntico.

---

## 10. Consideraciones legales y éticas

Ninguna amplía la superficie de exposición sobre terceros más allá de lo
ya cubierto en memorias anteriores:

- Shodan y la resolución de CNAME (takeover) son consultas a servicios de
  terceros (Shodan, resolvers DNS), no tráfico dirigido a la
  infraestructura del dominio analizado — mismo carácter pasivo que crt.sh
  y la resolución DNS del Paso 2.
- La restricción de seguridad #6 ("nunca verificar explotabilidad") se
  aplica de forma literal y verificable en `discovery/takeover.py` (sin
  petición HTTP al recurso de terceros) y en el *system prompt* de
  `ai/takeover_detective.py` (nunca afirma que el recurso esté confirmado
  como secuestrable).
- Dos claves de API nuevas en `.env` (`SHODAN_API_KEY`, `GEMINI_API_KEY`),
  ambas gitignoradas, nunca versionadas — mismo tratamiento que
  `ANTHROPIC_API_KEY` desde el Paso 5.

---

## 11. Limitaciones actuales

- **Shodan sin cobertura real** con la clave disponible (plan `oss`, sin
  acceso a `/dns/domain`) — código completo y probado, pendiente de una
  clave de pago para aportar subdominios reales.
- **Tabla de patrones de takeover no exhaustiva** (~20 proveedores) — deuda
  técnica documentada, no silenciada, mismo criterio que `COMMON_PORTS`.
- **Verificación en vivo de los 5 agentes nuevos, pendiente con Anthropic**
  (el proveedor por defecto del proyecto). Probados con dobles
  deterministas y verificados en vivo contra **Gemini** (interfaz
  compartida, así que si funciona con uno funciona con el otro), pero no
  contra Anthropic por no disponer de esa clave en este entorno — queda
  como verificación formal pendiente antes de la defensa, no dada por
  hecha solo porque funcionó con el otro proveedor.
- **Sin caché ni límite global de coste de IA entre los seis agentes.**
  Cada uno acota su propia concurrencia (heredada de `settings.ai_*`),
  pero no hay un límite agregado de gasto por sesión de usuario.
- **Dashboard: pendiente de cierre** al escribir esta memoria — ver
  sección 8.3.

---

## 12. Bloque de defensa: preguntas previsibles

### Sobre la decisión de ampliar

**¿Por qué esto y no otra pieza de la deuda técnica?**
Shodan y takeover porque ya estaban señalados desde el Paso 2 con el
motivo concreto de por qué importaban. El sistema de agentes porque es,
según el propio diseño del proyecto desde el Paso 1, el componente
diferencial — la pieza que más peso tiene en una defensa que evalúa
también la capa IA, no solo el descubrimiento.

**¿Estos requisitos eran obligatorios para aprobar?**
No. Los cinco requisitos y los siete pasos estaban cerrados antes de
empezar esta ampliación (`Memoria_Paso7`). Esto profundiza el componente
diferencial y la calidad percibida, no cubre una carencia de la entrega.

### Sobre Shodan

**¿Por qué Shodan devuelve 403 y no subdominios reales?**
La clave disponible es del plan gratuito `oss`; `/dns/domain/{domain}`
requiere un plan de pago — verificado contra la API real con `GET
/api-info`. El código distingue correctamente ese caso (no reintenta un
fallo de autorización) de un fallo transitorio, pero no hay forma de
obtener cobertura real sin cambiar de plan.

**¿Por qué crt.sh y Shodan se consultan a la vez y no uno tras otro?**
Son fuentes independientes entre sí (hosts distintos, sin autenticación
compartida): consultarlas concurrentemente con `asyncio.gather` reduce el
tiempo total del escaneo sin ningún coste de correctitud.

### Sobre el takeover

**¿Por qué no comprobar si el recurso realmente está libre?**
Porque cruzaría de reconocimiento a verificación de explotabilidad,
prohibido explícitamente por la restricción de seguridad #6. Una petición
HTTP al proveedor de terceros para ver si responde "no existe" sería
exactamente ese tipo de comprobación. Se prefiere señalar el patrón, con
el riesgo de algún falso positivo, a confirmar un takeover real.

**¿Por qué mirar los hosts que NO resuelven, y no los activos?**
Porque un host `active` ya tiene una IP real detrás — no depende de un
CNAME de terceros sin reclamar. La señal característica de takeover vive
en los hosts que existen en DNS (crt.sh o Shodan los indexó alguna vez)
pero ya no tienen A/AAAA: es justo el patrón de un CNAME que apuntaba a un
recurso que se liberó.

### Sobre el sistema de agentes

**¿Qué diferencia hay entre esto y tener un único prompt con todo el
contexto?**
El contexto que necesita cada tarea es de tamaño y naturaleza muy
distinta: un hallazgo aislado, un escaneo completo, una lista de
candidatos de takeover, un par de escaneos a comparar. Mezclarlos en un
único prompt haría competir datos irrelevantes para cada pregunta
concreta por la atención del modelo, y perdería la asimetría de
degradación (colección vs. puntual) que sí tiene sentido tratar de forma
distinta según el caso.

**¿Cómo decide el Prompter a qué agente enviar una pregunta?**
Con una llamada a herramienta forzada (`complete_tool`) que el modelo debe
responder siempre, devolviendo tanto el agente elegido como la pregunta
reformulada con contexto ya incorporado. Si la clasificación no es fiable
(agente no reconocido, pregunta reformulada vacía), usa el agente genérico
por defecto — nunca se queda sin responder por un fallo de enrutado.

**¿Por qué `ai/query.py` se eliminó en vez de dejarlo como estaba?**
Porque quedó sin ningún llamador tras el cambio — verificado con `grep`
antes de borrarlo, no asumido — y el proyecto trata el código sin
llamador igual que trataría un stub inalcanzable: no debe quedarse. Su
función la cubre `ai/analyst.py::analyze_scan()` con más señal, no menos.

### Sobre `GeminiProvider`

**¿Qué demuestra sumar un segundo proveedor, más allá de la opción en
sí?**
Que la interfaz `LLMProvider` realmente aísla el modelo de la lógica de
negocio, como se venía afirmando desde el Paso 1. La prueba es que
`GeminiProvider` se implementó sin cambiar una sola línea de `triage.py`
ni de los cinco agentes nuevos — antes de esto, esa afirmación no tenía
una segunda implementación real que la respaldara.

**¿Qué bug real se encontró y cómo?**
Un `AttributeError` sin controlar cuando un `candidate` de la respuesta de
Gemini trae `content=None` (observado en vivo bajo presión de cuota del
free tier). Se corrigió con un guard explícito y se cubrió con un test
específico que reproduce el caso.

### Sobre la metodología

**¿Por qué usar subagentes de Claude Code para esto?**
Para dividir un encargo grande en piezas con responsabilidad exclusiva,
verificables una a una, en vez de un único cambio monolítico difícil de
revisar. Cada pieza se aceptó solo tras comprobar tests, integración real
y un caso manual — no solo el resumen del propio subagente. Es tooling de
desarrollo, no parte del producto Atalaya.

---

## 13. Estado de los requisitos de la práctica

Sin cambios respecto al cierre del Paso 7 — los cinco siguen cubiertos, y
esta ampliación no era necesaria para ninguno de ellos:

| Requisito | Estado |
|---|---|
| Base de datos | ✅ Sin cambios de fondo (nuevo `finding_type`, mismo mecanismo genérico) |
| API o webhook | ✅ Amplía: diff, prompter, Shodan/Gemini como consumo externo |
| Aplicación web | ✅ Rediseño visual en curso, funcionalidad sin cambios |
| GitHub con historial | ✅ Commits por unidad lógica de esta ampliación |
| Reporte con portada | ✅ Amplía: `risk_score` + resumen ejecutivo con IA |

---

## 14. Conclusión

Esta ampliación no cierra ningún requisito pendiente — todos lo estaban ya
— pero convierte una afirmación de diseño ("la capa IA es una interfaz,
no una dependencia rígida") en un hecho demostrado con dos proveedores
reales, y una limitación documentada desde el Paso 2 ("fuente única, sin
CNAME") en dos módulos completos, probados y verificados sobre datos
reales. El método no cambió respecto al resto del proyecto: cada pieza se
verificó de forma independiente antes de aceptarse, y los dos defectos
reales que aparecieron en el proceso (`GeminiProvider` con `content=None`,
el CSS del dashboard) se encontraron *precisamente* por insistir en esa
verificación en vez de aceptar el resumen de quien hizo el trabajo.
