# Arquitectura de Atalaya

## 1. Objetivo

Atalaya es una plataforma de **Attack Surface Management (ASM)**: a partir de un
dominio, descubre los activos que una organización expone en Internet, evalúa su
riesgo y emplea un LLM para priorizar y explicar los hallazgos. El valor
diferencial no es escanear (hay muchas herramientas que lo hacen), sino
**convertir un volcado técnico ruidoso en decisiones accionables** mediante IA.

## 2. Visión de componentes

### 2.1 API (FastAPI) — `src/atalaya/api`
Núcleo de la aplicación. Expone la API REST propia (requisito de la práctica) y
orquesta el resto de módulos. Endpoints principales:

- `POST /scans` ✅ — lanza un escaneo completo (subdominios [crt.sh + Shodan]
  + puertos + cabeceras + TLS + riesgo de takeover) **en segundo plano**:
  valida y autoriza el dominio (400/403 al momento, sin crear nada), crea el
  escaneo en `running` y responde **202** con `Location: /scans/{id}`. El
  trabajo lo hace `core/scan_runner.py::run_scan` con su propia sesión de BD
  y termina en `completed` o en `failed` con el motivo (§11). `?wait=true` lo
  espera en la misma llamada y responde 201 con el detalle, como antes.
  Triar, pedir el informe o preguntar por un escaneo en curso da **409**, y
  comparar exige que los dos estén completados.
- `GET  /scans`, `GET /scans/{id}` ✅ — consulta de escaneos (404 si no existe).
- `GET  /assets` ✅ — activos descubiertos, filtrables por `scan_id`.
- `GET  /findings` ✅ — hallazgos, filtrables por `asset_id`/`scan_id`;
  `severity` es `unknown` hasta triarlos.
- `POST /scans/{id}/triage` ✅ — triaja con IA los hallazgos `unknown` de un
  escaneo ya persistido. Idempotente: no repite los ya triados, salvo con
  `?force=true` (p. ej. tras cambiar de modelo); un re-triaje que falla
  conserva el triaje anterior. Sin `force`, antes de llamar al modelo copia
  el triaje de los hallazgos de otros escaneos del dominio con el mismo
  contexto exacto (`ai/triage_reuse.py`); la respuesta dice cuántos
  (`reused`) y cuántas llamadas hizo (`model_calls`).
- `POST /findings/ask` ✅ — consulta en lenguaje natural, enrutada por
  `ai/prompter.py` al agente adecuado (visión global o riesgo de takeover)
  sobre el último escaneo completado de un dominio (o uno concreto vía
  `scan_id`).
- `GET /scans/{id}/diff/{other_id}` ✅ — compara dos escaneos del mismo
  dominio (`core/repository.py::diff_scans()`: hostnames nuevos,
  desaparecidos y comunes, y en `cambiados` los comunes que cambiaron de
  estado, puertos o hallazgos) y valora los cambios con
  `ai/diff_analyst.py`. `previous`/`current` se deciden por `started_at`,
  no por el orden en la URL. `?analysis=false` devuelve solo el cálculo, sin
  llamar al modelo (`analysis: null`), y por tanto sin posible 502.
- `GET /scans/{id}/report` ✅ — informe PDF con portada, `risk_score` y
  resumen ejecutivo de `ai/report_writer.py` (opcional: el informe se
  genera igual sin IA disponible, ver 2.5).
- `GET /config/status` ✅ — qué está configurado, para la bienvenida del
  dashboard: las comprobaciones de `atalaya doctor` que no salen a la red
  (§2.9, §10.5). Estado y texto por comprobación, nunca valores. Solo
  lectura: configurar es cosa de `atalaya init`.
- `POST/GET /monitors`, `GET/PATCH/DELETE /monitors/{id}` ✅ — vigilancia
  programada: un escaneo del dominio cada `interval_hours` (mínimo 1) y un
  aviso por **webhook** cuando aparecen, desaparecen o cambian activos, o
  cuando el escaneo falla (§12). Al crear: dominio autorizado (400/403), un
  monitor por dominio (409) y webhook `https` hacia una dirección pública
  (400, protección contra SSRF). La respuesta nunca lleva la URL completa ni
  el secreto de la firma: `webhook` sale enmascarado y `signed` dice si hay
  firma. `PATCH` pausa o reanuda (`active`).

`api/schemas.py` define la frontera Pydantic entre las tablas y la respuesta
pública; `api/main.py` traduce `InvalidTargetError`/`InvalidWebhookError`/
`UnauthorizedTargetError` a 400/400/403 y `AIProviderError` a 502 vía
`exception_handler`, en vez de que
cada ruta gestione sus propios códigos de error. El triaje y el informe no
llegan a ese 502 porque degradan antes (ver 2.4 y 2.5).

**Autenticación opcional por `X-API-Key`** (`api/security.py`). Con `API_KEY`
vacía (por defecto) no se exige nada y la API se comporta como antes. Con
valor, `require_api_key()` se aplica a los cinco routers y a `/`: sin la
cabecera, o con una clave distinta, 401 con `WWW-Authenticate: X-API-Key`,
antes de ejecutar la ruta (un `POST /scans` rechazado no llega a tocar la red).
Se deja fuera `/health`, que usan el healthcheck de Docker y la sonda del
dashboard; `/docs` y `/openapi.json` también, porque describen la API sin
devolver datos, y desde `/docs` se introduce la clave con «Authorize» (la
cabecera se declara con `APIKeyHeader`, así que aparece en el esquema OpenAPI).
La comparación usa `secrets.compare_digest` sobre bytes: tiempo constante
respecto al contenido, y sin el `TypeError` que lanzaría con texto no ASCII.
Se aplica por router y no en `FastAPI(dependencies=...)` para poder excluir
`/health`; `tests/test_api_auth.py` recorre el esquema OpenAPI para que un
router nuevo que olvide la dependencia haga fallar la suite.

### 2.2 Descubrimiento — `src/atalaya/discovery` (Paso 2 ✅ + ampliación)
Cada técnica es un módulo independiente con salida normalizada:

| Módulo         | Qué obtiene                                    | Fuente                  |
|----------------|------------------------------------------------|-------------------------|
| `subdomains`   | Subdominios, verificados por DNS y filtrados de wildcards DNS (§7.6) | crt.sh (CT logs) + `shodan` (opcional), concurrentes, fusionados por hostname |
| `shodan`       | Segunda fuente de subdominios                  | API DNS de Shodan (`SHODAN_API_KEY` opcional — sin ella, se omite sin incidencia) |
| `ports`        | Puertos TCP abiertos (`COMMON_PORTS` por defecto) | Conexión asíncrona, concurrencia acotada |
| `headers`      | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; redirección HTTP → HTTPS (`http_sin_redireccion_https`); cookies sin `Secure`/`HttpOnly`/`SameSite` (un hallazgo por tipo y host, nombres sin valores) | Petición HTTPS y, en paralelo, HTTP (que además sirve de respaldo para `sin_https`) |
| `tls`          | Versión de protocolo, emisor, caducidad del certificado; hostname cubierto por los SAN (`tls_hostname_no_coincide`) y cadena de confianza (`tls_cadena_no_confiable`). En el 443 de todo host activo y en los puertos con TLS implícito (465/993/995/8443) que el escaneo encuentre abiertos | `cryptography` sobre el `ssl_object` de la conexión; en paralelo, una negociación con verificación contra el almacén de Mozilla (`certifi`) |
| `takeover`     | Riesgo de *subdomain takeover* (patrón de CNAME hacia hosting de terceros) | Resolución DNS de CNAME sobre hosts **sin** A/AAAA — reconocimiento pasivo puro (la verificación, opcional, vive en `takeover_verify`) |
| `takeover_verify` | Verificación HTTP **opt-in** (`TAKEOVER_VERIFY`) de un candidato: huella de "recurso no reclamado" en la página de error del proveedor | `GET` al destino del CNAME — off por defecto, gated por `SCAN_ALLOWLIST`, con auditoría (ver §8.3) |
| `enrichment`   | Orquesta `ports`+`headers`+`tls` (hosts activos) y `takeover` (todos los registros), concurrentemente; encadena `takeover_verify` si está activado | Compone los cinco anteriores |

`ports`/`headers`/`tls`/`takeover` nunca lanzan excepción: un host sin ese
servicio (p. ej. sin HTTPS en el 443) se refleja en el campo `error` del
resultado, mismo criterio de degradación controlada que `subdomains`.
`enrichment.enrich_scan()` actúa sobre `SubdomainScanResult.active_records`
para puertos/cabeceras/TLS — un host que no resuelve, o que solo resuelve a
direccionamiento interno, no tiene servicio real que inspeccionar — pero
sobre **todos** los registros (`.records`) para `takeover`: la señal de un
CNAME abandonado vive precisamente en los hosts que no resuelven por
A/AAAA. Los módulos devuelven `DiscoveryFinding`/`TakeoverCandidate`
(`discovery/models.py`), no un `Finding` de SQLAlchemy: la capa de
descubrimiento no conoce la de persistencia.

TLS en puertos distintos del 443 es la única dependencia entre técnicas: se
lanza **después** del `gather`, porque necesita los puertos abiertos
(`_extra_tls_targets`), y solo añade latencia a los hosts que los tienen. Sus
hallazgos se fusionan en `EnrichmentResult.findings_by_hostname()` en **uno
por tipo y host** (`_merge_tls_findings`), la invariante de la que dependen
`diff_scans()` y la reutilización del triaje. Un hallazgo que solo aparece
en el 443 conserva la evidencia exacta de siempre: cambiarla haría pagar de
nuevo el triaje de todo hallazgo TLS ya triado. Los puertos con STARTTLS
(25, 587, 110, 143) quedan fuera: exigen hablar antes el protocolo.

### 2.3 Persistencia (PostgreSQL) — `src/atalaya/core`
Modelo de datos relacional (`core/models.py`, Paso 3 ✅):

- **Scan** — un escaneo (dominio objetivo, fecha, estado, incidencias).
- **Asset** — activo descubierto (host, IPs, alcance, estado de resolución
  como texto libre —sin enum de BD, así que un estado nuevo como `wildcard`
  no requiere migración—, puertos abiertos).
- **Finding** — hallazgo (tipo, evidencia, severidad, remediación, `asset_id`).
- **Monitor** — vigilancia programada de un dominio (único): intervalo,
  webhook y su secreto, `next_run_at`, el último escaneo que lanzó y la
  **línea base** contra la que compara el siguiente (§12). Solo referencia
  escaneos por id (`ON DELETE SET NULL`).

Las fechas se guardan como UTC *naive* (`TIMESTAMP WITHOUT TIME ZONE`) a
través de `UtcDateTime`, que convierte al escribir: asyncpg rechaza un
`datetime` con zona en esas columnas (SQLite no), y sin esa conversión ningún
escaneo llegaba a guardarse en PostgreSQL.

Relaciones: `Scan 1─N Asset`, `Asset 1─N Finding`. Las migraciones viven en
`migrations/` (Alembic, motor async). `core/persistence.py` traduce los
resultados de descubrimiento a estas filas: `save_subdomain_scan()` (un
`SubdomainScanResult` → `Scan`+`Asset`; un host con
`leaks_internal_addressing` genera además un `Finding`), `apply_port_scan()`
(`EnrichmentResult.ports_by_ip` → `Asset.open_ports`) y
`apply_discovery_findings()` (hallazgos de cabeceras/TLS/takeover →
`Finding`, con severidad `unknown` hasta el triaje).

`core/repository.py` es la contraparte de lectura: `get_scan`, `list_scans`,
`get_latest_scan`, `list_assets`, `list_findings`, las de los monitores
(`list_monitors`, `get_monitor`, `get_monitor_by_domain`,
`get_latest_completed_scan_id`) y `diff_scans()` (compara
dos escaneos del mismo dominio — la razón de ser de persistir escaneos en el
tiempo). Además de los hostnames nuevos y desaparecidos, recorre los comunes
y devuelve en `cambiados` los que cambiaron de estado, de puertos abiertos o
de hallazgos, estos con su severidad. Los hallazgos se comparan por
`finding_type` y no por evidencia, que varía sin que cambie el problema
(días hasta la caducidad), y las IPs no se comparan (CDN, balanceo). Lo que
falta se llama «desaparecido», no «cerrado» ni «resuelto»: un timeout de la
sonda deja el mismo rastro que una corrección. La API (2.1) y el dashboard (2.6) consultan
por aquí, no construyen `select()` propios.

### 2.4 Capa IA — `src/atalaya/ai` (Paso 5 ✅ + sistema de agentes)

- `provider` — `LLMProvider` (interfaz, ABC) + `AnthropicProvider` +
  `GeminiProvider`. Dos formas de pedir una respuesta: `complete()` (texto
  libre) y `complete_tool()` (fuerza una llamada a herramienta — `tool_choice`
  fijo en Anthropic, `FunctionCallingConfig(mode="ANY",
  allowed_function_names=[...])` en Gemini — para una respuesta con forma
  garantizada, más fiable que pedir "responde en JSON" sobre texto libre).
  `AI_PROVIDER` en `.env` elige cuál se instancia; ningún otro módulo de
  `ai/` conoce el SDK concreto. `GeminiProvider` suma un presupuesto de
  razonamiento acotado a `max_output_tokens` y reintenta en `mode="AUTO"`
  ante `MALFORMED_FUNCTION_CALL` — dos bugs reales, detallados en CLAUDE.md
  ("Deuda técnica conocida → Resuelta").
- `triage` — `triage_finding`/`triage_findings`: reciben un `Asset` y un
  `Finding`, devuelven severidad razonada, impacto explicado y remediación
  concreta. Aquí se aplica el principio que el proyecto asume como central:
  **dar a la IA contexto estructurado** (`build_finding_context`, campos
  seleccionados a propósito), **no un dump de la fila de BD**. Degradación
  controlada: un fallo de un hallazgo no aborta el resto (`TriageBatchResult`).
- `triage_reuse` — `reuse_previous_triage`: antes de triar, copia el triaje de
  un hallazgo ya triado de otro escaneo del dominio cuyo contexto
  (`build_finding_context`) es idéntico; como el resto del prompt es
  constante, es reutilizar la respuesta a la misma pregunta exacta. No
  deduplica dentro de un escaneo (el contexto lleva el host, así que no hay
  prompts repetidos) ni agrupa por tipo (el modelo perdería el host). En la
  demo ahorra un 27 % al triar el segundo escaneo; `force` no reutiliza.
  **Sin tocar desde el Paso 5**, por decisión explícita.

Sobre esa misma interfaz, un sistema de **cinco agentes especializados**
más (no un único prompt genérico), cada uno con contexto y responsabilidad
propia, y sin solape entre ellos:

| Agente | Fichero | Contexto que recibe | Devuelve |
|---|---|---|---|
| Prompter (intermediario) | `prompter.py` | Resumen ligero del escaneo (nº activos, hallazgos por severidad, si hay candidatos de takeover) + la pregunta | `AnalystResult`, tras enrutar a `analyst` o `takeover_detective` |
| Analista | `analyst.py` | Dominio, distribución de severidades, hallazgos `critical`/`high` (con impacto ya triado si existe) | `AnalystResult`: respuesta, patrones, combinaciones preocupantes, prioridades |
| Detective de takeover | `takeover_detective.py` | Los `TakeoverCandidate`/`Finding(finding_type="subdomain_takeover_risk")` ya detectados | Lista de `TakeoverAssessment` (prioridad + razonamiento, sin confirmar explotabilidad) |
| Redactor de informes | `report_writer.py` | `risk_score`, hallazgos `critical`/`high` | 2-3 párrafos en prosa, sin jerga técnica |
| Comparador de escaneos | `diff_analyst.py` | `ScanDiff` (nuevos/desaparecidos/comunes/cambiados) + los dos `Scan` completos | Valoración en prosa: expansión de superficie, cambios en activos existentes, riesgo de lo desaparecido |

Dos asimetrías deliberadas, consistentes con el criterio ya establecido en
el Paso 5 (`ask()` propaga, `triage_finding()` degrada):

- **Colección → degrada con gracia**: `takeover_detective` (una lista de
  candidatos) nunca lanza; un fallo del proveedor no debe tumbar el resto
  del escaneo.
- **Petición puntual → propaga `AIProviderError`**: `prompter`, `analyst`,
  `report_writer` y `diff_analyst` sí propagan (→ 502 vía `exception_handler`)
  — **excepto** cuando se integran en el informe PDF (2.5), donde el
  criterio cambia porque el informe no puede depender de la IA.

`ai/query.py::ask()` (Paso 5) se **retiró**: `POST /findings/ask` pasa por
`prompter.py`, que lo reemplaza con más señal (patrones, combinaciones,
prioridades) en vez de solo prosa libre.

**Proveedor de reserva para la demo (`replay.py`).** Tercera implementación
de `LLMProvider`, activable con `AI_PROVIDER=replay`, que no es un modelo:
sirve respuestas reales grabadas (`demo/ai_recordings.json`) para que la demo
funcione sin red. `RecordingProvider` envuelve al proveedor real y graba;
`ReplayProvider` reproduce. La clave de cada grabación es un hash de la
petición completa (prompt de sistema, prompt, herramienta y schema), así que
una petición no grabada — una pregunta fuera del guion, o datos distintos de
los sembrados — falla con `AIProviderError` (el mismo 502 que un proveedor
caído): nunca se sirve una respuesta "parecida". Como los prompts incluyen el
orden de activos y hallazgos, `Scan.assets` y `Asset.findings` llevan
`order_by` por id (en PostgreSQL, sin él, un `UPDATE` del triaje cambia el
orden de lectura). Ningún agente cambió para incorporarlo. Datos y guion:
§2.8.

### 2.5 Informes — `src/atalaya/reporting` (Paso 7 ✅ + resumen con IA)
Genera un informe ejecutivo en PDF a partir de un escaneo ya persistido:
portada (dominio, fecha), `risk_score` (0-100), resumen ejecutivo en
lenguaje natural (opcional, con IA), y el detalle de cada activo y hallazgo
con impacto y remediación. Cubre el requisito de "reporte con portada".

- `generator.py` — `render_html()` (Jinja2, puro y síncrono, fácil de probar
  sin generar un PDF real) y `generate_report()` (convierte a PDF con
  `xhtml2pdf` en un hilo aparte vía `asyncio.to_thread`, para no bloquear el
  loop de eventos con trabajo de CPU). Recibe un `Scan` ya cargado, no un
  `scan_id` — mismo criterio que `ai/prompter.py`/`ai/analyst.py`.
- `risk_score` (0-100) — sale de `core/scoring.py::compute_risk_score()`,
  fuente de verdad única que usan el PDF y la API (y, a través de ella, el
  dashboard). **La banda la fija la severidad máxima presente** (solo `low`
  → 1-24, `medium` → 25-49, `high` → 50-74, `critical` → 75-100): ningún
  volumen de hallazgos leves alcanza la banda de uno grave, y un solo
  crítico basta para la banda crítica. Dentro de la banda, el volumen con
  rendimientos decrecientes por tipo (`peso · log2(1 + n)` por
  `(severidad, finding_type)`) y saturación suave hacia el techo. Monótono:
  añadir o triar un hallazgo nunca baja el índice. Sustituye a la suma
  ponderada acotada (`min(100, Σ peso·n)`), que saturaba con volumen:
  github.com, con 194 `low` y 9 `medium`, salía 100/100 «crítico».
- `generate_report(scan, provider=None)` — con `provider`, incluye un
  resumen ejecutivo de `ai/report_writer.py::write_executive_summary()`.
  **Si `provider` es `None`, o si falla (`AIProviderError`), el informe se
  genera igual, sin resumen** — el informe con portada era un requisito
  obligatorio antes de que existiera la capa IA, así que nunca puede
  depender de ella. Asimetría deliberada frente al endpoint de diff (2.1),
  que sí propaga el fallo del proveedor.
- `pdf_text.py` — el texto del modelo llega con Markdown (`código`, `**`,
  `##`) y con caracteres que las fuentes estándar del PDF no tienen (`→`).
  Filtros Jinja `md`/`md_inline` renderizan un subconjunto de Markdown
  **escapando antes el HTML** (nunca la librería `markdown`, que deja pasar
  HTML crudo e imágenes remotas que xhtml2pdf descargaría), y el `finalize`
  del entorno sustituye glifos en toda la salida de la plantilla.
- Se elige **xhtml2pdf** sobre WeasyPrint porque es Python puro: no depende
  de Pango/Cairo/GTK, ausentes en un Windows sin ese runtime instalado.
- El PDF se escribe de forma determinista en
  `reports/atalaya_informe_{dominio}_{id}.pdf`: descargarlo de nuevo tras
  triar hallazgos nuevos lo regenera y sobrescribe, en vez de acumular una
  copia por cada clic de descarga.
- Expuesto vía `GET /scans/{id}/report` (API) y un botón en la pestaña
  «Escaneos» del dashboard.

### 2.6 Dashboard (Streamlit) — `dashboard/` (Paso 6 ✅ + rediseño visual)
Aplicación web que consume la API: lanzar escaneos, explorar activos y
hallazgos, triar con IA, consultar en lenguaje natural, descargar el
informe PDF de un escaneo, y ver el `risk_score` como métrica principal del
detalle de un escaneo (lo devuelve `GET /scans/{id}` como `risk_score`,
calculado por `core/scoring.py`: el dashboard lo pinta sin recalcularlo, así
que no puede contradecir al PDF — antes replicaba la fórmula con una copia
de los pesos sincronizada a mano; el dashboard sigue siendo un cliente HTTP
puro de la API). Si la API exige clave, el dashboard la envía en `X-API-Key`:
la toma de `ATALAYA_API_KEY` o, si esa variable no existe, de `API_KEY` en el
`.env` del directorio de trabajo — la misma que la activa en la API, para que
en local se configure una sola vez. Sin clave no envía la cabecera.

**Comparar con otro escaneo.** Si hay más de un escaneo del mismo dominio, el
detalle ofrece un selector «Comparar con» (por defecto, el anterior más
reciente) y, al pulsar «Comparar», pinta `GET /scans/{id}/diff/{other_id}`:
recuentos de nuevos, desaparecidos, cambiados y sin cambios, los hostnames
de cada grupo, una fila por activo cambiado (estado, puertos y hallazgos `+`/`−`,
con el filo de la severidad) y la valoración de `ai/diff_analyst.py`. Va
después del score y antes de los activos. Se pide con botón, no al cambiar el
selector, y se guarda en `session_state` por pareja de escaneos: el endpoint
llama al modelo y Streamlit reejecuta el script en cada interacción. Si la
IA falla (502), repite con `?analysis=false` y muestra los cambios con un
aviso del motivo: los hostnames son puro cálculo y no deben perderse porque
falte el proveedor (Docker sin `.env`, o `replay` con una pareja no grabada).

**Vigilancia.** La pestaña «Vigilancia» es el cliente de `/monitors` (§12):
una tabla de monitores (HTML propio, no `st.dataframe`, para colorear el
resultado por celda) que se refresca sola cada 10 s en un fragmento, con el
resultado de la última ejecución deducido de los campos del monitor
(escaneando, si su último escaneo sigue en curso; atención, si hay
`last_error`; avisado, si `last_notified_at` es posterior a `last_run_at`;
si no, sin cambios o pendiente). Atención va en ámbar: el rojo sigue siendo
solo de `critical` y de la API caída. Pausar/reanudar (`PATCH`), borrar con
confirmación en la página (el visor no tiene `confirm()`) y un formulario de
alta con la frecuencia entre opciones fijas (mínimo 1 h, así no puede dar
422) y la firma activada: sin secreto propio, el panel genera uno
(`secrets.token_urlsafe`) y lo enseña una sola vez, porque la API no lo
devuelve nunca. Los rechazos de la API (SSRF, allowlist, duplicado) se
muestran con su motivo.

**Puesta en marcha (fase B).** La cabecera lleva la torre de celosía de
`atalaya init`/`doctor` en SVG en línea, sin colores propios (los pone
`_CSS`). Cuando la API responde a `/scans` con la lista vacía, encima de las
pestañas sale una bienvenida: qué es la herramienta, el estado de
`GET /config/status` con la pista de cada aviso, y tres pasos con el activo
marcado (configurar con `atalaya init` mientras falte alcance, `.env` o clave
de IA, o haya un error; después, el primer escaneo, sugiriendo
`scanme.nmap.org` solo si el alcance no está restringido). La barra lateral
muestra el mismo estado en compacto también con escaneos y, con la API
caída, pregunta «¿Has ejecutado `atalaya init`?» con los comandos para
arrancarla. Sin respuesta de `/scans` no se pinta ni la bienvenida ni
«Todavía no hay escaneos»: no se sabe si los hay. `/config/status` se guarda
60 s por sesión (tarda unas décimas y Streamlit reejecuta en cada clic) y su
fallo no se pinta (API antigua, 401 ya visible en `/scans`); todo texto que
viene de la API se escapa antes de pintarlo.

**Escaneo en segundo plano.** «Nuevo escaneo» lanza el escaneo (202) y lo
sigue con un fragmento de Streamlit (`st.fragment(run_every=2)`) que consulta
`GET /scans/{id}` sin reejecutar el resto del script: el panel sigue usable y
el escaneo continúa aunque se cierre. Al terminar relanza la app con el
resumen o el motivo del fallo. En «Escaneos», un escaneo en curso muestra solo
su estado (también autorrefrescado) y uno fallido su motivo, sin índice ni
botones; «Comparar con» solo ofrece completados. El dashboard llama a la API
en `127.0.0.1` y no en `localhost`: en Windows, `localhost` prueba antes IPv6
y cada petición perdía unos 2 s.

Estética rediseñada en `_CSS` (inyectado con `st.html()`, no
`st.markdown(..., unsafe_allow_html=True)` — ver "Decisiones de diseño")
para parecer una herramienta comercial de seguridad (referentes: Shodan,
VirusTotal, Maltego), no la demo por defecto de Streamlit: fondo oscuro,
tipografía monoespaciada para datos técnicos, acento único, rojo reservado
a severidad crítica. Selectores escritos contra el DOM real de Streamlit
1.63 (`data-testid`, no `data-baseweb`: los widgets migraron de BaseWeb a
react-aria y los selectores antiguos dejan de pintar sin dar error). Por
eso la versión está fijada (`streamlit==1.64.0` en `pyproject.toml`, con un
test que exige una versión exacta): de 1.63 a 1.64 se rompió la barra lateral
plegada, y subirla exige volver a mirar el dashboard en el navegador.
Verificado con capturas de pantalla reales, no solo con la suite de tests
(`tests/test_dashboard.py` comprueba comportamiento, nunca estilo).
Detalle completo del proceso, incluidos los bugs de renderizado
encontrados y corregidos, en `memorias/Memoria_Ampliacion_Agentes_Atalaya.md`.

### 2.7 Despliegue — `docker-compose.yml`, `docker/`

Tres servicios: `db` (PostgreSQL 16), `api` y `dashboard`. La API aplica
`alembic upgrade head` en cada arranque antes de levantar uvicorn (idempotente)
y siempre usa el Postgres del compose: `DATABASE_URL` se fija en
`environment`, que prevalece sobre el `.env`. El `.env` es opcional (sin él
solo la IA queda sin clave) y el dashboard no lo recibe: es un cliente HTTP
puro y no necesita las claves de IA ni de Shodan. Recibe solo
`ATALAYA_API_KEY: ${API_KEY:-}`, que Compose interpola desde el `.env` del
proyecto (vacía sin él: autenticación desactivada en los dos lados). Todos los
puertos se publican solo en `127.0.0.1`, porque la BD usa credenciales fijas
de desarrollo y la autenticación de la API está desactivada por defecto (y,
aun activada, sin TLS la clave viaja en claro). El dashboard espera al
healthcheck de la API, que usa `/health`, abierto aunque haya clave.
`tests/test_deploy_config.py` fija estas propiedades sin levantar Docker.

### 2.8 Datos de reserva para la demo — `scripts/`, `demo/`

Herramienta de demo, fuera del paquete `atalaya` (mismo criterio que
`_shot.py`). `demo/github.com.json` contiene dos escaneos reales de
github.com hechos con `POST /scans` (21/09 y 28/09/2026), triados por el
modelo real salvo los hallazgos que aparecieron entre uno y otro, que quedan
`unknown` para triarlos en directo. `scripts/seed_demo_data.py --reset` los
carga en la BD configurada (SQLite o el PostgreSQL de Docker, cuya imagen de
la API incluye `scripts/` y `demo/`), reiniciando las secuencias para que los
ids sean siempre #1 y #2: el prompt del diff los incluye. Se niega a pisar una
BD con escaneos o monitores sin `--reset`, y con él vacía también los
monitores: uno que sobreviviera escanearía de verdad en mitad de la demo. Toda
tabla con clave foránea hacia las que se vacían tiene que vaciarse con ellas,
porque PostgreSQL rechaza el `TRUNCATE` de una tabla referenciada aunque la
otra esté vacía (la tabla `monitors` rompió así la siembra en Docker hasta
`757f0f3`; SQLite no lo ve, y un test lo comprueba sobre el esquema).
`scripts/build_demo_data.py` es quien los
produjo (una vez, con red): tría con el modelo real, recorre el guion por la
API antes y después del triaje en directo — el orden de los pasos en la demo
no importa — graba solo lo usado y verifica la reproducción en `replay`.
`tests/test_demo_data.py` repite esa verificación en la suite: si un cambio
de prompt deja obsoleta la grabación, falla la suite, no la defensa.

### 2.9 Puesta en marcha guiada — `src/atalaya/onboarding` (ampliación)

Dos comandos de la CLI para quien llega de fuera: `atalaya init` configura
(escribe el `.env`) y `atalaya doctor` diagnostica (no escribe nada). Se
configura en la terminal y no en el dashboard a propósito: los secretos se
escriben en la máquina del operador, y un formulario web exigiría un endpoint
que reciba claves, abierto a cualquiera con `API_KEY` vacía (el default).

| Módulo | Papel |
|---|---|
| `ui.py` | Identidad visual: logo de la torre (una torre de vigilancia que es también una A), paleta del dashboard, piezas de pantalla. Modo ASCII si la salida no es UTF-8 |
| `checks.py` | Comprobaciones que devuelven `CheckResult` (datos, no texto): las comparten `doctor`, `init` y `GET /config/status` (solo las locales, `run_local_checks`) |
| `doctor.py` | Ejecuta las comprobaciones (las de red en paralelo) y pinta el diagnóstico con cómo resolver cada error o aviso |
| `envfile.py` | Lee y escribe el `.env`: atómico, con copia, verificado con el parser de la aplicación; enmascara secretos |
| `wizard.py` | `init` interactivo (5 pasos) y `--non-interactive` (mismas respuestas desde opciones y entorno) |

Los módulos reciben los valores explícitamente en vez de leer `settings`, y
`cli.py` importa la configuración dentro de cada comando: un `.env` con un
valor inválido no impide arrancar `doctor`, que es quien debe diagnosticarlo.
`inputs_from_settings()` traduce una configuración ya cargada a esos valores:
`doctor` la carga de nuevo, la API pasa la de su proceso. La configuración
puede llegar sin fichero: en Docker, Compose pasa el `.env` como variables de
entorno y el fichero no está en el contenedor, así que sin `.env` pero con
campos en el entorno la comprobación de configuración es correcta, no un
aviso. Detalle de los flujos en §10.

## 3. Flujo de datos

```
dominio
   │  POST /scans  → 202 (running); el resto, en segundo plano (§11)
   ▼
[Descubrimiento]  subdominios (crt.sh + Shodan) → DNS → filtro de wildcards
   │               → puertos → cabeceras → TLS (solo activos)
   │               → riesgo de takeover (sobre TODOS los registros)
   │               → verificación HTTP de takeover (opt-in)
   │  hallazgos crudos
   ▼
[PostgreSQL]  se persisten activos y hallazgos
   │
   ▼
[Capa IA]  triaje: severidad + impacto + remediación
   │       (+ prompter/analyst/takeover_detective/report_writer/diff_analyst)
   │
   ├──▶ [Dashboard]  visualización, consulta NL, risk_score, «Comparar con» (diff)
   └──▶ [Informes]   PDF con portada + risk_score + resumen ejecutivo IA

[Vigilancia]  cada monitor, cada N horas: mismo escaneo → diff SIN IA contra
              su línea base → si cambia algo (o falla), POST al webhook (§12)
```

## 4. Decisiones de diseño

- **FastAPI** por rendimiento asíncrono y documentación OpenAPI automática, que
  además sirve de evidencia de la API en la defensa.
- **PostgreSQL** frente a SQLite en producción por concurrencia y por ser un
  motor realista; SQLite queda como fallback de desarrollo.
- **Capa IA desacoplada** tras una interfaz `LLMProvider`: el modelo es un
  detalle de configuración, no una dependencia rígida — demostrado sumando
  `GeminiProvider` sin tocar ni `triage.py` ni los cinco agentes nuevos.
- **Sistema de agentes especializados, no un prompt único**: cada tarea de
  IA (triaje, visión global, takeover, informe, diff, enrutado) tiene su
  propio contexto y su propio criterio de degradación — ver 2.4.
- **Módulos de descubrimiento independientes**: se pueden añadir o desactivar
  técnicas sin tocar el resto del sistema (Shodan y takeover se sumaron sin
  modificar `ports`/`headers`/`tls`).
- **Wildcards DNS: reclasificar, no borrar.** Un host que solo resuelve a la
  IP del comodín pasa a `wildcard`: sale del inventario activo pero se
  conserva en el resultado, para que el filtro sea auditable (§7.6).
- **Salvaguarda de autorización** (`SCAN_ALLOWLIST`): limita los objetivos
  escaneables, alineado con un uso responsable de la herramienta.
- **Autenticación por clave compartida, opcional** (`API_KEY` →
  `X-API-Key`), no cuentas de usuario: un operador y un cliente propio no
  justifican login ni rotación de tokens. Desactivada por defecto para que la
  demo y el stack sin `.env` no cambien — ver 2.1.
- **Reconocimiento no confirma explotabilidad ni intenta el secuestro**
  (restricción de seguridad #6): la detección (`discovery/takeover.py`) es
  patrón de CNAME puro, sin HTTP. La verificación HTTP (`discovery/
  takeover_verify.py`) existe pero es **opt-in** y acotada: lee la página de
  error pública del proveedor, eleva a "alta sospecha — no confirmado" (nunca
  "confirmado"), exige `TAKEOVER_VERIFY=true` + hostname en `SCAN_ALLOWLIST` +
  auditoría de cada petición. Detalle y justificación en §8.3.
- **Diff: comparar lo que cambia la exposición, no lo que varía solo.**
  Hallazgos por tipo y no por evidencia (los días hasta la caducidad varían
  cada semana); IPs no comparadas (CDN, balanceo); lo ausente se llama
  «desaparecido», porque un timeout de la sonda deja el mismo rastro que una
  corrección — ver 2.3.
- **Reutilizar el triaje solo ante el prompt exacto**, entre escaneos del
  mismo dominio: se copia la respuesta que el modelo ya dio a la misma
  pregunta, nunca a una parecida (mismo criterio que `replay`). No se agrupa
  por tipo de hallazgo, que ahorraría más, porque el modelo dejaría de ver el
  host — ver 2.4.
- **Vigilancia: el aviso no se pierde y la URL no es un punto de entrada.**
  La línea base de un monitor solo avanza cuando el aviso se entrega (un
  webhook caído no hace perder el cambio); el diff va sin IA (no gasta
  crédito); y el webhook, que es una petición del servidor a donde diga el
  usuario, pasa la misma regla que los objetivos de escaneo: solo
  direcciones enrutables, validadas al crear y al enviar, conectando a la IP
  validada — ver §12.
- **`st.html()`, no `st.markdown(unsafe_allow_html=True)`**, para CSS
  grande en el dashboard: el parser de Markdown de Streamlit no trata de
  forma fiable un bloque `<style>` grande con líneas en blanco dentro — bug
  real, reproducido y corregido (ver `memorias/` y CLAUDE.md).

## 5. Mapa de requisitos → implementación

| Requisito de la práctica | Dónde se resuelve                          |
|--------------------------|--------------------------------------------|
| Base de datos            | `core/models.py` + `core/persistence.py` (Paso 3 ✅) |
| API / webhook            | `api/` (propia, Paso 4 ✅) + `discovery/`/`ai/` (consumo de crt.sh, Shodan, Anthropic/Gemini) + avisos por webhook de la vigilancia (`core/webhooks.py`, §12) |
| Aplicación web           | `dashboard/app.py`                         |
| GitHub con historial     | Commits por fase                           |
| Reporte con portada      | `reporting/generator.py`, `GET /scans/{id}/report` |

## 6. Hoja de ruta

1. **Paso 1 — Arquitectura + esqueleto** ✅
2. **Paso 2 — Motor de descubrimiento** ✅ (subdominios, puertos, cabeceras y TLS)
3. **Paso 3 — Base de datos + modelos** ✅ (persiste subdominios, puertos y hallazgos de cabeceras/TLS)
4. **Paso 4 — API REST completa** ✅ (`scans`/`assets`/`findings`, `/scans/{id}/triage`,
   `/findings/ask`)
5. **Paso 5 — Capa IA (triaje + consulta NL)** ✅
6. **Paso 6 — Dashboard completo** ✅
7. **Paso 7 — Generador de informes** ✅ (PDF con portada, API + dashboard)

Los siete pasos numerados son la entrega evaluable; están cerrados desde
antes de lo que sigue. Ampliación posterior, más allá de los requisitos
obligatorios:

8. **Shodan + subdomain takeover** ✅ — segunda fuente de enumeración,
   detección de riesgo de takeover vía CNAME.
9. **Sistema de agentes de IA** ✅ — 5 agentes nuevos sobre `LLMProvider`
   (prompter, analyst, takeover_detective, report_writer, diff_analyst),
   `GeminiProvider`, endpoint de diff, resumen ejecutivo del informe.
10. **Dashboard: diseño visual profesional** ✅ — estética de herramienta
    comercial de seguridad, `risk_score` como métrica principal, verificado
    con capturas de pantalla reales. *(Detalle completo del proceso en
    `memorias/`.)*
11. **Robustez** ✅ — instalación limpia verificada (`greenlet` declarado),
    `ruff`/`mypy` a cero, detección de wildcards DNS (§7.6) y verificación
    HTTP opt-in de subdomain takeover (§8.3).
    *(`memorias/Memoria_Ampliacion_Robustez_Atalaya.md`.)*
12. **Cierre pre-entrega** ✅ — PostgreSQL y Docker verificados de verdad
    (dos fallos graves corregidos), demo sin red, `risk_score` rehecho;
    autenticación opcional (§2.1), «Comparar con» (§2.6), redirección
    HTTP → HTTPS, cookies y validación TLS (§2.2), re-triaje forzado y
    diff sin IA (§2.1).
    *(`memorias/Memoria_Cierre_Preentrega_Atalaya.md`.)*
13. **Diff de activos comunes y reutilización del triaje** ✅ — `cambiados`
    en el diff (estado, puertos y hallazgos de los comunes; §2.1, §2.3,
    §2.6) y reutilización del triaje ante el mismo prompt exacto (§2.1,
    §2.4). *(`memorias/Memoria_Ampliacion_Diff_Triaje_Atalaya.md`.)*
14. **Puesta en marcha guiada** ✅ — TLS en los puertos con TLS implícito
    (§2.2), hosts `wildcard` fuera del escaneo de puertos (§7.6),
    `atalaya doctor`/`atalaya init` (§2.9, §10) y, en la fase B,
    `GET /config/status` (§2.1, §10.5) con la bienvenida, el logo y el estado
    de la configuración en el dashboard (§2.6).
    *(`memorias/Memoria_Ampliacion_Puesta_En_Marcha_Atalaya.md`.)*
15. **Escaneo en segundo plano y monitorización** 🚧 — `POST /scans` en
    segundo plano con su seguimiento en el dashboard (§2.1, §2.6, §11) y
    vigilancia programada con aviso por webhook (§2.1, §12) y su panel en el
    dashboard (§2.6). Pendiente: el cierre.
    *(`memorias/Memoria_Ampliacion_Segundo_Plano_Monitorizacion_Atalaya.md`, en curso.)*

La numeración de esta sección agrupa las ampliaciones de forma distinta a
CLAUDE.md (que cuenta Shodan, takeover y agentes como una sola ampliación);
el contenido es el mismo.

---

## 7. Detalle: módulo de subdominios (Paso 2)

### 7.1 Por qué Certificate Transparency

Certificate Transparency es un estándar (RFC 6962) que obliga a las
autoridades de certificación a publicar en registros auditables cada
certificado TLS que emiten. Consultar esos registros permite descubrir
subdominios **sin enviar un solo paquete a la infraestructura objetivo**:
es enumeración estrictamente pasiva, apoyada en información pública.

La contrapartida es que CT refleja lo que *se certificó alguna vez*, no lo
que está activo hoy. De ahí la fase de verificación DNS.

### 7.2 Flujo interno

```
dominio
   │
   ▼
[ensure_authorized]  valida formato y comprueba SCAN_ALLOWLIST
   │
   ▼
[fetch_crtsh]  GET crt.sh + reintentos con backoff exponencial
   │  JSON de certificados
   ▼
[parse_crtsh_payload]  extrae SAN y common_name
   │
   ▼
[normalize_hostname]  minúsculas · sin punto final · expande comodines
   │                  descarta correos y nombres fuera de alcance
   │  conjunto de candidatos únicos
   ▼
[detect_wildcard_dns]  resuelve <uuid>.dominio: si responde, hay comodín
   │                    y esas son sus IPs (nunca lanza)
   ▼
[resolve_hostname]  A + AAAA, concurrente, acotado por semáforo
   │
   ▼
[reclasificar]  active cuyas IPs ⊆ IPs del comodín → wildcard
   │
   ▼
SubdomainScanResult  (registros + resumen + incidencias + wildcard_ips)
```

### 7.3 Decisiones relevantes

| Decisión | Justificación |
|---|---|
| Reintentos con backoff ante fallo de crt.sh | El servicio es gratuito e históricamente inestable; un 502 puntual no debe invalidar el escaneo |
| Degradación controlada en vez de excepción | Si una fuente cae, el escaneo continúa y el fallo se registra como incidencia trazable |
| Semáforo sobre la concurrencia DNS | Evita saturar el resolver y el descarte de respuestas por *rate limiting* |
| `resolve_hostname` nunca lanza excepción | Un host problemático no puede abortar la enumeración completa |
| Expansión de comodines (`*.x.com` → `x.com`) | Un comodín no es un host; conservarlo generaría un activo inexistente |
| Verificación de sufijo estricta | `ejemplo.com.evil.net` no pertenece a `ejemplo.com`; comprobar solo `endswith` sin el punto sería explotable |
| Modelos Pydantic | Validan la entrada externa y sirven directamente como esquema de respuesta en la API (Paso 4) |

### 7.4 Estados de resolución

| Estado | Significado |
|---|---|
| `active` | Resuelve a una o más IPs **enrutables**; superficie real |
| `unroutable` | Resuelve, pero solo a direcciones no alcanzables |
| `nxdomain` | El nombre no existe; superficie histórica |
| `no_answer` | Existe pero sin registros A/AAAA (p. ej. solo MX) |
| `wildcard` | Resuelve, pero solo a las IPs del comodín DNS del dominio: no es un servicio real (§7.6) |
| `timeout` | El resolver no respondió a tiempo |
| `error` | Fallo inesperado, detallado en el campo `error` |

### 7.5 Alcance de las direcciones IP

Resolver correctamente no equivale a ser alcanzable. El módulo
`core/netutils.py` clasifica cada dirección antes de considerarla un activo:

| Alcance | Rango | Tratamiento |
|---|---|---|
| `public` | Enrutable en Internet | Objetivo válido de escaneo |
| `unspecified` | `0.0.0.0`, `::` | Registro anulado: el servicio se retiró sin borrar el DNS |
| `loopback` | `127.0.0.0/8`, `::1` | No es un host remoto |
| `private` | RFC 1918, RFC 4193 | No alcanzable, pero **filtra direccionamiento interno** |
| `cgnat` | `100.64.0.0/10` | RFC 6598 |
| `link_local` | `169.254.0.0/16`, `fe80::/10` | No enrutable |
| `multicast` | `224.0.0.0/4`, `ff00::/8` | No es un host individual |
| `documentation` | RFC 5737, RFC 3849 | Rangos de ejemplo |
| `reserved` | Otros rangos reservados | No enrutable |
| `invalid` | — | Entrada malformada |

Dos matices de implementación que justifican el orden explícito de
comprobación: `ipaddress.is_global` devuelve verdadero para direcciones
multicast, y Python clasifica los rangos de documentación como privados.
Apoyarse solo en `is_global` produciría clasificaciones erróneas.

**Por qué importa.** Un nombre que resuelve a `0.0.0.0` inflaría el recuento
de activos con hosts inexistentes, y esas direcciones llegarían al módulo de
puertos provocando intentos de conexión inútiles o dirigidos al propio equipo
que ejecuta la herramienta. Por eso `scan_targets()` devuelve exclusivamente
direcciones enrutables.

**Direccionamiento interno como hallazgo.** Un subdominio público que resuelve
a una IP privada no es un activo alcanzable, pero revela estructura de red
interna. Se marca mediante `leaks_internal_addressing`, genera un `Finding`
(`core/persistence.py`) y la capa IA lo tría como hallazgo propio
(`POST /scans/{id}/triage`).

### 7.6 Wildcards DNS

Un dominio con **DNS wildcard** (`*.dominio` → una IP fija) hace que
cualquier nombre resuelva, exista o no como servicio. Sin filtro, cada
candidato de crt.sh/Shodan que nunca se dio de alta contaría como activo: el
mismo tipo de falso positivo que `0.0.0.0` (§7.5), por eso se trata como un
defecto de corrección y no como una limitación.

- `detect_wildcard_dns()` resuelve un subdominio con un **UUID** (no puede
  existir de verdad) antes de la resolución masiva. Si responde, sus IPs son
  las del comodín. Un fallo del resolver se trata como "no hay wildcard"
  (degradación controlada).
- Tras resolver, todo registro `active` cuyas IPs sean **subconjunto** de las
  del comodín pasa a `wildcard`. Un host con alguna IP propia sigue `active`:
  puede ser un servicio real que además comparta la IP del comodín.
- `wildcard` no es `active`, así que el host sale de `active_records` y del
  recuento sin tocar esas propiedades. `scan_targets()` recorre solo los
  activos, y `apply_port_scan()` solo asigna puertos a activos `active`: la
  IP del comodín se escanea únicamente si un host activo de verdad resuelve
  a ella, y aun así el host `wildcard` no hereda sus puertos (hasta
  `e581fa3` no era así, pese a lo que decía este apartado). Tampoco es
  `no_answer`/`nxdomain`/`unroutable`, así que no entra en la detección de
  takeover (tiene IP: no hay CNAME colgante). El registro se conserva en
  `records`, y `summary()` expone `wildcard_dns`/`wildcard_filtered`.

### 7.7 Integración

- **Paso 2 (puertos, cabeceras, TLS)** ✅ — `SubdomainScanResult.scan_targets()`
  alimenta el escaneo de puertos (`discovery/ports.py`), ya filtrado de
  direcciones no enrutables; `SubdomainScanResult.active_records` alimenta
  cabeceras y TLS (`discovery/headers.py`, `discovery/tls.py`), orquestados
  por `discovery/enrichment.py::enrich_scan()`.
- **Paso 3 (BD)** ✅ — cada `SubdomainRecord` se corresponde con una fila de
  `Asset` (`core/persistence.py::save_subdomain_scan`); los puertos y
  hallazgos del enriquecimiento se aplican con `apply_port_scan()` y
  `apply_discovery_findings()`.
- **Paso 4 (API)** ✅ — `POST /scans` devuelve el `Scan` persistido a través de
  `api/schemas.py` (no se exponen los modelos ORM directamente).

---

## 8. Detalle: riesgo de subdomain takeover (ampliación)

### 8.1 Por qué mirar exactamente los hosts que NO resuelven

Un *subdomain takeover* ocurre cuando un CNAME sigue apuntando a un
servicio de hosting de terceros (GitHub Pages, Heroku, S3, Azure...) cuyo
recurso ya no está reclamado: cualquiera puede darlo de alta en ese
proveedor y servir contenido bajo el dominio de la víctima.

Un host `active` (resuelve por A/AAAA a una IP real) tiene un servicio
propio detrás — no depende de un CNAME de terceros sin reclamar. La señal
vive en los hosts `no_answer`/`nxdomain`/`unroutable`: existen en DNS
(crt.sh los certificó alguna vez, o Shodan los indexó) pero no tienen IP
propia asociada — exactamente el patrón de un CNAME que apuntaba a un
recurso que se liberó. Es la deuda técnica que el propio CLAUDE.md ya
documentaba tras el escaneo de `github.com` en el Paso 2 (~50 hosts en
`no_answer`).

### 8.2 Flujo interno

```
SubdomainScanResult.records  (TODOS, no solo active_records)
   │
   ▼
[filtrar por status]  no_answer / nxdomain / unroutable
   │  candidatos a inspeccionar
   ▼
[_resolve_cname]  consulta CNAME, concurrente, acotada por semáforo
   │  nunca lanza excepción (degradación controlada)
   ▼
[match_takeover_pattern]  compara contra TAKEOVER_PATTERNS (~20 proveedores)
   │                      comparación por sufijo + punto separador (mismo
   │                      criterio anti-engaño que normalize_hostname)
   ▼
list[TakeoverCandidate]  (hostname, cname, provider, pattern_matched)
```

Integrado en `discovery/enrichment.py::enrich_scan()` como cuarta rama del
`asyncio.gather`, junto a puertos/cabeceras/TLS — pero sobre
`result.records` completo, no `result.active_records`. Cada
`TakeoverCandidate` se traduce a `DiscoveryFinding`
(`finding_type="subdomain_takeover_risk"`) dentro de
`EnrichmentResult.findings_by_hostname()`, así que se persiste con el mismo
mecanismo genérico que cabeceras/TLS, sin que `core/persistence.py`
necesite conocer este tipo de hallazgo.

### 8.3 Verificación HTTP opt-in, y por qué sigue sin "confirmar"

Coincidir con un patrón de la tabla **no** confirma que el recurso esté sin
reclamar. La detección por patrón (`discovery/takeover.py`) se queda
deliberadamente ahí: es reconocimiento DNS puro, sin una sola petición HTTP.

El **segundo nivel** —comprobar si el destino del CNAME sirve la huella de
"recurso no reclamado" del proveedor (el 404 «There isn't a GitHub Pages
site here», el `NoSuchBucket` de S3...)— vive en un módulo aparte,
`discovery/takeover_verify.py`, y es **opt-in** (`TAKEOVER_VERIFY`, off por
defecto). La versión original de la restricción #6 prohibía *toda* petición
HTTP al recurso de terceros; se reabre de forma estrecha y razonada (no en
silencio — ver la propia restricción #6 en CLAUDE.md, reescrita en paralelo
a este cambio).

**Por qué esto sigue del lado del reconocimiento.** La verificación hace un
`GET` a una página de error **pública** del proveedor y busca su huella
textual. No reclama el recurso, no da de alta nada en el proveedor, no
prueba que el ataque funcione. Por eso el resultado nunca es "takeover
confirmado": el hallazgo se eleva a **"alta sospecha — no confirmado"**, con
la huella como *indicio adicional* sobre el patrón, no como prueba de
explotabilidad. La frontera que #6 protege —no confirmar, no secuestrar—
se mantiene intacta.

**Las tres salvaguardas son la "autorización expresa" que #6 exige**, y son
obligatorias, aplicadas en el propio `takeover_verify.py`:

1. **Opt-in explícito.** Sin `TAKEOVER_VERIFY=true`, `verify_candidates()`
   devuelve los candidatos sin tocar y no se hace ninguna petición: el
   comportamiento por defecto de la herramienta no cambia.
2. **Limitado a `SCAN_ALLOWLIST`.** Antes de sondear el destino de un
   candidato, su hostname debe pasar `is_authorized()`. El sondeo contacta
   necesariamente al proveedor de terceros (es la naturaleza de la
   comprobación), pero solo para candidatos surgidos de un escaneo
   autorizado.
3. **Auditoría.** Cada petición a un tercero deja traza (hostname, destino
   y resultado) en el logger de auditoría de `core/audit.py`, para que quede
   registro de qué infraestructura ajena se ha contactado y por qué. Ese
   logger tiene nivel y handler propios: se emite siempre, sin depender de
   `LOG_LEVEL`, de `-v` ni de cómo configure uvicorn el logging (con un
   `logger.info` corriente la traza se descartaba en silencio bajo la API).

Degradación controlada, igual que el resto del descubrimiento: si el destino
no resuelve, la conexión falla o no hay huella, el candidato se queda en
detección por patrón (sin `unclaimed_indicator`), nunca en error.

La capa IA (`ai/takeover_detective.py`) razona sobre el candidato —con o sin
indicio— y explica el motivo del riesgo, pero con la misma restricción en su
*system prompt*: nunca afirma que el recurso esté confirmado como
secuestrable.

## 9. Detalle: enrutado de preguntas en lenguaje natural (ampliación)

```
pregunta del usuario
   │  POST /findings/ask {domain|scan_id, question}
   ▼
[resolver Scan]  repository.get_scan()/get_latest_scan() — igual que antes
   │  404 si no hay escaneo completado
   ▼
[ai/prompter.py::route_and_answer]
   │
   ├─ build_routing_context(scan)  resumen ligero: nº activos, hallazgos
   │                                por severidad, si hay candidatos de takeover
   │
   ├─ complete_tool("route_query")  el modelo decide: "analyst" o "takeover",
   │                                y reformula la pregunta con contexto ya
   │                                incorporado (refined_question)
   │
   │  clasificación insegura (agent no reconocido, o refined_question
   │  vacía) → fallback silencioso a "analyst", nunca se queda sin responder
   │
   ├─▶ "analyst"   → ai/analyst.py::analyze_scan(provider, scan, question=...)
   └─▶ "takeover"  → hallazgos finding_type="subdomain_takeover_risk" ya
                     persistidos (no vuelve a invocar discovery/takeover.py)
                     → ai/takeover_detective.py, envuelto en AnalystResult
   │
   ▼
AnalystResult  (answer, patterns, concerning_combinations, priorities)
   │  siempre la misma forma, venga de cualquiera de los dos agentes
   ▼
AskResponse  (API) — expone los cuatro campos, no solo `answer`
```

El paso de enrutado es una petición puntual: si el proveedor falla ahí,
`AIProviderError` se propaga (→ 502), igual que hacía `ai/query.py::ask()`
en el Paso 5 — no hay nada parcial que conservar en una única pregunta.

---

## 10. Detalle: puesta en marcha guiada (`init` y `doctor`)

### 10.1 `atalaya init`: nada se escribe hasta confirmar

```
[1 Alcance]     dominios → normalize_domain() → confirmación de autorización
                (vacío solo con --allow-any; sin autorización → sale, código 1)
[2 Base datos]  SQLite / Postgres del compose / URL propia → probe_database()
                (conecta y lee la revisión de Alembic; un SQLite inexistente
                 no se abre: abrirlo lo crearía)
[3 IA]          Anthropic / Gemini / más tarde → lista de modelos (gratuita)
                → modelo disponible con esa clave
[4 Shodan]      opcional → /api-info (gratuito) → aviso si el plan es oss
[5 Seguridad]   X-API-Key (secrets.token_urlsafe(32)) y takeover opt-in
        │
[Resumen]  secretos enmascarados (sk-ant-…a1b2, URL sin contraseña)
        │  ¿Escribir? ── no ──→ código 1, nada escrito
        ▼
write_env()  → check_secrets() (git) → apply_migrations() → siguientes pasos
```

Ctrl+C en cualquier punto anterior al resumen sale con 130 y sin cambios: por
eso las migraciones se aplican al final, sobre la base de datos elegida y
después de escribir el `.env`, y no al elegirla. Alembic recibe esa URL por
`config.attributes` (`migrations/env.py`), porque el `.env` que la contiene
aún no existía al arrancar el proceso, y se ejecuta en un hilo aparte
(`env.py` hace `asyncio.run()`). Con un `.env` previo, Enter conserva cada
valor actual.

`--non-interactive` reúne las mismas respuestas desde opciones (`--allowlist`,
`--database`, `--ai-provider`...) y los secretos **solo** desde variables de
entorno: como argumentos quedarían en el historial y en la lista de
procesos. Opciones incompletas → código 2; algo que no valida → código 1;
en ambos casos sin escribir nada. Sin terminal interactiva (un pipe, Git Bash
sin `winpty`), `init` lo explica y sale con 2 en vez de quedarse esperando.

### 10.2 Escritura del `.env`

1. Se parte del `.env` existente o, si no hay, de `.env.example`, y solo se
   reemplazan los valores pedidos: comentarios, orden y demás campos quedan.
2. El texto resultante se vuelve a leer con `python-dotenv` (el mismo parser
   que usa pydantic-settings) y se compara con lo pedido. Si algo no sale
   idéntico, no se escribe. Caso real: `${...}` se expande incluso entre
   comillas simples y no tiene escape.
3. Copia del anterior en `.env.bak-AAAAMMDD-HHMMSS`; escritura en un temporal
   del mismo directorio y `os.replace` (atómico); `chmod 600` en POSIX.
4. Las copias y temporales llevan las mismas claves: `.gitignore` y
   `.dockerignore` los excluyen, y `doctor` comprueba que git los ignore.

### 10.3 `atalaya doctor`

| Comprobación | Error | Aviso |
|---|---|---|
| Configuración | un valor del `.env` no carga | no hay `.env`; claves que Atalaya no conoce (pydantic las ignora sin avisar) |
| Alcance | entrada que no es un dominio | `SCAN_ALLOWLIST` vacía (sin restricción) |
| Base de datos | no conecta | no existe, sin migrar o migraciones pendientes |
| IA | clave rechazada, proveedor desconocido, `replay` sin grabaciones | sin clave, modelo no disponible, no se pudo comprobar |
| Shodan | clave rechazada | plan sin búsqueda DNS |
| crt.sh | — | no responde (el escaneo sigue solo con DNS) |
| API | — | sin `X-API-Key` |
| Secretos | `.env` o una copia versionados o sin ignorar en git | — |

Sale con 1 si hay algún error; los avisos no cuentan como fallo. Las
comprobaciones de red van en paralelo y `--offline` las omite. Ninguna
devuelve un secreto: hay un test que lo exige sobre la salida completa.

**Sin coste y sin prometer de más.** Las claves se validan con llamadas que no
consumen crédito (lista de modelos, `/api-info`), y por eso mismo no
comprueban el saldo: una clave válida sin crédito pasa, y la pantalla lo dice.
La clave de Gemini va en la cabecera `x-goog-api-key`; la de Shodan solo
puede ir en la URL, y la CLI deja `httpx` en WARNING para que no acabe en el
log (era un defecto real de `atalaya -v`).

### 10.4 Terminal

`rich`, con menús numerados: las librerías de menús con flechas
(`prompt_toolkit`) fallan en Git Bash. Si la salida no es UTF-8 (redirigida
en Windows, cp1252), logo, iconos y reglas pasan a ASCII y la salida se
reconfigura con `errors="replace"`: escribir `●` en cp1252 lanzaba
`UnicodeEncodeError` dentro de `rich` (reproducido al maquetar). No se fuerza
UTF-8: quien recibe la salida redirigida espera su codificación. Las claves
se leen con `getpass` y, al terminar, la línea se reescribe con puntos.

### 10.5 El estado en el dashboard: `GET /config/status`

```
dashboard (cada carga, 60 s por sesión)
   │  GET /config/status  (X-API-Key si está configurada)
   ▼
api/routes/config.py ── inputs_from_settings(settings del proceso, cwd)
   ▼
onboarding/checks.py::run_local_checks()
   ├─ config, alcance, API ............ en memoria
   ├─ base de datos ................... la propia de la herramienta (sin escribir)
   ├─ IA, Shodan ...................... «clave configurada, sin validar»
   └─ secretos (git) .................. en un hilo, para no bloquear el bucle
   ▼
ConfigStatusOut { checks: [CheckResult…], errors, warnings }
```

Son las comprobaciones de `doctor` sin crt.sh y sin validar claves: el
dashboard las pide al cargar, y validar contra Anthropic, Google o Shodan en
cada carga serían llamadas externas por mirar una pantalla. `run_local_checks`
fuerza el modo sin red sea cual sea la entrada, y el cliente HTTP que reciben
IA y Shodan rechaza cualquier petición con un error que no es de `httpx`: si
un cambio hiciera que una de ellas saliera a la red, fallaría con un 500 en
vez de convertirse en silencio en «no se pudo comprobar». Un test sustituye el
transporte real de `httpx` por uno que falla y exige el 200.

Describe la configuración con la que corre el proceso (`settings`, cargada al
arrancar), no el `.env` de ahora: si alguien lo edita sin reiniciar la API,
lo que cuenta es lo que está usando. `CheckResult` es la frontera: `key`
estable para el dashboard, `detail` y `hint` sin secretos (la URL de la base
de datos sale como `host:puerto`, sin contraseña). Un test recorre la
respuesta completa con claves y contraseña configuradas y exige que no
aparezcan. Tarda unas décimas (la base de datos, la revisión de Alembic y
las llamadas a `git`), que es por lo que el dashboard la guarda 60 s.

## 11. Escaneo en segundo plano

```
POST /scans {"domain": ...}
   │  ensure_authorized()  ── no válido → 400 · no autorizado → 403 (nada creado)
   │  INSERT scans (status=running) · commit
   ├─ ?wait=true ──▶ run_scan() en línea ──▶ 201 + detalle
   └─ por defecto ─▶ 202 + Location: /scans/{id}
                      │  BackgroundTasks, después de responder
                      ▼
              run_scan(session_factory, scan_id)        core/scan_runner.py
                 sesión propia ── enumerate_subdomains (vuelve a autorizar)
                               ── enrich_scan
                               ── activos y hallazgos en UNA transacción
                 ├─ bien        → completed (+ incidencias en errors)
                 └─ excepción   → rollback → failed: «el escaneo falló: motivo»
arranque de la API (lifespan)
   └─ fail_interrupted_scans(): running → failed «interrumpido: la API se detuvo…»
```

**Por qué así.** El escaneo de un dominio grande dura minutos; dentro de la
petición, la conexión quedaba abierta todo ese tiempo y un cliente con
timeout lo daba por fallido aunque siguiera. La validación va antes de crear
la fila para que un dominio no autorizado sea un 403 inmediato, no un escaneo
`failed` en la base de datos; `run_scan` vuelve a autorizar porque
`enumerate_subdomains` lo hace siempre (restricción #1). La tarea abre su
propia sesión (`get_session_factory`, sustituible en los tests) porque la de
la petición se cierra al responder. Activos y hallazgos se guardan juntos al
final: quien consulta mientras corre ve el escaneo vacío, nunca a medias.

**Fallos.** `run_scan` no lanza: todo fallo acaba en `failed`. De una
excepción propia guarda su mensaje (pensado para el usuario); de una
inesperada, solo el tipo, porque su texto podría llevar una URL con una clave
(Shodan solo la acepta en la URL). Si la API se detiene a mitad, la tarea
muere sin marcarlo, y el `lifespan` lo cierra al volver a arrancar; si la
base de datos no está lista en ese momento, se registra y la API arranca
igual.

**Límite.** El trabajo vive en el proceso de la API. Con varios procesos
(`uvicorn --workers N`) sobre la misma base de datos, uno que arranca cerraría
como fallidos los escaneos que otro está ejecutando. Se despliega con uno.

## 12. Vigilancia programada

```
POST /monitors {domain, webhook_url, interval_hours, secret?}
   │  ensure_authorized()        ── 400/403 · ya vigilado → 409
   │  validate_webhook_url()     ── https, sin credenciales, todas sus IPs
   │                                públicas → si no, 400 (y auditoría)
   │  línea base = último escaneo completado del dominio (o ninguna)
   └─ INSERT monitors (next_run_at = ahora) → 201

lifespan de la API ── monitor_loop(): cada 60 s          core/monitor_runner.py
   └─ run_due_monitors(): activos con next_run_at <= ahora, DE UNO EN UNO
        ├─ reclamar: UPDATE … SET next_run_at = ahora + intervalo
        │            WHERE id = … AND next_run_at = <leído>   (solo uno gana)
        ├─ ensure_authorized() otra vez ── no → aviso «escaneo_fallido», sin escanear
        ├─ Scan(running) → run_scan()   (el mismo de POST /scans)
        └─ comparar con la línea base, SIN IA:
             escaneo fallido                     → «escaneo_fallido»
             sin línea base                      → este escaneo es la base
             una fuente (crt.sh, Shodan) que     → «escaneo_fallido» (fuente caída,
               aportó hosts a la base y ahora       no «sus hosts desaparecieron»)
               ninguno
             diff con nuevos/desaparecidos/      → «cambios»; la base avanza
               cambiados                            SOLO si el aviso se entregó
             sin cambios                         → la base avanza, sin aviso

send_webhook()                                              core/webhooks.py
   resolver otra vez → todas públicas → POST a la IP validada
   (Host y SNI = nombre; certificado verificado contra el nombre)
   sin redirecciones · cliente nuevo por intento · X-Atalaya-Event
   · X-Atalaya-Signature: sha256=HMAC(secreto, cuerpo) si hay secreto
   · auditoría de cada intento con la URL enmascarada
```

**Por qué existe.** Un ASM se define por vigilar en el tiempo; hasta aquí los
escaneos se lanzaban a mano. El diff (`cambiados`, §2.3) ya decía qué cambió;
esto es el disparador. Reutiliza `run_scan` (§11), así que un escaneo
programado es exactamente uno lanzado a mano, con las mismas restricciones.

**La línea base.** Cada monitor guarda el escaneo contra el que compara el
siguiente, y solo la avanza si el aviso llegó o no había nada que avisar.
Comparando siempre con el escaneo anterior, un aviso que falla (receptor
caído, 503) se perdería: la siguiente ejecución compararía contra un escaneo
que ya incluye el cambio. Así, el aviso fallido se repite acumulado. No hay
reintentos inmediatos: el siguiente intento es la siguiente ejecución.

**Falsas alarmas.** Con crt.sh caído, el escaneo termina «completado» (es
degradación controlada) pero sin los hosts que aportaba crt.sh, y el diff los
daría por desaparecidos. El criterio es **por fuente**: si crt.sh o Shodan
aportaron hosts a la línea base (`Asset.sources`) y ninguno al escaneo
actual, esa fuente cayó; se avisa como escaneo fallido y la base no se mueve.
crt.sh es histórico: una fuente que aportaba hosts no vuelve a cero sin más.
No sirve contar activos: el dominio raíz entra siempre aunque no responda
ninguna fuente, así que crt.sh caído deja 1 activo, no 0. La primera versión
usaba «0 activos» y la prueba completa lo destapó (`f541101`): en github.com
habría avisado de 116 «desaparecidos». Tampoco sirve mirar las incidencias:
con clave de Shodan, su 403 aparece en todo escaneo. Fuente a fuente cubre la
caída parcial (crt.sh cae, Shodan responde), y una fuente que nunca aportó
(crt.sh a `scanme.nmap.org`) no cuenta. Límite: si una fuente deja de
responder para siempre (una suscripción que caduca), cada ejecución avisa del
fallo, y no compara, hasta que se corrija la configuración. El aviso de cambios incluye las incidencias del escaneo,
para que el receptor sepa si un «desaparecido» viene de un escaneo degradado.

**También se avisan los fallos** (`escaneo_fallido`): escaneo fallido, fuente
caída o dominio que ya no está en la allowlist. En vigilancia, el peor fallo
es el silencioso: una semana sin avisos se lee como «nada ha cambiado».

**SSRF.** El webhook es una petición de la API a una URL que da el usuario.
Mismo criterio que la restricción #2 para los objetivos: solo direcciones
enrutables (`classify_ip`). Basta una dirección interna entre las del nombre
para rechazarlo. Se valida al crear y otra vez al enviar, y al enviar se
conecta a la IP validada en vez de dejar que httpx resuelva el nombre otra
vez: entre dos resoluciones, un DNS con TTL 0 podría cambiar la respuesta a
`127.0.0.1` (*DNS rebinding*). El nombre va en `Host` y en el SNI, y el
certificado se verifica contra él (comprobado contra un servidor real: con un
nombre que el certificado no cubre, la conexión se rechaza). Si una dirección
no conecta, se prueba la siguiente de las validadas (sin esto, un host con
IPv6 en primer lugar no recibiría avisos desde una máquina sin IPv6); una vez
conectado, no se reintenta, porque el aviso pudo llegar. No se siguen
redirecciones. El mensaje de rechazo dice el tipo de dirección, no la IP.

**Secretos.** Las URL de Slack o Discord llevan el token en la ruta: la API
devuelve `https://host/…`, la auditoría registra lo mismo, y de un error de
httpx solo se guarda el tipo (su texto lleva la URL). El secreto de la firma
no se devuelve nunca. Ambos se guardan en claro en la base de datos (los
necesita para enviar y firmar), como las claves del `.env`. Solo `https`: el
aviso es un mapa de la superficie de exposición.

**Firma.** Con `secret` (mínimo 16 caracteres), cada aviso lleva
`X-Atalaya-Signature: sha256=<HMAC-SHA256 del cuerpo>`, el esquema de los
webhooks de GitHub. El cuerpo incluye `sent_at`, así que la firma cubre la
fecha y un receptor puede rechazar un aviso antiguo reenviado.

**Intrusividad.** Intervalo mínimo de 1 hora (restricción #5): un escaneo hace
cientos de conexiones al objetivo, y repetirlo cada pocos minutos sería un
barrido continuo. Un monitor por dominio, por la misma razón. Los monitores
pendientes se ejecutan de uno en uno (crt.sh limita a quien le pide mucho a la
vez), y tras una parada larga el siguiente turno se calcula desde ahora: un
monitor horario se ejecuta una vez, no veinticuatro seguidas.

**Varios procesos.** El bucle vive en el proceso de la API. Con varios, cada
uno tendría el suyo, pero cada ejecución se reclama con un `UPDATE`
condicional sobre el `next_run_at` leído y solo uno lo gana (probado con dos
revisiones simultáneas). El límite de §11 (el arranque de un proceso cierra
los escaneos en curso de otro) sigue en pie.

**Límites.** El diff no distingue un cambio real de una fluctuación de DNS o
un timeout: un dominio grande puede avisar en casi cada ejecución. Sin
reintento inmediato de un aviso fallido. Los escaneos programados no se
distinguen de los manuales en `GET /scans` (el monitor guarda su último
escaneo). El panel no edita un monitor (se borra y se crea otro) ni guarda un
historial de avisos.
