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
  + puertos + cabeceras + TLS + riesgo de takeover) y lo persiste.
- `GET  /scans`, `GET /scans/{id}` ✅ — consulta de escaneos (404 si no existe).
- `GET  /assets` ✅ — activos descubiertos, filtrables por `scan_id`.
- `GET  /findings` ✅ — hallazgos, filtrables por `asset_id`/`scan_id`;
  `severity` es `unknown` hasta triarlos.
- `POST /scans/{id}/triage` ✅ — triaja con IA los hallazgos `unknown` de un
  escaneo ya persistido. Idempotente: no repite los ya triados.
- `POST /findings/ask` ✅ — consulta en lenguaje natural, enrutada por
  `ai/prompter.py` al agente adecuado (visión global o riesgo de takeover)
  sobre el último escaneo completado de un dominio (o uno concreto vía
  `scan_id`).
- `GET /scans/{id}/diff/{other_id}` ✅ — compara dos escaneos del mismo
  dominio (`core/repository.py::diff_scans()`) y valora los cambios con
  `ai/diff_analyst.py`. `previous`/`current` se deciden por `started_at`,
  no por el orden en la URL.
- `GET /scans/{id}/report` ✅ — informe PDF con portada, `risk_score` y
  resumen ejecutivo de `ai/report_writer.py` (opcional: el informe se
  genera igual sin IA disponible, ver 2.5).

`api/schemas.py` define la frontera Pydantic entre las tablas y la respuesta
pública; `api/main.py` traduce `InvalidTargetError`/`UnauthorizedTargetError`
a 400/403 vía `exception_handler`, en vez de que cada ruta gestione sus
propios códigos de error.

### 2.2 Descubrimiento — `src/atalaya/discovery` (Paso 2 ✅ + ampliación)
Cada técnica es un módulo independiente con salida normalizada:

| Módulo         | Qué obtiene                                    | Fuente                  |
|----------------|------------------------------------------------|-------------------------|
| `subdomains`   | Subdominios                                    | crt.sh (CT logs) + `shodan` (opcional), concurrentes, fusionados por hostname |
| `shodan`       | Segunda fuente de subdominios                  | API DNS de Shodan (`SHODAN_API_KEY` opcional — sin ella, se omite sin incidencia) |
| `ports`        | Puertos TCP abiertos (`COMMON_PORTS` por defecto) | Conexión asíncrona, concurrencia acotada |
| `headers`      | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Petición HTTP(S) |
| `tls`          | Versión de protocolo, emisor, caducidad del certificado | `cryptography` sobre el `ssl_object` de la conexión |
| `takeover`     | Riesgo de *subdomain takeover* (patrón de CNAME hacia hosting de terceros) | Resolución DNS de CNAME sobre hosts **sin** A/AAAA — reconocimiento pasivo, sin verificar |
| `enrichment`   | Orquesta `ports`+`headers`+`tls` (hosts activos) y `takeover` (todos los registros), concurrentemente | Compone los cuatro anteriores |

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

### 2.3 Persistencia (PostgreSQL) — `src/atalaya/core`
Modelo de datos relacional (`core/models.py`, Paso 3 ✅):

- **Scan** — un escaneo (dominio objetivo, fecha, estado, incidencias).
- **Asset** — activo descubierto (host, IPs, alcance, puertos abiertos).
- **Finding** — hallazgo (tipo, evidencia, severidad, remediación, `asset_id`).

Relaciones: `Scan 1─N Asset`, `Asset 1─N Finding`. Las migraciones viven en
`migrations/` (Alembic, motor async). `core/persistence.py` traduce los
resultados de descubrimiento a estas filas: `save_subdomain_scan()` (un
`SubdomainScanResult` → `Scan`+`Asset`; un host con
`leaks_internal_addressing` genera además un `Finding`), `apply_port_scan()`
(`EnrichmentResult.ports_by_ip` → `Asset.open_ports`) y
`apply_discovery_findings()` (hallazgos de cabeceras/TLS → `Finding`, con
severidad `unknown` hasta el triaje).

`core/repository.py` es la contraparte de lectura: `get_scan`, `list_scans`,
`get_latest_scan`, `list_assets`, `list_findings` y `diff_scans()` (compara
los hostnames de dos escaneos del mismo dominio — la razón de ser de
persistir escaneos en el tiempo). La API (2.1) y el dashboard (2.6) consultan
por aquí, no construyen `select()` propios.

### 2.4 Capa IA — `src/atalaya/ai` (Paso 5 ✅ + sistema de agentes)

- `provider` — `LLMProvider` (interfaz, ABC) + `AnthropicProvider` +
  `GeminiProvider`. Dos formas de pedir una respuesta: `complete()` (texto
  libre) y `complete_tool()` (fuerza una llamada a herramienta — `tool_choice`
  fijo en Anthropic, `FunctionCallingConfig(mode="ANY",
  allowed_function_names=[...])` en Gemini — para una respuesta con forma
  garantizada, más fiable que pedir "responde en JSON" sobre texto libre).
  `AI_PROVIDER` en `.env` elige cuál se instancia; ningún otro módulo de
  `ai/` conoce el SDK concreto.
- `triage` — `triage_finding`/`triage_findings`: reciben un `Asset` y un
  `Finding`, devuelven severidad razonada, impacto explicado y remediación
  concreta. Aquí se aplica el principio que el proyecto asume como central:
  **dar a la IA contexto estructurado** (`build_finding_context`, campos
  seleccionados a propósito), **no un dump de la fila de BD**. Degradación
  controlada: un fallo de un hallazgo no aborta el resto (`TriageBatchResult`).
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
| Comparador de escaneos | `diff_analyst.py` | `ScanDiff` (nuevos/desaparecidos/comunes) + los dos `Scan` completos | Valoración en prosa: expansión de superficie, riesgo de lo desaparecido |

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
- `_compute_risk_score()` — pesos por severidad (`critical=25, high=10,
  medium=4, low=1`), sumados y acotados a 100. Fuente de verdad única: el
  dashboard replica exactamente estos pesos para no mostrar un número
  distinto al del PDF del mismo escaneo.
- `generate_report(scan, provider=None)` — con `provider`, incluye un
  resumen ejecutivo de `ai/report_writer.py::write_executive_summary()`.
  **Si `provider` es `None`, o si falla (`AIProviderError`), el informe se
  genera igual, sin resumen** — el informe con portada era un requisito
  obligatorio antes de que existiera la capa IA, así que nunca puede
  depender de ella. Asimetría deliberada frente al endpoint de diff (2.1),
  que sí propaga el fallo del proveedor.
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
detalle de un escaneo (calculado en el propio dashboard a partir de la
severidad de los hallazgos ya devueltos por `GET /scans/{id}`, con los
mismos pesos que `reporting/generator.py::_RISK_WEIGHTS`, sin llamar a la
capa de reporting directamente — el dashboard es siempre un cliente HTTP
puro de la API).

Estética rediseñada en `_CSS` (inyectado con `st.html()`, no
`st.markdown(..., unsafe_allow_html=True)` — ver "Decisiones de diseño")
para parecer una herramienta comercial de seguridad (referentes: Shodan,
VirusTotal, Maltego), no la demo por defecto de Streamlit: fondo oscuro,
tipografía monoespaciada para datos técnicos, acento único, rojo reservado
a severidad crítica. *(Sección a completar/verificar con el detalle final
de esa fase — ver `memorias/` para el proceso completo, incluido el bug de
renderizado encontrado y corregido.)*

## 3. Flujo de datos

```
dominio
   │  POST /scans
   ▼
[Descubrimiento]  subdominios (crt.sh + Shodan) → puertos → cabeceras → TLS
   │               → riesgo de takeover (sobre TODOS los registros)
   │  hallazgos crudos
   ▼
[PostgreSQL]  se persisten activos y hallazgos
   │
   ▼
[Capa IA]  triaje: severidad + impacto + remediación
   │       (+ prompter/analyst/takeover_detective/report_writer/diff_analyst)
   │
   ├──▶ [Dashboard]  visualización, consulta NL, risk_score, diff
   └──▶ [Informes]   PDF con portada + risk_score + resumen ejecutivo IA
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
- **Salvaguarda de autorización** (`SCAN_ALLOWLIST`): limita los objetivos
  escaneables, alineado con un uso responsable de la herramienta.
- **Reconocimiento nunca verifica explotabilidad** (restricción de seguridad
  #6): aplicado literalmente en `discovery/takeover.py` — patrón de CNAME,
  nunca una petición HTTP al recurso de terceros para confirmar si está
  libre.
- **`st.html()`, no `st.markdown(unsafe_allow_html=True)`**, para CSS
  grande en el dashboard: el parser de Markdown de Streamlit no trata de
  forma fiable un bloque `<style>` grande con líneas en blanco dentro — bug
  real, reproducido y corregido (ver `memorias/` y CLAUDE.md).

## 5. Mapa de requisitos → implementación

| Requisito de la práctica | Dónde se resuelve                          |
|--------------------------|--------------------------------------------|
| Base de datos            | `core/models.py` + `core/persistence.py` (Paso 3 ✅) |
| API / webhook            | `api/` (propia, Paso 4 ✅) + `discovery/`/`ai/` (consumo de crt.sh, Shodan, Anthropic/Gemini) |
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
10. **Dashboard: diseño visual profesional** 🔨 — estética de herramienta
    comercial de seguridad, `risk_score` como métrica principal. *(Detalle
    completo del proceso en `memorias/`.)*

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
[resolve_hostname]  A + AAAA, concurrente, acotado por semáforo
   │
   ▼
SubdomainScanResult  (registros + resumen + incidencias)
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

### 7.6 Integración

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

### 8.3 Por qué nunca verifica el recurso de terceros

Coincidir con un patrón de la tabla **no** confirma que el recurso esté
sin reclamar — eso exigiría una petición HTTP al proveedor de terceros
para comprobar si responde "no existe", y eso cruzaría de reconocimiento a
verificación de explotabilidad, prohibido explícitamente por la
restricción de seguridad #6 de CLAUDE.md. Se prefiere un falso positivo
señalado por patrón a confirmar un takeover real. La capa IA
(`ai/takeover_detective.py`) razona sobre el candidato y explica el motivo
del riesgo, pero con la misma restricción aplicada a su *system prompt*:
nunca afirma que el recurso esté confirmado como secuestrable.

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
