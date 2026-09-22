# Atalaya — contexto del proyecto

Plataforma de **Attack Surface Management (ASM) con triaje por IA**. Entrega
de la Práctica 1 de un Máster en Ciberseguridad e IA. Desarrollo en solitario.

---

## Requisitos obligatorios de la entrega

El enunciado es explícito: **si falta uno de estos puntos, la práctica está
suspensa**. Cualquier decisión de diseño debe respetarlos.

| Requisito | Cómo se cubre | Estado |
|---|---|---|
| Base de datos | PostgreSQL + SQLAlchemy async | ✅ Modelos Scan/Asset/Finding + migraciones Alembic. Persiste subdominios, puertos abiertos y hallazgos de cabeceras/TLS/takeover |
| API o webhook | API REST propia **y** consumo de APIs externas | ✅ `scans`/`assets`/`findings`, triaje (`POST /scans/{id}/triage`), consulta NL vía agentes (`POST /findings/ask`), diff entre escaneos (`GET /scans/{id}/diff/{other_id}`) e informe (`GET /scans/{id}/report`) reales. Consume crt.sh, Shodan y (Anthropic o Gemini, configurable) |
| Aplicación web | Dashboard Streamlit | ✅ Escaneos, triaje IA, consulta NL, descarga de informe — rediseño visual profesional (ver "Dashboard: diseño visual" más abajo) |
| GitHub con historial | Commits por unidad lógica | ✅ commits por fase |
| Reporte con portada | Informe generado por la herramienta | ✅ PDF con portada, resumen ejecutivo en lenguaje natural (IA), `risk_score` y hallazgos (`reporting/generator.py`) |

**El historial de commits se evalúa.** No agrupar trabajo de varias fases en
un commit único; el desarrollo progresivo es parte de lo que se califica.

---

## Qué hace la herramienta

Recibe un dominio y ejecuta cuatro fases:

1. **Descubrimiento** — subdominios (Certificate Transparency + Shodan + DNS),
   puertos, cabeceras de seguridad HTTP, configuración TLS, riesgo de
   *subdomain takeover* (patrón de CNAME hacia hosting de terceros).
2. **Persistencia** — activos y hallazgos en base de datos, para comparar
   escaneos en el tiempo (`GET /scans/{id}/diff/{other_id}`).
3. **Triaje por IA** — un LLM prioriza hallazgos, explica impacto real y
   propone remediación. **Es el componente diferencial del proyecto.**
4. **Consulta e informe** — preguntas en lenguaje natural (a través de un
   sistema de agentes especializados, ver más abajo) e informe ejecutivo
   con resumen en lenguaje natural.

### Sistema de agentes de IA

La capa IA no es un único prompt genérico: cada tarea tiene un agente
especializado, todos sobre la misma interfaz `LLMProvider`
(`ai/provider.py`), intercambiable entre Anthropic (Claude) y Gemini vía
`AI_PROVIDER` en `.env`:

| Agente | Fichero | Responsabilidad |
|---|---|---|
| Triaje | `ai/triage.py` | Severidad/impacto/remediación de **un** hallazgo — el original, sin tocar desde el Paso 5 |
| Prompter | `ai/prompter.py` | Intermediario de `POST /findings/ask`: enruta la pregunta al agente adecuado |
| Analista | `ai/analyst.py` | Visión global de un escaneo: patrones, combinaciones preocupantes, prioridades |
| Detective de takeover | `ai/takeover_detective.py` | Prioriza y explica los candidatos a *subdomain takeover* ya detectados |
| Redactor de informes | `ai/report_writer.py` | Resumen ejecutivo del PDF, en lenguaje no técnico |
| Comparador de escaneos | `ai/diff_analyst.py` | Valora si el diff entre dos escaneos es preocupante |

No confundir con los **subagentes de Claude Code** (`.claude/agents/`), que
son herramienta de desarrollo, no parte del producto — ver "Cómo quiero
trabajar" al final de este documento.

---

## Estado del código

### Implementado y verificado

```
src/atalaya/
├── config.py                    Configuración desde entorno (.env)
├── cli.py                       CLI con subcomando `subdomains`
├── core/
│   ├── database.py              Engine async + Base declarativa + get_session
│   ├── models.py                Scan, Asset, Finding (SQLAlchemy 2.0)
│   ├── persistence.py           save_subdomain_scan(), apply_port_scan(),
│   │                             apply_discovery_findings() — descubrimiento → BD
│   ├── repository.py            Lectura: get_scan, list_scans, get_latest_scan,
│   │                             list_assets, list_findings, diff_scans()
│   ├── exceptions.py            AtalayaError, UnauthorizedTargetError, ...
│   ├── authorization.py         ensure_authorized() — SCAN_ALLOWLIST
│   └── netutils.py              classify_ip() — 10 alcances de red
├── discovery/
│   ├── models.py                SubdomainRecord, SubdomainScanResult,
│   │                             DiscoveryFinding, HeaderScanResult, TlsScanResult,
│   │                             TakeoverCandidate, EnrichmentResult
│   ├── subdomains.py            Enumeración (crt.sh + Shodan, concurrentes,
│   │                             fusionadas por hostname) + verificación DNS
│   ├── shodan.py                 fetch_shodan_subdomains() — segunda fuente,
│   │                             opcional (SHODAN_API_KEY vacía = se omite)
│   ├── ports.py                  scan_ports() — TCP asíncrono, puertos comunes
│   ├── headers.py                 analyze_headers() — HSTS/CSP/XFO/XCTO/
│   │                             Referrer-Policy/Permissions-Policy
│   ├── tls.py                     inspect_tls() — versión, emisor, caducidad
│   ├── takeover.py                find_takeover_candidates() — riesgo de
│   │                             subdomain takeover vía patrón de CNAME
│   │                             (reconocimiento pasivo, nunca verifica)
│   └── enrichment.py              enrich_scan() — orquesta las cuatro técnicas;
│                                 takeover corre sobre TODOS los registros,
│                                 las otras tres solo sobre los activos
├── ai/
│   ├── provider.py               LLMProvider (ABC) + AnthropicProvider + GeminiProvider
│   ├── triage.py                 triage_finding/triage_findings — contexto
│   │                             estructurado, nunca un dump de la fila de BD
│   ├── prompter.py               route_and_answer() — enruta una pregunta en
│   │                             lenguaje natural a analyst o takeover_detective
│   ├── analyst.py                analyze_scan() — visión global de un escaneo
│   ├── takeover_detective.py     assess_takeover_risk() — prioriza candidatos
│   │                             a subdomain takeover ya detectados
│   ├── report_writer.py          write_executive_summary() — resumen ejecutivo
│   │                             del informe PDF, en lenguaje no técnico
│   └── diff_analyst.py           analyze_diff() — valora el diff entre dos escaneos
│
│   `ai/query.py::ask()` (consulta NL original) se retiró: `POST /findings/ask`
│   pasa por `prompter.py`, que reemplaza su función y devuelve más señal
│   (patrones, combinaciones preocupantes, prioridades), no solo prosa libre.
├── reporting/
│   ├── generator.py               generate_report()/render_html() — informe PDF
│   │                               con portada (Jinja2 + xhtml2pdf)
│   └── templates/report.html      Plantilla del informe
└── api/
    ├── main.py                  FastAPI + exception_handler (dominio inválido → 400,
    │                             no autorizado → 403, fallo del proveedor IA → 502)
    ├── schemas.py                Esquemas Pydantic de respuesta (frontera BD ↔ API)
    └── routes/
        ├── scans.py              POST/GET /scans, GET /scans/{id},
        │                         POST /scans/{id}/triage,
        │                         GET /scans/{id}/diff/{other_id} — nuevo,
        │                         compara dos escaneos + valoración IA,
        │                         GET /scans/{id}/report — reales
        ├── assets.py              GET /assets?scan_id= — real
        └── findings.py            GET /findings, POST /findings/ask
                                    (vía ai/prompter.py) — reales

migrations/                      Alembic (async); URL desde settings.database_url
dashboard/app.py                 Dashboard Streamlit — escaneos, triaje IA,
                                  consulta NL, descarga de informe. Rediseño
                                  visual profesional (ver sección dedicada)
.claude/agents/                  Subagentes de proyecto de Claude Code (no
                                  es parte del producto, es tooling de
                                  desarrollo — ver "Cómo quiero trabajar")
```

> **Desviación del stub original:** este documento preveía los modelos
> dentro de `core/database.py`. Se separaron en `core/models.py` (entidades)
> y `core/persistence.py` (traducción resultado de descubrimiento → filas)
> para que el ciclo de vida del engine no dependa de qué entidades existen.
> `core/database.py` conserva solo engine/Base/sesión. `core/repository.py`
> sigue el mismo principio para la lectura: los endpoints y el dashboard
> consultan por aquí, nunca construyen su propio `select()`.

> **Desviación del stub original (Paso 5):** CLAUDE.md solo preveía
> `provider.py` y `triage.py` para la capa IA. Se añadió `ai/query.py`
> porque la consulta NL necesita el escaneo completo como contexto (todos
> los activos y hallazgos), no un hallazgo aislado como el triaje — mezclar
> ambos prompts en `triage.py` los habría acoplado sin necesidad. También se
> amplió `LLMProvider` con `complete_tool()` (además de `complete()`): el
> triaje necesita una respuesta con forma garantizada, y eso se consigue
> forzando una llamada a herramienta, no parseando JSON de texto libre.

> **Desviación del stub original (Paso 7):** CLAUDE.md preveía
> `generate_report(scan_id: int, fmt: str = "pdf") -> Path`. Se cambia
> `scan_id: int` por `scan: Scan` ya cargado, por el mismo motivo que
> `ai/query.py::ask()` recibe un `Scan` y no un id + sesión: quien llama
> (el endpoint `GET /scans/{id}/report`) ya lo resuelve vía
> `repository.get_scan()`, con activos y hallazgos precargados. Que este
> módulo aceptara `scan_id` le exigiría su propia sesión de BD y duplicaría
> esa consulta, acoplando la generación del informe a la capa de
> persistencia sin necesidad. Internamente usa Jinja2 (`reporting/templates/
> report.html`) + `xhtml2pdf`, no WeasyPrint: xhtml2pdf es Python puro y no
> depende de Pango/Cairo/GTK, ausentes en un Windows sin ese runtime.

> **Desviación del stub original (Paso 2, resto):** CLAUDE.md solo preveía
> `ports.py`, `headers.py` y `tls.py`. Se añade `discovery/enrichment.py`
> (`enrich_scan()`) para orquestar los tres, concurrentemente y con
> concurrencia acotada, sobre los hosts activos de un
> `SubdomainScanResult` — mismo motivo que separó `ai/query.py` de
> `ai/triage.py`: compone módulos independientes, no pertenece a ninguno en
> particular, y evita que `POST /scans` tenga que orquestar tres semáforos
> directamente en el endpoint. Cada módulo devuelve `DiscoveryFinding`
> (nuevo en `discovery/models.py`), no un `Finding` de SQLAlchemy — el
> descubrimiento no conoce la capa de persistencia; `core/persistence.py`
> traduce con `apply_port_scan()`/`apply_discovery_findings()`, mismo
> patrón que `save_subdomain_scan()`. Puertos/cabeceras/TLS no generan
> ningún código nuevo en `ai/triage.py` ni en `reporting/generator.py`:
> ambos ya procesan cualquier `Finding`/`Asset.open_ports` de forma
> genérica, sin mirar `finding_type`.

> **Ampliación (Shodan, post-Paso 7):** `discovery/subdomains.py` consulta
> crt.sh y `discovery/shodan.py::fetch_shodan_subdomains()` concurrentemente
> (`asyncio.gather`), fusionando resultados por hostname y conservando de
> qué fuente(s) procede cada uno (`DiscoverySource.SHODAN` nuevo). Shodan es
> opcional: sin `SHODAN_API_KEY`, se omite sin generar ninguna incidencia —
> crt.sh sigue siendo la fuente primaria y obligatoria. Verificado contra la
> API real: un plan gratuito (`oss`) devuelve `403` en `/dns/domain/{domain}`
> (requiere plan de pago), y el código no reintenta un fallo de autorización
> (401/403), solo los transitorios (5xx), igual criterio que crt.sh.

> **Ampliación (subdomain takeover, post-Paso 7):** `discovery/takeover.py`
> resuelve el CNAME de los hosts que **no** resuelven por A/AAAA
> (`no_answer`/`nxdomain`/`unroutable` — ahí vive la señal, no en los
> activos) y lo compara contra una tabla de ~20 patrones conocidos de
> hosting propenso a takeover (GitHub Pages, Heroku, S3, Azure...).
> Reconocimiento estrictamente pasivo: ninguna petición HTTP al recurso de
> terceros — cumple la restricción de seguridad #6. Los candidatos se
> traducen a `DiscoveryFinding` dentro de
> `EnrichmentResult.findings_by_hostname()`, así que se persisten con el
> mismo mecanismo genérico que cabeceras/TLS, sin tocar
> `core/persistence.py`. Módulo independiente de `subdomains.py` (sin
> import circular), mismo criterio que `shodan.py`.

> **Ampliación (sistema de agentes de IA, post-Paso 7):** además del triaje
> original, cinco agentes nuevos sobre la misma interfaz `LLMProvider` (ver
> tabla en "Sistema de agentes de IA" arriba). `ai/query.py::ask()` (la
> consulta NL del Paso 5) se **retiró**: `POST /findings/ask` pasa ahora por
> `ai/prompter.py::route_and_answer()`, que decide si la responde
> `ai/analyst.py` (visión global) o `ai/takeover_detective.py` (preguntas
> específicas de takeover), con *fallback* seguro a `analyst` si la
> clasificación no es segura. Todas las referencias a `ai/query.py` en notas
> de desviación anteriores de este documento son históricas — el módulo ya
> no existe.

> **Ampliación (`GeminiProvider`, post-Paso 7):** segunda implementación de
> `LLMProvider` sobre `google-genai` (cliente async, `client.aio.models.
> generate_content`), activable con `AI_PROVIDER=gemini`. Fuerza la llamada
> a herramienta con `FunctionCallingConfig(mode="ANY",
> allowed_function_names=[...])` — equivalente Gemini del `tool_choice`
> fijo de Anthropic. Ninguna línea de `triage.py`, ni de los agentes
> nuevos, cambió para incorporarlo: es la prueba de que la interfaz cumple
> lo que promete. Verificado contra el modelo real (no solo dobles):
> `complete()`, `complete_tool()` y `triage_finding()` end-to-end con
> respuestas coherentes.

> **Ampliación (diff + informe con IA, post-Paso 7):** `GET /scans/{id}/
> diff/{other_id}` expone `core/repository.py::diff_scans()` (existía sin
> usar desde el Paso 4) más una valoración de `ai/diff_analyst.py`.
> `previous`/`current` se deciden por `started_at`, no por el orden en la
> URL. Propaga `AIProviderError` → 502 (petición puntual). El informe PDF
> gana `risk_score` (0-100, pesos `critical=25/high=10/medium=4/low=1`,
> `reporting/generator.py::_RISK_WEIGHTS`) y un resumen ejecutivo de
> `ai/report_writer.py` — pero, a diferencia del diff, **nunca falla** por
> ausencia o fallo del proveedor de IA: el informe con portada era un
> requisito obligatorio antes de que existiera la capa IA, así que no puede
> depender de ella. Asimetría deliberada, documentada en el propio código.

Validado sobre `github.com`: 117 subdominios descubiertos, 61 activos,
55 objetivos de escaneo, 19 segundos. **262 tests en verde** (170 al cierre
del Paso 7; +90 en la ampliación posterior: Shodan, takeover, 5 agentes de
IA, GeminiProvider, diff + informe con IA; +2 en el rediseño del dashboard —
severidad fuera de la escala y formato de las marcas de tiempo, ver
"Dashboard: diseño visual").

---

## Hoja de ruta

1. ~~Paso 1 — Arquitectura y esqueleto~~ ✅
2. **Paso 2 — Motor de descubrimiento** ✅ — subdominios, puertos, cabeceras,
   TLS, orquestados por `enrich_scan()` sobre los hosts activos de cada escaneo
3. **Paso 3 — Modelos de BD y persistencia** — Scan/Asset/Finding + migraciones ✅ ·
   persiste subdominios, puertos y hallazgos de cabeceras/TLS
4. **Paso 4 — Endpoints REST** ✅ — `scans`/`assets`/`findings`, más
   `/scans/{id}/triage` y `/findings/ask`, añadidos al cerrar el Paso 5
5. **Paso 5 — Capa de IA** ✅ — `LLMProvider`/`AnthropicProvider`, triaje de
   hallazgos con contexto estructurado, consulta NL sobre un escaneo
6. **Paso 6 — Dashboard completo** ✅ — escaneos, triaje IA, consulta NL
7. **Paso 7 — Informe con portada** ✅ — PDF (Jinja2 + xhtml2pdf), descargable
   desde `GET /scans/{id}/report` y desde el dashboard

Se adelantó el Paso 3 antes de completar el resto del descubrimiento, tal
como se venía valorando: los módulos de puertos/cabeceras/TLS nacerán ya
con destino de persistencia en vez de requerir adaptación posterior.

Por el mismo motivo se adelantó el Paso 4 para `scans`/`assets`/`findings`
sin esperar a la capa IA: son CRUD reales sobre lo que ya persiste el
Paso 3.

`POST /scans/{id}/triage` no estaba en el diseño original del Paso 4; se
añadió al implementar el Paso 5 porque, sin una ruta que lo invoque,
`ai/triage.py` sería código alcanzable solo desde tests — lo que CLAUDE.md
pide evitar explícitamente ("los stubs no son código muerto").

8. **Ampliación — Sistema de agentes de IA** ✅ — Shodan (segunda fuente),
   detección de subdomain takeover, cinco agentes de IA nuevos
   (Prompter/Analyst/Takeover Detective/Report Writer/Diff Analyst),
   `GeminiProvider`, endpoint de diff, resumen ejecutivo del informe.
   No forma parte de la entrega numerada original (Pasos 1-7, todos ya
   cerrados y evaluables por sí solos); es trabajo posterior, más allá de
   los requisitos obligatorios, sobre la misma base.
9. **Ampliación — Dashboard: diseño visual profesional** ✅ — rediseño de
   `dashboard/app.py` con estética de herramienta comercial de seguridad
   (Shodan/VirusTotal/Maltego), score de riesgo como métrica principal.
   Sin cambios funcionales: las tres pestañas, el triaje, el informe PDF y la
   consulta en lenguaje natural hacen exactamente lo mismo que antes. Ver
   "Dashboard: diseño visual" para las reglas y las trampas de Streamlit que
   hubo que sortear.

**Plazo:** entrega a finales de septiembre. Los siete pasos de la hoja de
ruta y los cinco requisitos obligatorios están cerrados desde antes de esta
ampliación — nada de lo de abajo era necesario para aprobar, es trabajo
que profundiza el componente diferencial (capa IA) y la calidad percibida
(dashboard) de cara a la defensa oral.

---

## Convenciones del proyecto

### Código

- Python 3.11+, **todo asíncrono** (la carga está dominada por espera de red).
- Type hints en todas las firmas. `from __future__ import annotations`.
- Docstrings en español, explicando **por qué**, no solo qué.
- Pydantic para datos que cruzan una frontera (entrada externa, respuesta API).
- Línea máxima 100 caracteres (`ruff`).

### Manejo de errores

Principio establecido y aplicado en `subdomains.py`: **degradación controlada**.

- Una fuente externa caída **no aborta el escaneo**: se reintenta con backoff
  y, si falla, se registra en `result.errors` y se continúa.
- Las funciones que procesan un elemento de una colección (un host, un puerto)
  **nunca lanzan excepción**: reflejan el fallo en el estado del resultado.
- Las excepciones propias (`core/exceptions.py`) se reservan para condiciones
  que sí deben detener la operación: objetivo inválido o no autorizado.

### Tests

- **Deterministas y sin red.** Las fuentes externas se sustituyen por dobles:
  HTTP con `httpx.MockTransport`, DNS sustituyendo la función del resolver.
- Un fallo en la suite debe indicar siempre un problema del código, nunca una
  caída de servicio.
- Cubrir casos límite y los de seguridad, no solo el camino feliz.
- Ejecutar `pytest -q` antes de dar por terminado cualquier cambio.

### Commits

Convención `feat:` / `fix:` / `chore:` / `docs:` / `build:`, con ámbito:

```
feat(discovery): escaneo asíncrono de puertos con detección de servicios
fix(netutils): excluir multicast de las direcciones enrutables
```

Un commit por unidad lógica. No mezclar fases.

---

## Restricciones de seguridad — no negociables

Esta es una herramienta de reconocimiento. El proyecto se califica también por
cómo trata esto.

1. **Toda fase de descubrimiento pasa por `ensure_authorized()`** antes de
   tocar la red. Sin excepciones.
2. **Solo se escanean direcciones enrutables.** Usa
   `SubdomainScanResult.scan_targets()`, nunca `unique_ips()`. Sin ese filtro,
   un objetivo `127.0.0.1` haría que la herramienta escanee la propia máquina
   que la ejecuta, y `0.0.0.0` produciría conexiones sin destino.
3. **Nada de secretos en el código.** Todo por `.env`, que está en
   `.gitignore`. Solo se versiona `.env.example`.
4. **Comparación de dominios con el punto separador.** `endswith("ejemplo.com")`
   aceptaría `ejemplo.com.evil.net`, que un atacante puede registrar para
   inyectar activos ajenos en el inventario. Hay un test que lo cubre.
5. **Escaneo de puertos: intrusividad acotada.** `discovery/ports.py` limita
   concurrencia (`PORT_SCAN_CONCURRENCY`) y usa una lista reducida de puertos
   comunes por defecto (`COMMON_PORTS`), no un barrido de los 65535. Un
   escaneo agresivo puede degradar el servicio del objetivo y es
   indistinguible de un ataque.
6. **Nunca verificar explotabilidad.** La herramienta señala patrones de riesgo
   (p. ej. un nombre apuntando a hosting no reclamado); no comprueba si son
   explotables. Eso excede el reconocimiento y requiere autorización expresa.

---

## Decisiones ya tomadas (no reabrir sin motivo)

| Decisión | Motivo |
|---|---|
| FastAPI | Async nativo, validación Pydantic, OpenAPI automático |
| PostgreSQL, no SQLite en producción | Concurrencia de escritura durante escaneos |
| No Neo4j por ahora | El modelo es tabular; un segundo motor añade coste sin valor en plazo |
| Streamlit, no React | El plazo no permite invertirlo en frontend |
| Capa IA tras interfaz `LLMProvider` | El modelo es configuración, no dependencia rígida — probado sumando `GeminiProvider` sin tocar `triage.py` ni los agentes |
| Triaje IA **después** de persistir | La IA clasifica y explica sobre evidencia verificada; no descubre |
| Endpoints en 501, no ausentes | El contrato de la API se fija en diseño y se rellena por fases |
| Shodan sin verificación HTTP del CNAME (takeover) | Solo patrón DNS — comprobar si el recurso de terceros responde "no existe" cruzaría a verificar explotabilidad (restricción #6) |
| `st.html()`, no `st.markdown(..., unsafe_allow_html=True)`, para el CSS del dashboard | Con contenido grande (~20KB) y líneas en blanco dentro de `<style>`, el parser de Markdown de Streamlit deja de tratar el bloque como HTML a partir de cierto punto y lo muestra como texto literal — bug real, reproducido por bisección. `st.html()` evita el parser de Markdown por completo |

---

## Dashboard: diseño visual

El criterio es que alguien ajeno al proyecto, al abrirlo sin contexto,
asuma que es un producto comercial de seguridad y no un trabajo de máster.
Referentes: Shodan, VirusTotal, Maltego, Burp Suite.

**Reglas de la piel visual** (todas materializadas en `_CSS`, en
`dashboard/app.py`):

- Fondo oscuro y **un solo acento frío** (`#00c8e8`) para todo lo
  interactivo. El **rojo es exclusivo de la severidad crítica** y del único
  estado de fallo real (API caída); nunca decora.
- **Monoespaciada para el dato técnico** (hostnames, IPs, puertos, marcas de
  tiempo, identificadores) y sans (Inter) para el texto explicativo y la
  prosa que escribe el modelo. Esa frontera es la que hace que se lea como
  una consola y no como una web.
- **Tablas compactas, no tarjetas infladas.** El score de riesgo es la
  métrica principal y es lo primero que se ve al abrir un escaneo.
- Cero decoración sin función: ni iconos genéricos, ni animaciones.

**Dos sitios, no duplicación.** El aspecto vive en `_CSS` (el DOM que genera
Streamlit) y en `.streamlit/config.toml` (el tema). Se separan porque
`st.dataframe` se pinta sobre un `<canvas>` (glide-data-grid) al que
**ninguna regla CSS llega**: sus colores y su tipografía solo salen del
tema. Por eso `theme.font` es la monoespaciada — la tabla de escaneos es
dato técnico — y `_CSS` devuelve la sans a lo que es prosa.

**Trampas de Streamlit descubiertas aquí** (documentadas porque no dan
ningún error, simplemente el resultado sale mal):

| Trampa | Efecto | Solución |
|---|---|---|
| `st.html()` sanea con DOMPurify, que **borra entera** cualquier etiqueta cuyo texto parezca HTML | Escribir «`<p>`» en un *comentario* CSS tumbaba la hoja de estilos completa: la aplicación aparecía sin pintar | En los comentarios de `_CSS` no se escribe ninguna etiqueta. Las tipografías se cargan con `@import`, no con `<link>` (también se borraba) |
| Streamlit resta `1rem` al contenedor de cada bloque markdown para cancelar el margen del último párrafo | Nuestro HTML no acaba en párrafo: cada bloque medía 16px menos que su contenido y **se solapaba con el siguiente** | Envoltorio `.atl-blk` (`flow-root` + `margin-bottom: 1rem`), centralizado en `_html()` |
| Streamlit 1.63 migró los widgets de BaseWeb a **react-aria** | Los selectores `[data-baseweb="tab"]`, `[data-baseweb="input"]`… dejaron de existir; las reglas no daban error, simplemente no pintaban | Selectores contra el DOM real (`[data-testid="stTab"]`, `*RootElement`, `[role="group"]`), revisados con el navegador abierto |
| El tipo de aviso (`success`/`warning`/`error`) se pinta en un hijo, no en el contenedor con borde | Los cuatro tipos se veían como la misma caja gris: un error y un éxito eran indistinguibles | `[data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"])`, etc. |

Para el color de severidad de cada activo se usa `st.container(key=...)`,
que añade la clase `st-key-<clave>` al DOM: es **API pública** de Streamlit,
a diferencia de los `data-testid`, que son internos y pueden cambiar de
versión. Se prefiere a los colores de markdown (`:red[...]`) porque esos
salen de la paleta de Streamlit y no de la escala de severidad propia.

**Verificación visual.** El aspecto no se da por bueno sin mirarlo: `_shot.py`
(raíz del repo, fuera del proyecto) levanta un navegador real contra el
dashboard en marcha y captura inicio, listado, detalle, activo desplegado,
escaneo grande, triaje con IA, respuesta en lenguaje natural y el estado con
la API caída, en `.claude/shots/`. Las capturas en verde no sustituyen a la
suite: `tests/test_dashboard.py` sigue comprobando el comportamiento con
`AppTest`, nunca el estilo.

---

## Deuda técnica conocida

**Resuelta en la ampliación post-Paso 7** (se deja constancia para la
defensa, por si se pregunta por la evolución): la falta de consulta de
CNAME y la fuente única de enumeración, ambas documentadas aquí desde el
Paso 2, se cerraron con `discovery/takeover.py` y `discovery/shodan.py`
respectivamente.

- **Shodan: cobertura real limitada por el plan de la clave disponible.**
  `/dns/domain/{domain}` devuelve `403` en el plan gratuito `oss`
  ("Requires membership or higher to access"), verificado contra la API
  real. El código está completo y probado (con dobles, y en vivo el camino
  de fallo), pero no aporta subdominios reales con la clave actual — solo
  con un plan de pago.
- **Tabla de patrones de takeover no exhaustiva.** `discovery/takeover.py`
  cubre ~20 proveedores citados habitualmente (GitHub Pages, Heroku, S3,
  Azure...), no una lista cerrada — mismo criterio de honestidad que
  `COMMON_PORTS`.
- **Verificación en vivo de los 5 agentes de IA nuevos, pendiente con
  Anthropic.** `ai/analyst.py`, `ai/takeover_detective.py`,
  `ai/report_writer.py`, `ai/diff_analyst.py` y `ai/prompter.py` están
  probados con dobles deterministas y, algunos, verificados en vivo contra
  **Gemini** real (que sí tiene clave activa) — pero no contra Anthropic,
  el proveedor por defecto del proyecto (`AI_PROVIDER=anthropic` en
  `.env`), por no disponer de `ANTHROPIC_API_KEY`. Repetir antes de la
  defensa si se consigue la clave: es la misma interfaz, así que si
  funciona con Gemini funciona con Anthropic, pero queda como verificación
  formal pendiente, no dada por hecha.
- **`POST /findings/ask` con Gemini: fallo 502 observado una vez, sin
  reproducir.** Durante la verificación del dashboard, `prompter →
  analyst` devolvió `"el modelo no llamó a la herramienta
  'record_analysis'"` con `GeminiProvider`. `ai/analyst.py::_TOOL_SCHEMA`
  es un JSON Schema estándar (tipos básicos, arrays de string, sin
  features exóticas) — revisado y descartado como causa obvia. Ocurrió
  cerca de agotarse la cuota diaria gratuita de Gemini (ver punto
  siguiente), lo que apunta a una respuesta degradada por cuota antes que
  a una incompatibilidad real de *tool calling*, pero **no se confirmó**:
  no se pudo reproducir con cuota ya agotada. Repetir con cuota fresca
  antes de asumir que está resuelto o de intentar un arreglo a ciegas.
- **Cuota gratuita de Gemini: ~20 peticiones/día**, se agota rápido
  combinando triaje + prompter + diff + informe en la misma sesión de
  pruebas. Verlo como límite de verificación manual, no del código.
- **Sin detección de comodines DNS.** Un dominio que resuelve cualquier
  subdominio inexistente inflaría el recuento de activos.
- **API sin autenticación.** Asumible en local; bloqueante si se despliega con
  IP pública.
- **Variabilidad del DNS.** Dos escaneos del mismo dominio no dan resultados
  idénticos (timeouts, balanceo, caché). Es normal, y refuerza la necesidad de
  persistir escaneos para distinguir un cambio real de una fluctuación.
- **Informe solo en PDF, sin histórico.** `reporting/generator.py` sobrescribe
  un único PDF por escaneo (`reports/atalaya_informe_{dominio}_{id}.pdf`) en
  cada descarga; no guarda versiones anteriores ni ofrece DOCX (el parámetro
  `fmt` del stub original se conserva como punto de extensión, pero solo
  "pdf" está implementado).
- **Puertos: solo `COMMON_PORTS`, sin banner grabbing.** `discovery/ports.py`
  confirma si un puerto está abierto, no qué servicio ni versión corre
  detrás (eso exigiría enviar payloads específicos por protocolo, más
  intrusivo). Un barrido completo de los 65535 puertos tampoco está
  contemplado, por la misma razón de intrusividad acotada.
- **TLS: sin validar cadena de confianza ni hostname del certificado.**
  `discovery/tls.py` inspecciona el certificado que presenta el servidor
  (versión, emisor, caducidad) con `verify_mode=CERT_NONE` a propósito —
  necesita poder reportar un certificado autofirmado o caducado, no
  rechazarlo antes de verlo — pero no comprueba si la cadena es válida ni si
  el certificado corresponde al hostname consultado (mismatch de SAN/CN).
- **Cabeceras: sin seguir redirecciones entre esquemas ni evaluar CORS.**
  `discovery/headers.py` cubre las seis cabeceras que pide el enunciado; no
  evalúa `Access-Control-Allow-Origin` ni cookies (`Set-Cookie` con
  `Secure`/`HttpOnly`/`SameSite`), fuera del alcance explícito de este paso.

---

## Comandos

```bash
pip install -e ".[dev]"              # instalar con dependencias de desarrollo
pytest -q                            # tests (deben pasar los 260)
uvicorn atalaya.api.main:app --reload # API en :8000, docs en /docs
streamlit run dashboard/app.py       # dashboard en :8501
alembic upgrade head                 # aplica las migraciones (crea scans/assets/findings)
atalaya subdomains ejemplo.com       # CLI de enumeración
atalaya subdomains ejemplo.com --save # enumera y persiste el resultado en BD
ruff check src tests                 # linter
docker compose up --build            # stack completo
```

**Cambiar de proveedor de IA:** `AI_PROVIDER=anthropic` o `AI_PROVIDER=gemini`
en `.env`, con la clave correspondiente (`ANTHROPIC_API_KEY`/`GEMINI_API_KEY`).
Solo hace falta la clave del proveedor activo.

**Dominio de pruebas:** `scanme.nmap.org`, mantenido por el autor de Nmap
explícitamente para reconocimiento autorizado.

**Verificación visual del dashboard:** `_shot.py` en la raíz del proyecto
(no versionado, herramienta de desarrollo — Playwright) levanta el
dashboard real, lanza un escaneo real y captura pantallas en
`.claude/shots/`. Requiere la API y el dashboard ya arrancados
(`uvicorn`/`streamlit run`, arriba) y `playwright install` hecho una vez.

---

## Cómo quiero trabajar

- Explica el **porqué** de las decisiones, no solo el qué. El proyecto se
  defiende oralmente y necesito entender cada pieza.
- Análisis directo y con datos. Si algo no funciona o es mala idea, dilo.
- Ejecuta los tests antes de dar nada por terminado.
- Al terminar una tarea: qué has cambiado, cómo probarlo, qué commit hacer.
- Si detectas un defecto en lo ya implementado, señálalo aunque no sea el
  encargo. Ya ocurrió una vez con un falso positivo (`0.0.0.0` contado como
  activo) y corregirlo a tiempo evitó que contaminara la fase siguiente.
- No des por terminado un agente/subagente sin verificarlo tú mismo: tests
  en verde, integración real comprobada, y una prueba manual con un caso
  real — los tres, no solo lo que el propio agente afirme haber hecho. Ya
  ha pasado que un subagente diera algo por bueno sin serlo (el bug de
  `st.markdown`/CSS del dashboard, sección "Deuda técnica") y que otro
  hiciera un commit "WIP" automático sin que nadie lo pidiera al
  interrumpirse — revisa el `git log`/`git status` al retomar una sesión,
  no asumas que el estado del repo es el que dejaste la última vez.

### Subagentes de Claude Code (tooling de desarrollo, no parte del producto)

`.claude/agents/` define cuatro subagentes de proyecto para dividir el
trabajo de ampliar Atalaya, cada uno con responsabilidad exclusiva y sin
solape: `atalaya-discovery` (descubrimiento/DNS), `atalaya-ai-agents`
(capa IA), `atalaya-api` (cableado a la API) y `atalaya-dashboard`
(diseño visual). **Estos ficheros no se recargan dentro de una sesión ya
iniciada** — solo están disponibles como `subagent_type` con nombre propio
en sesiones que arrancan *después* de que existan; si no aparecen en la
lista de agentes disponibles, hay que despacharlos como `general-purpose`
pegando el contenido completo del `.md` correspondiente como instrucciones
(mismo resultado práctico, solo cambia el mecanismo de invocación).

Ninguno de los cuatro toca `ai/triage.py` — instrucción explícita, se
mantiene igual desde el Paso 5.
