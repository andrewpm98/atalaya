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
| API o webhook | API REST propia **y** consumo de APIs externas | ✅ `scans`/`assets`/`findings`, triaje (`POST /scans/{id}/triage`), consulta NL vía agentes (`POST /findings/ask`), diff entre escaneos (`GET /scans/{id}/diff/{other_id}`) e informe (`GET /scans/{id}/report`) reales, estado de la configuración (`GET /config/status`), con autenticación opcional por `X-API-Key`. Consume crt.sh, Shodan y (Anthropic o Gemini, configurable) |
| Aplicación web | Dashboard Streamlit | ✅ Escaneos, comparación entre escaneos (diff), triaje IA, consulta NL, descarga de informe, bienvenida con el estado de la configuración — rediseño visual profesional (ver "Dashboard: diseño visual" más abajo) |
| GitHub con historial | Commits por unidad lógica | ✅ commits por fase |
| Reporte con portada | Informe generado por la herramienta | ✅ PDF con portada, resumen ejecutivo en lenguaje natural (IA), `risk_score` y hallazgos (`reporting/generator.py`) |

**El historial de commits se evalúa.** No agrupar trabajo de varias fases en
un commit único; el desarrollo progresivo es parte de lo que se califica.

---

## Qué hace la herramienta

Recibe un dominio y ejecuta cuatro fases:

1. **Descubrimiento** — subdominios (Certificate Transparency + Shodan + DNS,
   con filtrado de wildcards DNS), puertos, cabeceras de seguridad HTTP,
   configuración TLS, riesgo de *subdomain takeover* (patrón de CNAME hacia
   hosting de terceros, con verificación HTTP opcional).
2. **Persistencia** — activos y hallazgos en base de datos, para comparar
   escaneos en el tiempo (`GET /scans/{id}/diff/{other_id}`, y «Comparar
   con» en el dashboard).
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
├── cli.py                       CLI: `subdomains`, `doctor` (diagnóstico) e
│                                 `init` (configuración guiada)
├── core/
│   ├── database.py              Engine async + Base declarativa + get_session
│   ├── models.py                Scan, Asset, Finding (SQLAlchemy 2.0)
│   ├── persistence.py           save_subdomain_scan(), apply_port_scan(),
│   │                             apply_discovery_findings() — descubrimiento → BD
│   ├── repository.py            Lectura: get_scan, list_scans, get_latest_scan,
│   │                             list_assets, list_findings, diff_scans() —
│   │                             hostnames y cambios de los activos comunes —,
│   │                             list_triaged_findings() (fuente de la
│   │                             reutilización del triaje)
│   ├── exceptions.py            AtalayaError, UnauthorizedTargetError, ...
│   ├── authorization.py         ensure_authorized() — SCAN_ALLOWLIST
│   ├── audit.py                 get_audit_logger() — traza de auditoría
│   │                             siempre visible (restricción #6, salvaguarda c)
│   ├── netutils.py              classify_ip() — 10 alcances de red
│   └── scoring.py               compute_risk_score() — índice 0-100: banda por
│                                 severidad máxima; única fuente (PDF y API)
├── discovery/
│   ├── models.py                SubdomainRecord, SubdomainScanResult,
│   │                             DiscoveryFinding, HeaderScanResult, TlsScanResult,
│   │                             TakeoverCandidate, EnrichmentResult
│   ├── subdomains.py            Enumeración (crt.sh + Shodan, concurrentes,
│   │                             fusionadas por hostname) + verificación DNS
│   │                             + detect_wildcard_dns() — descarta como
│   │                             `wildcard` los hosts que solo resuelven a la
│   │                             IP del comodín DNS
│   ├── shodan.py                 fetch_shodan_subdomains() — segunda fuente,
│   │                             opcional (SHODAN_API_KEY vacía = se omite)
│   ├── ports.py                  scan_ports() — TCP asíncrono, puertos comunes
│   ├── headers.py                 analyze_headers() — HSTS/CSP/XFO/XCTO/
│   │                             Referrer-Policy/Permissions-Policy,
│   │                             redirección HTTP→HTTPS (sonda en paralelo)
│   │                             y cookies (Secure/HttpOnly/SameSite)
│   ├── tls.py                     inspect_tls() — versión, emisor, caducidad,
│   │                             hostname (SAN) y cadena de confianza (certifi);
│   │                             IMPLICIT_TLS_PORTS (443 + 465/993/995/8443 si
│   │                             están abiertos), fusionados por tipo y host
│   ├── takeover.py                find_takeover_candidates() — riesgo de
│   │                             subdomain takeover vía patrón de CNAME
│   │                             (reconocimiento pasivo puro, nunca HTTP)
│   ├── takeover_verify.py         verify_candidates() — verificación HTTP
│   │                             opt-in (TAKEOVER_VERIFY): huella de "no
│   │                             reclamado" → "alta sospecha", nunca confirma
│   └── enrichment.py              enrich_scan() — orquesta las cuatro técnicas;
│                                 takeover corre sobre TODOS los registros,
│                                 las otras tres solo sobre los activos
├── ai/
│   ├── provider.py               LLMProvider (ABC) + AnthropicProvider + GeminiProvider
│   ├── triage.py                 triage_finding/triage_findings — contexto
│   │                             estructurado, nunca un dump de la fila de BD
│   ├── triage_reuse.py           reuse_previous_triage() — copia el triaje de
│   │                             otro escaneo ante el mismo prompt exacto
│   ├── prompter.py               route_and_answer() — enruta una pregunta en
│   │                             lenguaje natural a analyst o takeover_detective
│   ├── analyst.py                analyze_scan() — visión global de un escaneo
│   ├── takeover_detective.py     assess_takeover_risk() — prioriza candidatos
│   │                             a subdomain takeover ya detectados
│   ├── report_writer.py          write_executive_summary() — resumen ejecutivo
│   │                             del informe PDF, en lenguaje no técnico
│   ├── diff_analyst.py           analyze_diff() — valora el diff entre dos escaneos
│   └── replay.py                 RecordingProvider/ReplayProvider — respuestas
│                                 reales grabadas para la demo sin red
│                                 (AI_PROVIDER=replay); no es un modelo
│
│   `ai/query.py::ask()` (consulta NL original) se retiró: `POST /findings/ask`
│   pasa por `prompter.py`, que reemplaza su función y devuelve más señal
│   (patrones, combinaciones preocupantes, prioridades), no solo prosa libre.
├── onboarding/                  Puesta en marcha guiada (fase 13)
│   ├── ui.py                     Identidad visual en la terminal: logo de la
│   │                             torre, paleta del dashboard, modo ASCII si la
│   │                             salida no es UTF-8
│   ├── checks.py                 Comprobaciones (`CheckResult`): config, alcance,
│   │                             BD y migraciones, claves de IA/Shodan sin coste,
│   │                             crt.sh, API, `.env` fuera de git;
│   │                             run_local_checks() — las que no salen a la red,
│   │                             para GET /config/status
│   ├── doctor.py                 `atalaya doctor` — diagnóstico y cómo resolverlo
│   ├── envfile.py                `.env`: escritura atómica con copia, verificada
│   │                             con el parser de la app; enmascarado de secretos
│   └── wizard.py                 `atalaya init` — asistente de 5 pasos y
│                                 `--non-interactive` (secretos del entorno)
├── reporting/
│   ├── generator.py               generate_report()/render_html() — informe PDF
│   │                               con portada (Jinja2 + xhtml2pdf)
│   ├── pdf_text.py                Markdown del modelo → HTML seguro y glifos
│   │                               que el PDF no puede dibujar
│   └── templates/report.html      Plantilla del informe
└── api/
    ├── main.py                  FastAPI + exception_handler (dominio inválido → 400,
    │                             no autorizado → 403, fallo del proveedor IA → 502)
    ├── security.py               require_api_key() — X-API-Key opcional (API_KEY
    │                             vacía = desactivada); todo salvo /health
    ├── schemas.py                Esquemas Pydantic de respuesta (frontera BD ↔ API)
    └── routes/
        ├── scans.py              POST/GET /scans, GET /scans/{id},
        │                         POST /scans/{id}/triage,
        │                         GET /scans/{id}/diff/{other_id} — compara
        │                         dos escaneos + valoración IA,
        │                         GET /scans/{id}/report — reales
        ├── assets.py              GET /assets?scan_id= — real
        ├── findings.py            GET /findings, POST /findings/ask
        │                           (vía ai/prompter.py) — reales
        └── config.py              GET /config/status — estado de la
                                    configuración sin red ni valores (fase 13)

migrations/                      Alembic (async); URL desde settings.database_url
dashboard/app.py                 Dashboard Streamlit — escaneos, «Comparar
                                  con» (diff), triaje IA, consulta NL,
                                  descarga de informe, bienvenida y estado
                                  de la configuración. Rediseño
                                  visual profesional (ver sección dedicada)
.claude/agents/                  Subagentes de proyecto de Claude Code (no
                                  es parte del producto, es tooling de
                                  desarrollo — ver "Cómo quiero trabajar")
scripts/                         Datos de reserva de la demo (fuera del paquete):
                                  seed_demo_data.py (siembra, un comando) y
                                  build_demo_data.py (los produjo, con red)
demo/                            github.com.json (2 escaneos reales) +
                                  ai_recordings.json (respuestas grabadas)
_shot.py                         Capturas del dashboard con Playwright
                                  (tooling de desarrollo, versionado; no es
                                  parte del paquete `atalaya`)
docs/ARQUITECTURA.md             Arquitectura por componentes y flujos
memorias/                        Memorias técnicas por fase (ver "Documentación")
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

> **Ampliación (verificación HTTP de takeover, opt-in):** `discovery/
> takeover_verify.py` añade el segundo nivel — comprobar si el destino del
> CNAME sirve la huella de "recurso no reclamado" del proveedor (`GET` a la
> página de error pública, tabla `TAKEOVER_FINGERPRINTS` alineada por sufijo
> con `TAKEOVER_PATTERNS`). **Off por defecto** (`TAKEOVER_VERIFY=false`): el
> flujo estándar no cambia. Cuando se activa, `enrich_scan()` llama a
> `verify_candidates()` tras `find_takeover_candidates()`; el candidato con
> huella pasa a `TakeoverCandidate.unclaimed_indicator`, y
> `findings_by_hostname()` redacta la evidencia como **"alta sospecha — no
> confirmado"** (patrón + indicio), nunca "confirmado" — coherente con la
> restricción #6 reabierta arriba. Salvaguardas obligatorias en el propio
> módulo: opt-in, `is_authorized()` por hostname antes de sondear, y traza de
> auditoría de cada petición a un tercero (`core/audit.py`, siempre visible). `takeover.py` no se
> toca: sigue siendo pasivo puro y su test estático de "no importa httpx"
> sigue en verde — la petición HTTP vive solo en el módulo nuevo.

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
> fijo de Anthropic — con presupuesto de razonamiento acotado y un
> reintento en `mode="AUTO"` ante `MALFORMED_FUNCTION_CALL` (ver "Deuda
> técnica conocida": los dos son arreglos de bugs reproducidos en vivo, no
> precauciones especulativas). Ninguna línea de `triage.py`, ni de los agentes
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
> `reporting/generator.py::_RISK_WEIGHTS` — *fórmula sustituida después por
> `core/scoring.py`, ver "Decisiones ya tomadas"*) y un resumen ejecutivo de
> `ai/report_writer.py` — pero, a diferencia del diff, **nunca falla** por
> ausencia o fallo del proveedor de IA: el informe con portada era un
> requisito obligatorio antes de que existiera la capa IA, así que no puede
> depender de ella. Asimetría deliberada, documentada en el propio código.

> **Ampliación (robustez, post-agentes):** instalación limpia verificada de
> extremo a extremo en un venv nuevo (`greenlet` faltaba en `pyproject.toml`),
> `ruff` y `mypy` a cero avisos, y **detección de wildcards DNS**:
> `discovery/subdomains.py::detect_wildcard_dns()` resuelve un subdominio con
> un UUID antes de la resolución masiva; si responde, cualquier registro
> `active` cuyas IPs sean subconjunto de las del comodín pasa a
> `ResolutionStatus.WILDCARD` — deja de contar como activo y de recibir
> escaneo de puertos/cabeceras/TLS, pero se conserva en `records` (descartado,
> no perdido). `Asset.status` es texto libre en BD, así que el estado nuevo no
> requirió migración. Detalle en
> `memorias/Memoria_Ampliacion_Robustez_Atalaya.md`.

Validado sobre `github.com`: 117 subdominios descubiertos, 61 activos,
55 objetivos de escaneo, 19 segundos. **583 tests en verde** (170 al cierre
del Paso 7; +90 en la ampliación de agentes de IA: Shodan, takeover, 5
agentes de IA, GeminiProvider, diff + informe con IA; +2 en el rediseño del
dashboard — severidad fuera de la escala y formato de las marcas de tiempo,
ver "Dashboard: diseño visual"; +4 al corregir el *tool calling* de Gemini,
ver "Deuda técnica conocida"; +7 en la detección de wildcards DNS y +15 en la
verificación HTTP opt-in de takeover, ver `memorias/
Memoria_Ampliacion_Robustez_Atalaya.md`; +3 al corregir las fechas en
PostgreSQL, +8 al arreglar el stack de Docker y +6 al arreglar la auditoría y
`LOG_LEVEL`, ver "Deuda técnica conocida → Resuelta"; +21 en los datos de
reserva para la demo, ver la sección dedicada; +33 al rehacer el `risk_score`
y arreglar el PDF; +35 en la autenticación por `X-API-Key`; +6 en el diff del dashboard; +6 en la redirección HTTP → HTTPS; +10 en cookies; +2 en el re-triaje forzado; +3 en el diff sin IA; +20 en la validación TLS; +11 en el diff de activos comunes; +20 en la reutilización del triaje; +6 en TLS en otros puertos y +2 al excluir los hosts wildcard del escaneo de puertos; +2 al sacar la clave de Shodan del log de `atalaya -v`; +76 en `atalaya doctor` e `init`; +24 en la fase B: `GET /config/status` y la bienvenida del dashboard; +1 al arreglar la barra lateral plegada). La suite pasa también sobre
Python 3.11, el mínimo declarado y la versión de las imágenes.

---

## Hoja de ruta

1. **Paso 1 — Arquitectura y esqueleto** ✅
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
como se venía valorando: los módulos de puertos/cabeceras/TLS nacieron ya
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
10. **Ampliación — Robustez** ✅ — `greenlet` declarado, instalación limpia
    verificada, `ruff`/`mypy` a cero, detección de wildcards DNS y
    verificación HTTP opt-in de subdomain takeover (con la restricción #6
    reabierta de forma acotada). Memoria:
    `memorias/Memoria_Ampliacion_Robustez_Atalaya.md`.
11. **Cierre pre-entrega** ✅ — P0: PostgreSQL real, stack Docker, ensayo
    desde clon limpio, demo sin red, `risk_score` y PDF. P1: autenticación
    opcional (`X-API-Key`), «Comparar con» en el dashboard, redirección
    HTTP → HTTPS, cookies, validación TLS, re-triaje forzado y diff sin IA. Memoria:
    `memorias/Memoria_Cierre_Preentrega_Atalaya.md`.
12. **Ampliación — Diff de activos comunes y reutilización del triaje** ✅
    (06/10/2026) — el diff compara estado, puertos y hallazgos de los activos
    comunes (`cambiados`); el triaje reutiliza el de otro escaneo ante el
    mismo prompt exacto (27 % menos llamadas en la demo). Incluye la revisión
    crítica de la herramienta y sus carencias. Memoria:
    `memorias/Memoria_Ampliacion_Diff_Triaje_Atalaya.md`.
13. **Ampliación — Puesta en marcha guiada** ✅ (12-13/10/2026) —
    TLS en los puertos con TLS implícito y hosts `wildcard` fuera del escaneo
    de puertos; **fase A**: `atalaya doctor` (diagnóstico) y `atalaya init`
    (asistente de configuración) con identidad visual propia en la terminal;
    **fase B**: `GET /config/status` y, en el dashboard, la torre en la
    cabecera, una bienvenida cuando no hay escaneos y el estado de la
    configuración en la barra lateral. Las dos partes visuales, con maqueta
    aprobada antes de cerrarlas. Memoria:
    `memorias/Memoria_Ampliacion_Puesta_En_Marcha_Atalaya.md`.

**Plazo:** entrega a finales de septiembre (fecha registrada en el diseño;
a 06/10/2026 está pendiente de confirmar si la entrega ya se hizo y cuándo es
la defensa). Los siete pasos de la hoja de ruta y los cinco requisitos
obligatorios están cerrados desde antes de las ampliaciones 8-12 — ninguna era necesaria para aprobar: profundizan el
componente diferencial (capa IA), la calidad percibida (dashboard) y la
fiabilidad de la entrega (robustez y cierre pre-entrega) de cara a la
defensa oral.

---

## Estado al 13/10/2026 y próxima sesión

**Dónde se quedó:** fase 13 **cerrada** el 13/10/2026 con la fase B
(`GET /config/status`, y la bienvenida, la torre y el estado de la
configuración en el dashboard; maqueta aprobada:
https://claude.ai/artifact/XDwdtF4HAKm8anmajeSWW4). 583 tests, `ruff` (ahora
también sobre `dashboard/`) y `mypy` a cero. Los commits de la fase B
(`124fb8d`, `39136c6`, `9051799`, `ad0cd06`, los de documentación y
`912e6c5`, el arreglo de la barra lateral plegada) se hicieron **en local**: el `push`, cuando el usuario lo diga. Ningún prompt ha
cambiado: la demo en `replay` sigue intacta (`tests/test_demo_data.py`). Al
retomar, comprobar con `git status -sb` y `git log --oneline -5` que el repo
está como aquí se describe.

**Calendario:** a 12/10/2026, «hay algo de margen», sin fecha de defensa
concreta. El usuario trabaja **bloque a bloque**: se cierra uno (código,
tests, prueba real, docs, commits) antes de empezar el siguiente.

**Restricción operativa:** el **crédito de la API de Anthropic está
agotado**. Cualquier cambio de prompt o del contexto que recibe un agente
deja obsoleta `demo/ai_recordings.json`, y regrabar exige llamadas reales:
antes de un cambio así, parar y preguntar. Gemini, si hay
`GEMINI_API_KEY` (cuota gratuita ~20 peticiones/día), sirve para verificar
en vivo, no para regrabar la demo (grabada con `claude-sonnet-4-6`). Listar
modelos (`GET /v1/models`) y `/api-info` de Shodan no consumen crédito: es
lo que usan `doctor` e `init`.

### Plan acordado para las próximas sesiones (en este orden)

Diseño ya hablado con el usuario el 12/10/2026; no reabrirlo sin motivo.

**1. Fase B de la puesta en marcha** ✅ (13/10/2026) — hecha con el diseño
acordado; detalle en la memoria de la fase (§8). Queda **verificarla en el
stack Docker real**: Docker Desktop no estaba arrancado y se simuló lo que
hace el compose (API sin `.env` y con la configuración en variables de
entorno). Cabe al empezar el bloque 3, que también toca la API, o en el
cierre (bloque 5).

**2. Dossier de defensa** ✅ (13/10/2026) — documento vivo en Claude Docs:
https://claude.ai/code/artifact/c7ed9198-242a-442a-9fdb-05876d4e1e91 (el
usuario lo edita, comenta y exporta a PDF). Secciones: presentación de 2
minutos, arquitectura con diagrama, los 5 requisitos en la demo, guion de la
demo con plan B, cifras, decisiones, las 6 restricciones, límites,
**preguntas sobre la herramienta**, checklist del día y, al final, un anexo
técnico con las preguntas de las memorias.

- **Enfoque (pedido por el usuario el 13/10/2026):** en la defensa no espera
  preguntas sobre el código, sino sobre la herramienta: qué es, para quién,
  qué encuentra, qué aporta la IA, frente a qué alternativas, límites, uso
  responsable y preguntas trampa. Ese banco es el principal; lo técnico queda
  como anexo «por si la pregunta se vuelve técnica». Respuestas para decir en
  voz alta: cortas, con un dato real de la demo y sin hablar de código.

- **Se actualiza con cada bloque siguiente** (cargar antes el skill
  `anthropic-skills:docs`): las cifras (tests, commits), los límites que se
  cierren (monitorización, `POST /scans` síncrono), el guion si cambia la
  demo y las preguntas nuevas de cada bloque.
- **Regla:** cada respuesta del banco se comprueba contra el código actual.
  Si una memoria antigua dice otra cosa, manda el dossier, y el bloque de
  defensa de esa memoria se corrige con una nota «Estado posterior» (es la
  excepción a «las memorias son fotos fechadas»). Al hacerlo se corrigieron
  tres: autenticación (Paso 1), PostgreSQL sin probar (Paso 3) y la
  referencia a `ai/query.py` (Paso 7).

**3. `POST /scans` en segundo plano** — hoy el escaneo corre dentro de la
petición (19 s para github.com; minutos para un dominio grande).

- Devuelve **`202`** con el escaneo en `running` (`ScanStatus.RUNNING` ya
  existe); el dashboard consulta `GET /scans/{id}` hasta que acabe.
- **Validación y autorización antes de lanzar la tarea**: un dominio no
  autorizado sigue dando `403` al momento, no un escaneo `failed` después.
- **Hoy la fila del `Scan` se crea después de enumerar** (`create_scan` →
  `save_subdomain_scan`): hay que crearla antes, en `running`.
- La tarea abre **su propia sesión de BD**: la de la petición se cierra al
  responder.
- Al arrancar la API, los escaneos que quedaron en `running` (reinicio a
  mitad) pasan a `failed` con la incidencia en `errors`.
- **`?wait=true`** conserva el comportamiento síncrono actual, para no romper
  `scripts/build_demo_data.py`, los `curl` del README ni los tests.
- Commits separados: API y dashboard (consulta periódica del estado).

**4. Monitorización: escaneos programados con aviso por webhook** — la
carencia más grande como ASM. Depende del bloque 3 (reutiliza la función de
escaneo en segundo plano).

- Tabla nueva **`monitors`** (dominio, intervalo, `webhook_url`, último
  escaneo, activo) con su migración, y rutas `POST`/`GET`/`DELETE /monitors`.
- Un bucle en el `lifespan` de la API lanza los escaneos que tocan; al
  terminar, `diff_scans()` **sin IA** (no gasta crédito) y, si `nuevos`,
  `desaparecidos` o `cambiados` no están vacíos, `POST` del diff al webhook.
- **Seguridad, que se evalúa:** el dominio pasa `ensure_authorized()` al
  crear el monitor **y en cada ejecución**; el webhook es un vector de
  **SSRF**: resolver su host y rechazar direcciones no enrutables con
  `classify_ip()` (mismo criterio que la restricción #2); intervalo mínimo
  (p. ej. 1 h) por la restricción #5; cada aviso enviado, al log de
  auditoría (`core/audit.py`).
- **Límite a documentar:** el planificador vive en el proceso de la API; con
  varios workers de uvicorn, cada escaneo se lanzaría varias veces.
- Cumple de forma literal el requisito «API o webhook».

**5. Cierre de la fase** — docs de cada bloque (CLAUDE.md, ARQUITECTURA,
README, `.env.example` si hay campos nuevos), memoria de la fase con su bloque
de preguntas de defensa, guion de la demo recorrido en `replay` por HTTP sin
grabaciones faltantes, y `push` cuando el usuario lo diga.

**Después, o si el calendario aprieta:** ensayar la defensa con el dossier
(guion con `scripts/seed_demo_data.py --reset` y `AI_PROVIDER=replay` en una
BD aparte). **Cuando vuelva
el crédito:** regrabar la valoración del diff posterior al triaje (escribe
«`vpn-ca.github.com` (IAD)» en vez de `vpn-ca.iad.github.com`; 1 llamada) y
valorar quitar las IPs del prompt de triaje para que la reutilización
sobreviva a CDN (cambia todos los prompts: regrabación completa).

**Pendiente del usuario, fuera del código:** su `.env` de desarrollo aún
tiene `API_HOST`, `API_PORT` y `ENVIRONMENT` (retirados en `521019e`;
`atalaya doctor` los señala) y `SCAN_ALLOWLIST` vacía. Puede limpiarlo a mano
o pasar `atalaya init` (conserva el resto y deja copia).

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
- Ejecutar `pytest -q` antes de dar por terminado cualquier cambio, y
  `make lint` (`ruff check src tests` + `mypy src`): ambos están a cero avisos
  desde la ampliación de robustez y no deben volver a acumularse.

### Documentación

Cinco sitios, cada uno con un papel distinto. Un cambio de comportamiento no
está terminado hasta que los que le afectan lo reflejan:

| Documento | Papel | Se actualiza cuando... |
|---|---|---|
| `CLAUDE.md` | Estado vivo del proyecto y reglas de trabajo | Cambia cualquier cosa de lo que describe (árbol, deuda, conteo de tests, restricciones) |
| `docs/ARQUITECTURA.md` | Arquitectura por componentes y flujos internos | Cambia un flujo, un estado, un endpoint o un criterio de degradación |
| `README.md` | Presentación y uso para quien llega de fuera | Cambia lo que la herramienta hace o cómo se usa |
| `.env.example` | Contrato de configuración | Se añade/quita un campo de `config.py` (deben coincidir 1:1; lo comprueba `tests/test_deploy_config.py`) |
| `memorias/` | Una memoria técnica **por fase**, entregable de la práctica | Se cierra una fase nueva (memoria nueva) |

Las memorias son **fotos fechadas**: no se reescribe el cuerpo de una memoria
cerrada para que parezca que siempre dijo lo que hoy es cierto. Si una
afirmación queda superada, se añade una nota «Estado posterior» junto a ella,
con el commit o la memoria que la supera. Excepción: los bloques de
preguntas de defensa, que se usan para preparar la defensa oral y no pueden
contradecir el código actual.

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
6. **Nunca confirmar explotabilidad ni intentar el secuestro.** La herramienta
   señala patrones de riesgo (p. ej. un nombre apuntando a hosting no
   reclamado); jamás reclama el recurso de terceros, ni prueba que el ataque
   funcione, ni marca un hallazgo como "takeover confirmado". Ese paso excede
   el reconocimiento y requiere autorización expresa.

   **Excepción acotada — verificación HTTP opcional (`TAKEOVER_VERIFY`, off por
   defecto).** La versión original de esta restricción prohibía *toda* petición
   HTTP al recurso de terceros. Se reabre de forma deliberada y estrecha, no en
   silencio: cuando `TAKEOVER_VERIFY=true`, `discovery/takeover_verify.py` hace
   un `GET` a la **página de error pública** del proveedor apuntado por el CNAME
   y busca su huella de "recurso no reclamado" (p. ej. el 404 «There isn't a
   GitHub Pages site here»). Esto sigue del lado del reconocimiento —lee una
   respuesta pública, no reclama nada ni prueba el ataque— y por eso el hallazgo
   se eleva a **"alta sospecha — no confirmado"**, nunca a "confirmado". Las tres
   salvaguardas *son* la "autorización expresa" que esta restricción exige, y son
   obligatorias: (a) opt-in explícito (`TAKEOVER_VERIFY=false` por defecto — el
   comportamiento por defecto de la herramienta no cambia); (b) el hostname
   candidato debe pasar `is_authorized()` (estar en `SCAN_ALLOWLIST`) antes de
   sondear su destino; (c) cada petición a un tercero deja traza en el logger
   de auditoría (`core/audit.py`), que se emite **siempre**, sin depender de
   `LOG_LEVEL`, de `-v` ni de uvicorn. El módulo de detección `discovery/takeover.py` permanece
   estrictamente pasivo (solo DNS, sin `httpx`) y su test estático lo garantiza:
   la petición HTTP vive solo en el módulo de verificación, separado.

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
| Reutilizar triaje solo ante el prompt exacto, entre escaneos; no agrupar por tipo | Copiar una respuesta del modelo solo es honesto si la pregunta fue idéntica (mismo criterio que `replay`). Agrupar por tipo + evidencia ahorraría más, pero el modelo dejaría de ver el host, que sí cambia la severidad |
| Endpoints en 501, no ausentes | El contrato de la API se fijó en diseño y se rellenó por fases. **Cumplido**: hoy ningún endpoint devuelve 501; si se añade uno nuevo por fases, se aplica el mismo criterio |
| Fechas: UTC *naive* en BD vía `UtcDateTime`, no `TIMESTAMPTZ` | Arreglo del bug de PostgreSQL sin migración y con la misma salida de lectura en SQLite y PostgreSQL; toda columna de fecha nueva debe usar `UtcDateTime` (hay un test que lo exige) |
| Wildcards DNS: reclasificar, no borrar | Un host que solo resuelve a la IP del comodín pasa a `wildcard` y sale del inventario activo, pero se conserva en `records`: descartar en silencio impediría auditar el filtro |
| Detección de takeover: solo patrón DNS por defecto | La detección (`discovery/takeover.py`) es pasiva pura: patrón de CNAME, sin HTTP. La verificación HTTP existe pero es **opt-in** (`TAKEOVER_VERIFY`, off por defecto) y vive en un módulo aparte (`discovery/takeover_verify.py`) — ver restricción #6, "Excepción acotada". Eleva a "alta sospecha", nunca a "confirmado" |
| `risk_score`: la banda la fija la severidad máxima presente; el volumen solo mueve dentro de ella, con rendimientos decrecientes por tipo (`core/scoring.py`) | La suma ponderada acotada saturaba con volumen: github.com (194 `low` + 9 `medium`) salía 100/100 «crítico», igual que un escaneo con diez críticos. Monótono por construcción (`tests/test_scoring.py` lo comprueba por propiedades). Una sola función para PDF y API: el dashboard pinta el de la API, ya no replica pesos |
| Demo sin red: reproducir respuestas reales grabadas (`AI_PROVIDER=replay`), nunca inventarlas | Una petición no grabada falla con 502 como un proveedor caído; servir una respuesta "parecida" presentaría como análisis del modelo algo que nunca dijo sobre esos datos. `tests/test_demo_data.py` detecta grabaciones obsoletas |
| Autenticación: una clave compartida en `X-API-Key`, opcional (`API_KEY` vacía = desactivada), no usuarios ni tokens | Un operador y un cliente propio: cuentas, login y rotación de tokens no protegerían nada más. Desactivada por defecto para que la demo y el stack sin `.env` no cambien. Todo endpoint salvo `/health` (sondas de Docker y del dashboard) la exige; `/docs` y `/openapi.json` quedan abiertos (describen, no devuelven datos; «Authorize» introduce la clave). `secrets.compare_digest` en bytes. `tests/test_api_auth.py` recorre el esquema OpenAPI: un router nuevo sin la dependencia hace fallar la suite |
| Configuración guiada en la CLI (`atalaya init`), no en un formulario web | Los secretos se escriben en la máquina del operador. Un formulario en el dashboard exigiría un endpoint que reciba claves, y con `API_KEY` vacía (el default) cualquiera que llegue a la API podría cambiar la del proveedor de IA o la allowlist. La web solo **consulta** el estado (sí/no, nunca valores) |
| `init` exige alcance explícito; allowlist vacía solo con `--allow-any` | `SCAN_ALLOWLIST` vacía significa «sin restricción». Quien configura con `init` decide qué puede escanear y confirma que tiene autorización; lo permisivo hay que pedirlo. Sin `init`, la herramienta se comporta igual que antes |
| Las claves se validan con llamadas gratuitas (lista de modelos, `/api-info`) y se dice que eso no comprueba el saldo | Validar con una llamada al modelo costaría dinero en cada `init`/`doctor`. Una clave válida sin crédito pasa la validación: se avisa en vez de prometer lo que no se comprobó |
| Modo no interactivo: secretos desde variables de entorno, nunca como argumentos | Un argumento queda en el historial de la shell y en la lista de procesos |
| `rich` para la terminal; menús numerados, no con flechas | `questionary`/`prompt_toolkit` fallan en Git Bash (mintty) por no ser una consola de Windows. Con salida no UTF-8, iconos y logo en ASCII en vez de romper con `UnicodeEncodeError` (reproducido al maquetar) |
| `init` no toca nada hasta confirmar el resumen: las migraciones se aplican al final | La maqueta las mostraba en el paso 2, pero eso rompería la promesa de que Ctrl+C sale sin cambios. En el paso 2 solo se conecta y se informa de lo pendiente |
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
| Con la barra lateral plegada, el botón que la reabre (`stExpandSidebarButton`) vive **dentro** de `stToolbar` (Streamlit 1.64) | El rediseño ocultaba `stToolbar` con `display: none`: al plegar la barra lateral no había forma de volver a abrirla. Y su ancho forzado con `!important` la mantenía ocupando 268 px ya plegada | `stToolbar` con `visibility: hidden` y el botón con `visibility: visible` (un hijo puede revertirla); el ancho, solo con `aria-expanded="true"`. Guarda estática en `tests/test_dashboard.py` (`912e6c5`) |
| Un elemento escrito en un `st.container()` reservado arriba se pinta cuando el script llega a escribirlo, no cuando se reservó | La bienvenida va encima de las pestañas pero se rellena desde la de «Escaneos»: una captura que solo esperaba a las pestañas salía sin ella y parecía que no se pintaba | Al capturar, esperar al elemento concreto o a que termine el script, no solo a las pestañas |

La torre de la cabecera y de la bienvenida es SVG en línea pintado con
`_html()`: sobrevive al saneado (comprobado en el navegador, no solo con
`AppTest`), y sus colores los ponen clases de `_CSS`, como el resto de la
paleta. Todo texto que llega de la API y se pinta con HTML propio pasa por
`escape()` (`/config/status` tiene un test con un `<img onerror>` en el
detalle).

Para el color de severidad de cada activo se usa `st.container(key=...)`,
que añade la clase `st-key-<clave>` al DOM: es **API pública** de Streamlit,
a diferencia de los `data-testid`, que son internos y pueden cambiar de
versión. Se prefiere a los colores de markdown (`:red[...]`) porque esos
salen de la paleta de Streamlit y no de la escala de severidad propia.

**Verificación visual.** El aspecto no se da por bueno sin mirarlo: `_shot.py`
(raíz del repo, fuera del paquete) levanta un navegador real contra el
dashboard en marcha y captura inicio, listado, detalle, activo desplegado,
escaneo grande, triaje con IA, comparación entre escaneos, respuesta en
lenguaje natural y el estado con la API caída, en `.claude/shots/`. Las capturas en verde no sustituyen a la
suite: `tests/test_dashboard.py` sigue comprobando el comportamiento con
`AppTest`, nunca el estilo.

---

## Datos de reserva para la demo

Para hacer la demo completa (escaneos → triaje → pregunta NL → informe →
diff) aunque el día de la defensa no haya red o crt.sh/el proveedor de IA
fallen. Dos piezas: datos en BD y respuestas del modelo grabadas.

**Cargarlos (un solo comando, repetible antes de cada ensayo):**

```bash
python scripts/seed_demo_data.py --reset                               # local (DATABASE_URL de .env)
docker compose exec api python scripts/seed_demo_data.py --reset       # stack Docker (su Postgres)
```

Y en `.env`, `AI_PROVIDER=replay` (sin clave ni red). Aplicarlo **reiniciando
la API**; en Docker con `docker compose up -d`, no `restart` (no recarga
`.env`). Para volver al modelo real, `AI_PROVIDER=anthropic`. `API_KEY`
puede quedar vacía (autenticación desactivada, como se ensaya el guion); si
tiene valor, el dashboard la toma del mismo `.env` y la demo no cambia.

**`--reset` borra todos los escaneos de esa BD.** Sin él, el script se niega
si hay datos. No usarlo contra la BD de desarrollo (`atalaya.sqlite3`, con
escaneos de otras sesiones) sin querer perderlos: para ensayar, mejor
`DATABASE_URL=sqlite+aiosqlite:///./demo.sqlite3` en la misma terminal o el
stack Docker.

**Qué se carga** (`demo/github.com.json`): dos escaneos **reales** de
github.com hechos con `POST /scans` — #1 del 21/09/2026 (117 activos, 204
hallazgos) y #2 del 28/09/2026 (118 activos, 211 hallazgos) —, triados por
`claude-sonnet-4-6` el 28/09. Todo triado salvo **8 hallazgos del #2 que no
existían en el #1** (los 6 de `skills.github.com`, activo nuevo; un
`hsts_max_age_bajo` nuevo en `maintainers.github.com`; y un certificado de
`vpn-ca.iad.github.com` que caduca en ~27 días): quedan `unknown` para pulsar
«Triar con IA» en directo. El diff real es modesto — 1 activo nuevo
(`skills.github.com`), 0 desaparecidos, 117 comunes, de los que 3 cambian
(los dos hallazgos nuevos citados y un `csp_missing` que desaparece en
`copilot-billing-preview.github.com`) —, que es lo creíble en una semana para
una superficie como la de GitHub. El triaje del modelo da
solo `low`/`medium` (ningún `critical`/`high`), así que el índice es 39
«medio» antes del triaje en directo y 40 después.

**Guion grabado** (`demo/ai_recordings.json`, 26 respuestas, dominio
`github.com`): las cuatro preguntas siguientes, antes **y** después del
triaje en directo — el orden de los pasos en la defensa no importa —, más el
informe PDF de los dos escaneos (con resumen ejecutivo), el diff `2`↔`1`
(dos grabaciones: su contexto lleva la severidad de los hallazgos cambiados,
que pasa de `unknown` a triada) y el triaje de los 8 pendientes. El diff se enseña desde el dashboard («Comparar
con» en el detalle de cualquiera de los dos): la API ordena por `started_at`,
así que `2/diff/1` y `1/diff/2` usan la misma grabación.

1. ¿Algún activo filtra direccionamiento interno? *(placeholder del dashboard)*
2. ¿Qué debería arreglar primero y por qué?
3. ¿Qué subdominios parecen entornos de prueba o de uso interno?
4. ¿Hay riesgo de subdomain takeover en este dominio? *(enruta al detective;
   sin candidatos, responde sin segunda llamada)*

Mayúsculas y espacios dan igual; cualquier **otra** pregunta, o sobre otro
dominio, falla con 502 («no hay respuesta grabada») — a propósito: `replay`
nunca inventa una respuesta. En la defensa conviene decir que las respuestas
son grabadas (la API lo registra como `WARNING` en cada petición, con fecha y
modelo). Lanzar un escaneo nuevo sin red también es demostrable: crt.sh cae y
el escaneo se guarda con la incidencia en `errors` (degradación controlada).

**Cómo se produjeron** (`scripts/build_demo_data.py --previous 2 --current 7`,
con red y clave; versionado como respuesta a "¿de dónde salen?"): exporta dos
escaneos de la BD, los tría con el modelo real vía `RecordingProvider`,
escribe el fixture, recorre el guion por la API en una BD temporal (antes y
después del triaje) grabando solo lo usado, y lo verifica en `replay`. Costó
358 llamadas de triaje (los prompts idénticos entre escaneos se reutilizan
desde la caché `demo/.ai_cache.json`, no versionada) + 16 del guion, y 2 más
al regrabar los resúmenes ejecutivos tras el cambio de `risk_score`, y 2 al
ampliar el diff a los activos comunes (06/10/2026).

**Si la suite dice que la grabación está obsoleta**
(`tests/test_demo_data.py::test_la_demo_completa_se_reproduce_sin_red`): un
cambio tocó un prompt, el contexto que recibe el modelo o el orden de los
datos. Regenerar con el comando anterior (hace falta la BD de desarrollo con
los escaneos #2 y #7; con la caché presente, solo se pagan las llamadas nuevas).
Por eso `Scan.assets`/`Asset.findings` llevan `order_by` por id: en
PostgreSQL, sin él, el `UPDATE` del triaje cambia el orden de lectura y con
él los prompts.

**Verificado** (28/09/2026): guion completo por HTTP contra la API real en
`replay` sin ninguna clave, en local (SQLite) y en el stack Docker
(PostgreSQL 16), dos veces seguidas con `--reset` entre medias; dashboard
capturado con los datos sembrados y una pregunta del guion respondida.
Re-verificado el 06/10/2026 tras el diff ampliado y la reutilización del
triaje: guion completo por HTTP en `replay`, cero grabaciones faltantes.

**Defecto conocido de la grabación:** la valoración del diff posterior al
triaje escribe «`vpn-ca.github.com` (IAD)» en vez de `vpn-ca.iad.github.com`.
Es un descuido del modelo, no del código; si sale en la defensa, se explica
así. Regrabarlo cuesta 1 llamada cuando haya crédito.

---

## Deuda técnica conocida

### Pendiente

- **`GET /config/status` sin probar en el stack Docker real** (ver «Plan
  acordado», bloque 1): verificado con la API real en local y simulando el
  contenedor, no con Docker levantado.
- **`init` interactivo en Git Bash (mintty) exige `winpty atalaya init`**:
  mintty no ofrece a Python una consola de Windows y `getpass` no puede leer
  el teclado. `init` lo detecta (`MSYSTEM`) y lo explica en vez de colgarse;
  en PowerShell y Windows Terminal funciona sin más.
- **Un valor con `${` no se puede guardar en `.env`**: `python-dotenv` lo
  expande incluso entre comillas simples, y no hay escape (comprobado).
  `init` verifica el texto antes de escribirlo y se niega, en vez de guardar
  un valor que la aplicación leería distinto.

- **Sin monitorización continua.** Los escaneos se lanzan a mano: no hay
  escaneos programados ni alertas. Es la carencia más grande como producto
  de ASM, que se define por vigilar en el tiempo. El diff con `cambiados` es
  la pieza que permitiría alertar («ayer no tenía el 22 abierto»); falta el
  disparador (planificador + notificación cuando el diff no está vacío).
  **Planificado** como bloque 4 (diseño en «Plan acordado para las próximas
  sesiones»).
- **`POST /scans` es síncrono.** El escaneo completo corre dentro de la
  petición HTTP: 19 s para github.com, pero un dominio grande dejaría la
  conexión abierta minutos. Lo normal sería lanzarlo como tarea en segundo
  plano y consultar su estado. **Planificado** como bloque 3 (diseño en
  «Plan acordado para las próximas sesiones»).
- **Señal/ruido de los hallazgos.** En github.com, 194 de 211 hallazgos son
  `low`, casi todo higiene de cabeceras. La reutilización del triaje reduce
  el coste de triarlos, no su volumen ni el ruido para quien lee.
- **Crédito de Anthropic agotado (06/10/2026).** No es deuda del código, pero
  condiciona el trabajo: no se puede regrabar la demo ni verificar en vivo
  con Claude. Ver «Estado al 13/10/2026 y próxima sesión».
- **`replay` solo cubre el guion grabado.** Por diseño (ver "Datos de
  reserva para la demo"); no sustituye al modelo fuera de esos datos.

- **Shodan: cobertura real limitada por el plan de la clave disponible.**
  `/dns/domain/{domain}` devuelve `403` en el plan gratuito `oss`
  ("Requires membership or higher to access"), verificado contra la API
  real. El código está completo y probado (con dobles, y en vivo el camino
  de fallo), pero no aporta subdominios reales con la clave actual — solo
  con un plan de pago. **En la práctica, crt.sh es la única fuente
  efectiva**, frente a las decenas de fuentes de herramientas como subfinder
  o amass: la calidad del inventario limita todo lo que viene después.
- **Tabla de patrones de takeover no exhaustiva.** `discovery/takeover.py`
  cubre ~20 proveedores citados habitualmente (GitHub Pages, Heroku, S3,
  Azure...), no una lista cerrada — mismo criterio de honestidad que
  `COMMON_PORTS`. La tabla de huellas de verificación
  (`TAKEOVER_FINGERPRINTS` en `discovery/takeover_verify.py`) es un
  subconjunto aún menor: solo los proveedores con una huella de "recurso no
  reclamado" pública, estable y bien documentada. Un candidato cuyo
  proveedor tiene patrón pero no huella se queda en detección por patrón, sin
  verificar — igual de honesto que no inventar una huella frágil.
- **Verificación de takeover: acotada por el propio alcance de detección.**
  `find_takeover_candidates()` solo mira hosts que **no** resuelven por
  A/AAAA (`no_answer`/`nxdomain`/`unroutable`). Para esos, el destino del
  CNAME suele seguir resolviendo en la infraestructura compartida del
  proveedor (`*.github.io`, `*.s3.amazonaws.com`...) y devolver su 404 de
  "no reclamado" — que es justo lo que la verificación busca. Pero si el
  propio destino del CNAME tampoco resuelve, el `GET` no conecta y el
  candidato se queda en patrón puro (degradación controlada, no error). No se
  amplió el alcance de detección a hosts `active` con CNAME sospechoso: es
  una decisión separada, no la que se pidió aquí.
- **Cuota gratuita de Gemini: ~20 peticiones/día**, se agota rápido
  combinando triaje + prompter + diff + informe en la misma sesión de
  pruebas. Verlo como límite de verificación manual, no del código.
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
- **TLS: un error de cadena por host, sin STARTTLS ni cifrados.** OpenSSL
  reporta el primer fallo de verificación que encuentra: si un certificado
  tiene varios problemas de cadena, sale uno. Se inspeccionan el 443 y los
  puertos con TLS implícito abiertos (ver «Resuelta»), pero no los de
  STARTTLS (25, 587, 110, 143: exigen hablar antes SMTP/POP3/IMAP) ni la
  configuración de cifrados, terreno de herramientas específicas
  (testssl.sh), con otra intrusividad.
- **Cabeceras: sin CORS, y solo la portada.** `discovery/headers.py`
  evalúa la raíz (`/`) de cada host: las seis cabeceras del enunciado sobre
  la respuesta **final**, las cookies de toda la cadena de redirecciones y
  la redirección HTTP → HTTPS (ver "Resuelta"). No evalúa
  `Access-Control-Allow-Origin` (tendría sentido en rutas de API, no en la
  portada) ni cookies que solo se fijen en otras rutas (login, etc.).
- **Enumeración limitada a lo certificado o indexado.** Un subdominio que
  nunca tuvo certificado (crt.sh) ni aparece en Shodan no se descubre:
  contrapartida inherente al enfoque pasivo (sin fuerza bruta de nombres).
- **Sin límite global de coste ni de concurrencia de IA.** Cada llamada acota
  su propia concurrencia (`AI_CONCURRENCY` en el triaje), pero no hay un
  tope agregado entre peticiones simultáneas ni entre los seis agentes. Solo
  el triaje evita llamadas repetidas, y solo entre escaneos (ver «Resuelta»).
- **La reutilización del triaje se pierde con CDN.** La clave es el prompt
  exacto, y el prompt lleva las IPs: un host tras un balanceador que cambia
  de IP entre escaneos vuelve a pagar su triaje. En la demo, de los 203
  hallazgos del #2 que ya existían en el #1 (mismo host y tipo), solo 57
  tienen el prompt idéntico. Quitar las IPs del prompt ahorraría más, pero
  cambia lo que ve el modelo y obliga a regrabar la demo.
- **El triaje no ve el histórico del dominio** (hallazgos de escaneos
  previos): cada hallazgo se valora solo con su propio contexto.
- **Re-triaje solo por API.** `?force=true` (ver "Resuelta") no tiene botón en
  el dashboard a propósito: son cientos de llamadas en un escaneo grande y un
  clic accidental en la demo las dispararía.
- **API: sin paginación ni borrado.** `list_scans` acepta `limit` (50 por
  defecto) pero no `offset`; no existen rutas `PUT`/`DELETE`.
- **Dashboard sin triaje selectivo.** El triaje se lanza sobre el escaneo
  completo, nunca sobre un hallazgo concreto; la consulta NL no recuerda
  preguntas anteriores.

### Resuelta (se deja constancia para la defensa)

- ~~**Al plegar la barra lateral del dashboard no se podía volver a
  abrir**~~ (lo encontró el usuario al probar la fase B; venía del rediseño
  visual) → el botón que la reabre vive dentro de `stToolbar`, que `_CSS`
  ocultaba con `display: none`; y el ancho forzado dejaba una franja vacía
  de 268 px con la barra plegada. Ver la trampa en «Dashboard: diseño
  visual» (`912e6c5`).
- ~~**El dashboard no decía qué está configurado**~~ → fase B (fase 13):
  `GET /config/status` reutiliza las comprobaciones de `doctor` que no salen
  a la red (un cliente HTTP que rechaza toda petición lo garantiza) y el
  dashboard lo pinta en la barra lateral y, sin escaneos, en una bienvenida
  con el siguiente paso. Estado y texto, nunca valores (un test recorre la
  respuesta con claves y contraseña configuradas).
- ~~**En Docker, la configuración se daba por ausente**~~ (encontrado al
  diseñar `/config/status`): Compose pasa el `.env` como variables de entorno
  y el fichero no está en el contenedor, así que `doctor` y el estado habrían
  dicho «sin .env, ejecuta atalaya init». Ahora cuentan los campos del
  entorno.
- ~~**Con la API caída, el dashboard decía «Todavía no hay escaneos»**~~
  (encontrado al repasar el prototipo de la bienvenida, que también habría
  salido): un fallo de `/scans` se convertía en lista vacía. Ahora no se
  afirma nada que no se comprobó; test incluido.
- ~~**Configurar exigía editar `.env` a mano, y el alcance quedaba abierto
  por defecto**~~ → `atalaya init` (fase 13): cinco pasos validados al
  momento, alcance obligatorio con confirmación de autorización, `.env`
  escrito de forma atómica y con copia. Y `atalaya doctor` diagnostica en
  cualquier momento. Verificado en real en una pseudoconsola de Windows
  (ConPTY), con las claves de desarrollo tecleadas y validadas contra
  Anthropic y Shodan, sin ningún secreto en pantalla.
- ~~**Claves desconocidas en `.env` ignoradas sin avisar**~~ → pydantic
  (`extra="ignore"`) descarta en silencio una errata como `ANTHROPIC_APIKEY`.
  `doctor` las señala. En el `.env` de desarrollo encontró `API_HOST`,
  `API_PORT` y `ENVIRONMENT`, retirados del código en `521019e`.
- ~~**Un `.env` con un valor inválido impedía arrancar cualquier comando**~~
  (p. ej. `AI_MAX_TOKENS=mil`: traza de pydantic al importar) → `cli.py`
  carga la configuración dentro de cada comando, y `doctor` lo diagnostica
  («valor no válido en .env: AI_MAX_TOKENS»). Verificado en un proceso nuevo.
- ~~**`atalaya -v` imprimía la clave de Shodan**~~ → con el log raíz en INFO,
  `httpx` registraba la URL completa, y Shodan solo acepta la clave en la URL
  (`?key=...`). `httpx`/`httpcore` quedan en WARNING (`c58a746`). Verificado
  contra Shodan real: sin el arreglo la clave sale, con él no. La API no
  estaba afectada (solo configura el logger `atalaya`).

- ~~**TLS solo en el puerto 443**~~ → `enrich_scan()` repite la inspección
  en 465, 993, 995 y 8443 (`tls.py::IMPLICIT_TLS_PORTS`) cuando el escaneo
  de puertos los encuentra abiertos en una IP del host; el 443 se sigue
  inspeccionando en todo host activo, como antes. Los hallazgos de varios
  puertos se fusionan en **uno por tipo y host**
  (`models.py::_merge_tls_findings`), la invariante de la que dependen el diff
  y la reutilización del triaje; no se metió el puerto en el `finding_type`
  porque los escaneos antiguos dejarían de compararse con los nuevos. Si el
  hallazgo solo sale en el 443, la evidencia es **idéntica** a la de antes
  (si no, todo triaje TLS ya hecho dejaría de reutilizarse); si no, cita los
  puertos y agrupa los que comparten evidencia («Puertos 443 y 8443: …»).
  Verificado en real sobre github.com: `emails.github.com:8443` sirve el mismo
  certificado próximo a caducar que el 443 → un solo hallazgo;
  `info.github.com:8443` falla el handshake → degradación sin hallazgo.
- ~~**Los hosts `wildcard` seguían recibiendo escaneo de puertos**~~
  (encontrado al leer `scan_targets()` para lo anterior, contra lo que decían
  CLAUDE.md, ARQUITECTURA y la memoria de robustez) → `scan_targets()`
  recorría todos los registros, no solo los activos, y `apply_port_scan()`
  asignaba a un host `wildcard` los puertos del activo con el que compartiera
  IP. Ahora ambos se limitan a los `active`. Latente: ningún escaneo real
  guardado tiene hosts `wildcard`; los dos tests nuevos fallan contra la
  versión anterior.

- ~~**Cada re-escaneo pagaba otra vez el triaje de lo que no había
  cambiado**~~ → `ai/triage_reuse.py`: antes de llamar al modelo,
  `POST /scans/{id}/triage` copia el triaje de un hallazgo de otro escaneo
  del dominio con **el mismo contexto exacto** (`build_finding_context`;
  el resto del prompt es constante, así que mismo contexto = mismo prompt).
  Medido en la demo: triar el #2 desde cero con el #1 triado pasa de 211 a
  154 llamadas (**27 %**). No se deduplica dentro de un escaneo porque no
  hay nada que deduplicar (el contexto lleva el host: 211/211 prompts
  únicos), ni se agrupa por tipo + evidencia (211 → 11 llamadas, pero el
  modelo perdería el contexto del host y habría que regrabar la demo).
  `?force=true` no reutiliza (forzar es volver a preguntar al modelo
  actual); con todo reutilizado no se instancia el proveedor. La respuesta
  añade `reused` y `model_calls`, y la API registra «N hallazgos triados con
  M llamadas (ahorro del X %)». `ai/triage.py` no se toca. La demo no cambia:
  los 8 pendientes no tienen equivalente en el #1 (verificado por HTTP en
  `replay`: 8 llamadas, 0 grabaciones faltantes).
- ~~**El diff solo comparaba hostnames**~~ (un activo existente que abría un
  puerto o perdía HSTS salía «sin cambios») → `diff_scans()` añade
  `cambiados`: de los comunes, cambio de estado, puertos nuevos/desaparecidos
  y hallazgos nuevos/desaparecidos con su severidad (la del escaneo donde
  están). Hallazgos comparados por `finding_type`, no por evidencia (los días
  hasta la caducidad cambian sin que cambie el problema); IPs **no**
  comparadas (CDN y balanceo). «Desaparecido», no «cerrado» ni «resuelto»:
  un timeout de la sonda produce lo mismo, y el prompt de `diff_analyst` lo
  advierte. `comunes` sigue completo (contrato de la API intacto). El
  dashboard muestra «Cambiados» con chips por activo. Verificado en real con
  la demo en `replay`: 3 cambiados de 117 comunes, valoración regrabada.

- ~~**TLS: sin validar cadena de confianza ni hostname**~~ → dos hallazgos
  nuevos en `discovery/tls.py`. `tls_hostname_no_coincide`: comprobación sin
  red sobre los SAN del certificado, con las reglas de un navegador (RFC 6125:
  comodín solo como etiqueta izquierda completa, sin recurrir al CN).
  `tls_cadena_no_confiable`: segunda negociación **con** verificación, en
  paralelo con la de inspección, contra el almacén de Mozilla (`certifi`) y
  no el del sistema, que cambia entre Windows y Debian. Se desactiva
  `VERIFY_X509_STRICT`: Python 3.13+ lo activa por defecto y rechaza
  certificados que los navegadores aceptan, así que el mismo certificado
  salía válido en Docker (3.11) y no confiable en desarrollo (3.14). La
  caducidad no se duplica. Verificado en real contra `badssl.com` (autofirmado,
  nombre equivocado, raíz no confiable, caducado, cadena incompleta) y
  `github.com` como control, en Python 3.14 local y 3.11 en Docker, con el
  mismo resultado. Tests con un servidor TLS real en `127.0.0.1` y
  certificados generados en memoria (marcador `tls_local`).
- ~~**El diff del dashboard dependía de la IA**~~ (el endpoint da 502 si falla
  el proveedor, y con él se perdían los hostnames, que son puro cálculo) →
  `GET /scans/{id}/diff/{other_id}?analysis=false` devuelve solo el cálculo,
  sin llamar al modelo (`analysis: null`). El comportamiento por defecto no
  cambia (la IA sigue siendo parte del diff y su fallo, un 502): es una salida
  explícita. El dashboard la usa como respaldo solo ante un 502 y avisa del
  motivo; un 404/400 no se reintenta. Verificado en real sin clave de
  proveedor: 502 → nuevos/desaparecidos/sin cambios con el aviso.
- ~~**No se podía forzar un re-triaje**~~ (re-triar tras cambiar de modelo
  exigía devolver `severity` a `unknown` a mano en BD) → `POST /scans/{id}/
  triage?force=true` incluye los ya triados. Sin `force` sigue siendo
  idempotente. Un re-triaje fallido **conserva el triaje anterior**
  (`triage_finding` no toca el hallazgo si el proveedor falla): verificado en
  real con la demo en `replay` — 204 fallos, cero severidades perdidas.
- ~~**Cookies sin evaluar**~~ → `headers.py::evaluate_cookies()`:
  `cookie_sin_secure` (solo en sitios HTTPS), `cookie_sin_httponly` y
  `cookie_sin_samesite`, **uno por tipo y host** con los nombres afectados
  (veinte cookies mal configuradas son un problema, no veinte que inflen el
  score). Mira también las `Set-Cookie` de las redirecciones intermedias
  (`response.history`). **Nunca guarda el valor** de una cookie: puede ser un
  token de sesión, y la evidencia va a BD, al proveedor de IA y al PDF (hay un
  test). Verificado en real: en `github.com` solo sale `_octo` sin `HttpOnly`
  (analítica); `_gh_sess` y `logged_in` están bien configuradas.
- ~~**No se comprobaba que HTTP redirigiera a HTTPS**~~ (solo se caía a HTTP
  si HTTPS no respondía, lo que genera `sin_https`) → `analyze_headers()` pide
  HTTP en paralelo con HTTPS: si HTTPS responde y el acceso por HTTP no acaba
  en una URL `https` (siguiendo redirecciones, en cadena o a otro host), nuevo
  hallazgo `http_sin_redireccion_https`. Que HTTP no conteste no es hallazgo
  (nada se sirve en claro) y no se duplica con `sin_https`. En paralelo porque
  en serie un puerto 80 filtrado sumaría un timeout completo por host.
  Verificado en real: `example.org` (200 en claro) da el hallazgo, `nmap.org`
  (redirige) no, `scanme.nmap.org` (solo HTTP) da `sin_https`.
- ~~**Dashboard sin diff**~~ (`GET /scans/{id}/diff/{other_id}` solo por API)
  → selector «Comparar con» en el detalle de un escaneo cuando hay otro del
  mismo dominio (`dashboard/app.py::render_comparacion`). Por defecto propone
  el anterior más reciente; muestra nuevos, desaparecidos y sin cambios, y la
  valoración del modelo. Se pide con un botón y se guarda en `session_state`
  por pareja: el endpoint llama al modelo, y pedirlo al renderizar repetiría
  la llamada en cada reejecución de Streamlit.
- ~~**API sin autenticación**~~ (bloqueante si se desplegaba con IP pública)
  → `api/security.py::require_api_key()`: con `API_KEY` en `.env`, todo
  endpoint salvo `/health` responde 401 sin `X-API-Key` correcta (comparación
  con `secrets.compare_digest`). Vacía por defecto: la demo, el stack sin
  `.env` y la suite no cambian. El dashboard la envía si la tiene
  (`ATALAYA_API_KEY`, o `API_KEY` del mismo `.env` en local); en Docker recibe
  solo esa variable, no el `.env` entero. Los puertos siguen publicados solo
  en `127.0.0.1`: la clave no sustituye a TLS, que haría falta para exponerla
  de verdad (sin él, la clave viaja en claro).
- ~~**PDF: hostnames largos invadían la columna de estado**~~ (visto al
  revisar el PDF de la demo: 38 de 118 hosts) → anchos de columna medidos con
  las métricas de Helvetica, corte CJK solo en el host como último recurso e
  IPs una por línea. Dos intentos intermedios, descartados al mirar el PDF,
  partían una IPv4 por la mitad o pegaban las IPs sin separador; el test
  `test_tabla_de_activos_sin_solapes_ni_ips_partidas` mide la geometría real
  del PDF (posiciones con pypdf, anchos con reportlab) con el peor caso.
- ~~**`risk_score` saturado**~~ (encontrado al construir los datos de la
  demo) → github.com, con 194 `low` + 9 `medium` y ningún `critical`/`high`,
  salía «100/100 · riesgo crítico». Nueva fórmula en `core/scoring.py`
  (banda por severidad máxima, rendimientos decrecientes por tipo, monótona;
  ver "Decisiones ya tomadas"), única para PDF y API; el dashboard pinta el
  de la API. github.com pasa a 39 «medio». Regrabados solo los 2 resúmenes
  ejecutivos de la demo (su prompt lleva el score); el diff no cambia
  (`837d593`).
- ~~**PDF con Markdown literal y glifos en blanco**~~ → `reporting/pdf_text.py`
  renderiza el Markdown del modelo escapando antes el HTML (el modelo no
  puede inyectar etiquetas que xhtml2pdf siga, como una `<img>` remota) y el
  `finalize` de Jinja sustituye lo que Helvetica no dibuja (`→` → `->`). Un
  test genera el PDF real de la demo y exige cero avisos de glifo
  (`a2af874`).
- ~~**Sin consulta de CNAME / fuente única de enumeración**~~ (Paso 2) →
  `discovery/takeover.py` y `discovery/shodan.py` (ampliación de agentes).
- ~~**Sin detección de comodines DNS**~~ (Paso 2) → `detect_wildcard_dns()` +
  estado `wildcard`, commit `2d90b0a` (ampliación de robustez).
- ~~**Migraciones y escritura nunca probadas contra PostgreSQL**~~ → al
  probarlas contra PostgreSQL 16.12 real (binarios portables, sin Docker)
  apareció un bug grave: las fechas *aware* en columnas `TIMESTAMP WITHOUT TIME
  ZONE` hacían que asyncpg rechazara **toda** escritura de un `Scan`, así que
  `POST /scans` fallaba siempre en el motor de producción; SQLite lo tragaba en
  silencio. Arreglado con `core/models.py::UtcDateTime` (convierte a UTC
  *naive* al escribir; sin migración, `alembic check` limpio), commit
  `3b9e1a6`. Verificado: `alembic upgrade head`, 47/47 pruebas de BD y API
  sobre PostgreSQL (29 fallaban antes) y flujo real completo sobre
  `scanme.nmap.org`. La suite normal sigue en SQLite: la guarda
  `test_toda_columna_de_fecha_usa_utc_datetime` cubre la regresión sin Postgres.
- ~~**Stack Docker nunca levantado**~~ → al levantarlo (Docker Desktop sobre
  WSL 2), `POST /scans` devolvía 500 (`no such table: scans`) y la API usaba
  SQLite dentro del contenedor en vez del Postgres del compose. Cuatro
  defectos: la imagen de la API no copiaba ni aplicaba las migraciones; el
  `DATABASE_URL` de `.env` llegaba al contenedor; el dashboard no copiaba
  `.streamlit/`; no había `.dockerignore`. Arreglados en `97d97d9`, con
  endurecimiento: puertos solo en `127.0.0.1`, `.env` opcional, dashboard sin
  secretos, healthcheck de la API, `exec uvicorn` (parada limpia en 1,7 s) e
  imagen de la API de 1,51 a 1,04 GB. `tests/test_deploy_config.py` los fija
  sin Docker (cada prueba falla contra la versión original). Verificado desde
  cero, sin `.env`, con `.env.example`, tras reinicio y con la suite completa
  sobre Python 3.11. `.env.example` apunta ahora a `localhost:5432`
  (`de13de0`): con `@db` el arranque local del README fallaba.
- ~~**Auditoría de takeover invisible y `LOG_LEVEL` sin efecto**~~ →
  encontrado en el ensayo desde un clon limpio. La traza obligatoria de la
  restricción #6 se emitía con `logger.info`, pero nadie configuraba los
  loggers de `atalaya.*`: bajo uvicorn (solo configura `uvicorn.*`) y en la
  CLI sin `-v` el nivel efectivo era WARNING y se descartaba en silencio. El
  test existente no lo veía porque forzaba INFO con `caplog.at_level`.
  Arreglado con un logger de auditoría independiente (`core/audit.py`,
  `f719fbe`) y aplicando `LOG_LEVEL` en `api/main.py` (`da3cc83`); tests que
  reproducen la configuración real de uvicorn y de la CLI sin tocar niveles.
- ~~**Configuración muerta y README no apto para Windows**~~ → del mismo
  ensayo: `API_HOST`/`API_PORT`/`ENVIRONMENT` no los leía nadie (eliminados,
  `521019e`); `make api` escuchaba en `0.0.0.0` (`557f1e8`); el README
  dependía de `make` y de `source .venv/bin/activate`, no avisaba de que
  `docker compose restart` no recarga `.env`, no tenía ejemplo de
  `POST /scans` y sus `curl` fallan en PowerShell y, con tildes, en Git Bash
  (envía cp1252) (`7c4eefc`). Re-ensayado con el código commiteado.
- ~~**Dependencias transitivas no declaradas**~~ → `greenlet` explícito
  (`f547a44`), instalación limpia verificada de extremo a extremo.
- ~~**Verificación en vivo de los 5 agentes de IA nuevos, pendiente con
  Anthropic.**~~ **Resuelto.** Con `ANTHROPIC_API_KEY` ya disponible, se
  verificaron en vivo los seis agentes (incluido `ai/triage.py`, que
  tampoco se había probado nunca contra el modelo real de Anthropic desde
  el Paso 5) sobre datos reales: `triage_finding` sobre un hallazgo real
  de `mediamarkt.es` (severidad `LOW` razonada correctamente),
  `analyst.analyze_scan` sobre un escaneo mediano y sobre el escaneo
  grande de `github.com` (117 activos/204 hallazgos — el caso que rompía
  con Gemini antes del arreglo del punto siguiente; con Anthropic
  nunca falló), `prompter.route_and_answer` en sus dos rutas (general →
  analyst, takeover → takeover_detective), `assess_takeover_risk` sobre
  un candidato construido a mano, `analyze_diff` sobre dos escaneos
  reales, y `write_executive_summary`. Las seis respuestas fueron
  coherentes y bien razonadas.
- ~~**`POST /findings/ask` con Gemini: fallo 502 observado una vez, sin
  reproducir.**~~ **Resuelto: no era la cuota, eran dos bugs reales de
  `GeminiProvider.complete_tool()`**, ambos reproducidos en vivo contra la
  API real con cuota disponible. `ai/analyst.py::_TOOL_SCHEMA` quedó
  definitivamente descartado como causa.
  1. **`max_output_tokens` de Gemini no significa lo mismo que `max_tokens`
     de Anthropic.** Los modelos 2.5 razonan siempre y sus tokens de
     razonamiento **se descuentan de `max_output_tokens`**; mapear
     `settings.ai_max_tokens` directamente dejaba que el razonamiento se
     comiera el límite y la generación se cortara *antes* de emitir la
     llamada a herramienta → `finish_reason=MAX_TOKENS`,
     `candidate.content=None`, y por tanto el mensaje `"el modelo no llamó a
     la herramienta 'record_analysis'"`. Es también la causa real del
     `candidate.content=None` que ya se había parcheado antes atribuyéndolo
     a la cuota. **Arreglo:** `thinking_config` con presupuesto acotado
     (`_GEMINI_THINKING_BUDGET = 512`) **sumado** a `ai_max_tokens`, que así
     vuelve a significar lo mismo en los dos proveedores: tokens para la
     respuesta.
  2. **`mode="ANY"` rompe la decodificación restringida en prompts
     grandes.** Con un escaneo de 117 activos / 204 hallazgos, Gemini
     devuelve `finish_reason=MALFORMED_FUNCTION_CALL`, sin contenido y sin
     consumir tokens de salida — con cualquier límite de tokens. El mismo
     prompt se responde correctamente con `mode="AUTO"`. **Arreglo:**
     reintento único en `AUTO` solo ante ese `finish_reason` (se pierde la
     *garantía* de la llamada, por eso no es el modo por defecto, pero si
     el modelo contesta con texto se sigue degradando a `AIProviderError`,
     nunca a una respuesta sin forma).
  3. **El mensaje de error era opaco.** MAX_TOKENS, MALFORMED_FUNCTION_CALL
     y "el modelo contestó con texto" producían el mismo texto, que es por
     lo que el fallo se atribuyó a la cuota durante una sesión entera. Ahora
     el `finish_reason` va en el mensaje. Dato que lo confirma: agotar la
     cuota da un error **distinto** (`fallo del proveedor Gemini: 429
     RESOURCE_EXHAUSTED`, verificado en vivo), así que la hipótesis de la
     cuota nunca encajó con el síntoma.

  Verificado en vivo antes y después del arreglo (mismos casos: fallaban,
  ahora responden) y cubierto con 4 tests de regresión deterministas en
  `tests/test_ai_provider.py`.

---

## Comandos

```bash
pip install -e ".[dev]"              # instalar con dependencias de desarrollo
atalaya init                         # configuración guiada: alcance, BD, claves (.env)
atalaya doctor                       # qué funciona y cómo arreglar lo que no (--offline)
pytest -q                            # tests (deben pasar los 583)
uvicorn atalaya.api.main:app --reload # API en :8000, docs en /docs
streamlit run dashboard/app.py       # dashboard en :8501
alembic upgrade head                 # aplica las migraciones (crea scans/assets/findings)
atalaya subdomains ejemplo.com       # CLI de enumeración
atalaya subdomains ejemplo.com --save # enumera y persiste el resultado en BD
ruff check src tests                 # linter (0 avisos)
mypy src                             # tipos (0 errores); ambos: make lint
docker compose up --build -d         # stack completo (migra solo; .env opcional)
docker compose up -d db              # solo PostgreSQL, para la API en local
python scripts/seed_demo_data.py --reset # BORRA la BD y carga la demo de reserva
```

**Cambiar de proveedor de IA:** `AI_PROVIDER=anthropic` o `AI_PROVIDER=gemini`
en `.env`, con la clave correspondiente (`ANTHROPIC_API_KEY`/`GEMINI_API_KEY`).
Solo hace falta la clave del proveedor activo.

**Dominio de pruebas:** `scanme.nmap.org`, mantenido por el autor de Nmap
explícitamente para reconocimiento autorizado.

**Verificación visual del dashboard:** `_shot.py` en la raíz del proyecto
(versionado desde `e815dda`, pero herramienta de desarrollo, no parte del
paquete — Playwright; `playwright` no está en las dependencias declaradas)
abre un
navegador real contra el dashboard en marcha y captura pantallas en
`.claude/shots/`, reutilizando los escaneos que ya hay en BD; `--scan` lanza
además uno real contra `scanme.nmap.org`, `--triage` lo tría y `--diff` pulsa
«Comparar» sobre el escaneo grande (con la demo sembrada, github.com). Puerto por
defecto 8502: con `streamlit run` (8501) hay que pasar `--port 8501`.
Requiere la API y el dashboard ya arrancados y `playwright install` hecho
una vez.

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

`.claude/agents/` define cuatro subagentes de proyecto, uno por área y sin
solape: `atalaya-discovery` (`discovery/` + `core/persistence.py`),
`atalaya-ai-agents` (`ai/`, salvo `triage.py`), `atalaya-api` (`api/`,
`core/repository.py`, `reporting/`) y `atalaya-dashboard` (`dashboard/`,
`.streamlit/`, `_shot.py`). Nacieron como encargos de la ampliación de
agentes y se reescribieron como **responsables de mantenimiento** de su
área: cada uno recoge las reglas y trampas ya aprendidas en ella, verifica
con `pytest`/`ruff`/`mypy` más una prueba real, **no hace commits** y
termina diciendo qué documentos hay que actualizar. **Estos ficheros no se
recargan dentro de una sesión ya iniciada** — solo están disponibles como
`subagent_type` con nombre propio en sesiones que arrancan *después* de su
última modificación; si no aparecen en la lista de agentes disponibles, hay
que despacharlos como `general-purpose` pegando el contenido completo del
`.md` correspondiente como instrucciones.

Ninguno de los cuatro toca `ai/triage.py` — instrucción explícita, se
mantiene igual desde el Paso 5. `onboarding/` (fase 13) no tiene subagente
propio: la fase B (`GET /config/status` y la bienvenida) se hizo desde la
sesión principal con las reglas de `atalaya-api` y `atalaya-dashboard`.
