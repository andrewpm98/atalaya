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

- `POST /scans` ✅ — lanza un escaneo completo (subdominios + puertos +
  cabeceras + TLS sobre los hosts activos) y lo persiste.
- `GET  /scans`, `GET /scans/{id}` ✅ — consulta de escaneos (404 si no existe).
- `GET  /assets` ✅ — activos descubiertos, filtrables por `scan_id`.
- `GET  /findings` ✅ — hallazgos, filtrables por `asset_id`/`scan_id`;
  `severity` es `unknown` hasta triarlos.
- `POST /scans/{id}/triage` ✅ — triaja con IA los hallazgos `unknown` de un
  escaneo ya persistido. Idempotente: no repite los ya triados.
- `POST /findings/ask` ✅ — consulta en lenguaje natural sobre el último
  escaneo completado de un dominio (o uno concreto vía `scan_id`).

`api/schemas.py` define la frontera Pydantic entre las tablas y la respuesta
pública; `api/main.py` traduce `InvalidTargetError`/`UnauthorizedTargetError`
a 400/403 vía `exception_handler`, en vez de que cada ruta gestione sus
propios códigos de error.

### 2.2 Descubrimiento — `src/atalaya/discovery` (Paso 2 ✅)
Cada técnica es un módulo independiente con salida normalizada:

| Módulo         | Qué obtiene                                    | Fuente                  |
|----------------|------------------------------------------------|-------------------------|
| `subdomains`   | Subdominios                                    | crt.sh (CT logs) + DNS  |
| `ports`        | Puertos TCP abiertos (`COMMON_PORTS` por defecto) | Conexión asíncrona, concurrencia acotada |
| `headers`      | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Petición HTTP(S) |
| `tls`          | Versión de protocolo, emisor, caducidad del certificado | `cryptography` sobre el `ssl_object` de la conexión |
| `enrichment`   | Orquesta `ports`+`headers`+`tls` sobre los hosts activos de un escaneo, concurrentemente | Compone los tres anteriores |

`ports`/`headers`/`tls` nunca lanzan excepción: un host sin ese servicio (p.
ej. sin HTTPS en el 443) se refleja en el campo `error` del resultado, mismo
criterio de degradación controlada que `subdomains`. `enrichment.enrich_scan()`
solo actúa sobre `SubdomainScanResult.active_records` — un host que no
resuelve, o que solo resuelve a direccionamiento interno, no tiene servicio
real que inspeccionar. Los tres módulos devuelven `DiscoveryFinding`
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

### 2.4 Capa IA — `src/atalaya/ai` (Paso 5 ✅)
- `provider` — `LLMProvider` (interfaz, ABC) + `AnthropicProvider`. Dos formas
  de pedir una respuesta: `complete()` (texto libre) y `complete_tool()`
  (fuerza una llamada a herramienta con `tool_choice` fijo, para una
  respuesta con forma garantizada — más fiable que pedir "responde en JSON"
  sobre texto libre, que basta una frase de cortesía para romper).
- `triage` — `triage_finding`/`triage_findings`: reciben un `Asset` y un
  `Finding`, devuelven severidad razonada, impacto explicado y remediación
  concreta. Aquí se aplica el principio que el proyecto asume como central:
  **dar a la IA contexto estructurado** (`build_finding_context`, campos
  seleccionados a propósito), **no un dump de la fila de BD**. Degradación
  controlada: un fallo de un hallazgo no aborta el resto (`TriageBatchResult`).
- `query` — `ask()`: consulta en lenguaje natural sobre un escaneo completo
  (todos los activos y hallazgos, no uno aislado). Separado de `triage` porque
  ambos prompts necesitan un contexto de tamaño muy distinto.

### 2.5 Informes — `src/atalaya/reporting` (Paso 7 ✅)
Genera un informe ejecutivo en PDF a partir de un escaneo ya persistido:
portada (dominio, fecha), resumen ejecutivo con contadores por severidad, y
el detalle de cada activo y hallazgo con impacto y remediación. Cubre el
requisito de "reporte con portada".

- `generator.py` — `render_html()` (Jinja2, puro y síncrono, fácil de probar
  sin generar un PDF real) y `generate_report()` (convierte a PDF con
  `xhtml2pdf` en un hilo aparte vía `asyncio.to_thread`, para no bloquear el
  loop de eventos con trabajo de CPU). Recibe un `Scan` ya cargado, no un
  `scan_id` — mismo criterio que `ai/query.py::ask()`.
- Se elige **xhtml2pdf** sobre WeasyPrint porque es Python puro: no depende
  de Pango/Cairo/GTK, ausentes en un Windows sin ese runtime instalado.
- El PDF se escribe de forma determinista en
  `reports/atalaya_informe_{dominio}_{id}.pdf`: descargarlo de nuevo tras
  triar hallazgos nuevos lo regenera y sobrescribe, en vez de acumular una
  copia por cada clic de descarga.
- Expuesto vía `GET /scans/{id}/report` (API) y un botón en la pestaña
  «Escaneos» del dashboard.

### 2.6 Dashboard (Streamlit) — `dashboard/` (Paso 6 ✅)
Aplicación web que consume la API: lanzar escaneos, explorar activos y
hallazgos, triar con IA, consultar en lenguaje natural, y descargar el
informe PDF de un escaneo.

## 3. Flujo de datos

```
dominio
   │  POST /scans
   ▼
[Descubrimiento]  subdominios → puertos → cabeceras → TLS
   │  hallazgos crudos
   ▼
[PostgreSQL]  se persisten activos y hallazgos
   │
   ▼
[Capa IA]  triaje: severidad + impacto + remediación
   │
   ├──▶ [Dashboard]  visualización y consulta NL
   └──▶ [Informes]   PDF con portada
```

## 4. Decisiones de diseño

- **FastAPI** por rendimiento asíncrono y documentación OpenAPI automática, que
  además sirve de evidencia de la API en la defensa.
- **PostgreSQL** frente a SQLite en producción por concurrencia y por ser un
  motor realista; SQLite queda como fallback de desarrollo.
- **Capa IA desacoplada** tras una interfaz `LLMProvider`: el modelo es un
  detalle de configuración, no una dependencia rígida.
- **Módulos de descubrimiento independientes**: se pueden añadir o desactivar
  técnicas sin tocar el resto del sistema.
- **Salvaguarda de autorización** (`SCAN_ALLOWLIST`): limita los objetivos
  escaneables, alineado con un uso responsable de la herramienta.

## 5. Mapa de requisitos → implementación

| Requisito de la práctica | Dónde se resuelve                          |
|--------------------------|--------------------------------------------|
| Base de datos            | `core/models.py` + `core/persistence.py` (Paso 3 ✅) |
| API / webhook            | `api/` (propia, Paso 4 ✅) + `discovery/`/`ai/` (consumo de crt.sh y Anthropic) |
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
