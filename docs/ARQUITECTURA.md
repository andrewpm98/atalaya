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

- `POST /scans` — lanza un escaneo sobre un dominio.
- `GET  /scans`, `GET /scans/{id}` — consulta de escaneos.
- `GET  /assets` — activos descubiertos.
- `GET  /findings` — hallazgos priorizados por IA.
- `POST /findings/ask` — consulta en lenguaje natural.

### 2.2 Descubrimiento — `src/atalaya/discovery`
Cada técnica es un módulo independiente con salida normalizada:

| Módulo         | Qué obtiene                                    | Fuente                  |
|----------------|------------------------------------------------|-------------------------|
| `subdomains`   | Subdominios ✅ implementado                     | crt.sh (CT logs) + DNS  |
| `ports`        | Puertos/servicios abiertos                     | Escaneo asíncrono       |
| `headers`      | Cabeceras de seguridad HTTP                    | header-analyzer (reuso) |
| `tls`          | Versión TLS, certificado, caducidad            | `cryptography`          |

### 2.3 Persistencia (PostgreSQL) — `src/atalaya/core`
Modelo de datos relacional. Entidades previstas (Paso 3):

- **Scan** — un escaneo (dominio objetivo, fecha, estado).
- **Asset** — activo descubierto (subdominio/host, IP, puertos).
- **Finding** — hallazgo (tipo, evidencia, severidad, remediación, `scan_id`).

Relaciones: `Scan 1─N Asset`, `Asset 1─N Finding`.

### 2.4 Capa IA — `src/atalaya/ai`
- `provider` — abstracción del LLM (Anthropic por defecto, intercambiable).
- `triage` — recibe hallazgos crudos y devuelve severidad, impacto explicado y
  remediación. Aquí se aplica el principio que el proyecto asume como central:
  **dar a la IA contexto estructurado, no datos en bruto**.

### 2.5 Informes — `src/atalaya/reporting`
Genera un informe ejecutivo con portada (PDF/DOCX) a partir de un escaneo.
Cubre el requisito de "reporte con portada" de forma automatizada.

### 2.6 Dashboard (Streamlit) — `dashboard/`
Aplicación web que consume la API: lanzar escaneos, explorar activos y
hallazgos, y consultar en lenguaje natural.

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
   └──▶ [Informes]   PDF/DOCX con portada
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
| Base de datos            | `core/database.py` + modelos (Paso 3)      |
| API / webhook            | `api/` (propia) + `discovery/` (consumo)   |
| Aplicación web           | `dashboard/app.py`                         |
| GitHub con historial     | Commits por fase                           |
| Reporte con portada      | `reporting/generator.py`                   |

## 6. Hoja de ruta

1. **Paso 1 — Arquitectura + esqueleto** ✅
2. **Paso 2 — Motor de descubrimiento** (subdominios ✅ · puertos, cabeceras y TLS pendientes)
3. **Paso 3 — Base de datos + modelos**
4. **Paso 4 — API REST completa + APIs externas**
5. **Paso 5 — Capa IA (triaje + consulta NL)**
6. **Paso 6 — Dashboard completo**
7. **Paso 7 — Generador de informes**


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
interna. Se marca mediante `leaks_internal_addressing` y la capa IA lo tratará
como hallazgo propio (Paso 5).

### 7.6 Integración prevista

- **Paso 2 (puertos)** — `SubdomainScanResult.scan_targets()` alimenta el escaneo de puertos, ya filtrado de direcciones no enrutables.
- **Paso 3 (BD)** — cada `SubdomainRecord` se corresponde con una fila de `Asset`.
- **Paso 4 (API)** — los modelos se devuelven como respuesta de `POST /scans` sin conversión.
