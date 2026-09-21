# Atalaya — contexto del proyecto

Plataforma de **Attack Surface Management (ASM) con triaje por IA**. Entrega
de la Práctica 1 de un Máster en Ciberseguridad e IA. Desarrollo en solitario.

---

## Requisitos obligatorios de la entrega

El enunciado es explícito: **si falta uno de estos puntos, la práctica está
suspensa**. Cualquier decisión de diseño debe respetarlos.

| Requisito | Cómo se cubre | Estado |
|---|---|---|
| Base de datos | PostgreSQL + SQLAlchemy async | ✅ Modelos Scan/Asset/Finding + migraciones Alembic. Persiste subdominios, puertos abiertos y hallazgos de cabeceras/TLS |
| API o webhook | API REST propia **y** consumo de APIs externas | ✅ `scans`/`assets`/`findings`, triaje (`POST /scans/{id}/triage`), consulta NL (`POST /findings/ask`) e informe (`GET /scans/{id}/report`) reales |
| Aplicación web | Dashboard Streamlit | ✅ Escaneos, triaje IA, consulta NL, descarga de informe |
| GitHub con historial | Commits por unidad lógica | ✅ commits por fase |
| Reporte con portada | Informe generado por la herramienta | ✅ PDF con portada, resumen y hallazgos (`reporting/generator.py`) |

**El historial de commits se evalúa.** No agrupar trabajo de varias fases en
un commit único; el desarrollo progresivo es parte de lo que se califica.

---

## Qué hace la herramienta

Recibe un dominio y ejecuta cuatro fases:

1. **Descubrimiento** — subdominios (Certificate Transparency + DNS), puertos,
   cabeceras de seguridad HTTP, configuración TLS.
2. **Persistencia** — activos y hallazgos en base de datos, para comparar
   escaneos en el tiempo.
3. **Triaje por IA** — un LLM prioriza hallazgos, explica impacto real y
   propone remediación. **Es el componente diferencial del proyecto.**
4. **Consulta e informe** — preguntas en lenguaje natural e informe ejecutivo.

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
│   │                             EnrichmentResult
│   ├── subdomains.py            Enumeración completa (crt.sh + DNS)
│   ├── ports.py                  scan_ports() — TCP asíncrono, puertos comunes
│   ├── headers.py                 analyze_headers() — HSTS/CSP/XFO/XCTO/
│   │                             Referrer-Policy/Permissions-Policy
│   ├── tls.py                     inspect_tls() — versión, emisor, caducidad
│   └── enrichment.py              enrich_scan() — orquesta las tres técnicas
│                                 anteriores sobre los hosts activos
├── ai/
│   ├── provider.py               LLMProvider (ABC) + AnthropicProvider
│   ├── triage.py                 triage_finding/triage_findings — contexto
│   │                             estructurado, nunca un dump de la fila de BD
│   └── query.py                  ask() — consulta NL sobre un escaneo completo
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
        │                         GET /scans/{id}/report — reales
        ├── assets.py              GET /assets?scan_id= — real
        └── findings.py            GET /findings, POST /findings/ask — reales

migrations/                      Alembic (async); URL desde settings.database_url
dashboard/app.py                 Dashboard Streamlit — escaneos, triaje IA,
                                  consulta NL, descarga de informe
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

Validado sobre `github.com`: 117 subdominios descubiertos, 61 activos,
55 objetivos de escaneo, 19 segundos. **170 tests en verde.**

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

**Plazo:** entrega a finales de septiembre. Los siete pasos de la hoja de
ruta y los cinco requisitos obligatorios están cerrados. El margen restante
es para robustecer lo ya entregado (ver "Deuda técnica conocida") y preparar
la defensa oral, no para nuevas fases.

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
| Capa IA tras interfaz `LLMProvider` | El modelo es configuración, no dependencia rígida |
| Triaje IA **después** de persistir | La IA clasifica y explica sobre evidencia verificada; no descubre |
| Endpoints en 501, no ausentes | El contrato de la API se fija en diseño y se rellena por fases |

---

## Deuda técnica conocida

- **Sin consulta de registros CNAME.** En el escaneo de `github.com` unos 50
  hosts quedaron en `no_answer`: existen pero sin A/AAAA, probablemente con
  CNAME. Importa porque **un CNAME apuntando a un recurso no reclamado es la
  señal característica del subdomain takeover**. Incorporar cuando la capa IA
  lo necesite.
- **Fuente única de enumeración** (crt.sh). `SHODAN_API_KEY` ya está previsto
  en la configuración para ampliar cobertura.
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
pytest -q                            # tests (deben pasar los 170)
uvicorn atalaya.api.main:app --reload # API en :8000, docs en /docs
streamlit run dashboard/app.py       # dashboard en :8501
alembic upgrade head                 # aplica las migraciones (crea scans/assets/findings)
atalaya subdomains ejemplo.com       # CLI de enumeración
atalaya subdomains ejemplo.com --save # enumera y persiste el resultado en BD
ruff check src tests                 # linter
docker compose up --build            # stack completo
```

**Dominio de pruebas:** `scanme.nmap.org`, mantenido por el autor de Nmap
explícitamente para reconocimiento autorizado.

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
