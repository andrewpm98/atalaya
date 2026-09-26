# Memoria técnica — Ampliación: robustez, wildcards DNS y verificación de takeover

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Segunda ampliación posterior a los 7 pasos de la hoja de
ruta (todos cerrados) y a la ampliación del sistema de agentes de IA (ver
`Memoria_Ampliacion_Agentes`). No es un requisito obligatorio: robustece la
entrega para una instalación limpia y cierra dos piezas de deuda técnica con
valor real de cara a la defensa.
**Estado:** Completa. Dependencia faltante corregida, instalación limpia
verificada de extremo a extremo, lint y tipado a cero avisos, detección de
wildcards DNS, verificación en vivo del flujo con IA real, y verificación HTTP
opt-in de subdomain takeover — todo implementado, verificado de forma
independiente (tests + integración + prueba manual real) y en `origin/main`.

---

## 1. Resumen ejecutivo

Con la entrega ya funcional, esta fase persigue dos objetivos: que el proyecto
**instale y pase sus tests desde cero** (no solo en el `.venv` de desarrollo,
que arrastra dependencias de sesiones previas), y **cerrar deuda técnica con
valor de defensa**, no añadir funcionalidad porque sí.

Resultados tangibles, un commit por unidad lógica:

- **`greenlet` declarado como dependencia explícita** (`f547a44`). Faltaba en
  `pyproject.toml`; `sqlalchemy.ext.asyncio` lo necesita en runtime y `pytest`
  no arrancaba en un entorno limpio.
- **Instalación limpia verificada de extremo a extremo** (venv nuevo →
  `pip install -e ".[dev]"` → `alembic upgrade head` → `pytest` → `ruff` →
  `mypy`). No genera commit: es verificación de despliegue.
- **Lint a cero** (`3740a73`): 24 avisos de `ruff` (preexistentes, no
  introducidos por el fix anterior) corregidos sin tocar comportamiento.
- **Tipado a cero** (`885dd0c`, `7e46223`): 11 avisos de `mypy` corregidos, el
  último (`parse_certificate` devolvía `dict[str, object]`) con un `TypedDict`,
  separado en su propio commit por tocar una firma.
- **Detección y filtrado de wildcards DNS** (`2d90b0a`): un dominio con
  comodín inflaba el recuento de activos con hosts que no existen. Defecto de
  corrección, no solo la limitación que ya documentaba el proyecto.
- **Verificación en vivo del flujo completo con IA real** (Gemini): escaneo →
  triaje → consulta NL, de punta a punta, sin 502 atribuible a bug.
- **Verificación HTTP opt-in de subdomain takeover** (`3516a88` docs +
  `327ac74` código): el segundo nivel sobre la detección por patrón, con la
  restricción de seguridad #6 reabierta de forma acotada y razonada.
- **288 tests en verde** (266 al inicio de la sesión; +7 wildcards, +15
  verificación de takeover).

---

## 2. Por qué esta ampliación y no otra

El riesgo real de una entrega no es "falta una feature", es que **falle en el
entorno de quien la evalúa** por algo que en la máquina de desarrollo funciona
por acumulación. La primera mitad de la sesión ataca justamente eso: dejar el
proyecto en un estado donde una instalación desde cero pasa la suite completa
sin intervención manual. La pista fue concreta —`pytest` no arrancaba porque
`greenlet` no estaba declarado— y motivó verificar el resto (lint, tipado,
migraciones) en un venv limpio y aislado, no en el de desarrollo.

La segunda mitad cierra dos piezas de deuda técnica **elegidas por su valor**,
no por comodidad: los wildcards DNS (un falso positivo que contamina el
inventario de activos, exactamente el tipo de defecto que el propio proyecto ya
había corregido antes con `0.0.0.0`) y la verificación de subdomain takeover
(el hallazgo más accionable que puede producir una herramienta ASM). Esta
última obligó a reabrir una restricción de seguridad del proyecto — y se hizo
de forma explícita y documentada, no en silencio (sección 5).

---

## 3. Robustez: instalación limpia, lint y tipado

### 3.1 `greenlet` no declarado (`f547a44`)

`sqlalchemy.ext.asyncio` requiere `greenlet` en runtime. Estaba instalado en el
`.venv` de desarrollo como dependencia transitiva de alguna sesión previa, pero
**no figuraba en `pyproject.toml`**. En un entorno limpio, `tests/conftest.py`
fallaba al importar `AsyncSession` con un `ImportError` antes de recolectar un
solo test. Se añadió `greenlet>=3.0` junto a `sqlalchemy` en `dependencies`
(no en `dev`: es dependencia de ejecución, no de desarrollo).

### 3.2 Verificación en venv limpio de extremo a extremo

Para descartar que hubiera más dependencias transitivas no declaradas, se
simuló lo que hará quien evalúe la práctica: venv nuevo y aislado,
`pip install -e ".[dev]"` **solo** con lo declarado, `alembic upgrade head`
contra una BD SQLite limpia, `pytest -q`, `ruff check` y `mypy src`. La
instalación resolvió todo (incluido `greenlet`), las migraciones aplicaron sin
fricción y los tests pasaron idénticos al venv de desarrollo. Es verificación
de despliegue, no desarrollo: no genera commit, pero es la garantía de que la
entrega no depende del estado acumulado de una máquina concreta.

### 3.3 Lint a cero (`3740a73`)

24 avisos de `ruff`, **preexistentes** (el `.venv` de dev y el limpio daban los
mismos con idéntica versión, 0.16.9 — no los introdujo el fix de `greenlet`):

- **15 mecánicos** (auto-fix): `datetime.timezone.utc` → alias `datetime.UTC`,
  y un `startswith`+slice sustituido por `removeprefix("*.")` en
  `normalize_domain` (equivalente exacto, sin cambiar la comparación de
  dominios que protege la restricción #4).
- **9 de `B008`** (`Depends(get_session)` en las firmas de las rutas): no es un
  bug, es el idiom estándar de inyección de dependencias de FastAPI. No se
  reescribió el código; se añadió `extend-immutable-calls = ["fastapi.Depends"]`
  en `[tool.ruff.lint.flake8-bugbear]` de `pyproject.toml`.

### 3.4 Tipado a cero (`885dd0c`, `7e46223`)

11 avisos de `mypy`, ninguno un bug de comportamiento, separados en dos commits
por el criterio "un commit por unidad lógica":

- **`885dd0c`** — tres arreglos que solo tocan anotaciones/config: la tupla
  desempaquetada `(*header_results, *tls_results)` de
  `EnrichmentResult.findings_by_hostname` se ensanchaba a `BaseModel` genérico
  (anotación explícita `list[HeaderScanResult | TlsScanResult]`); el `mode: str`
  de `GeminiProvider._tool_call` se envuelve en el enum
  `FunctionCallingConfigMode` (el SDK ya lo acepta en runtime, verificado en
  vivo); y `xhtml2pdf`, sin stubs de tipos, se ignora vía
  `[[tool.mypy.overrides]]` — no es corregible en código propio.
- **`7e46223`** — el único hueco real, separado por tocar una firma:
  `parse_certificate` devolvía `dict[str, object]`, así que todo lo que salía de
  ahí perdía el tipo desde el origen y `build_tls_findings`/`TlsScanResult`
  recibían `object`. Se sustituyó por un `TypedDict` (`CertificateInfo`). El
  subíndice de diccionario no cambia en runtime, por eso los tests de TLS no se
  tocaron.

---

## 4. Detección y filtrado de wildcards DNS (`2d90b0a`)

### 4.1 Por qué es un defecto de corrección, no una limitación

Un dominio con **DNS wildcard** (`*.dominio` → una IP fija) hace que
**cualquier** subdominio resuelva, exista o no como servicio real. Sin filtro,
cada candidato de crt.sh/Shodan que nunca se dio de alta se contaba como
activo: el inventario se inflaba con hosts inexistentes y sin generar ninguna
incidencia. Es el mismo tipo de falso positivo que el proyecto ya había
corregido con `0.0.0.0` (registro anulado contado como activo) — por eso se
trató como un bug de corrección, no como una limitación documentada más.

### 4.2 Diseño

- `discovery/subdomains.py::detect_wildcard_dns()` consulta un subdominio con un
  **UUID** (no puede existir de verdad) antes de la resolución masiva. Si
  resuelve, esas IPs son las del wildcard. Nunca lanza: un fallo del resolver se
  trata como "no hay wildcard" (degradación controlada, mismo criterio que
  `resolve_hostname`).
- `enumerate_subdomains()` reclasifica a `ResolutionStatus.WILDCARD` (estado
  nuevo) cualquier registro `ACTIVE` cuyas IPs sean subconjunto de las del
  wildcard, **antes** de la confirmación "activo → fuente DNS": `is_active` ya
  lo excluye de `scan_targets()`/`active_records`/`total_active` sin tocar esas
  propiedades. El registro se conserva en `records` con su IP real (descartado
  como activo, no perdido silenciosamente).
- `SubdomainScanResult` gana `wildcard_ips` / `has_wildcard_dns` /
  `wildcard_records`, y `summary()` expone `wildcard_dns`/`wildcard_filtered`;
  la CLI lo imprime.
- `discovery/takeover.py` y `enrichment.py` no se tocaron y no hay regresión:
  ambos filtran por `status`, y `WILDCARD` no es
  `NO_ANSWER`/`NXDOMAIN`/`UNROUTABLE` (un host wildcard sí tiene IP: no hay CNAME
  colgante que revisar) ni `ACTIVE` (no se le hace port/header/TLS scan) —
  correcto en ambos casos, verificado leyendo los dos módulos antes de tocar
  nada.

### 4.3 Verificación

7 tests deterministas sin red: `detect_wildcard_dns` aislado (con/sin wildcard,
degradación ante error del resolver) y la integración completa (filtra el que
coincide, conserva el que no, no fuerza el filtro sin wildcard). Prueba manual
con caso real contra `scanme.nmap.org` (dominio de pruebas autorizado): sin
wildcard, `detect_wildcard_dns` devuelve `[]` correctamente, sin falso
positivo. No se probó el caso positivo (wildcard real) contra un tercero:
dispararía consultas contra un dominio sin autorización explícita; queda
cubierto con dobles deterministas.

---

## 5. Verificación en vivo del flujo con IA real (Gemini)

Con `AI_PROVIDER=gemini` temporalmente, se levantó la API (`uvicorn`) y se
recorrió el flujo completo sobre `scanme.nmap.org`: `POST /scans` (escaneo
real, 7 hallazgos), `POST /scans/{id}/triage` (5/7 triados con
severidad/impacto/remediación coherentes y específicos del hallazgo; 2 fallaron
por un **503 transitorio** de Gemini — el endpoint degradó a 200 con detalle en
`errors`, no a 502, como está diseñado) y `POST /findings/ask` (502 en el primer
intento por cuota gratuita agotada —`429 RESOURCE_EXHAUSTED`, límite de 5/min—,
correcto y ya documentado; 200 al reintentar). Ningún 502 atribuible a un bug
real: los únicos fallos fueron cuota/disponibilidad transitoria del tier
gratuito, la deuda técnica que el proyecto ya documenta. `.env` se devolvió a
`AI_PROVIDER=anthropic`. Es verificación, no código: sin commit.

---

## 6. Verificación HTTP de subdomain takeover (opt-in)

El punto de más peso de la sesión, y el que obligó a una decisión de criterio.

### 6.1 El conflicto con la restricción #6, y cómo se resolvió

La detección existente (`discovery/takeover.py`) señala el patrón de CNAME
hacia hosting de terceros, pero nunca comprueba si el recurso está realmente
sin reclamar — porque la restricción de seguridad **#6** ("nunca verificar
explotabilidad") lo prohibía, y esa postura estaba documentada **tres veces**
(la propia restricción, la tabla de decisiones "no reabrir sin motivo", y
`ARQUITECTURA.md §8.3`). Verificar por HTTP choca de frente con ella.

En vez de implementar en silencio, se planteó el conflicto explícitamente y se
decidió **reabrir la restricción de forma acotada y razonada**, documentándola
*antes* de tocar código (commit `docs:` separado, `3516a88`). La restricción #6
pasó de "nunca **verificar**" a "nunca **confirmar** explotabilidad ni intentar
el secuestro": la verificación lee la página de error **pública** del proveedor,
no reclama el recurso ni prueba el ataque, así que sigue del lado del
reconocimiento. El hallazgo se eleva a **"alta sospecha — no confirmado"**,
nunca a "confirmado". La frontera que #6 protege se mantiene intacta.

### 6.2 Diseño: módulo separado + tres salvaguardas

- **Módulo aparte** (`discovery/takeover_verify.py`), no dentro de
  `takeover.py`: la detección sigue siendo pasiva pura (sin `httpx`) y su test
  estático de restricción #6 sigue en verde. La única petición HTTP vive en el
  módulo nuevo, tras opt-in. Mismo criterio de módulos independientes que
  `shodan.py`.
- **`TAKEOVER_FINGERPRINTS`**: tabla de huellas de "recurso no reclamado" por
  proveedor (el 404 «There isn't a GitHub Pages site here.», el `NoSuchBucket`
  de S3...), un subconjunto **deliberadamente menor** que la tabla de patrones
  (solo proveedores con huella pública y estable). Alineada por sufijo con
  `TAKEOVER_PATTERNS`.
- **Tres salvaguardas obligatorias**, en el propio módulo: (a) opt-in
  (`TAKEOVER_VERIFY=false` por defecto — sin el flag, `verify_candidates`
  devuelve los candidatos sin tocar y no hace ninguna petición); (b)
  `is_authorized()` por hostname antes de sondear el destino de terceros
  (limitado a `SCAN_ALLOWLIST`); (c) auditoría (`logger.info`) de cada petición
  a un tercero, con hostname, destino, status y resultado.
- **Degradación controlada**: destino que no resuelve, conexión que falla o
  ausencia de huella → el candidato se queda en detección por patrón, nunca en
  error. `enrichment.py` encadena `verify_candidates()` tras
  `find_takeover_candidates()` (fuera del `gather`: depende de que los
  candidatos existan); con el flag off, transparente.

### 6.3 El hallazgo: "alta sospecha — no confirmado"

`TakeoverCandidate` gana `verification_attempted` y `unclaimed_indicator`.
`models.py::_takeover_evidence()` redacta la evidencia: con indicio, "ALTA
SOSPECHA — NO CONFIRMADO ... indicio adicional sobre el patrón, no una
confirmación de explotabilidad; requiere revisión manual"; sin indicio, el texto
de patrón puro (idéntico al previo). El `finding_type` sigue siendo
`subdomain_takeover_risk`: se persiste con el mismo mecanismo genérico, sin
tocar `core/persistence.py`.

### 6.4 Verificación en tres capas

- **Tests**: 15 deterministas sin red (`httpx.MockTransport`): huella
  detectada/ausente, fallback https→http, degradación ante `ConnectError`, gate
  de allowlist que omite un hostname no autorizado sin hacer HTTP, auditoría
  emitida, y evidencia que nunca dice "confirmado".
- **Integración**: revisada — `takeover.py` intacto (test estático de "no
  importa httpx" en verde), `enrichment.py` encadenado correctamente.
- **Prueba manual con caso real**: contra la infraestructura pública real de
  **GitHub Pages** (un GET benigno a un `*.github.io` inexistente, sin víctima
  ni dominio ajeno). Confirmó que la huella sigue vigente (las huellas se
  degradan con el tiempo: verificar contra la realidad importa) y que el flujo
  end-to-end —opt-in + gate de allowlist + auditoría + indicador— produce la
  evidencia esperada.

---

## 7. Estado final y commits

Siete commits, en `origin/main`:

| Commit    | Tipo  | Qué |
|-----------|-------|-----|
| `f547a44` | fix(deps)   | `greenlet` como dependencia explícita |
| `3740a73` | chore(lint) | 24 avisos de `ruff` a cero |
| `885dd0c` | chore(lint) | 3 arreglos de `mypy` (anotaciones + config) |
| `7e46223` | chore(lint) | `parse_certificate` → `TypedDict` (último `mypy`) |
| `2d90b0a` | fix(discovery) | detección y filtrado de wildcards DNS |
| `3516a88` | docs        | restricción #6 reabierta de forma acotada |
| `327ac74` | feat(discovery) | verificación HTTP opt-in de subdomain takeover |

**288 tests en verde**, `mypy` limpio (38 ficheros) y `ruff` limpio.
Instalación limpia verificada de extremo a extremo. La verificación en vivo del
flujo con IA (Gemini) y la prueba manual de takeover contra GitHub real no
generan commit: son verificación, no código.
