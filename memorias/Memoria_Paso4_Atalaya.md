# Memoria técnica — Paso 4: Endpoints REST completos

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 4 de 7 — API REST sobre escaneos, activos y hallazgos
**Estado:** Completado y verificado sobre datos reales

---

## 1. Resumen ejecutivo

El Paso 4 convierte los seis endpoints declarados en el Paso 1 —hasta ahora
todos en `501 Not Implemented`, a propósito— en una API real que orquesta
descubrimiento, persistencia y consulta. Es el paso que cierra, junto con el
historial de Git, dos de los cinco requisitos obligatorios de la entrega.

Resultados tangibles:

- `core/repository.py`: capa de lectura (`get_scan`, `list_scans`,
  `get_latest_scan`, `list_assets`, `list_findings`, `diff_scans()`) —
  contrapartida de `core/persistence.py`, que solo escribe.
- Cinco endpoints reales: `POST /scans`, `GET /scans`, `GET /scans/{id}`,
  `GET /assets`, `GET /findings`. (`POST /findings/ask` queda pendiente:
  depende de la capa IA, Paso 5.)
- `api/schemas.py`: la frontera Pydantic entre las tablas y la respuesta
  pública — la API nunca serializa un modelo ORM directamente.
- Traducción de excepciones de dominio a HTTP (`InvalidTargetError` → 400,
  `UnauthorizedTargetError` → 403) mediante `exception_handler`, tal como
  anticipaba el propio docstring de `core/exceptions.py` desde el Paso 1.
- **12 pruebas automatizadas nuevas** (88 en total: 76 + 12), más una
  verificación manual end-to-end contra la API real en ejecución.
- Un defecto de concurrencia (`MissingGreenlet`) detectado por las propias
  pruebas y corregido antes de publicarse — documentado en la sección 5.
- Tres commits, hasta 22 en el repositorio.

---

## 2. Qué se ha construido

### 2.1 Componentes

| Fichero | Responsabilidad | Estado |
|---|---|---|
| `src/atalaya/core/repository.py` | Consultas de lectura sobre `Scan`/`Asset`/`Finding` | Nuevo (122 líneas) |
| `src/atalaya/api/schemas.py` | Esquemas Pydantic de petición/respuesta | Nuevo (94 líneas) |
| `src/atalaya/api/routes/scans.py` | `POST/GET /scans`, `GET /scans/{id}` | Reescrito (96 líneas) |
| `src/atalaya/api/routes/assets.py` | `GET /assets?scan_id=` | Reescrito (22 líneas) |
| `src/atalaya/api/routes/findings.py` | `GET /findings?asset_id=&scan_id=` | Reescrito |
| `src/atalaya/api/main.py` | `exception_handler` de `InvalidTargetError`/`UnauthorizedTargetError` | Ampliado |
| `tests/test_repository.py` | 7 pruebas del repositorio de lectura | Nuevo |
| `tests/test_api_scans.py` | 5 pruebas de los endpoints vía `TestClient` | Nuevo |
| `tests/conftest.py` | Fixture `client`: `TestClient` con `get_session` inyectado | Ampliado |

### 2.2 Por qué un repositorio de lectura separado

`core/persistence.py` (Paso 3) solo traduce un resultado de descubrimiento a
filas nuevas; no existía ninguna función para **leer** lo ya persistido. Sin
ella, cada endpoint habría construido su propio `select()` de SQLAlchemy, con
dos problemas: código de consulta duplicado entre `scans.py`, `assets.py` y
`findings.py`, y el riesgo de que cada uno cargara las relaciones (`Asset`,
`Finding`) de forma distinta — inconsistente e innecesariamente costoso.

`core/repository.py` centraliza seis funciones: `get_scan` y `get_latest_scan`
precargan activos y hallazgos con `selectinload` (detalle de un escaneo);
`list_scans`, `list_assets` y `list_findings` no precargan nada (listados,
donde esas relaciones no hacen falta); `diff_scans()` compara los hostnames
de dos escaneos del mismo dominio — es la función que explota el motivo por
el que el proyecto persiste escaneos en primer lugar (ver Paso 3, sección
6.4, "variabilidad del DNS").

### 2.3 Flujo de `POST /scans`

```
{"domain": "ejemplo.com", "resolve": true}
   │
   ▼
[enumerate_subdomains]   valida, autoriza y enumera (Paso 2)
   │  SubdomainScanResult
   ▼
[save_subdomain_scan]    traduce a Scan + Asset (+ Finding) (Paso 3)
   │
   ▼
session.commit()
   │
   ▼
[repository.get_scan]    recarga con selectinload (ver sección 5)
   │
   ▼
ScanDetail (schemas.py)  201 Created
```

---

## 3. Bloque de entendimiento: los conceptos

### 3.1 `response_model` y por qué la API nunca devuelve el objeto ORM

Cada ruta declara `response_model=ScanDetail` (o `AssetOut`, `FindingOut`).
FastAPI usa ese modelo Pydantic para **validar y serializar** lo que la
función de la ruta devuelve, aunque esa función devuelva directamente un
objeto `Scan` de SQLAlchemy: `schemas.py` declara `model_config =
ConfigDict(from_attributes=True)`, que le dice a Pydantic "lee los valores
como atributos de un objeto, no como claves de un diccionario".

La razón de no devolver el modelo ORM tal cual —aunque Pydantic pueda leerlo—
no es técnica, es de contrato: `Asset` tiene una columna `scan_id`, un
`__tablename__`, y mañana puede tener columnas internas que no deban salir
por la API. `schemas.py` es la frontera: define explícitamente qué campos
son públicos, independientemente de cómo evolucione el esquema de la BD.

### 3.2 `Depends()`: inyección de dependencias en FastAPI

Cada función de ruta recibe `session: AsyncSession = Depends(get_session)`.
`get_session` es un generador (`core/database.py`) que abre una sesión,
la entrega (`yield`), y la cierra cuando la petición termina. FastAPI llama
a ese generador antes de ejecutar la ruta e inyecta lo que produce.

La ventaja frente a abrir la sesión a mano dentro de cada función: la sesión
se cierra siempre, incluso si la ruta lanza una excepción a medio camino —
FastAPI gestiona el ciclo de vida del generador con un `try/finally`
implícito. Es el mismo patrón que ya usa la CLI (`async with SessionLocal()`),
adaptado a que aquí el "bloque `with`" lo abre y cierra el framework, no el
código de la ruta.

### 3.3 `exception_handler`: traducir excepciones de dominio a HTTP

`core/exceptions.py` define `InvalidTargetError` y `UnauthorizedTargetError`
desde el Paso 2, con un docstring que ya decía por qué: "permite que la capa
API traduzca cada error de dominio al código HTTP adecuado sin inspeccionar
mensajes de texto". Hasta este paso, esa traducción no existía.

```python
@app.exception_handler(UnauthorizedTargetError)
async def _unauthorized_target_handler(request, exc):
    return JSONResponse(status_code=403, content={"detail": str(exc)})
```

La alternativa —un `try/except` dentro de cada ruta que pudiera lanzar esas
excepciones— habría funcionado igual, pero habría repetido la misma
traducción en cada sitio y, más importante, habría sido fácil de olvidar en
una ruta nueva. Con el `exception_handler` registrado una vez en `main.py`,
**cualquier** ruta que deje escapar un `InvalidTargetError` obtiene un 400
automáticamente, sin tener que acordarse de capturarlo.

### 3.4 Eager loading (`selectinload`) y el problema N+1

Cuando `GET /scans/{id}` devuelve un escaneo con sus activos y los hallazgos
de cada activo, hay dos formas de traer esos datos: una consulta por cada
`Asset` para pedir sus `Finding` (el problema clásico **N+1**: una consulta
para los `N` activos, más una por cada uno para sus hallazgos), o una única
consulta adicional que trae **todos** los hallazgos de todos los activos de
una vez y los reparte en memoria. `selectinload` hace lo segundo:

```python
select(Scan).where(Scan.id == scan_id).options(
    selectinload(Scan.assets).selectinload(Asset.findings)
)
```

Con un escaneo de 61 activos (el caso real de `github.com`, Paso 2), la
diferencia es 2 consultas frente a 62.

### 3.5 Códigos de estado nuevos en esta fase

- **201 Created** — `POST /scans` no solo procesa la petición, crea un
  recurso nuevo (un `Scan`). REST distingue esto de un `200 OK` genérico.
- **400 Bad Request** — el dominio no tiene forma de dominio válido.
- **403 Forbidden** — el dominio es válido pero no está en `SCAN_ALLOWLIST`.
- **404 Not Found** — se pide un `scan_id` que no existe.

---

## 4. Decisiones de diseño

| Decisión | Justificación |
|---|---|
| `core/repository.py` separado de `core/persistence.py` | Mismo principio que separó modelos de motor en el Paso 3: la lectura no debe mezclarse con la escritura, y cada endpoint no debe construir su propio `select()` |
| `list_scans`/`list_assets`/`list_findings` no precargan relaciones; `get_scan`/`get_latest_scan` sí | Un listado no necesita el detalle completo de cada fila; cargarlo sería trabajo desperdiciado en la vista que menos lo necesita |
| `api/schemas.py` como frontera Pydantic | El contrato público de la API no debe acoplarse a la forma de las tablas; ver 3.1 |
| `exception_handler` centralizado en `main.py`, no `try/except` por ruta | Una única traducción de excepción → HTTP que cubre toda ruta presente y futura, sin depender de que cada una recuerde capturarla |
| `POST /scans` recarga el escaneo tras persistir, en vez de devolver el objeto en memoria | Ver sección 5: el objeto en memoria no tiene todas las relaciones cargadas de forma uniforme |
| `enumerate_subdomains` valida y autoriza internamente; la ruta no repite la comprobación | Ya lo hacía la CLI (Paso 2); duplicarlo en la ruta sería la misma lógica en dos sitios que podrían divergir |

---

## 5. Corrección detectada durante el desarrollo: `MissingGreenlet`

Esta sección documenta un defecto encontrado por las propias pruebas antes
de publicarse, siguiendo el mismo criterio de trazabilidad que las memorias
de los Pasos 2 y 3.

### 5.1 Síntoma

La primera versión de `create_scan` devolvía directamente el objeto `scan`
que produce `save_subdomain_scan()`, tras el `commit()`:

```python
scan = await save_subdomain_scan(session, result)
await session.commit()
return scan
```

La primera prueba que ejercitó un escaneo con **varios** activos, donde solo
uno de ellos genera un `Finding` (el caso `leaks_internal_addressing`),
falló con:

```
MissingGreenlet: greenlet_spawn has not been called; can't call
await_only() here. Was IO attempted in an unexpected place?
```

### 5.2 Causa

`save_subdomain_scan()` construye cada `Asset` en memoria y, **solo si**
`leaks_internal_addressing` es verdadero, le añade un `Finding` con
`asset.findings.append(...)`. Ese `.append()` es lo que SQLAlchemy considera
"la colección `findings` está cargada" para ese `Asset` concreto. Para los
demás —los que nunca recibieron un `.append()`— la colección `findings`
sigue sin cargar, aunque el objeto ya esté en memoria.

Al serializar la respuesta, Pydantic recorre `scan.assets[i].findings` para
cada activo. Para el que sí tiene un finding, es una lectura en memoria
inmediata. Para los demás, SQLAlchemy intenta un *lazy load*: lanzar una
consulta a la base de datos en ese preciso instante. En una sesión
**asíncrona**, eso solo es posible dentro de un contexto `await` gestionado
por SQLAlchemy (`greenlet_spawn`); la serialización de FastAPI ocurre fuera
de ese contexto, de ahí el error.

### 5.3 Corrección

```python
scan = await save_subdomain_scan(session, result)
await session.commit()
loaded = await repository.get_scan(session, scan.id)
return loaded
```

Se sustituye el objeto en memoria por una recarga explícita vía
`repository.get_scan()`, que usa `selectinload` (sección 3.4) para cargar
**todas** las colecciones `findings` de forma uniforme, tengan o no
elementos. El coste es una consulta adicional; la alternativa —dejar el
objeto en memoria tal cual— es incorrecta, no más barata: solo parecía
funcionar en las primeras pruebas porque su escaneo de ejemplo tenía un único
activo, precisamente el que sí recibía el `.append()`.

### 5.4 Por qué importa más allá del error concreto

El defecto no era visible con un solo activo por escaneo, y `github.com`
(Paso 2) tiene 61. Sin la prueba que construye un escaneo con activos
heterogéneos —algunos con hallazgo, otros sin él—, esto habría llegado a
producción y solo se habría manifestado con datos reales, en el momento
menos oportuno para depurarlo.

---

## 6. Validación

### 6.1 Pruebas automatizadas

**12 pruebas nuevas, 88 en total (76 + 12), todas en verde:**

| Fichero | Nº | Qué cubre |
|---|---|---|
| `tests/test_repository.py` | 7 | `get_scan`, `list_scans` (orden y filtro por dominio), `get_latest_scan` (ignora `RUNNING`), `list_assets`/`list_findings` (filtros), `diff_scans` |
| `tests/test_api_scans.py` | 5 | `POST /scans` (éxito, dominio inválido → 400, no autorizado → 403), `GET /scans`/`GET /scans/{id}` (incluye 404), filtrado de `/assets` y `/findings` por `scan_id` |

`enumerate_subdomains` se sustituye por un doble en las pruebas de la API
(`monkeypatch`), igual que en `test_subdomains.py`: estas pruebas verifican
el cableado HTTP → descubrimiento → persistencia, no la enumeración en sí,
que ya tiene su propia suite.

### 6.2 Verificación end-to-end sobre la API real en ejecución

A diferencia de `TestClient` (que ejercita la aplicación ASGI en el mismo
proceso), se levantó `uvicorn atalaya.api.main:app` como proceso real,
contra una base de datos sqlite nueva con las migraciones aplicadas, y se
lanzaron peticiones HTTP reales con `curl` contra `scanme.nmap.org`:

```
POST /scans   {"domain": "scanme.nmap.org"}     -> 201 Created
GET  /scans                                      -> 200 OK  (1 escaneo)
GET  /scans/1                                    -> 200 OK  (con su Asset)
GET  /assets?scan_id=1                           -> 200 OK
GET  /scans/999                                  -> 404 Not Found
```

Respuesta real de `POST /scans`:

```json
{"id":1,"domain":"scanme.nmap.org","status":"completed",
 "started_at":"2026-09-21T13:48:43.066039Z",
 "finished_at":"2026-09-21T13:48:48.689054Z","errors":[],
 "assets":[{"id":1,"hostname":"scanme.nmap.org","status":"active",
 "ip_addresses":["2600:3c01::f03c:91ff:fe18:bb2f","45.33.32.156"],
 "sources":["crt.sh","dns"],"is_active":true,
 "leaks_internal_addressing":false,"open_ports":[],"findings":[]}]}
```

Esto confirma, sobre infraestructura real y un proceso HTTP real (no una
llamada en el mismo intérprete), tanto la corrección de la sección 5
(`findings: []` se serializa sin error para un activo sin hallazgos) como el
flujo completo descubrimiento → persistencia → API.

---

## 7. Consideraciones legales y éticas

Esta fase no amplía la superficie de exposición sobre terceros: `POST
/scans` ejecuta exactamente la misma enumeración pasiva del Paso 2, ahora
accesible por HTTP en lugar de solo por CLI, y sigue pasando por
`ensure_authorized()` sin excepción. La única superficie nueva es la propia
API: sigue sin autenticación (limitación ya declarada desde el Paso 1),
asumible mientras el despliegue sea local.

---

## 8. Limitaciones actuales

- **`POST /findings/ask` sigue en 501.** Depende de la capa IA (Paso 5);
  simularlo con una respuesta fija habría sido peor que declararlo pendiente.
- **Sin paginación real en los listados.** `list_scans` acepta un `limit`
  (por defecto 50) pero no un `offset`; suficiente para el volumen actual,
  insuficiente si el histórico de escaneos crece mucho.
- **`PUT`/`DELETE` no existen.** No hay forma de borrar un escaneo por API
  (sí es posible a nivel de BD, con cascada, ver Paso 3). No se ha
  identificado un caso de uso que lo requiera todavía.
- **Sin autenticación**, limitación ya declarada y sin cambios en esta fase.

---

## 9. Bloque de defensa: preguntas previsibles

### Sobre la API

**¿Por qué `POST /scans` devuelve 201 y no 200?**
Porque crea un recurso nuevo. REST distingue `200 OK` (petición procesada,
sin más) de `201 Created` (además, algo nuevo existe ahora con una
identidad propia — en este caso, un `Scan` con su `id`).

**¿Qué pasa si pido un `scan_id` que no existe?**
`repository.get_scan()` devuelve `None`, y la ruta lo traduce a `404 Not
Found` con un mensaje explícito. No hay diferencia observable entre "no
existe" y "existía y se borró", que es el comportamiento estándar de REST.

**¿Por qué los esquemas de respuesta no son directamente los modelos de
SQLAlchemy?**
Porque acoplarían el contrato público de la API a la forma interna de las
tablas. Si mañana se añade una columna interna a `Asset`, no debe aparecer
en la respuesta de la API sin que sea una decisión explícita en
`schemas.py`.

### Sobre el repositorio de lectura

**¿Por qué no reutilizar `core/persistence.py` para las lecturas?**
Porque mezclaría dos responsabilidades distintas — escribir y leer — en el
mismo fichero, y porque `persistence.py` no hace `commit()` a propósito (el
llamador decide la transacción); una función de lectura no tiene ese mismo
problema y complicaría el fichero sin necesidad.

**¿Qué es `selectinload` y por qué no cargar todo siempre?**
Es la instrucción que le dice a SQLAlchemy que traiga una relación (por
ejemplo, los `Finding` de cada `Asset`) en una consulta adicional en vez de
una por fila. No se usa en los listados (`list_scans`) porque esas vistas no
necesitan el detalle completo; cargarlo ahí sería trabajo desperdiciado.

### Sobre el defecto de `MissingGreenlet`

**¿Qué lo causó exactamente?**
Que una colección de SQLAlchemy (`asset.findings`) solo se considera
"cargada" para un objeto si se ha tocado explícitamente con un `.append()`
o una consulta. Los activos sin hallazgo nunca recibían ese `.append()`, y
al serializar la respuesta, SQLAlchemy intentaba una consulta perezosa fuera
del contexto asíncrono que la permite.

**¿Por qué no apareció en las primeras pruebas manuales?**
Porque el primer escaneo de prueba tenía un único activo, precisamente el
que sí generaba un `Finding`. El defecto solo se manifestó al escribir una
prueba con varios activos heterogéneos — lo que demuestra el valor de
probar casos mixtos y no solo el camino feliz más simple.

**¿Cómo se corrigió, y por qué esa solución y no otra?**
Recargando el escaneo con `repository.get_scan()` tras el `commit()`, que
usa `selectinload` para cargar todas las colecciones de forma uniforme. La
alternativa —forzar la carga navegando el objeto en memoria antes de
devolverlo— habría sido más frágil: dependería de tocar cada relación a
mano en el sitio correcto, en vez de delegar en la misma función de lectura
que ya usan el resto de rutas.

### Preguntas de comprensión

**¿Qué hace `Depends()` en FastAPI?**
Declara una dependencia que el framework resuelve antes de ejecutar la
ruta. `Depends(get_session)` entrega una sesión de base de datos por
petición y garantiza que se cierre al terminar, sin que cada ruta tenga que
abrir y cerrar la suya a mano.

**¿Qué es el problema N+1 y cómo se evita aquí?**
Es traer una lista de `N` filas y luego lanzar una consulta adicional por
cada una para sus datos relacionados: `N+1` consultas en total. Se evita con
`selectinload`, que trae la relación de todas las filas en una sola consulta
adicional.

---

## 10. Estado de los requisitos de la práctica

| Requisito | Estado tras el Paso 4 |
|---|---|
| **API o webhook** | ✅ `scans`/`assets`/`findings` reales; `/findings/ask` pendiente de la capa IA |
| **GitHub con historial** | ✅ 22 commits publicados (3 de esta fase) |
| **Base de datos** | 🔨 Sin cambios en esta fase; solo persiste subdominios (Paso 3) |
| **Aplicación web** | 🔨 Sin cambios en esta fase |
| **Reporte con portada** | ⬜ Paso 7 |

---

## 11. Próximos pasos

| Fase | Contenido |
|---|---|
| **Paso 5** | Capa de IA: `LLMProvider`, triaje de hallazgos, consulta NL — activa `/findings/ask` |
| **Paso 2 (resto)** | Puertos, cabeceras HTTP y TLS |
| **Paso 6** | Dashboard completo, consumiendo esta API |
| **Paso 7** | Generador de informes con portada |

---

## 12. Conclusión del Paso 4

El Paso 4 entrega una API funcionalmente completa para lo que hoy persiste
el sistema: cinco endpoints reales, probados con dobles y verificados contra
un proceso HTTP real, más un repositorio de lectura que evita que la lógica
de consulta se disperse por cada ruta.

La aportación que más vale la pena subrayar no es el volumen de endpoints,
sino el defecto de la sección 5: un fallo de concurrencia asíncrona que solo
se manifestaba con datos heterogéneos, detectado por una prueba antes de
llegar a producción. Es el mismo patrón de trabajo que ya dejaron los Pasos
2 y 3 — verificar sobre casos reales y no dar nada por bueno sin comprobarlo
— aplicado ahora a la capa de concurrencia de la API.
