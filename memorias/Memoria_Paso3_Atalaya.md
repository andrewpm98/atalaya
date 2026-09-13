# Memoria técnica — Paso 3: Base de datos y persistencia

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 3 de 7 — Modelos de base de datos y persistencia de escaneos
**Estado:** Completado y verificado sobre datos reales

---

## 1. Resumen ejecutivo

El Paso 3 cierra el requisito obligatorio de **base de datos**: hasta ahora
existía el motor (Paso 1) y un módulo de descubrimiento que producía
resultados en memoria y los perdía al terminar (Paso 2). Esta fase define el
modelo relacional, lo versiona con migraciones, y conecta el módulo de
subdominios para que cada escaneo quede persistido.

Resultados tangibles:

- Tres entidades ORM (`Scan`, `Asset`, `Finding`) con sus relaciones,
  usando SQLAlchemy 2.0 en modo declarativo tipado.
- Migraciones gestionadas con **Alembic** (motor asíncrono), generadas por
  `--autogenerate` a partir de los modelos y verificadas aplicándolas.
- `save_subdomain_scan()`: traduce un `SubdomainScanResult` (Paso 2) a filas
  de `Scan`/`Asset`/`Finding`, sin reinterpretar sus campos.
- Un flag `--save` en la CLI que demuestra el camino completo
  descubrimiento → base de datos sin esperar a la API (Paso 4).
- **76 pruebas automatizadas** (70 previas + 6 nuevas), todas deterministas.
- Verificación end-to-end contra una base de datos real (no solo dobles de
  prueba): `atalaya subdomains scanme.nmap.org --save`.
- Cinco commits adicionales, hasta 16 en el repositorio antes de esta memoria.

Se adelantó este paso respecto al resto del descubrimiento (puertos,
cabeceras, TLS), tal como se venía valorando desde el Paso 2: así esos
módulos nacerán ya con destino de persistencia, en lugar de requerir una
adaptación posterior.

---

## 2. Qué se ha construido

### 2.1 Componentes

| Fichero | Responsabilidad | Estado |
|---|---|---|
| `src/atalaya/core/models.py` | Entidades ORM: `Scan`, `Asset`, `Finding` | Nuevo |
| `src/atalaya/core/persistence.py` | `save_subdomain_scan()` — descubrimiento → BD | Nuevo |
| `src/atalaya/core/database.py` | Engine, `Base`, `get_session` | Docstring actualizado |
| `migrations/env.py`, `alembic.ini` | Configuración de Alembic (async) | Nuevo |
| `migrations/versions/50a2c71b981a_*.py` | Migración inicial (3 tablas + índices) | Nuevo |
| `src/atalaya/cli.py` | Flag `--save` en `subdomains` | Ampliado |
| `Makefile` | `make migrate`, `make revision MSG="..."` | Ampliado |
| `tests/conftest.py` | Fixture de sesión BD (sqlite en memoria) | Nuevo |
| `tests/test_models.py` | 3 pruebas de relaciones y cascada | Nuevo |
| `tests/test_persistence.py` | 3 pruebas de mapeo descubrimiento → BD | Nuevo |

### 2.2 Modelo de datos

```
Scan
 ├─ id, domain, status (running|completed|failed)
 ├─ started_at, finished_at
 └─ errors (JSON: incidencias no fatales, p. ej. "crt.sh caído")
     │
     │ 1─N
     ▼
Asset
 ├─ id, scan_id (FK, cascade)
 ├─ hostname, status (active|unroutable|nxdomain|no_answer|timeout|error)
 ├─ ip_addresses (JSON), sources (JSON)
 ├─ is_active, leaks_internal_addressing
 └─ open_ports (JSON) — vacío hasta que exista discovery/ports.py
     │
     │ 1─N
     ▼
Finding
 ├─ id, asset_id (FK, cascade)
 ├─ finding_type, evidence
 ├─ severity (unknown|low|medium|high|critical)
 └─ impact, remediation — los rellena la capa IA (Paso 5)
```

### 2.3 Flujo de persistencia

```
SubdomainScanResult (en memoria, Paso 2)
   │
   ▼
[save_subdomain_scan]
   │  por cada SubdomainRecord:
   │    - crea un Asset con sus campos (copia directa, no reinterpretación)
   │    - si leaks_internal_addressing → añade un Finding al Asset
   │
   ▼
session.flush()   (asigna IDs; el commit lo hace quien llama)
   │
   ▼
Scan con sus Asset y Finding, listo para comparar con el siguiente escaneo
```

---

## 3. Bloque de entendimiento: los conceptos

### 3.1 Por qué ORM tipado (SQLAlchemy 2.0) y no SQL a mano

SQLAlchemy 2.0 permite declarar cada columna como una anotación de tipo
Python (`Mapped[str]`, `Mapped[int | None]`), y el propio ORM infiere el
tipo de columna SQL correspondiente. La ventaja no es solo comodidad: un
error de tipo (asignar un `int` donde se espera una lista de IPs) lo detecta
el analizador estático o el propio ORM al construir la consulta, no una
prueba en producción. Y como ya se explicó en la memoria del Paso 1, evita
por completo la inyección SQL: no hay una sola cadena de consulta construida
a mano en todo el proyecto.

### 3.2 Por qué Alembic y no `Base.metadata.create_all()`

`create_all()` crea las tablas que faltan, pero no sabe **modificar** una
tabla existente: si más adelante se añade una columna a `Asset` (por
ejemplo, cuando `ports.py` empiece a rellenar `open_ports` con datos reales
en vez de una lista vacía y necesite una columna adicional), `create_all()`
no altera nada y el esquema en producción queda desincronizado del código.

Alembic resuelve esto con **migraciones versionadas**: cada cambio al modelo
se traduce en un script con un `upgrade()` y un `downgrade()` explícitos,
encadenados unos con otros. Es el mecanismo estándar en cualquier proyecto
con SQLAlchemy que vaya a evolucionar su esquema, y es coherente con el
principio de que el historial de cambios importa tanto como el estado final
— el mismo criterio que ya se aplica al historial de commits.

### 3.3 `--autogenerate`: qué hace y qué no

Alembic puede **comparar** el estado de `Base.metadata` (lo que dicen los
modelos Python) contra el esquema real de la base de datos, y generar el
script de migración por diferencia. Es lo que se usó para producir
`50a2c71b981a_modelos_iniciales_scans_assets_findings.py`: detectó las tres
tablas nuevas y sus índices porque no existía ninguna tabla previa.

Lo que **no** hace: no adivina la intención de un cambio ambiguo (por
ejemplo, si una columna se renombró o se borró y se creó otra con datos
distintos, generará un `drop` + `add` en vez de un `rename`). Por eso cada
migración autogenerada se revisa antes de aplicarla — en este caso se
comprobó leyendo el script generado y aplicándolo contra un sqlite de
desarrollo antes de darlo por bueno (sección 6).

### 3.4 Una sola fuente de verdad para la URL de conexión

`alembic.ini` trae por defecto una plantilla `sqlalchemy.url = driver://...`
pensada para escribir la cadena de conexión directamente en ese fichero. Se
descartó deliberadamente: la URL real ya vive en `.env` vía
`atalaya.config.settings.database_url`, y duplicarla en `alembic.ini`
crearía dos sitios que pueden divergir — exactamente el tipo de
inconsistencia que un cambio de credenciales en producción dejaría
desincronizada sin que nadie lo note hasta que una migración falle contra la
base de datos equivocada.

En su lugar, `migrations/env.py` importa `settings` y hace
`config.set_main_option("sqlalchemy.url", settings.database_url)` antes de
ejecutar cualquier migración. La configuración de la aplicación manda sobre
la de Alembic, no al revés.

### 3.5 Por qué las relaciones no reutilizan los enums de `discovery`

`Asset.status` guarda `"active"`, `"unroutable"`, etc. — los mismos valores
que produce `ResolutionStatus` en `discovery/models.py` — pero como cadena,
no importando ese enum directamente en `core/models.py`. Es una decisión
deliberada de acoplamiento: la capa de persistencia no depende del módulo de
descubrimiento que hoy la alimenta (subdominios), porque mañana la
alimentarán también puertos, cabeceras y TLS, cada uno con su propio
vocabulario de estados. Acoplar el esquema de base de datos al enum de un
módulo concreto habría atado el modelo de datos a una sola fuente.

La contrapartida, documentada en el propio código: la base de datos no
valida a nivel de tipo que `status` sea uno de los valores esperados — esa
garantía la da el enum de origen antes de llegar a `persistence.py`.

### 3.6 `values_callable`: un detalle de SQLAlchemy que habría corrompido los datos

`ScanStatus` y `FindingSeverity` sí son enums propios del ORM (no representan
un vocabulario ajeno, son el ciclo de vida del propio `Scan`/`Finding`). Al
mapearlos con `sa.Enum(ScanStatus)`, SQLAlchemy por defecto **guarda el
nombre del miembro** (`RUNNING`), no su valor (`running`). Habría producido
una inconsistencia silenciosa: el resto del proyecto usa minúsculas en todos
los campos de estado (`ResolutionStatus.ACTIVE.value == "active"`), y la
tabla `scans` habría guardado `"RUNNING"` en mayúsculas sin que ninguna
prueba lo detectara hasta que algo comparase cadenas entre capas.

Se corrigió pasando `values_callable=lambda enum_cls: [m.value for m in
enum_cls]` a cada `sa.Enum(...)`, que fuerza a guardar `.value`. Se
verificó leyendo directamente el SQL generado por la migración
autogenerada (sección 6): la columna queda como
`sa.Enum('running', 'completed', 'failed', name='scanstatus')`, en
minúsculas.

### 3.7 Cascada de borrado: por qué `Asset`/`Finding` no pueden quedar huérfanos

Las relaciones se declaran con `cascade="all, delete-orphan"`. Significa que
borrar un `Scan` borra en cascada sus `Asset`, y borrar un `Asset` borra sus
`Finding`. La alternativa — dejar que el borrado falle por una restricción
de clave foránea, o peor, permitir `Asset` sin `Scan` — no tiene sentido de
negocio: un activo solo existe en el contexto de un escaneo que lo descubrió.
Se verifica explícitamente en `test_borrar_scan_arrastra_assets_y_findings`.

---

## 4. Decisiones de diseño

| Decisión | Justificación |
|---|---|
| Modelos en `core/models.py`, no en `core/database.py` | El stub original (Paso 1) preveía los modelos ahí; separarlos evita acoplar el ciclo de vida del engine a qué entidades existen. Documentado como desviación explícita en `CLAUDE.md` |
| Persistencia en `core/persistence.py`, no en `discovery/subdomains.py` | El módulo de descubrimiento no debe saber que existe una base de datos; la traducción resultado→filas es responsabilidad de la capa de persistencia |
| `Asset.status`/`sources` como `str`/`JSON`, no reutilizando los enums de `discovery` | Evita acoplar el esquema de datos a un único módulo de descubrimiento cuando habrá varios (puertos, cabeceras, TLS) |
| `values_callable` en los enums propios del ORM | Sin él, SQLAlchemy guarda `.name` (mayúsculas) en vez de `.value`, inconsistente con el resto del proyecto |
| `open_ports` ya presente en `Asset`, vacío | Es parte del modelo ya fijado en `docs/ARQUITECTURA.md` desde el Paso 1; añadirlo ahora evita una migración adicional cuando `ports.py` exista |
| `save_subdomain_scan()` no hace commit | La transacción queda a cargo de quien llama, para poder combinarla con otras escrituras en la misma unidad de trabajo (relevante en el Paso 4, cuando la API orqueste descubrimiento + persistencia) |
| Alembic con motor asíncrono | Coherencia con el resto del proyecto: todo el código de acceso a datos es `async` |
| URL de conexión desde `settings`, no en `alembic.ini` | Una sola fuente de verdad; evita que las credenciales de BD queden en dos sitios que pueden divergir |
| `leaks_internal_addressing` genera un `Finding`, no solo un campo en `Asset` | Ya se estableció en el Paso 2 que es un hallazgo por derecho propio, no un dato de inventario; la persistencia respeta esa distinción |
| Tests con sqlite en memoria + `StaticPool` | El motor async por defecto abre una conexión nueva por operación; sin `StaticPool`, cada conexión vería una base de datos `:memory:` distinta y las tablas creadas en el `setup` desaparecerían |

---

## 5. Corrección previa, fuera de esta fase pero relevante para la trazabilidad

Antes de empezar el Paso 3 se hizo una revisión completa del estado del
repositorio (código, tests, lint) para confirmar que lo documentado en
`CLAUDE.md` era exacto. Se encontró un defecto menor en
`core/authorization.py` (Paso 2): `is_authorized()` devolvía `True` sin
validar el formato del dominio cuando `SCAN_ALLOWLIST` estaba vacía —
el caso por defecto. No era explotable con el código actual (el único
llamador, `ensure_authorized()`, ya normalizaba antes de invocarla), pero
quedaba como una trampa latente para cualquier código futuro que llamara a
`is_authorized()` de forma aislada, algo previsible en el Paso 4 al decidir
si un endpoint devuelve 403 sin lanzar excepción.

Se corrigió moviendo `normalize_domain()` antes de la comprobación de la
allowlist (commit `312a9d5`, previo a los commits de este Paso 3). Se
documenta aquí porque es el mismo principio que ya se aplicó en el Paso 2
con el defecto de `0.0.0.0`: un problema detectado por revisión antes de que
se propagara, no por un fallo en producción.

---

## 6. Validación

### 6.1 Pruebas automatizadas

**76 pruebas, todas en verde** (70 previas + 6 nuevas de esta fase):

| Fichero | Nº | Qué cubre |
|---|---|---|
| `tests/test_models.py` | 3 | Relación Scan-Asset-Finding, borrado en cascada, valores por defecto |
| `tests/test_persistence.py` | 3 | Mapeo de campos, generación de `Finding` por direccionamiento interno, estado `running` si el escaneo no ha terminado |

Ninguna depende de Postgres ni de `DATABASE_URL`: usan un motor sqlite en
memoria propio (`tests/conftest.py`), creado y destruido por test. Es el
mismo criterio de determinismo ya aplicado en el Paso 2: un fallo en la
suite debe señalar siempre un problema del código.

### 6.2 Migración generada y aplicada

```bash
alembic revision --autogenerate -m "modelos iniciales: scans, assets, findings"
# Detected added table 'scans' / 'assets' / 'findings' + sus índices

alembic upgrade head
# Running upgrade  -> 50a2c71b981a, modelos iniciales: scans, assets, findings
```

Se verificó inspeccionando el sqlite resultante con `sqlite3` directamente:
las tres tablas (`scans`, `assets`, `findings`) más `alembic_version`
existen con el esquema esperado.

### 6.3 Verificación end-to-end sobre datos reales

Se ejecutó `atalaya subdomains scanme.nmap.org --save` contra la base de
datos sqlite de desarrollo (no un doble de prueba). El entorno de ejecución
no tenía salida a `crt.sh` (403/502 en los tres reintentos), lo que en la
práctica ejercitó dos comportamientos a la vez:

1. **Degradación controlada** (Paso 2): el escaneo no abortó; registró la
   incidencia en `errors` y continuó con el dominio raíz.
2. **Persistencia** (Paso 3): el resultado parcial se guardó igualmente.

```
WARNING crt.sh intento 1/3: crt.sh respondió 404
WARNING crt.sh intento 2/3: crt.sh respondió 502
WARNING crt.sh intento 3/3: crt.sh respondió 502
[BD] Escaneo #1 guardado (1 activos).
```

Inspección directa de la base de datos:

```
scans:  (1, 'scanme.nmap.org', 'completed', '2026-09-13 14:33:14...',
         '2026-09-13 14:33:30...', '["crt.sh no disponible tras 3 intentos: ..."]')
assets: (1, 1, 'scanme.nmap.org', 'active', '["45.33.32.156"]', 1)
```

Esto es más representativo que una prueba con dobles: confirma que la
incidencia de una fuente externa caída se conserva en el campo `errors` del
propio registro persistido, no solo en el log de ejecución — que es
justamente el dato que en el Paso 5 permitirá a la IA saber que un escaneo
tiene cobertura parcial antes de razonar sobre sus hallazgos.

### 6.4 Lint

`ruff check` limpio en todos los ficheros de esta fase. Se dejó
deliberadamente sin aplicar la sugerencia `UP017` (`datetime.UTC` en vez de
`datetime.timezone.utc`) en los ficheros nuevos, por consistencia con el
estilo ya establecido en `discovery/subdomains.py`: introducir un alias
distinto en código nuevo mientras el resto del proyecto usa el otro habría
dejado un estilo mixto sin necesidad.

---

## 7. Consideraciones legales y éticas

Esta fase no añade superficie de exposición nueva sobre terceros — no se
envía tráfico adicional a ningún objetivo, solo se guarda lo que el Paso 2
ya obtenía. La consideración relevante aquí es otra: **la base de datos pasa
a acumular un historial de escaneos**, lo cual tiene dos implicaciones:

- Persistir resultados de reconocimiento sobre un dominio de terceros, aunque
  sea información pública, implica retenerla más allá de la ejecución
  puntual. La salvaguarda `SCAN_ALLOWLIST` (Paso 2) sigue siendo el control
  que decide qué dominios pueden llegar a generar ese historial.
- Ningún dato sensible propio del atacante ni credenciales se guardan en
  estas tablas: solo hostnames, IPs y su clasificación de alcance, que ya
  eran públicos antes de la persistencia.

---

## 8. Limitaciones actuales

- **Solo se persisten subdominios.** `save_subdomain_scan()` es la única
  función de traducción; puertos, cabeceras y TLS se conectarán cuando esos
  módulos existan (resto del Paso 2).
- **Sin capa de comparación entre escaneos.** El modelo permite guardar
  varios `Scan` del mismo dominio, pero no hay todavía una consulta que
  compare dos escaneos y señale qué cambió — es precisamente el caso de uso
  que motivó adelantar esta fase, y queda para cuando la API (Paso 4) o el
  dashboard (Paso 6) lo necesiten.
- **`open_ports` vacío.** La columna existe para no requerir otra migración,
  pero no se rellena hasta que `discovery/ports.py` esté implementado.
- **Sin autenticación ni control de acceso a nivel de fila.** Coherente con
  la limitación ya declarada para la API (Paso 1): asumible en local,
  pendiente si se despliega con IP pública.
- **Migraciones probadas solo contra sqlite.** El motor de producción es
  PostgreSQL (`docker-compose.yml`); la migración usa tipos estándar de
  SQLAlchemy (`JSON`, `Enum`, `Text`) compatibles con ambos motores, pero no
  se ha ejecutado aún contra un Postgres real — pendiente de validar la
  primera vez que se levante el stack completo con Docker.

---

## 9. Bloque de defensa: preguntas previsibles

### Sobre el modelo de datos

**¿Por qué `Asset 1─N Finding` y no `Scan 1─N Finding` directamente?**
Porque un hallazgo siempre es sobre un activo concreto (un host con
direccionamiento interno filtrado, más adelante un puerto de gestión
abierto o un certificado caducado). Atarlo al `Scan` en vez de al `Asset`
perdería esa granularidad: para saber a qué host pertenece el hallazgo
habría que guardarlo también ahí, duplicando el dato.

**¿Qué pasa si se borra un `Scan`?**
Se borran en cascada sus `Asset` y los `Finding` de esos `Asset`
(`cascade="all, delete-orphan"`). Verificado con un test explícito. Es la
semántica correcta: un activo no tiene sentido fuera del escaneo que lo
descubrió.

**¿Por qué `errors` es una columna JSON y no una tabla aparte?**
Porque es una lista corta de incidencias no fatales (típicamente 0 o 1
elemento: "crt.sh no disponible"), no una entidad con identidad propia que
necesite consultarse de forma independiente. Una tabla aparte añadiría una
relación sin aportar capacidad de consulta que se vaya a usar.

### Sobre Alembic

**¿Por qué no bastaba con `Base.metadata.create_all()` en el arranque de la API?**
Porque no sabe modificar un esquema existente, solo crear lo que falta. El
día que se añada una columna a un modelo, `create_all()` no la añadiría a
una base de datos que ya tiene la tabla creada, y el esquema real quedaría
desincronizado del código sin ningún aviso.

**¿Qué hace `--autogenerate` exactamente?**
Compara `Base.metadata` (lo que describen los modelos Python) contra el
esquema real de la base de datos conectada, y genera un script con las
diferencias. No es infalible: un cambio ambiguo (renombrar una columna) lo
interpreta como borrar una y crear otra. Por eso toda migración autogenerada
se revisa antes de aplicarse.

**¿De dónde saca Alembic la cadena de conexión?**
De `atalaya.config.settings.database_url`, inyectada en `migrations/env.py`
antes de ejecutar cualquier migración — no de `alembic.ini`, que llegó a
traer una plantilla de ejemplo (`driver://user:pass@localhost/dbname`) sin
tocar. Mantener una sola fuente de verdad evita que una URL cambiada en
`.env` deje una copia obsoleta en otro fichero.

### Sobre la persistencia

**¿Por qué `save_subdomain_scan()` no hace `commit()`?**
Para no decidir por quien la llama cuándo cierra la transacción. En el
Paso 4, un endpoint podría necesitar persistir un escaneo y, en la misma
transacción, actualizar otro registro (por ejemplo, marcar el escaneo
anterior como superado); si la función hiciera su propio commit, esa
composición no sería posible sin una segunda transacción.

**¿Por qué `Asset.status` no usa el mismo enum `ResolutionStatus` de
`discovery/models.py`?**
Para no acoplar el esquema de base de datos a un solo módulo de
descubrimiento. Cuando `ports.py`, `headers.py` y `tls.py` empiecen a
producir hallazgos, cada uno tendrá su propio vocabulario de estados; atar
la tabla `assets` al enum de subdominios habría exigido rehacer la columna
más adelante.

**¿Se verificó esto contra una base de datos real, o solo con mocks?**
Ambas cosas. Las 76 pruebas automatizadas usan sqlite en memoria para ser
deterministas y rápidas, pero además se ejecutó manualmente
`atalaya subdomains scanme.nmap.org --save` contra un sqlite de desarrollo
real y se inspeccionaron las filas resultantes con `sqlite3` directamente
(sección 6.3), incluyendo un caso con una fuente externa caída de verdad.

### Preguntas de comprensión

**¿Qué es una migración de base de datos?**
Un script versionado que describe cómo pasar el esquema de una versión a la
siguiente (`upgrade`) y cómo deshacerlo (`downgrade`). El conjunto de
migraciones aplicadas queda registrado en una tabla propia
(`alembic_version`), de modo que cualquier entorno sepa en qué versión del
esquema está y qué migraciones le faltan por aplicar.

**¿Por qué `cascade="all, delete-orphan"` y no simplemente una clave foránea?**
Una clave foránea por sí sola solo garantiza integridad referencial (no
puede existir un `Asset` con un `scan_id` que no exista); no decide qué pasa
al borrar el `Scan`. `cascade` es la instrucción explícita de qué hacer con
los hijos cuando el padre desaparece — en este caso, borrarlos con él,
porque no tienen sentido de forma aislada.

---

## 10. Estado de los requisitos de la práctica

| Requisito | Estado tras el Paso 3 |
|---|---|
| **Base de datos** | 🔨 Modelos y migraciones completos; solo persiste subdominios |
| **GitHub con historial** | ✅ 16 commits publicados (5 de esta fase) |
| **API o webhook** | 🔨 Sin cambios en esta fase; consumo de crt.sh ya implementado (Paso 2) |
| **Aplicación web** | 🔨 Sin cambios en esta fase |
| **Reporte con portada** | ⬜ Paso 7 |

---

## 11. Próximos pasos

| Fase | Contenido |
|---|---|
| **Paso 2 (resto)** | Puertos, cabeceras HTTP y TLS — cada uno con su propia función `save_*` en `core/persistence.py` |
| **Paso 4** | Endpoints REST completos: `POST /scans` orquesta descubrimiento + persistencia en una transacción |
| **Paso 5** | Capa de IA: triaje sobre los `Finding` ya persistidos |
| **Paso 6** | Dashboard completo |
| **Paso 7** | Generador de informes con portada |

---

## 12. Conclusión del Paso 3

El Paso 3 entrega el modelo de datos completo y verificado, no solo
diseñado: migraciones generadas y aplicadas, persistencia probada con datos
reales y no únicamente con dobles, y una decisión de acoplamiento (los
estados de `Asset` como cadenas, no como el enum de un módulo concreto de
descubrimiento) que anticipa los tres módulos de descubrimiento aún
pendientes sin tener que rehacer el esquema cuando lleguen.

Más allá del código, esta fase deja dos aportaciones que conviene destacar:

1. **Una fuente de verdad única para la configuración de conexión**, tanto
   en la aplicación como en Alembic, evitando la clase de desincronización
   que un cambio de credenciales en producción podría dejar pasar
   desapercibida.
2. **Verificación end-to-end sobre una base de datos real**, no solo sobre
   dobles de prueba, que además confirmó que la degradación controlada del
   Paso 2 y la persistencia de este Paso 3 conviven correctamente: una
   fuente externa caída se refleja en el propio registro persistido, no
   solo en el log de ejecución.
