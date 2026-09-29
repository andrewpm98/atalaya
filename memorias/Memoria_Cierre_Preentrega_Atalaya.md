# Memoria técnica — Cierre pre-entrega: bloqueantes (P0) y brechas de producto (P1)

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Cierre previo a la entrega (27–29/09/2026), posterior a
los 7 pasos de la hoja de ruta y a las ampliaciones de agentes de IA, diseño
visual y robustez. No añade fases nuevas: busca que lo ya construido funcione
**donde se va a evaluar** (PostgreSQL, Docker, una máquina sin red el día de
la defensa) y cierra las brechas de producto que un evaluador vería primero.
**Estado:** Completa. P0 cerrado y en `origin/main`; P1 cerrado en local
(pendiente de `push`). 441 tests, `ruff` y `mypy` a cero, suite verificada
también sobre Python 3.11 con instalación limpia.

---

## 1. Resumen ejecutivo

El plan acordado el 27/09 ordenaba el trabajo en tres tramos: **P0**, lo que
podía suspender o arruinar la defensa; **P1**, brechas de producto con valor
visible; y congelar el código en las últimas 24 horas. Esta memoria cubre P0
y P1.

**P0 no encontró detalles, encontró fallos graves.** Dos de ellos hacían que
la herramienta no funcionara en absoluto en su configuración de producción:

- Con PostgreSQL, **ninguna escritura de un escaneo llegaba a la base de
  datos** (fechas con zona horaria en columnas sin ella). SQLite lo toleraba
  en silencio, y toda la suite corría sobre SQLite.
- El **stack de Docker no podía guardar un solo escaneo**: la imagen no
  aplicaba las migraciones y, además, usaba la SQLite del `.env` de
  desarrollo en vez del PostgreSQL del propio compose.

**P1 cerró siete brechas**, cada una en su commit: autenticación opcional de
la API, comparación entre escaneos en el dashboard, tres comprobaciones
nuevas de descubrimiento (redirección HTTP → HTTPS, atributos de cookies y
validez del certificado TLS), re-triaje forzado, y un diff que no depende de
la IA para enseñar lo que es puro cálculo.

---

## 2. Criterio de la fase

Cada punto se eligió por lo que pasaría **en la evaluación** si faltara, no
por lo que costaba hacerlo:

| Punto | Qué pasaba sin él |
|---|---|
| PostgreSQL real | La herramienta no persiste nada en el motor declarado de producción |
| Docker | `docker compose up`, lo primero que probaría un evaluador, da 500 |
| Clon limpio | El README no llevaba a una instalación funcional en Windows |
| Demo sin red | Un fallo de red o de crt.sh el día de la defensa la dejaba sin demo |
| `risk_score` | github.com, con solo hallazgos leves, salía «100/100 · crítico» |
| Autenticación | Deuda marcada como «bloqueante si se despliega con IP pública» |
| Diff en dashboard | La comparación temporal, parte del enunciado de la herramienta, solo existía por API |
| HTTP→HTTPS, cookies | Dos comprobaciones básicas de cualquier escáner web que faltaban |
| Validez TLS | Un certificado autofirmado o emitido para otro dominio pasaba sin hallazgo |
| Re-triaje | Cambiar de modelo exigía editar la BD a mano |

---

## 3. P0 — Bloqueantes (27–28/09, en `origin/main`)

Resumen; el detalle de cada defecto está en CLAUDE.md, «Deuda técnica
conocida → Resuelta».

### 3.1 PostgreSQL: fechas *aware* (`3b9e1a6`)

Las columnas eran `TIMESTAMP WITHOUT TIME ZONE` y el código escribía fechas
con zona. asyncpg lo rechaza, y con ello **toda** escritura de un `Scan`:
`POST /scans` fallaba siempre. Se arregló con un tipo `UtcDateTime` que
convierte a UTC *naive* al escribir, **sin migración**. Antes del arreglo
fallaban 29 de las 47 pruebas de BD y API ejecutadas contra PostgreSQL 16;
después, ninguna. Una guarda (`test_toda_columna_de_fecha_usa_utc_datetime`)
impide la regresión sin necesitar PostgreSQL en la suite.

### 3.2 Stack de Docker (`97d97d9`, `de13de0`, `7948803`)

Cuatro defectos: la imagen no copiaba ni aplicaba las migraciones; el
`DATABASE_URL` del `.env` llegaba al contenedor; el dashboard no copiaba el
tema; no había `.dockerignore`. Se endureció de paso: puertos solo en
`127.0.0.1`, `.env` opcional, dashboard sin secretos, healthcheck,
`exec uvicorn` (parada limpia) e imagen de la API de 1,51 a 1,04 GB.
`tests/test_deploy_config.py` fija todo esto sin levantar Docker.

### 3.3 Ensayo desde un clon limpio (`f719fbe`, `da3cc83`, `521019e`, `557f1e8`, `7c4eefc`)

Seguir el README al pie de la letra destapó que la **traza de auditoría**
obligatoria de la restricción de seguridad #6 no se emitía nunca bajo uvicorn
(nadie configuraba los loggers de `atalaya.*`), que `LOG_LEVEL` no tenía
efecto, tres variables de configuración que nadie leía, `make api` escuchando
en `0.0.0.0`, y un README que no funcionaba en Windows.

### 3.4 Datos de reserva para la demo (`59f67cd`, `a46cde0`, `74f3738`, `2183453`)

Proveedor `replay` que sirve respuestas **reales grabadas** del modelo (nunca
inventadas: una petición no grabada falla con 502), dos escaneos reales de
github.com y un comando de siembra. Un test recorre el guion entero y detecta
si un cambio de prompt deja obsoleta la grabación.

### 3.5 `risk_score` y PDF (`837d593`, `a2af874`, `30f3c25`)

La suma ponderada saturaba con volumen: 194 `low` + 9 `medium` daban 100/100.
Nueva fórmula en `core/scoring.py` (la banda la fija la severidad máxima; el
volumen solo mueve dentro de ella), única para PDF y API. En el PDF: Markdown
del modelo renderizado sin permitir inyección de etiquetas, glifos que
Helvetica no dibuja, y una tabla de activos sin solapes, medida con un test de
geometría sobre el PDF real.

---

## 4. P1 — Brechas de producto (29/09, en local)

### 4.1 Autenticación opcional por `X-API-Key` (`54a4cf2`)

**Diseño.** Una clave compartida en `API_KEY`. Vacía (por defecto), la API
no exige nada: la demo, el stack sin `.env` y la suite no cambian. Con valor,
`api/security.py::require_api_key()` exige `X-API-Key` en todo endpoint salvo
`/health`, que usan el healthcheck de Docker y la sonda del dashboard.

**Por qué una clave y no usuarios.** Hay un operador y un cliente propio.
Cuentas, login y rotación de tokens no protegerían nada que no proteja ya una
clave larga y aleatoria, y costarían una tabla y un flujo nuevos.

**Decisiones de seguridad concretas:**

- `secrets.compare_digest` en vez de `==`, que corta en el primer carácter
  distinto y filtra por tiempo cuánto prefijo acertó un atacante.
- Comparación en **bytes**: con texto no ASCII, `compare_digest` lanza
  `TypeError`. Comparando `str` habría sido un 500 provocable desde fuera
  (hay un test con una cabecera latin-1).
- Rechazo **antes** de ejecutar la ruta: un `POST /scans` sin clave no llega
  a tocar la red (test con la enumeración sustituida por una trampa).
- Aplicada por router y no en `FastAPI(dependencies=...)`, que la habría
  impuesto también a `/health`.
- El dashboard la envía si la tiene. En Docker recibe **solo** esa variable
  (`ATALAYA_API_KEY: ${API_KEY:-}`), no el `.env` con las claves de IA.

**Trampa encontrada.** La guarda que comprueba que *toda* ruta exige la clave
recorría `app.routes`. En FastAPI 0.141 los routers incluidos aparecen ahí
envueltos (`_IncludedRouter`) y sus rutas no se ven: la guarda comprobaba
solo `/` y habría pasado con la API entera abierta. Se reescribió sobre el
esquema OpenAPI (API pública) y se validó con una mutación: quitar la
dependencia de un router hace fallar la suite.

**Límite reconocido.** Sin TLS la clave viaja en claro. Por eso los puertos
siguen publicados solo en `127.0.0.1`: la clave no sustituye a un proxy TLS
si se quisiera exponer la API.

### 4.2 «Comparar con» en el dashboard (`caff8dd`)

Selector en el detalle de un escaneo cuando hay otro del mismo dominio. Por
defecto propone el **anterior más reciente**, que responde a «qué ha cambiado
desde la última vez». Muestra nuevos, desaparecidos y sin cambios, los
hostnames de cada grupo y la valoración de la IA.

La comparación se pide con un **botón** y se guarda en `session_state` por
pareja de escaneos. Streamlit reejecuta el script entero en cada interacción:
pedirla al renderizar repetiría una llamada al modelo cada vez que se pulsa
cualquier otra cosa. Verificado en el log real: una sola llamada aunque
después se generó el informe.

Las capturas con navegador destaparon tres defectos que la suite no ve (el
rótulo duplicado, el botón lejos del selector y los títulos Markdown del
modelo a tamaño de portada), corregidos antes del commit.

### 4.3 Redirección HTTP → HTTPS (`f9ad1ab`)

Antes solo se miraba HTTP si HTTPS no respondía (hallazgo `sin_https`). Ahora
`analyze_headers()` pide HTTP **en paralelo** con HTTPS. Si HTTPS responde y
el acceso por HTTP no acaba en una URL `https` (siguiendo redirecciones, en
cadena o a otro host), aparece el hallazgo `http_sin_redireccion_https`.
Importa porque esa primera petición en claro es la que permite *SSL
stripping*, y HSTS solo protege a partir de la primera visita.

- **En paralelo**, no en serie: un puerto 80 filtrado no responde nunca, y en
  serie cada host así sumaría un timeout entero al escaneo. Un test lo fija:
  cada petición espera a que la otra haya empezado.
- Que HTTP no conteste **no** es hallazgo: no se sirve nada en claro.
- Redirecciones seguidas por petición, no por la configuración del cliente:
  un test lo destapó al pasar un cliente que no las seguía.

Verificado en real: `example.org` (200 en claro) da el hallazgo, `nmap.org`
(redirige) no, y `scanme.nmap.org` (solo HTTP) da `sin_https` sin duplicar.

### 4.4 Atributos de las cookies (`3940ca9`)

Tres hallazgos: `cookie_sin_secure` (solo en sitios HTTPS),
`cookie_sin_httponly` y `cookie_sin_samesite`.

- **Uno por tipo y host**, con los nombres afectados. Veinte cookies sin
  `SameSite` son un problema de configuración, no veinte hallazgos que
  inflarían el `risk_score` por volumen, justo el defecto corregido en 3.5.
- Se miran también las `Set-Cookie` de las **redirecciones intermedias**
  (`response.history`): una cookie de sesión fijada en el 302 del login se
  perdería mirando solo la respuesta final.
- **Nunca se guarda el valor** de una cookie. Puede ser un token de sesión, y
  la evidencia se guarda en BD, se envía al proveedor de IA y sale en el PDF.
  Hay un test con un token simulado.

Verificado en real sobre github.com: solo `_octo` (analítica) sale sin
`HttpOnly`; `_gh_sess` y `logged_in` están bien configuradas. La herramienta
no decide si eso es grave: lo decide el triaje, con el nombre delante.

### 4.5 Re-triaje forzado (`47ebdab`)

`POST /scans/{id}/triage?force=true` incluye los hallazgos ya triados. Sin
`force`, el endpoint sigue siendo idempotente. La propiedad clave es que **un
re-triaje fallido conserva el triaje anterior**: `ai/triage.py` no toca el
hallazgo si el proveedor falla, así que un proveedor caído a mitad no borra
nada. Verificado en real con la demo en `replay`: 204 re-triajes fallidos (no
hay grabación para ellos) y cero severidades perdidas.

Sin botón en el dashboard a propósito: son cientos de llamadas en un escaneo
grande, y un clic accidental en la demo las dispararía.

### 4.6 Diff sin valoración IA (`b628830`)

El endpoint de diff devuelve 502 si falla el proveedor, y con él se perdían
también los hostnames, que son puro cálculo: en el stack de Docker sin
`.env`, «Comparar con» no enseñaba nada. `?analysis=false` devuelve solo el
cálculo, sin llamar al modelo. **El comportamiento por defecto no cambia**
(la IA sigue siendo parte integral del diff, decisión documentada en el
endpoint). El dashboard usa la variante solo como respaldo ante un 502 y
avisa del motivo; un 404 o 400 no se reintenta. Verificado en real sin clave
de proveedor.

### 4.7 Validez del certificado TLS (`06b3e53`)

`tls.py` inspeccionaba el certificado con `CERT_NONE`, a propósito (tiene que
poder *ver* un certificado inválido para reportarlo), pero no comprobaba si un
cliente lo aceptaría. Dos hallazgos nuevos:

- **`tls_hostname_no_coincide`**, sin red, sobre los SAN del certificado ya
  obtenido y con las reglas de un navegador: el comodín solo vale como
  etiqueta izquierda completa y cubre exactamente una, y no se recurre al CN
  (los navegadores lo ignoran desde 2017).
- **`tls_cadena_no_confiable`**, con una segunda negociación **con**
  verificación, en paralelo con la de inspección (no añade latencia).

Dos decisiones con consecuencias medibles:

- **Almacén de CA explícito (`certifi`)**, no el del sistema. El del sistema
  cambia entre Windows y Debian, y un contenedor sin CA instaladas marcaría
  *todos* los hosts como no confiables.
- **`VERIFY_X509_STRICT` desactivado.** Python 3.13+ lo activa por defecto y
  rechaza certificados sin extensiones que los navegadores no exigen. Se
  descubrió porque el test de «cadena correcta» fallaba con *Missing
  Authority Key Identifier*: el mismo certificado habría salido válido en
  Docker (Python 3.11) y no confiable en desarrollo (3.14). El criterio es el
  del cliente real.

La caducidad no se duplica: OpenSSL la reporta como error de verificación,
pero ya tiene su propio hallazgo. Los tests levantan un servidor TLS real en
`127.0.0.1` con certificados y una CA generados en memoria. Verificado contra
`badssl.com`, un servicio público para probar clientes TLS: autofirmado,
nombre equivocado, raíz no confiable, caducado y cadena incompleta dan cada
uno su hallazgo, y `github.com` sale limpio. El resultado es idéntico en
Python 3.14 local y 3.11 en la imagen de Docker.

---

## 5. Verificación

Cuatro capas, ninguna sustituye a las otras:

1. **Suite**: de 359 a **441 tests**, `ruff` y `mypy` a cero antes de cada
   commit.
2. **Integración real en local**: API con uvicorn y dashboard con Streamlit,
   dirigidos por un navegador (Playwright). Incluye el guion completo de la
   demo en `replay` con la autenticación desactivada: cuatro preguntas antes y
   después del triaje, informe, diff en los dos órdenes, triaje en directo
   8/8, `risk_score` de 39 a 40 y **cero** peticiones sin grabación.
3. **Docker con PostgreSQL**, en un proyecto de Compose aparte para no tocar
   el volumen existente: el mismo guion completo, y después el stack
   recreado con `API_KEY` (401 sin cabecera, 200 con ella, healthcheck sano
   y el dashboard del contenedor cargando datos con la clave interpolada).
4. **Python 3.11 con instalación limpia** en un contenedor, a partir solo de
   los ficheros versionados: 421 tests (antes de la validación TLS), `ruff` y
   `mypy` a cero. La validación TLS se verificó después en la imagen de la API.

Por último, un escaneo real de `scanme.nmap.org` por la API con la clave
activada, con todo integrado: se completó con crt.sh caído de verdad (502,
registrado en `errors`), y los hallazgos llegaron a la BD y a la respuesta.

---

## 6. Lo que no se hizo, y por qué

| Punto | Motivo |
|---|---|
| CORS (`Access-Control-Allow-Origin`) | Se analiza la portada; CORS tiene sentido en rutas de API, que la herramienta no enumera |
| Cookies fijadas en otras rutas (login…) | Solo se pide `/`; recorrer rutas sería rastreo, fuera del alcance acotado |
| `/docs` y `/openapi.json` tras la clave | Describen la API sin devolver datos, y desde `/docs` se introduce la clave con «Authorize» |
| Botón de re-triaje forzado | Coste y riesgo de clic accidental en la demo (4.5) |
| TLS en la API | Fuera del plazo; mitigado publicando solo en `127.0.0.1` |
| TLS en otros puertos (8443…) y cifrados | Solo se inspecciona el 443; enumerar cifrados exige muchas negociaciones por host |

---

## 7. Estado final y commits de P1

| Commit    | Tipo | Qué |
|-----------|------|-----|
| `54a4cf2` | feat(api)       | autenticación opcional por `X-API-Key` |
| `caff8dd` | feat(dashboard) | «Comparar con» otro escaneo del mismo dominio |
| `f9ad1ab` | feat(discovery) | hallazgo si HTTP no redirige a HTTPS |
| `3940ca9` | feat(discovery) | atributos de seguridad de las cookies |
| `47ebdab` | feat(api)       | re-triaje forzado (`?force=true`) |
| `b628830` | feat(api)       | diff sin valoración IA y respaldo en el dashboard |
| `d6efad9` | chore(tooling)  | `_shot.py --diff` |
| `06b3e53` | feat(discovery) | validación TLS de hostname y cadena de confianza |

Ninguno toca un prompt de `ai/` ni los datos de la demo: la grabación sigue
reproduciéndose completa.

---

## 8. Bloque de defensa: preguntas previsibles

### Sobre P0

**¿Cómo pasó un bug que impedía toda escritura en PostgreSQL si había cientos de tests?**
Porque toda la suite corre sobre SQLite, que acepta fechas con zona en una
columna sin ella sin quejarse. Los tests eran deterministas y rápidos, pero
probaban otro motor. La lección está aplicada: hay una guarda que exige el
tipo `UtcDateTime` en toda columna de fecha, y la corrección se verificó
contra PostgreSQL 16 real.

**¿Por qué datos grabados y no un modelo simulado para la demo?**
Porque un modelo simulado presentaría como análisis de la IA algo que la IA
nunca dijo sobre esos datos. `replay` solo reproduce respuestas reales, y lo
que no está grabado falla con 502, igual que un proveedor caído.

### Sobre la autenticación

**¿Por qué `compare_digest` y no `==`?**
`==` termina en el primer carácter distinto: cuanto más prefijo acierta el
atacante, más tarda la respuesta, y midiendo tiempos se puede adivinar la
clave carácter a carácter. `compare_digest` tarda lo mismo sea cual sea el
contenido. Además se compara en bytes, porque con texto no ASCII lanzaría una
excepción, es decir, un 500 que cualquiera podría provocar.

**¿Por qué está desactivada por defecto? ¿No es inseguro?**
Por defecto la API solo escucha en `127.0.0.1`: nadie de fuera de la máquina
llega a ella. Activarla por defecto rompería la demo y el arranque sin `.env`
sin añadir protección real en ese escenario. Quien la exponga, la activa con
una variable, y el `.env.example` explica cómo generar una clave aleatoria.

**¿Cómo sabe que ningún endpoint se ha quedado sin proteger?**
Un test recorre el esquema OpenAPI y pide cada ruta sin clave, esperando 401.
Se comprobó quitando la protección de un router: la suite falla. La primera
versión de esa guarda no servía (FastAPI 0.141 oculta en `app.routes` las
rutas de los routers incluidos) y solo se descubrió porque el test
parametrizado generaba menos casos de los esperados.

### Sobre los hallazgos nuevos

**¿Por qué un hallazgo por tipo de cookie y no uno por cookie?**
Por coherencia con el `risk_score`: se acababa de corregir que el volumen de
hallazgos leves saturara el índice. Veinte cookies sin `SameSite` son una
decisión de configuración, y se corrigen con un solo cambio.

**¿No es peligroso guardar cookies de terceros?**
Por eso nunca se guarda el valor, solo el nombre. El valor se descarta en la
propia función que parsea la cabecera y hay un test que lo comprueba con un
token simulado.

**¿Por qué la sonda HTTP va en paralelo?**
Porque un puerto 80 filtrado no responde: la conexión espera hasta el
timeout. En serie, cada host así sumaría ese timeout al escaneo; en paralelo
no añade nada al tiempo de HTTPS.

### Sobre la validación TLS

**Si la herramienta desactiva la verificación para inspeccionar, ¿cómo valida?**
Con dos negociaciones en paralelo: una sin verificación, para poder leer
cualquier certificado, incluido uno inválido, y otra con verificación, para
saber si un cliente lo aceptaría. Leer y juzgar son operaciones distintas.

**¿Por qué `certifi` y no el almacén del sistema?**
Para que el resultado no dependa de dónde se ejecute. Con el del sistema, un
contenedor sin paquete de CA marcaría todos los hosts como no confiables: un
falso positivo masivo que parecería un hallazgo.

**¿Por qué relajar el modo estricto de Python? ¿No es menos seguro?**
El objetivo es informar de lo que un navegador rechazaría, no de lo que
rechazaría la configuración más estricta posible. Con el modo estricto, la
herramienta daba resultados distintos según la versión de Python para el
mismo certificado, y eso es un error de medida, no rigor.

### Sobre el diff

**Si el diff sin IA existe, ¿por qué el endpoint sigue dando 502 por defecto?**
Porque la valoración es parte del contrato del endpoint desde que nació, y
quien lo llama sin más espera recibirla. `analysis=false` es una salida
explícita para quien solo necesita el cálculo. El dashboard la usa como
respaldo y dice por qué falta la valoración, en vez de ocultar el fallo.

**¿Qué significa exactamente «sin cambios»?**
Mismo hostname en ambos escaneos. El diff no compara los puertos ni los
hallazgos de los activos comunes, y la interfaz lo aclara en una nota bajo
los recuentos.
