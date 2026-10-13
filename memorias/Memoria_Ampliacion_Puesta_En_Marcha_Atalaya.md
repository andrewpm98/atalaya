# Memoria técnica — Ampliación: puesta en marcha guiada

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación 13, del 12 al 13/10/2026. Cierra un límite
del descubrimiento (TLS solo en el 443), corrige dos defectos encontrados por
el camino y añade la puesta en marcha guiada: `atalaya doctor` y `atalaya init`
en la terminal y, en la fase B, el estado de la configuración en el dashboard.
**Estado:** Completa. Fase A subida a `origin/main` el 12/10/2026 (558
tests); fase B cerrada el 13/10/2026 (583 tests). `ruff` y `mypy` a cero, cada
commit verificado en verde por separado.

---

## 1. Resumen ejecutivo

La sesión empezó con una hoja de ruta de cuatro bloques (TLS en otros
puertos, `POST /scans` en segundo plano, monitorización y cierre). Antes de
empezar, el usuario planteó una pregunta de producto: alguien que descarga la
herramienta no sabe qué claves necesita ni para qué sirve cada una, así que
¿por qué no un formulario de bienvenida que las pida? De esa pregunta sale la
parte central de la fase.

1. **TLS en los puertos con TLS implícito.** Además del 443, se inspeccionan
   465, 993, 995 y 8443 cuando el escaneo de puertos los encuentra abiertos.
   Un mismo problema en varios puertos es un solo hallazgo que los cita.
2. **Dos defectos encontrados por el camino**, ambos con un test que falla
   contra la versión anterior: los hosts `wildcard` seguían recibiendo escaneo
   de puertos, y `atalaya -v` imprimía la clave de Shodan en claro.
3. **`atalaya doctor`**: diagnóstico de la configuración (qué funciona, qué
   no y cómo arreglarlo), con código de salida para CI.
4. **`atalaya init`**: asistente de cinco pasos que escribe el `.env`
   comprobando cada dato al momento. Se diseñó con una maqueta real que el
   usuario aprobó antes de escribir una línea del producto.
5. **Fase B: el estado en el dashboard.** `GET /config/status` devuelve las
   comprobaciones de `doctor` que no salen a la red, y el dashboard las
   enseña en una bienvenida (cuando no hay escaneos) y en la barra lateral,
   con la torre de la terminal en la cabecera. Por el camino aparecieron dos
   defectos más: en Docker la configuración se habría dado por ausente, y con
   la API caída el dashboard afirmaba que no había escaneos.

Ningún prompt de IA ha cambiado: la grabación de la demo sigue válida.

---

## 2. Criterio de la fase

**Configurar en la terminal, no en un formulario web.** La propuesta inicial
del usuario era un formulario de bienvenida en el dashboard. Se descartó con
tres argumentos, y el usuario los aceptó:

1. El dashboard es un cliente HTTP: alguien tendría que guardar las claves, y
   eso exige un endpoint que reciba secretos. Con `API_KEY` vacía (el valor
   por defecto), cualquiera que llegue a la API podría cambiar la clave del
   proveedor de IA.
2. Lo más importante que hay que configurar no son las claves, sino el
   alcance (`SCAN_ALLOWLIST`). Un formulario web que lo edite deja la
   restricción de seguridad #1 en manos de quien tenga el navegador abierto.
3. La API lee el `.env` al arrancar: el cambio no tendría efecto sin
   reiniciar, y recargarlo en caliente es otra fuente de errores.

La alternativa conserva la idea y quita el riesgo: **la configuración, que es
local y con secretos, va en la CLI; la consulta del estado, que es web y solo
de lectura, irá al dashboard** (fase B, solo sí/no, nunca valores).

**El alcance, primero y obligatorio.** Al revisar la autorización apareció un
dato que reforzó la propuesta: `SCAN_ALLOWLIST` vacía significa «sin
restricción», y así estaba el `.env` de desarrollo. `init` exige al menos un
dominio y una confirmación de autorización; lo permisivo hay que pedirlo
(`--allow-any`). Sin `init`, la herramienta se comporta igual que antes.

---

## 3. TLS en los puertos con TLS implícito (`239cf88`)

Era «el límite más barato de cerrar» de la deuda técnica: los puertos
abiertos ya estaban en `Asset.open_ports` e `inspect_tls()` ya aceptaba un
puerto. La dificultad estaba en no romper una invariante.

**La invariante.** El diff entre escaneos y la reutilización del triaje
asumen como mucho un hallazgo de cada tipo por host. Dos opciones:

- Meter el puerto en el `finding_type` (`certificado_caducado_8443`). Se
  descartó: los escaneos antiguos dejarían de compararse con los nuevos.
- **Fusionar** los hallazgos del mismo tipo en uno que cite los puertos
  (`models.py::_merge_tls_findings`). Elegida.

**La evidencia del 443 no cambia.** Si un hallazgo solo aparece en el 443, su
texto es idéntico al de antes. No es estética: la reutilización del triaje
compara el prompt exacto, y cambiar esa redacción haría pagar otra vez el
triaje de todo hallazgo TLS ya triado.

**Qué puertos.** Los de TLS implícito presentes en `COMMON_PORTS` (465, 993,
995, 8443). Los de STARTTLS (25, 587, 110, 143) quedan fuera: exigen hablar
antes SMTP, POP3 o IMAP, más intrusivo y específico de cada servicio. El 443
se sigue inspeccionando en todo host activo; los demás, solo con evidencia de
que están abiertos (sin ella serían negociaciones a ciegas). Un test exige que
`IMPLICIT_TLS_PORTS` esté contenido en `COMMON_PORTS`: si no, la inspección
de ese puerto no se lanzaría nunca.

**Resultado real sobre github.com.** `emails.github.com:8443` sirve el mismo
certificado que el 443, a 20 días de caducar: un único hallazgo. La primera
redacción repetía el texto entero por puerto; al verlo en el caso real se
cambió a agrupar los puertos con la misma evidencia («Puertos 443 y 8443:
…»). `info.github.com:8443` falla en la negociación TLS: degradación
controlada, sin hallazgo. Los 1023 hallazgos del escaneo cumplen la
invariante.

---

## 4. Hosts `wildcard` fuera del escaneo de puertos (`e581fa3`)

Al leer `scan_targets()` para el punto anterior apareció un defecto que
contradecía CLAUDE.md, ARQUITECTURA y la memoria de robustez:

1. `scan_targets()` recorría **todos** los registros, no solo los activos:
   la IP del comodín DNS se escaneaba por puertos.
2. `apply_port_scan()` asignaba a un host `wildcard` los puertos del activo
   con el que compartiera IP, presentándolo como un servicio propio en el
   dashboard, el diff y el contexto de la IA.

La memoria de robustez lo daba por «verificado leyendo los dos módulos». Se
añadió una nota «Estado posterior» junto a esa frase, sin reescribirla.

**Un test que pasaba por la razón equivocada.** El primer test usaba
`198.51.100.7`, que es TEST-NET-2: `classify_ip()` ya la descarta por no
enrutable, así que pasaba antes del arreglo. Se cambió a una IP pública y
falló, como debía. La regla que deja este episodio, ya escrita en el
subagente de descubrimiento: un estado nuevo de resolución se valida con un
test por cada consumidor, no leyendo el código.

Era latente: ningún escaneo guardado tiene hosts `wildcard`.

---

## 5. La clave de Shodan en el log (`c58a746`)

Al diseñar la validación de claves de `doctor` se comprobó cómo viajaba la
de Shodan: **en la URL** (`?key=...`), que es la única forma que admite su API.
`httpx` registra a nivel INFO la URL completa de cada petición, y con
`atalaya -v` el log raíz pasa a INFO. Reproducido contra Shodan real con una
clave falsa:

```
INFO httpx: HTTP Request: GET https://api.shodan.io/dns/domain/scanme.nmap.org?key=CLAVE-FALSA-XYZ789 "HTTP/1.1 401 Unauthorized"
```

Arreglo: `httpx` y `httpcore` en WARNING dentro de la CLI. Sus avisos se
siguen viendo. La API no estaba afectada (solo configura el logger
`atalaya`). Por el mismo motivo, `doctor` envía la clave de Gemini en la
cabecera `x-goog-api-key` y no en la URL, aunque Google acepta ambas.

---

## 6. Diseño de `init` y `doctor`: de la maqueta a la aprobación

**Maqueta real, no un dibujo.** El usuario pidió ver el resultado antes de
implementarlo, con un diseño profesional y un logo de marca. La maqueta se
construyó con `rich`, la misma librería del producto, y se exportó a imagen
desde la propia consola. Lo aprobado es, literalmente, lo que pinta la
terminal.

**El logo.** Se probaron cuatro versiones y se eligió una torre de celosía
con baliza `( ● )`: es una torre de vigilancia (el significado de *atalaya*)
y, vista de lejos, una **A**. Las ondas transmiten vigilancia continua, que es
el concepto de un ASM. Las otras parecían una pieza de ajedrez, un faro o un
cohete. El logo completo solo sale al dar la bienvenida (`init`); el resto de
comandos usan una cabecera de una línea.

**La identidad es la del dashboard.** La misma paleta (`.streamlit/
config.toml`): un solo acento cian para la marca y lo interactivo, verde para
lo correcto, ámbar para los avisos y rojo solo para los fallos reales.

**Lo que destapó la maqueta.** Con la salida redirigida en Windows (cp1252),
`rich` lanzaba `UnicodeEncodeError` al escribir `●`. La vista previa que se
iba a dar al usuario para ejecutarla en su terminal habría fallado igual. De
ahí el modo ASCII del producto (§7.1).

**Una desviación respecto a lo aprobado.** La maqueta mostraba «Migraciones
aplicadas» en el paso 2. Eso rompería la promesa de que Ctrl+C sale sin
cambios, así que en el paso 2 solo se conecta y se informa («se aplicará al
confirmar»), y las migraciones se aplican al final. Se registró en CLAUDE.md
antes de escribir el código.

**Decisiones registradas antes del código** (`950c66c`, en CLAUDE.md):
configuración en la CLI y no en la web; alcance explícito; validación de
claves sin coste y sin prometer saldo; secretos del entorno en modo no
interactivo; `rich` con menús numerados; migraciones al confirmar.

---

## 7. Implementación (`8f03f6a`, `eb063a9`, `778d2c7`)

```
src/atalaya/onboarding/
├── ui.py        logo, paleta, piezas de pantalla, modo ASCII
├── checks.py    comprobaciones → CheckResult (datos, no texto pintado)
├── doctor.py    atalaya doctor
├── envfile.py   lectura y escritura segura del .env
└── wizard.py    atalaya init (interactivo y --non-interactive)
```

### 7.1 Terminal

`rich` con menús numerados. Las librerías de menús con flechas dependen de
`prompt_toolkit`, que falla en Git Bash (mintty) por no ser una consola de
Windows. Si la salida no es UTF-8, el logo, los iconos y las reglas pasan a
ASCII (`rich` sustituye solo los bordes de los paneles; las reglas hubo que
pasarlas a guiones a mano, porque salían como `???`). No se fuerza UTF-8 sobre
una salida que no lo es: quien la recibe (un `| Out-File` de PowerShell)
espera su codificación. Como red de seguridad, `errors="replace"`.

### 7.2 Comprobaciones (`checks.py`)

Reciben los valores explícitamente en vez de leer `settings`, y `cli.py`
importa la configuración dentro de cada comando. Motivo: un `.env` con un
valor inválido (`AI_MAX_TOKENS=mil`) hacía que **cualquier** comando de la
CLI muriera con una traza de pydantic al importar. Ahora `doctor` lo
diagnostica: «valor no válido en .env: AI_MAX_TOKENS».

Las claves se validan con llamadas que no consumen crédito: la lista de
modelos (Anthropic, Gemini) y `/api-info` (Shodan). Por eso mismo **no
comprueban el saldo**, y la pantalla lo dice en lugar de prometerlo. Es el
caso del entorno de desarrollo: la clave de Anthropic es válida y el crédito
está agotado. `/api-info` devuelve además el plan, y con él se avisa antes de
escanear de lo que se descubrió a mano en la fase de agentes: el plan `oss`
da 403 en la búsqueda DNS.

La comprobación de configuración detecta claves que Atalaya no conoce:
pydantic (`extra="ignore"`) las descarta en silencio, así que una errata deja
un campo sin efecto sin ningún aviso.

### 7.3 Escritura del `.env` (`envfile.py`)

1. Se parte del `.env` existente o de `.env.example`, y solo se reemplazan
   los valores pedidos: comentarios, orden y demás campos se conservan.
2. El texto se vuelve a leer con `python-dotenv` (el parser que usa
   pydantic-settings) y, si algún valor no sale idéntico, no se escribe.
3. Copia del anterior (`.env.bak-AAAAMMDD-HHMMSS`), escritura en un temporal
   del mismo directorio y `os.replace`: o queda el nuevo entero o el anterior
   intacto.
4. Las copias contienen las mismas claves: **no estaban ignoradas** ni en
   `.gitignore` ni en `.dockerignore`. Un `git add .` las habría subido. Se
   añadieron `.env.bak-*` y `.env.tmp-*` a ambos, con test.

**Una suposición propia que los tests desmintieron.** El comentario original
de `format_value()` afirmaba que las comillas simples evitan que dotenv
expanda `${...}`. Un test con `pa$$word${HOME}` lo refutó: dotenv expande
también entre comillas simples y no hay escape. La verificación del punto 2
es la que impide guardar un valor que la aplicación leería distinto; se
corrigió el comentario y la limitación quedó en la deuda técnica.

### 7.4 El asistente (`wizard.py`)

Las preguntas pasan por un `Prompter`: `RichPrompter` en la terminal
(`getpass` para las claves; al terminar, la línea se reescribe con puntos) y
un guion de respuestas en los tests. El asistente reúne todas las respuestas
en un objeto `Answers` y solo escribe al confirmar el resumen.

`--non-interactive` reúne las mismas respuestas desde opciones y los
secretos **solo** desde variables de entorno: como argumentos quedarían en el
historial de la shell y en la lista de procesos. Sin terminal interactiva (un
pipe, Git Bash sin `winpty`), `init` explica cómo seguir y sale con 2 en vez
de quedarse esperando.

Alembic recibe la URL de la base de datos elegida por `config.attributes`
(`migrations/env.py`), porque el `.env` que la contiene no existía al arrancar
el proceso. De paso se escapa el `%`: una contraseña con `%` rompía la
interpolación de la configuración de Alembic.

---

## 8. Fase B: el estado en el dashboard (`124fb8d`, `39136c6`, `9051799`, `ad0cd06`)

La fase A dejó la configuración en la terminal. La fase B cumple la otra
mitad de §2: que el dashboard diga qué está configurado y oriente a quien
llega de fuera, sin recibir ni enseñar ningún valor.

### 8.1 `GET /config/status`

Reutiliza `checks.py` con una función nueva, `run_local_checks()`: las
comprobaciones de `doctor` sin crt.sh y con la IA y Shodan en «clave
configurada, sin validar». El motivo es de coste, no de capacidad: el
dashboard la pide al cargar, y validar claves en cada carga serían llamadas a
Anthropic, Google o Shodan por mirar una pantalla. La base de datos sí se
comprueba: es la de la propia herramienta.

**Que no salga a la red, garantizado y no solo prometido.** La función fuerza
el modo sin red sea cual sea la entrada, y el cliente HTTP que reciben IA y
Shodan rechaza cualquier petición con un error que no es de `httpx`. Si no
fuera así, `_get` lo convertiría en «no se pudo comprobar» y una llamada
externa pasaría desapercibida. Un test sustituye el transporte real de
`httpx` por uno que falla y exige el 200; otro, con mutación incluida,
comprueba que una entrada sin `offline` tampoco valida claves.

**Lo que destapó el diseño: Docker.** Al repasar cómo llega la configuración
a la API del contenedor apareció un defecto latente. Compose pasa el `.env`
como variables de entorno y `.dockerignore` deja el fichero fuera de la
imagen, así que la comprobación de configuración habría dicho «sin .env,
ejecuta atalaya init» con la API perfectamente configurada (y lo mismo
`atalaya doctor` ejecutado dentro del contenedor). Ahora, sin `.env` pero con
campos en el entorno, es correcta: «sin .env · N campos desde variables de
entorno». Se comprobó lanzando la API desde un directorio sin `.env` y con la
configuración en el entorno; Docker Desktop no estaba arrancado para probarlo
con el compose (§10).

**Frontera.** La respuesta es `CheckResult` tal cual, más el recuento de
errores y avisos: el mismo resultado que pinta `doctor`, así que terminal y
dashboard no pueden describir la misma configuración de dos formas. `key`
es estable y el dashboard elige por ella, no por el texto. Un test recorre
la respuesta completa con las tres claves, la de la API y una contraseña de
PostgreSQL configuradas, y exige que ninguna aparezca. Describe la
configuración con la que corre el proceso, no el `.env` del momento: si
alguien lo edita sin reiniciar, lo que cuenta es lo que la API está usando.

### 8.2 El dashboard: maqueta antes que código

Como en la fase A, el usuario pidió ver el resultado antes de cerrarlo. La
maqueta fueron capturas del dashboard real con el prototipo ya conectado a
la API, en cuatro situaciones: base de datos vacía con el `.env` de
desarrollo, vacía con todo configurado, con escaneos y con la API caída. Se
aprobaron los cuatro puntos, incluido uno que no estaba en el plan: el bloque
«Configuración» en la barra lateral, para que el estado se vea también
cuando ya hay escaneos.

- **La torre**, la de `init`/`doctor`, en SVG en línea en la cabecera y en
  la bienvenida. El plan advertía de que `st.html()` sanea con DOMPurify; se
  comprobó en el navegador (no con `AppTest`, que no sanea) que el SVG llega
  al documento en las cuatro situaciones.
- **La bienvenida**, encima de las pestañas, solo cuando `/scans` responde
  con la lista vacía: qué es la herramienta, el estado con la pista de cada
  aviso y tres pasos con el activo marcado. «Configura» se da por hecho
  cuando no hay errores y hay `.env` (o variables), alcance y clave de IA;
  `scanme.nmap.org` solo se sugiere si el alcance no está restringido, para
  no proponer un dominio que la allowlist rechazaría.
- **Con la API caída**, la barra lateral pregunta «¿Has ejecutado `atalaya
  init`?» y da los dos comandos para arrancarla, cada uno en su línea.

**Lo que corrigió la maqueta.** Las primeras capturas no mostraban la
bienvenida y parecía un fallo: se rellena desde la pestaña «Escaneos» (donde
se pide `/scans` y se pintan sus errores) y la captura se hacía al aparecer
las pestañas, antes de que el script terminase. Era la herramienta de
captura, no el producto. Sí eran defectos reales, y se corrigieron antes de
enseñarla: el punto de estado caía entre líneas cuando el detalle ocupaba
dos, la barra lateral se alargaba con detalles de tres líneas (ahora se
cortan y se leen enteros al pasar el ratón), los comandos se partían a mitad
y el título «Bienvenido» presuponía el género de quien llega.

**Un defecto anterior a la fase.** Al repasar el prototipo antes de escribir
los tests: `scans = api_get("/scans") or []` convertía un fallo de la API en
una lista vacía. Con la API caída, el dashboard decía «Todavía no hay
escaneos» (ya ocurría antes de esta fase) y habría dado la bienvenida de
primer arranque. Ahora, sin respuesta, no se afirma nada; el test falla
contra la versión anterior.

**Detalles que se defienden solos.** `/config/status` tarda unas décimas
(base de datos, revisión de Alembic, `git`) y Streamlit reejecuta el script
en cada clic: se guarda 60 s por sesión, no con `st.cache_data`, que es
global al proceso y mezclaría el estado entre pruebas. Su fallo no se pinta
(una API sin la ruta o un 401, que `/scans` ya enseña). Y todo texto que
viene de la API se escapa antes de pintarlo con HTML propio: hay un test con
un `<img onerror>` en el detalle.

**Una afirmación propia corregida.** El primer comentario del CSS justificaba
que los colores de la torre fueran clases diciendo que los atributos del SVG
no admiten `var()`, algo que no se había comprobado. El motivo real basta:
tener la paleta en un solo sitio. Con él se corrigió también el color de las
ondas, que iba como hexadecimal suelto contra la regla del propio CSS
(`ad0cd06`).

**Lo que encontró el usuario al probarlo.** Con todo levantado, plegó la
barra lateral y no pudo volver a abrirla. No era de esta fase, sino del
rediseño visual: en Streamlit 1.64 el botón que la reabre vive dentro de la
barra de herramientas, que `_CSS` ocultaba con `display: none`; y el ancho de
la barra lateral, forzado con `!important`, la mantenía ocupando 268 px ya
plegada. Se diagnosticó midiendo el DOM en Chromium, se corrigió (la barra de
herramientas, invisible salvo ese botón; el ancho, solo abierta; y la
cabecera, con sitio para el botón, que caía encima de la torre por debajo de
~1500 px) y se añadió una guarda estática, porque `AppTest` no pinta CSS
(`912e6c5`).

## 9. Verificación

**Tests:** de 472 a 558 (+86): 6 de TLS multipuerto, 2 de hosts `wildcard`,
2 del log de Shodan, 56 de `doctor` (capa visual, `.env`, comprobaciones y
extremo a extremo) y 20 de `init`. Los de la base de datos usan SQLite real
en un directorio temporal y un PostgreSQL inalcanzable en `127.0.0.1:1`; los
de git, un repositorio real temporal; los de proveedores, `httpx.MockTransport`.
Dos tests recorren la salida completa de `doctor` e `init` y exigen que no
aparezca ningún secreto.

La fase B suma 24 (de 558 a 582), más 1 por la barra lateral (583): 6 del endpoint, 3 de las comprobaciones
locales y de la configuración por variables de entorno, 1 de la guarda de
autenticación (la ruta nueva entra sola en el recorrido del esquema OpenAPI)
y 14 del dashboard. Cuatro mutaciones (quitar el modo sin red forzado, la
rama de variables de entorno, la comprobación de la API caída y el escapado)
hacen fallar los tests que las cubren. `ruff` pasa ahora también sobre
`dashboard/`, que estaba limpio y se mantiene así.

**Pruebas reales:**

| Prueba | Resultado |
|---|---|
| `doctor` sobre la configuración de desarrollo | Detecta `API_HOST`, `API_PORT` y `ENVIRONMENT` en el `.env`, retirados del código en `521019e`; la clave de Anthropic válida; el plan `oss` de Shodan; la allowlist vacía |
| `doctor` en un proceso nuevo con `AI_MAX_TOKENS=mil` | Diagnostica el valor en lugar de lanzar una traza |
| `init --non-interactive` en un proyecto temporal | Valida contra Anthropic y Shodan reales, crea y migra SQLite, escribe el `.env` con las claves exactas, sin secretos en pantalla |
| `init` interactivo en una pseudoconsola de Windows (ConPTY, `pywinpty` instalado aparte) | Las claves reales tecleadas pasan por `getpass` sin mostrarse, la línea queda con puntos, el `.env` es correcto. La captura coincide con la maqueta aprobada |
| `doctor` tras ese `init` | 7 correctos y el aviso de Shodan |
| `alembic current` / `alembic check` | El Alembic de siempre (el de Docker) sigue funcionando con el cambio de `env.py` |
| `atalaya -v subdomains` con una clave de Shodan falsa | Sin el arreglo, la clave sale en el log; con él, no |
| `GET /config/status` contra la API real con el `.env` de desarrollo | 200 en ~0,4 s; las tres claves retiradas, el alcance abierto y la API sin clave como avisos; ninguna clave en la respuesta |
| La API lanzada sin `.env` y con la configuración en variables (lo que hace el compose) | «sin .env · 3 campos desde variables de entorno», correcto |
| Dashboard en Chromium (Playwright) en cuatro situaciones | La torre llega al documento en todas; bienvenida solo con la base de datos vacía; con la API caída, ni bienvenida ni «Todavía no hay escaneos», y sí la pista de `init` |
| Color de la torre tras pasarlo a la paleta | Trazo calculado `rgb(10, 127, 148)`, el mismo de antes |
| Plegar y reabrir la barra lateral, a 1600 y 1280 px | Botón visible fuera de la torre; al pulsarlo, la barra vuelve; plegada, el contenido ocupa todo el ancho |

Las llamadas a proveedores de estas pruebas fueron la lista de modelos y
`/api-info`: no consumen crédito, coherente con la restricción operativa del
crédito de Anthropic agotado.

---

## 10. Límites que quedan

- **`init` interactivo en Git Bash exige `winpty atalaya init`.** mintty no
  ofrece a Python una consola de Windows; `init` lo detecta y lo explica.
- **Un valor con `${` no se puede guardar en `.env`** (§7.3). `init` se niega.
- **Validar no es comprobar saldo.** Por diseño: comprobarlo costaría dinero
  en cada `init` y `doctor`.
- **`init` no pregunta todos los campos.** Timeouts, concurrencias y demás
  conservan sus valores; se editan en el `.env`.
- **`GET /config/status` sin probar con Docker levantado.** Se simuló lo
  que hace el compose; falta verlo en el stack real.
- **El dashboard no valida claves.** Dice «clave configurada, sin validar»;
  validarla es `atalaya doctor`. Por diseño (§8.1).
- **El estado se refresca cada 60 s por sesión**, y en cualquier caso
  refleja la configuración con la que arrancó la API: un cambio en el `.env`
  no se ve hasta reiniciarla.
- **La URL de la base de datos sale como `host:puerto`**, sin contraseña. Es
  información de infraestructura: queda tras `X-API-Key` cuando está
  configurada y la API escucha solo en `127.0.0.1`.

---

## 11. Lo que queda de la fase

Nada: la fase queda cerrada con la fase B. Lo que sigue ya no es parte de
ella, en el orden acordado el 12/10/2026 (detalle en CLAUDE.md, «Plan
acordado para las próximas sesiones»):

1. **Dossier de defensa**: documento vivo, exportable a PDF, que reúna el
   material hoy repartido entre las memorias, incluida esta.
2. **`POST /scans` en segundo plano** (`202`, `running`, `?wait=true`).
3. **Monitorización** con aviso por webhook, protegido contra SSRF.
4. **Cierre**: documentación, preguntas de defensa y guion de la demo.

---

## 12. Commits

| Commit | Contenido |
|---|---|
| `239cf88` | feat(discovery): TLS en los puertos con TLS implícito |
| `e581fa3` | fix(discovery): los hosts wildcard no reciben escaneo de puertos |
| `18f66e5`, `8f5b5b0` | docs y reglas del subagente de descubrimiento |
| `c58a746` | fix(cli): el log detallado no imprime la clave de Shodan |
| `950c66c` | docs: decisiones de `init`/`doctor`, antes del código |
| `8f03f6a` | build: `rich` |
| `eb063a9` | feat(onboarding): `atalaya doctor` |
| `778d2c7` | feat(onboarding): `atalaya init` |
| `d12dc6e`, `d974680` | docs: CLAUDE.md, ARQUITECTURA, README, `.env.example` y esta memoria |
| `280b5db`, `600525d` | docs: plan de las próximas sesiones y dossier de defensa |
| `124fb8d` | feat(onboarding): comprobaciones locales y configuración por variables de entorno |
| `39136c6` | feat(api): `GET /config/status` |
| `9051799` | feat(dashboard): bienvenida, torre y estado de la configuración |
| `ad0cd06` | refactor(dashboard): el color de las ondas de la torre, en la paleta |
| `912e6c5` | fix(dashboard): la barra lateral plegada se puede volver a abrir |
| (este) | docs: cierre de la fase B en CLAUDE.md, ARQUITECTURA, README y esta memoria |

---

## 13. Bloque de defensa: preguntas previsibles

### Sobre la puesta en marcha

**¿Por qué no un formulario de configuración en el dashboard?**
Porque obligaría a exponer un endpoint que recibe secretos, y con la
autenticación desactivada por defecto cualquiera que llegue a la API podría
cambiar la clave del proveedor o el alcance. Los secretos se escriben en la
máquina del operador; la web solo consultará el estado, con sí/no.

**¿Cómo sabe `init` que una clave es válida sin gastar dinero?**
Pidiendo la lista de modelos (Anthropic, Gemini) o `/api-info` (Shodan), que
son gratuitas. A cambio, no comprueban el saldo, y la herramienta lo dice. Es
mejor un aviso honesto que una validación que promete lo que no comprobó.

**¿Qué pasa si `init` se interrumpe a mitad?**
Antes de confirmar el resumen, nada: no se ha escrito ni migrado. Por eso las
migraciones van al final y la base de datos SQLite ni siquiera se abre al
comprobarla (abrirla la crearía). Después de confirmar, el `.env` se escribe
de forma atómica: o el nuevo entero o el anterior intacto, con copia.

**¿Por qué el modo no interactivo no acepta las claves como argumentos?**
Porque un argumento queda en el historial de la shell y en la lista de
procesos, visible para otros usuarios de la máquina.

**¿Por qué exigir el alcance si la herramienta funciona sin él?**
Porque sin él se puede escanear cualquier dominio, y escanear sin autorización
puede ser delito. `init` hace explícita esa decisión; lo permisivo existe
(`--allow-any`), pero hay que pedirlo.

### Sobre el estado en el dashboard (fase B)

**¿Por qué el dashboard no valida las claves, si `doctor` sí lo hace?**
Porque lo pide en cada carga: serían llamadas a Anthropic, Google o Shodan
por mirar una pantalla, con su latencia en cada carga. Dice «clave
configurada, sin validar» y remite a `doctor`, que valida cuando se le pide.

**¿Cómo garantizas que `GET /config/status` no sale a la red?**
Las comprobaciones de IA y Shodan reciben un cliente HTTP que rechaza toda
petición con un error que no se puede confundir con «no se pudo comprobar».
Un cambio que las hiciera salir daría un 500, no una llamada silenciosa. Y un
test sustituye el transporte real de `httpx` por uno que falla.

**¿No es un riesgo publicar el estado de la configuración?**
Devuelve estado y texto, nunca valores: ni claves ni contraseña. Lo más
sensible es `host:puerto` de la base de datos. Está tras `X-API-Key` cuando
hay clave, la API escucha en `127.0.0.1` y es de solo lectura: configurar
sigue siendo `init`, en la máquina del operador. Un test recorre la respuesta
completa con secretos configurados.

**¿Qué pasaba en Docker?**
Que la API recibe la configuración como variables de entorno y el `.env` no
está en el contenedor: habría dicho «sin .env, ejecuta atalaya init» estando
bien configurada. Se vio al diseñar el endpoint, antes de que nadie lo
sufriera.

**¿Por qué la bienvenida no sale con la API caída?**
Porque sin respuesta de `/scans` no se sabe si hay escaneos. Antes de esta
fase el dashboard ya decía «Todavía no hay escaneos» en ese caso, porque
convertía el error en una lista vacía; se corrigió con un test que falla
contra la versión anterior.

**El dashboard pinta HTML con texto de la API: ¿y el XSS?**
Todo texto que viene de la API pasa por `escape()` antes de entrar en el HTML
propio. Hay un test con `<img src=x onerror=alert(1)>` en el detalle de una
comprobación.

### Sobre los defectos encontrados

**¿Cómo se filtraba la clave de Shodan?**
Shodan solo acepta la clave en la URL, y `httpx` registra las URL en INFO.
Con `atalaya -v`, la clave salía en la terminal. Se reprodujo contra Shodan
real, se escribió un test que fallaba y se dejó `httpx` en WARNING.

**¿Cómo pasó desapercibido lo de los hosts `wildcard`?**
Se validó leyendo el código, no con un test por cada consumidor del estado.
Al arreglarlo, el primer test también engañaba: usaba una IP de
documentación que ya se descartaba por otra vía. Un test tiene que fallar
contra el código antiguo para demostrar algo.

### Sobre TLS

**¿Por qué no un hallazgo por puerto?**
Porque el diff y la reutilización del triaje cuentan con un hallazgo por tipo
y host, y meter el puerto en el tipo rompería la comparación con los escaneos
antiguos. Un certificado caducado en 443 y 8443 es un problema en dos puertos.

**¿Por qué no STARTTLS?**
Porque exige hablar SMTP, POP3 o IMAP antes de negociar TLS: más intrusivo y
específico de cada protocolo, y la restricción #5 pide intrusividad acotada.
