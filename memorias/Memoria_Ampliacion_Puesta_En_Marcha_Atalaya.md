# Memoria técnica — Ampliación: puesta en marcha guiada

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación 13, iniciada el 12/10/2026. Cierra un límite
del descubrimiento (TLS solo en el 443), corrige dos defectos encontrados por
el camino y añade la puesta en marcha guiada: `atalaya doctor` y `atalaya init`.
**Estado:** En curso. Fase A completa y subida a `origin/main` el 12/10/2026:
558 tests, `ruff` y `mypy` a cero, cada commit verificado en verde por
separado. Fase B pendiente (`GET /config/status` y bienvenida en el
dashboard); ver §10.

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

## 8. Verificación

**Tests:** de 472 a 558 (+86): 6 de TLS multipuerto, 2 de hosts `wildcard`,
2 del log de Shodan, 56 de `doctor` (capa visual, `.env`, comprobaciones y
extremo a extremo) y 20 de `init`. Los de la base de datos usan SQLite real
en un directorio temporal y un PostgreSQL inalcanzable en `127.0.0.1:1`; los
de git, un repositorio real temporal; los de proveedores, `httpx.MockTransport`.
Dos tests recorren la salida completa de `doctor` e `init` y exigen que no
aparezca ningún secreto.

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

Las llamadas a proveedores de estas pruebas fueron la lista de modelos y
`/api-info`: no consumen crédito, coherente con la restricción operativa del
crédito de Anthropic agotado.

---

## 9. Límites que quedan

- **`init` interactivo en Git Bash exige `winpty atalaya init`.** mintty no
  ofrece a Python una consola de Windows; `init` lo detecta y lo explica.
- **Un valor con `${` no se puede guardar en `.env`** (§7.3). `init` se niega.
- **Validar no es comprobar saldo.** Por diseño: comprobarlo costaría dinero
  en cada `init` y `doctor`.
- **`init` no pregunta todos los campos.** Timeouts, concurrencias y demás
  conservan sus valores; se editan en el `.env`.
- **Fase B pendiente:** el dashboard aún no dice qué está configurado.

---

## 10. Lo que queda de la fase

La sesión del 12/10/2026 se cerró con la fase A subida a `origin/main`. Queda,
en este orden y con el diseño ya hablado (detalle en CLAUDE.md, «Plan
acordado para las próximas sesiones»):

1. **Fase B:** `GET /config/status` (solo comprobaciones locales, estado sin
   valores, con `X-API-Key`), bienvenida en el dashboard cuando no hay
   escaneos y el logo de la torre en su cabecera, con maqueta previa.
2. **`POST /scans` en segundo plano** (`202`, `running`, `?wait=true`).
3. **Monitorización** con aviso por webhook, protegido contra SSRF.
4. **Cierre**: documentación, preguntas de defensa y guion de la demo.

Esta memoria se completará con la fase B antes de darla por cerrada.

---

## 11. Commits

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

---

## 12. Bloque de defensa: preguntas previsibles

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
