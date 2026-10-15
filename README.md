# 🛡️ Atalaya

**Plataforma de Attack Surface Management (ASM) con triaje por IA.**

Atalaya descubre los activos que una organización expone en Internet a partir de
un dominio, evalúa su riesgo y usa un modelo de lenguaje para **priorizar los
hallazgos, explicar su impacto real y sugerir remediación**. Además permite
consultar la superficie de exposición **en lenguaje natural**.

> Práctica 1 — Máster en Ciberseguridad e IA.

---

## ¿Qué hace?

1. **Descubre** — subdominios (Certificate Transparency + Shodan + DNS),
   puertos y servicios, cabeceras de seguridad HTTP, configuración TLS, y
   riesgo de *subdomain takeover* (patrón de CNAME hacia hosting de
   terceros).
2. **Evalúa** — asigna riesgo a cada activo y hallazgo; compara escaneos
   en el tiempo (diff) para detectar expansión de superficie, por API o con
   «Comparar con» en el dashboard.
3. **Prioriza con IA** — un sistema de **agentes especializados** (no un
   único prompt genérico) ordena los hallazgos por severidad real, explica
   el impacto, prioriza candidatos de takeover y propone cómo corregirlos.
   Anthropic (Claude) o Gemini, intercambiables.
4. **Responde en lenguaje natural** — *"¿qué activos son más peligrosos?"*
   — enrutado automáticamente al agente adecuado.
5. **Informa** — genera un informe ejecutivo con portada, `risk_score` y
   resumen en lenguaje natural, en PDF, descargable desde la API y desde
   el dashboard.
6. **Vigila** — escanea un dominio cada cierto tiempo y avisa por
   **webhook** cuando aparecen, desaparecen o cambian activos (o cuando el
   escaneo falla). Avisos firmados con HMAC y protegidos contra SSRF.

## Puesta en marcha

Requisitos: Docker Desktop con su motor Linux en marcha (en Windows, sobre
WSL 2) para la vía recomendada, o Python 3.11+ para la local. En Windows,
clona en una ruta corta (p. ej. `C:\proyectos\atalaya`): alguna dependencia
tiene rutas internas muy largas y, sin *long paths* activado, `pip` falla si
la ruta base ya es profunda.

### Con Docker (recomendado)

```bash
cp .env.example .env         # rellena ANTHROPIC_API_KEY o GEMINI_API_KEY (según AI_PROVIDER)
                             # o, con Python instalado: atalaya init (ver más abajo)
docker compose up --build -d # levanta db + api + dashboard (equivale a `make up`)
```

- Dashboard: http://localhost:8501
- API:       http://localhost:8000/docs — interfaz interactiva: cada endpoint
  se puede probar desde el navegador («Try it out»), en cualquier sistema.

La API aplica las migraciones sola al arrancar. Sin `.env` el stack arranca
igual: todo funciona salvo los endpoints de IA, que responden con un error
explicando que falta la clave (el informe PDF se genera sin resumen
ejecutivo). Los puertos solo se publican en `127.0.0.1`: la base de datos usa
credenciales fijas de desarrollo y la autenticación de la API está
desactivada por defecto (ver «Autenticación» más abajo).

> **Si editas `.env` con el stack levantado**, aplícalo con
> `docker compose up -d`, **no** con `docker compose restart`: `restart`
> reutiliza el contenedor con las variables antiguas y la clave nueva no llega
> a la API.

La CLI también está disponible dentro del contenedor:
`docker compose exec api atalaya subdomains scanme.nmap.org --save`.

### En local (API y dashboard fuera de Docker)

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"            # make install
atalaya init                       # configura .env paso a paso y crea las tablas
atalaya doctor                     # comprueba que todo está en orden
uvicorn atalaya.api.main:app       # make api — en una terminal
streamlit run dashboard/app.py     # make dashboard — en otra
pytest -q                          # make test — suite completa (deterministas, sin red)
```

`make` es opcional (Windows no lo trae): cada objetivo del `Makefile` es un
alias del comando que aparece a su izquierda.

Sin `atalaya init`, a mano: `cp .env.example .env` (en cmd, `copy`), edita
las claves y `alembic upgrade head`. Para PostgreSQL en lugar de SQLite,
`docker compose up -d db` antes.

### Configuración guiada: `atalaya init` y `atalaya doctor`

`atalaya init` pregunta en cinco pasos lo que hace falta y lo comprueba en el
momento, sin coste:

1. **Alcance autorizado**: los dominios que se pueden escanear
   (`SCAN_ALLOWLIST`), con confirmación de que tienes autorización.
2. **Base de datos**: SQLite local, el PostgreSQL de Docker o una URL propia
   (se comprueba la conexión).
3. **IA**: Anthropic o Gemini; la clave se valida y se elige un modelo
   disponible. La validación no comprueba el saldo.
4. **Shodan** (opcional): avisa si el plan de la clave no incluye la
   búsqueda DNS.
5. **Seguridad**: genera la clave de la API (`X-API-Key`) y deja la
   verificación HTTP de takeover desactivada salvo que la pidas.

Las claves no se ven al escribirlas. Nada se guarda hasta confirmar el
resumen (Ctrl+C sale sin cambios); entonces escribe el `.env` (con copia del
anterior, si lo había) y crea las tablas. Si ya hay un `.env`, Enter conserva
cada valor.

`atalaya doctor` comprueba en cualquier momento la configuración, la base de
datos, las claves, crt.sh y que el `.env` no se vaya a subir a git, y dice
cómo resolver cada problema. Sale con código 1 si hay errores (útil en CI);
`--offline` no sale a la red.

El dashboard muestra el mismo estado en la barra lateral y, mientras no hay
ningún escaneo, en una pantalla de bienvenida que indica el siguiente paso.
Lo obtiene de `GET /config/status`, que devuelve el estado y el texto de cada
comprobación, nunca valores, y no sale a la red: dice si hay clave de IA,
pero validarla es cosa de `atalaya doctor`.

Para scripts y CI, sin preguntas. Los secretos van **siempre** en variables
de entorno, nunca como argumentos (quedarían en el historial):

```bash
ANTHROPIC_API_KEY=sk-ant-... atalaya init --non-interactive \
    --allowlist ejemplo.com --database sqlite --ai-provider anthropic --protect-api
```

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
atalaya init --non-interactive --allowlist ejemplo.com --database sqlite --ai-provider anthropic --protect-api
```

En Git Bash, el modo interactivo necesita `winpty atalaya init`: su terminal
no ofrece a Python una consola de Windows. En PowerShell y Windows Terminal
funciona directamente.

### Autenticación

Opcional (`atalaya init` la genera si lo eliges). Con `API_KEY` vacía en
`.env` (por defecto) la API no pide nada.
Con un valor, todo endpoint salvo `/health` exige la cabecera `X-API-Key` y
responde `401` sin ella o con una clave distinta:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # genera una clave
# en .env: API_KEY=<la clave>   — y reinicia la API (Docker: docker compose up -d)
curl -H "X-API-Key: <la clave>" http://localhost:8000/scans
```

El dashboard la envía solo: la lee del mismo `.env` en local y, en Docker,
Compose le pasa únicamente esa variable. En http://localhost:8000/docs se
introduce con el botón «Authorize». Con la clave activada, añade
`-H "X-API-Key: ..."` a los ejemplos de `curl` de este README.

### Ejemplos de uso con `curl`

Los ejemplos de las secciones siguientes son de bash (Linux, macOS o WSL).
En Windows hay dos trampas, ambas comprobadas: en PowerShell, `curl` es un
alias de `Invoke-WebRequest` y no acepta estas opciones (usa `curl.exe`); y
el `curl` de Git Bash envía el texto de `-d` en la codificación de Windows
(cp1252), no en UTF-8, así que una pregunta con tildes o «¿» llega corrupta y
la API la rechaza. En Windows, lo más cómodo es la interfaz de
http://localhost:8000/docs. Lanza primero un escaneo:

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "scanme.nmap.org"}'
# 202 al momento, con el escaneo en "running" y su id (cabecera Location)
curl http://localhost:8000/scans/1
# repite hasta que "status" pase a "completed" (o "failed", con el motivo en "errors")
```

El escaneo corre en segundo plano: de segundos a minutos según el dominio.
Si prefieres esperar en la misma llamada, añade `?wait=true` y la respuesta
(201) trae ya el escaneo completo. Un dominio no válido o fuera de
`SCAN_ALLOWLIST` da 400 o 403 al momento, sin crear el escaneo.

`scanme.nmap.org` lo mantiene el autor de Nmap precisamente para pruebas de
reconocimiento autorizadas; úsalo para probar la herramienta.

## Uso rápido: enumeración de subdominios

Ya operativo (Paso 2). Desde la línea de comandos:

```bash
atalaya subdomains ejemplo.com                # enumera y verifica por DNS
atalaya subdomains ejemplo.com --only-active  # solo hosts que resuelven
atalaya subdomains ejemplo.com --no-resolve   # solo candidatos de CT, sin DNS
atalaya subdomains ejemplo.com --json         # salida estructurada
atalaya subdomains ejemplo.com --save         # además, persiste el escaneo en BD
```

`--save` requiere que las tablas existan (`alembic upgrade head` una vez) y,
además de subdominios, enriquece los hosts activos con puertos, cabeceras y
TLS (ver más abajo) antes de persistir.

La enumeración consulta los registros de **Certificate Transparency** vía
crt.sh —técnica pasiva: no envía tráfico al objetivo— normaliza y deduplica
los resultados, y verifica por DNS cuáles están realmente activos. Esa
distinción entre superficie *histórica* y *real* es la información útil:
un certificado emitido en su día no implica un host vivo hoy.

Cada dirección resuelta se clasifica por alcance: un nombre que apunta a
`0.0.0.0` (registro anulado), a bucle local o a direccionamiento privado **no**
cuenta como activo alcanzable. Los que resuelven a IPs privadas se destacan
aparte, porque filtrar direccionamiento interno es un hallazgo en sí mismo.

Si el dominio tiene **DNS wildcard** (cualquier subdominio resuelve), Atalaya
lo detecta antes de resolver y descarta como `wildcard` los hosts que solo
responden con la IP del comodín: sin ese filtro, cada nombre inventado
contaría como un activo real. Se conservan en el resultado, y la CLI indica
cuántos se descartaron.

> ⚠️ Respeta `SCAN_ALLOWLIST`. Analiza solo dominios propios o autorizados.

## Uso rápido: puertos, cabeceras y TLS

Ya operativo (Paso 2). Un escaneo (`POST /scans`, o `atalaya subdomains --save`) enumera
subdominios y, sobre los hosts que resultan **activos**, enriquece
automáticamente cada uno con:

- **Puertos** — conexión TCP a un conjunto acotado de puertos comunes (web,
  correo, bases de datos, gestión remota), concurrencia limitada por host.
- **Cabeceras de seguridad HTTP** — HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy y Permissions-Policy; además,
  que el acceso por HTTP redirija a HTTPS y que las cookies lleven
  `Secure`, `HttpOnly` y `SameSite` (se registra su nombre, nunca su valor).
- **TLS** — versión de protocolo, emisor y caducidad del certificado;
  marca como hallazgo un certificado caducado o a menos de 30 días de
  caducar, versiones obsoletas (TLS 1.0/1.1), un certificado que no cubre el
  hostname y una cadena que no lleva a una CA de confianza (autofirmado,
  raíz desconocida o intermedio no enviado). Se inspecciona el 443 y,
  si están abiertos, los demás puertos con TLS (465, 993, 995, 8443); un
  mismo problema en varios puertos es un solo hallazgo que los cita.

No hace falta invocar nada aparte: es parte del mismo escaneo. Los hallazgos
resultantes entran al mismo flujo que el resto — triaje por IA
(`POST /scans/{id}/triage`) e informe (`GET /scans/{id}/report`) los
procesan sin distinguir su origen. Lo mismo aplica al riesgo de
*subdomain takeover*: se detecta automáticamente sobre los hosts que no
resuelven por A/AAAA (donde vive la señal de un CNAME abandonado), por
patrón de CNAME y sin ninguna petición HTTP al recurso de terceros —
reconocimiento pasivo.

**Verificación de takeover (opcional, desactivada por defecto):** con
`TAKEOVER_VERIFY=true`, además se consulta la página de error pública del
proveedor apuntado (p. ej. el 404 «There isn't a GitHub Pages site here») y,
si muestra la huella de "recurso no reclamado", el hallazgo sube a **alta
sospecha — no confirmado**. Nunca se marca como confirmado ni se intenta
reclamar el recurso; solo actúa sobre hostnames incluidos en `SCAN_ALLOWLIST`
y cada petición a un tercero queda registrada en el log.

**Segunda fuente de enumeración:** con `SHODAN_API_KEY` en `.env`, se
consulta también la API DNS de Shodan, concurrentemente con crt.sh.
Opcional: sin clave, se omite sin ninguna incidencia.

## Uso rápido: agentes de IA y consulta en lenguaje natural

Ya operativo. Requiere `ANTHROPIC_API_KEY` **o** `GEMINI_API_KEY` en `.env`
(según `AI_PROVIDER=anthropic|gemini` — ambos proveedores son
intercambiables, la lógica de negocio no depende de cuál esté activo). Con
la API levantada y un escaneo ya persistido (`POST /scans`, ver "Puesta en
marcha", o `atalaya subdomains scanme.nmap.org --save`):

```bash
# Triaja los hallazgos sin triar del escaneo #1 (idempotente). Los ya triados
# en otro escaneo del dominio con el mismo contexto exacto se reutilizan sin
# llamar al modelo (la respuesta dice cuántos: `reused`, `model_calls`)
curl -X POST http://localhost:8000/scans/1/triage
# ...y re-triar también los ya triados (p. ej. tras cambiar de modelo; una
# llamada al proveedor por hallazgo). Si alguno falla, conserva su triaje.
curl -X POST "http://localhost:8000/scans/1/triage?force=true"

# Pregunta sobre la superficie ya escaneada — un agente "Prompter" decide
# si la responde el analista de visión global o el detective de takeover
curl -X POST http://localhost:8000/findings/ask \
  -H "Content-Type: application/json" \
  -d '{"domain": "scanme.nmap.org", "question": "¿qué activos son más peligrosos?"}'

# Compara dos escaneos del mismo dominio, con valoración de IA: hosts nuevos y
# desaparecidos, y en `cambiados` los comunes que cambiaron de estado, puertos
# o hallazgos (requiere dos escaneos; en el dashboard: «Comparar con»)
curl http://localhost:8000/scans/1/diff/2
# ...o solo el cálculo, sin IA (no necesita clave del proveedor)
curl "http://localhost:8000/scans/1/diff/2?analysis=false"
```

El triaje recibe **contexto estructurado** (hostname, IPs, estado, fuentes,
tipo de hallazgo y evidencia) — nunca la fila de base de datos en bruto — y
responde con una severidad razonada, no una plantilla fija. Un fallo del
proveedor de IA en un hallazgo no aborta los demás; se reporta en `errors`.
Es uno de **seis agentes especializados**, cada uno con su propio contexto
y criterio (detalle en [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md)).

## Uso rápido: informe con portada

Ya operativo (Paso 7). Genera y descarga el PDF de un escaneo ya persistido:

```bash
curl -o informe.pdf http://localhost:8000/scans/1/report
```

Regenera el informe en cada descarga (nunca sirve una copia cacheada sin
comprobar nada), así que siempre refleja el triaje más reciente. Incluye
portada (dominio y fecha), `risk_score`, resumen ejecutivo con IA (opcional
— sin proveedor disponible, el informe se genera igual, sin resumen) y el
detalle de cada activo y hallazgo con su impacto y remediación. También se
descarga desde la pestaña «Escaneos» del dashboard.

## Uso rápido: vigilancia programada (webhook)

Desde el dashboard, en la pestaña **«Vigilancia»** (crear, pausar, borrar y
ver el resultado de cada monitor), o por la API:

Un **monitor** escanea un dominio cada `interval_hours` (mínimo 1) y hace un
`POST` con JSON al webhook cuando algo cambia. La primera ejecución es en el
minuto siguiente a crearlo, y compara con el último escaneo completado del
dominio (si no hay ninguno, queda como referencia y no avisa). Sin IA: no
gasta crédito.

```bash
curl -X POST http://localhost:8000/monitors \
  -H "Content-Type: application/json" \
  -d '{"domain": "scanme.nmap.org", "webhook_url": "https://hooks.ejemplo.com/atalaya",
       "interval_hours": 24, "secret": "un-secreto-de-al-menos-16-caracteres"}'
curl http://localhost:8000/monitors          # resultado de la última ejecución de cada uno
curl -X PATCH http://localhost:8000/monitors/1 \
  -H "Content-Type: application/json" -d '{"active": false}'   # pausar
curl -X DELETE http://localhost:8000/monitors/1                 # dejar de vigilar
```

Dos tipos de aviso (cabecera `X-Atalaya-Event`):

- **`cambios`** — `nuevos`, `desaparecidos` y `cambiados` (puertos o
  hallazgos de los activos que ya existían), con `summary` en una línea y las
  incidencias del escaneo en `errors`.
- **`escaneo_fallido`** — el escaneo falló, una fuente de subdominios
  (crt.sh, Shodan) dejó de aportar los hosts que aportaba (no se avisan como
  «desaparecidos») o el dominio ya no
  está en `SCAN_ALLOWLIST`. Una vigilancia que falla en silencio parece una
  vigilancia sin cambios.

Si el aviso no se entrega, el cambio se vuelve a avisar en la siguiente
ejecución: el monitor no avanza su escaneo de referencia hasta que llega.

**Comprobar la firma** (solo si el monitor tiene `secret`): HMAC-SHA256 del
cuerpo exacto, como los webhooks de GitHub.

```python
import hashlib, hmac

def es_de_atalaya(cuerpo: bytes, firma: str, secreto: str) -> bool:
    esperada = "sha256=" + hmac.new(secreto.encode(), cuerpo, hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperada, firma)  # firma = cabecera X-Atalaya-Signature
```

**Seguridad.** El webhook tiene que ser `https` y apuntar a una dirección
pública: una URL hacia `localhost`, la red interna o el servicio de metadatos
de la nube se rechaza con 400 (protección contra SSRF), al crear el monitor y
otra vez en cada aviso. La API nunca devuelve la URL completa (las de Slack o
Discord llevan un token en la ruta) ni el secreto, y cada aviso queda en el
log de auditoría. Detalle en [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md)
(§12).


## Demo sin red: datos de reserva

Para enseñar la herramienta aunque crt.sh o el proveedor de IA no respondan,
el repositorio incluye dos escaneos **reales** de github.com (21/09 y
28/09/2026) ya triados por el modelo, y las respuestas reales del modelo a un
guion de preguntas, grabadas para reproducirlas sin conexión:

```bash
python scripts/seed_demo_data.py --reset   # BORRA escaneos y monitores de la BD y siembra la demo
# en .env: AI_PROVIDER=replay              # sin clave ni red; reinicia la API
```

Con Docker: `docker compose exec api python scripts/seed_demo_data.py --reset`
y `AI_PROVIDER=replay` en `.env` aplicado con `docker compose up -d`. Ahí
`--reset` vacía la base de datos del stack; para conservarla, levanta la demo
como otro proyecto, con su propio volumen: `docker compose -p atalaya-demo
up --build -d` (con el stack principal parado: los contenedores tienen nombre
fijo).

`AI_PROVIDER=replay` **no es un modelo**: sirve respuestas grabadas (y lo
avisa en el log de la API). Solo responde a las peticiones grabadas — las
preguntas del guion sobre estos datos, que el script imprime al sembrar —;
cualquier otra falla con 502, igual que un proveedor caído. El detalle está
en `CLAUDE.md` («Datos de reserva para la demo»).

## Arquitectura (resumen)

```
        ┌─────────────┐     REST      ┌──────────────┐
        │  Dashboard  │ ◀───────────▶ │   API        │
        │ (Streamlit) │               │  (FastAPI)   │
        └─────────────┘               └──────┬───────┘
                                              │
             ┌────────────────────────────────┼────────────────────────┐
             ▼                ▼                ▼                         ▼
      ┌────────────┐   ┌────────────┐   ┌────────────┐          ┌──────────────┐
      │Descubrimien│   │  Agentes   │   │ PostgreSQL │          │  Informes    │
      │to (scan +  │   │  de IA     │   │ (persist.) │          │  (PDF + IA)  │
      │ takeover)  │   │ (triaje,   │   └────────────┘          └──────────────┘
      └─────┬──────┘   │ prompter,  │
            │          │ analyst... │
     APIs externas     └─────┬──────┘
   (crt.sh, Shodan)          │
                    Claude (Anthropic) o Gemini
```

Detalle completo en [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).

## Stack

| Capa            | Tecnología                          |
|-----------------|-------------------------------------|
| API             | FastAPI + Uvicorn                   |
| Base de datos   | PostgreSQL (SQLAlchemy 2.0 async)   |
| Descubrimiento  | httpx, dnspython, cryptography      |
| IA              | Anthropic (Claude) o Google Gemini, abstraídos tras `LLMProvider` |
| Dashboard web   | Streamlit                           |
| Orquestación    | Docker Compose                      |

## Cómo cubre los requisitos de la práctica

| Requisito              | En Atalaya                                              |
|------------------------|--------------------------------------------------------|
| Base de datos          | PostgreSQL con modelos de activos / escaneos / hallazgos |
| API o webhook          | API REST propia, consumo de APIs externas (crt.sh, Shodan, Anthropic/Gemini) **y** avisos por webhook de la vigilancia programada |
| Aplicación web         | Dashboard Streamlit (local o desplegado)               |
| GitHub con historial   | Commits por fase, historial real                       |
| Reporte con portada    | PDF generado por la propia herramienta (`GET /scans/{id}/report`) |

## Estado del proyecto

Desarrollo por fases (ver `docs/ARQUITECTURA.md`):

- [x] **Paso 1** — Arquitectura + esqueleto del repositorio
- [x] **Paso 2** — Motor de descubrimiento
  - [x] Subdominios (Certificate Transparency + DNS)
  - [x] Puertos y servicios
  - [x] Cabeceras de seguridad HTTP
  - [x] Configuración TLS
- [x] **Paso 3** — Base de datos + modelos (Scan/Asset/Finding, migraciones Alembic;
      persiste subdominios, puertos y hallazgos de cabeceras/TLS)
- [x] **Paso 4** — API REST completa
  - [x] `scans` / `assets` / `findings` — creación y lectura real
  - [x] `/scans/{id}/triage`, `/findings/ask` — activados junto al Paso 5
- [x] **Paso 5** — Capa IA
  - [x] `LLMProvider` / `AnthropicProvider`
  - [x] Triaje de hallazgos con contexto estructurado
  - [x] Consulta en lenguaje natural sobre un escaneo
- [x] **Paso 6** — Dashboard completo (escaneos, triaje IA, consulta NL, informe)
- [x] **Paso 7** — Generador de informes (PDF con portada, API + dashboard)

Los siete pasos son la entrega evaluable de la práctica; están cerrados.
Ampliación posterior, más allá de los requisitos obligatorios:

- [x] Shodan como segunda fuente de enumeración de subdominios (opcional)
- [x] Detección de riesgo de *subdomain takeover* (patrón de CNAME)
- [x] Sistema de agentes de IA especializados (Prompter, Analista, Detective
      de takeover, Redactor de informes, Comparador de escaneos)
- [x] `GeminiProvider` — segundo proveedor de IA intercambiable
- [x] `GET /scans/{id}/diff/{other_id}` — comparación de escaneos con IA
- [x] `risk_score` y resumen ejecutivo con IA en el informe PDF
- [x] Rediseño visual del dashboard (estética de herramienta comercial de
      seguridad), verificado con capturas de pantalla reales
- [x] Detección y filtrado de wildcards DNS
- [x] Verificación HTTP opcional de *subdomain takeover* ("alta sospecha",
      nunca "confirmado")
- [x] Instalación limpia verificada de extremo a extremo; `ruff` y `mypy`
      sin avisos (`make lint`)
- [x] Cierre pre-entrega: PostgreSQL y Docker verificados, demo sin red,
      autenticación opcional por `X-API-Key`, «Comparar con» en el
      dashboard, redirección HTTP → HTTPS, cookies, validación TLS
      (hostname y cadena) y re-triaje forzado
- [x] Diff con cambios de los activos comunes (estado, puertos y hallazgos)
      y reutilización del triaje entre escaneos ante el mismo prompt exacto
- [x] TLS también en los puertos abiertos con TLS implícito (465, 993,
      995, 8443)
- [x] `atalaya init` (configuración guiada) y `atalaya doctor`
      (diagnóstico), con identidad visual propia en la terminal
- [x] Escaneo en segundo plano (`POST /scans` responde 202) con su
      seguimiento en el dashboard
- [x] Vigilancia programada: escaneos periódicos con aviso por webhook
      (firmado con HMAC, protegido contra SSRF), por API y desde el dashboard

La memoria técnica de cada fase está en [`memorias/`](memorias/).

## Aviso legal

Atalaya realiza reconocimiento sobre infraestructura. **Úsalo solo sobre
dominios que te pertenezcan o para los que tengas autorización explícita.**
La variable `SCAN_ALLOWLIST` restringe los objetivos permitidos; `atalaya
init` la pide en su primer paso.

## Licencia

MIT — ver [`LICENSE`](LICENSE).
