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
   en el tiempo (diff) para detectar expansión de superficie.
3. **Prioriza con IA** — un sistema de **agentes especializados** (no un
   único prompt genérico) ordena los hallazgos por severidad real, explica
   el impacto, prioriza candidatos de takeover y propone cómo corregirlos.
   Anthropic (Claude) o Gemini, intercambiables.
4. **Responde en lenguaje natural** — *"¿qué activos son más peligrosos?"*
   — enrutado automáticamente al agente adecuado.
5. **Informa** — genera un informe ejecutivo con portada, `risk_score` y
   resumen en lenguaje natural, en PDF, descargable desde la API y desde
   el dashboard.

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

> ⚠️ Respeta `SCAN_ALLOWLIST`. Analiza solo dominios propios o autorizados.

## Uso rápido: puertos, cabeceras y TLS

Ya operativo (Paso 2). `POST /scans` (y `atalaya subdomains --save`) enumera
subdominios y, sobre los hosts que resultan **activos**, enriquece
automáticamente cada uno con:

- **Puertos** — conexión TCP a un conjunto acotado de puertos comunes (web,
  correo, bases de datos, gestión remota), concurrencia limitada por host.
- **Cabeceras de seguridad HTTP** — HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy y Permissions-Policy.
- **TLS** — versión de protocolo, emisor y caducidad del certificado;
  marca como hallazgo un certificado caducado o a menos de 30 días de
  caducar, y versiones obsoletas (TLS 1.0/1.1).

No hace falta invocar nada aparte: es parte del mismo escaneo. Los hallazgos
resultantes entran al mismo flujo que el resto — triaje por IA
(`POST /scans/{id}/triage`) e informe (`GET /scans/{id}/report`) los
procesan sin distinguir su origen. Lo mismo aplica al riesgo de
*subdomain takeover*: se detecta automáticamente sobre los hosts que no
resuelven por A/AAAA (donde vive la señal de un CNAME abandonado), sin
ninguna petición HTTP al recurso de terceros — reconocimiento pasivo, sin
verificar explotabilidad.

**Segunda fuente de enumeración:** con `SHODAN_API_KEY` en `.env`, se
consulta también la API DNS de Shodan, concurrentemente con crt.sh.
Opcional: sin clave, se omite sin ninguna incidencia.

## Uso rápido: agentes de IA y consulta en lenguaje natural

Ya operativo. Requiere `ANTHROPIC_API_KEY` **o** `GEMINI_API_KEY` en `.env`
(según `AI_PROVIDER=anthropic|gemini` — ambos proveedores son
intercambiables, la lógica de negocio no depende de cuál esté activo). Con
la API levantada (`make api`) y un escaneo ya persistido (`atalaya
subdomains ejemplo.com --save`, o `POST /scans`):

```bash
# Triaja los hallazgos sin triar del escaneo #1 (idempotente)
curl -X POST http://localhost:8000/scans/1/triage

# Pregunta sobre la superficie ya escaneada — un agente "Prompter" decide
# si la responde el analista de visión global o el detective de takeover
curl -X POST http://localhost:8000/findings/ask \
  -H "Content-Type: application/json" \
  -d '{"domain": "ejemplo.com", "question": "¿qué activos son más peligrosos?"}'

# Compara dos escaneos del mismo dominio, con valoración de IA
curl http://localhost:8000/scans/1/diff/2
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
| API o webhook          | API REST propia **y** consumo de APIs externas (crt.sh, Shodan, Anthropic/Gemini) |
| Aplicación web         | Dashboard Streamlit (local o desplegado)               |
| GitHub con historial   | Commits por fase, historial real                       |
| Reporte con portada    | PDF generado por la propia herramienta (`GET /scans/{id}/report`) |

## Puesta en marcha

### Con Docker (recomendado)

```bash
cp .env.example .env      # rellena ANTHROPIC_API_KEY o GEMINI_API_KEY (según AI_PROVIDER)
make up                   # levanta db + api + dashboard
```

- API:       http://localhost:8000/docs
- Dashboard: http://localhost:8501

### En local (sin Docker)

```bash
python -m venv .venv && source .venv/bin/activate
make install
make api          # en una terminal
make dashboard    # en otra
```

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

## Aviso legal

Atalaya realiza reconocimiento sobre infraestructura. **Úsalo solo sobre
dominios que te pertenezcan o para los que tengas autorización explícita.**
La variable `SCAN_ALLOWLIST` permite restringir los objetivos permitidos.

## Licencia

MIT — ver [`LICENSE`](LICENSE).
