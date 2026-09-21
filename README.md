# 🛡️ Atalaya

**Plataforma de Attack Surface Management (ASM) con triaje por IA.**

Atalaya descubre los activos que una organización expone en Internet a partir de
un dominio, evalúa su riesgo y usa un modelo de lenguaje para **priorizar los
hallazgos, explicar su impacto real y sugerir remediación**. Además permite
consultar la superficie de exposición **en lenguaje natural**.

> Práctica 1 — Máster en Ciberseguridad e IA.

---

## ¿Qué hace?

1. **Descubre** — subdominios (Certificate Transparency + DNS), puertos y
   servicios, cabeceras de seguridad HTTP y configuración TLS.
2. **Evalúa** — asigna riesgo a cada activo y hallazgo.
3. **Prioriza con IA** — un LLM ordena los hallazgos por severidad real,
   explica el impacto y propone cómo corregirlos.
4. **Responde en lenguaje natural** — *"¿qué activos tienen TLS obsoleto y
   puertos de gestión abiertos?"*.
5. **Informa** — genera un informe ejecutivo con portada en PDF, descargable
   desde la API y desde el dashboard.

## Uso rápido: enumeración de subdominios

Ya operativo (Paso 2). Desde la línea de comandos:

```bash
atalaya subdomains ejemplo.com                # enumera y verifica por DNS
atalaya subdomains ejemplo.com --only-active  # solo hosts que resuelven
atalaya subdomains ejemplo.com --no-resolve   # solo candidatos de CT, sin DNS
atalaya subdomains ejemplo.com --json         # salida estructurada
atalaya subdomains ejemplo.com --save         # además, persiste el escaneo en BD
```

`--save` requiere que las tablas existan (`alembic upgrade head` una vez).

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

## Uso rápido: triaje por IA y consulta en lenguaje natural

Ya operativo (Paso 5). Requiere `ANTHROPIC_API_KEY` en `.env`. Con la API
levantada (`make api`) y un escaneo ya persistido (`atalaya subdomains
ejemplo.com --save`, o `POST /scans`):

```bash
# Triaja los hallazgos sin triar del escaneo #1 (idempotente)
curl -X POST http://localhost:8000/scans/1/triage

# Pregunta sobre la superficie ya escaneada de un dominio
curl -X POST http://localhost:8000/findings/ask \
  -H "Content-Type: application/json" \
  -d '{"domain": "ejemplo.com", "question": "¿algún activo filtra direccionamiento interno?"}'
```

El triaje recibe **contexto estructurado** (hostname, IPs, estado, fuentes,
tipo de hallazgo y evidencia) — nunca la fila de base de datos en bruto — y
responde con una severidad razonada, no una plantilla fija. Un fallo del
proveedor de IA en un hallazgo no aborta los demás; se reporta en `errors`.

## Uso rápido: informe con portada

Ya operativo (Paso 7). Genera y descarga el PDF de un escaneo ya persistido:

```bash
curl -o informe.pdf http://localhost:8000/scans/1/report
```

Regenera el informe en cada descarga (nunca sirve una copia cacheada sin
comprobar nada), así que siempre refleja el triaje más reciente. Incluye
portada (dominio y fecha), resumen ejecutivo con contadores por severidad, y
el detalle de cada activo y hallazgo con su impacto y remediación. También
se descarga desde la pestaña «Escaneos» del dashboard.

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
      │Descubrimien│   │  Capa IA   │   │ PostgreSQL │          │  Informes    │
      │to (scan)   │   │ (triaje)   │   │ (persist.) │          │    (PDF)     │
      └─────┬──────┘   └─────┬──────┘   └────────────┘          └──────────────┘
            │                │
     APIs externas     LLM (Anthropic)
   (crt.sh, OSV,       Claude
    Shodan)
```

Detalle completo en [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).

## Stack

| Capa            | Tecnología                          |
|-----------------|-------------------------------------|
| API             | FastAPI + Uvicorn                   |
| Base de datos   | PostgreSQL (SQLAlchemy 2.0 async)   |
| Descubrimiento  | httpx, dnspython, cryptography      |
| IA              | Anthropic (Claude), abstraído       |
| Dashboard web   | Streamlit                           |
| Orquestación    | Docker Compose                      |

## Cómo cubre los requisitos de la práctica

| Requisito              | En Atalaya                                              |
|------------------------|--------------------------------------------------------|
| Base de datos          | PostgreSQL con modelos de activos / escaneos / hallazgos |
| API o webhook          | API REST propia **y** consumo de APIs externas         |
| Aplicación web         | Dashboard Streamlit (local o desplegado)               |
| GitHub con historial   | Commits por fase, historial real                       |
| Reporte con portada    | PDF generado por la propia herramienta (`GET /scans/{id}/report`) |

## Puesta en marcha

### Con Docker (recomendado)

```bash
cp .env.example .env      # rellena ANTHROPIC_API_KEY
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
- [ ] **Paso 2** — Motor de descubrimiento
  - [x] Subdominios (Certificate Transparency + DNS)
  - [ ] Puertos y servicios
  - [ ] Cabeceras de seguridad HTTP
  - [ ] Configuración TLS
- [x] **Paso 3** — Base de datos + modelos (Scan/Asset/Finding, migraciones Alembic;
      solo persiste subdominios por ahora)
- [x] **Paso 4** — API REST completa
  - [x] `scans` / `assets` / `findings` — creación y lectura real
  - [x] `/scans/{id}/triage`, `/findings/ask` — activados junto al Paso 5
- [x] **Paso 5** — Capa IA
  - [x] `LLMProvider` / `AnthropicProvider`
  - [x] Triaje de hallazgos con contexto estructurado
  - [x] Consulta en lenguaje natural sobre un escaneo
- [x] **Paso 6** — Dashboard completo (escaneos, triaje IA, consulta NL, informe)
- [x] **Paso 7** — Generador de informes (PDF con portada, API + dashboard)

## Aviso legal

Atalaya realiza reconocimiento sobre infraestructura. **Úsalo solo sobre
dominios que te pertenezcan o para los que tengas autorización explícita.**
La variable `SCAN_ALLOWLIST` permite restringir los objetivos permitidos.

## Licencia

MIT — ver [`LICENSE`](LICENSE).
