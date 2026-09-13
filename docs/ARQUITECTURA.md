# Arquitectura de Atalaya

## 1. Objetivo

Atalaya es una plataforma de **Attack Surface Management (ASM)**: a partir de un
dominio, descubre los activos que una organización expone en Internet, evalúa su
riesgo y emplea un LLM para priorizar y explicar los hallazgos. El valor
diferencial no es escanear (hay muchas herramientas que lo hacen), sino
**convertir un volcado técnico ruidoso en decisiones accionables** mediante IA.

## 2. Visión de componentes

### 2.1 API (FastAPI) — `src/atalaya/api`
Núcleo de la aplicación. Expone la API REST propia (requisito de la práctica) y
orquesta el resto de módulos. Endpoints principales:

- `POST /scans` — lanza un escaneo sobre un dominio.
- `GET  /scans`, `GET /scans/{id}` — consulta de escaneos.
- `GET  /assets` — activos descubiertos.
- `GET  /findings` — hallazgos priorizados por IA.
- `POST /findings/ask` — consulta en lenguaje natural.

### 2.2 Descubrimiento — `src/atalaya/discovery`
Cada técnica es un módulo independiente con salida normalizada:

| Módulo         | Qué obtiene                                    | Fuente                  |
|----------------|------------------------------------------------|-------------------------|
| `subdomains`   | Subdominios                                    | crt.sh (CT logs) + DNS  |
| `ports`        | Puertos/servicios abiertos                     | Escaneo asíncrono       |
| `headers`      | Cabeceras de seguridad HTTP                    | header-analyzer (reuso) |
| `tls`          | Versión TLS, certificado, caducidad            | `cryptography`          |

### 2.3 Persistencia (PostgreSQL) — `src/atalaya/core`
Modelo de datos relacional. Entidades previstas (Paso 3):

- **Scan** — un escaneo (dominio objetivo, fecha, estado).
- **Asset** — activo descubierto (subdominio/host, IP, puertos).
- **Finding** — hallazgo (tipo, evidencia, severidad, remediación, `scan_id`).

Relaciones: `Scan 1─N Asset`, `Asset 1─N Finding`.

### 2.4 Capa IA — `src/atalaya/ai`
- `provider` — abstracción del LLM (Anthropic por defecto, intercambiable).
- `triage` — recibe hallazgos crudos y devuelve severidad, impacto explicado y
  remediación. Aquí se aplica el principio que el proyecto asume como central:
  **dar a la IA contexto estructurado, no datos en bruto**.

### 2.5 Informes — `src/atalaya/reporting`
Genera un informe ejecutivo con portada (PDF/DOCX) a partir de un escaneo.
Cubre el requisito de "reporte con portada" de forma automatizada.

### 2.6 Dashboard (Streamlit) — `dashboard/`
Aplicación web que consume la API: lanzar escaneos, explorar activos y
hallazgos, y consultar en lenguaje natural.

## 3. Flujo de datos

```
dominio
   │  POST /scans
   ▼
[Descubrimiento]  subdominios → puertos → cabeceras → TLS
   │  hallazgos crudos
   ▼
[PostgreSQL]  se persisten activos y hallazgos
   │
   ▼
[Capa IA]  triaje: severidad + impacto + remediación
   │
   ├──▶ [Dashboard]  visualización y consulta NL
   └──▶ [Informes]   PDF/DOCX con portada
```

## 4. Decisiones de diseño

- **FastAPI** por rendimiento asíncrono y documentación OpenAPI automática, que
  además sirve de evidencia de la API en la defensa.
- **PostgreSQL** frente a SQLite en producción por concurrencia y por ser un
  motor realista; SQLite queda como fallback de desarrollo.
- **Capa IA desacoplada** tras una interfaz `LLMProvider`: el modelo es un
  detalle de configuración, no una dependencia rígida.
- **Módulos de descubrimiento independientes**: se pueden añadir o desactivar
  técnicas sin tocar el resto del sistema.
- **Salvaguarda de autorización** (`SCAN_ALLOWLIST`): limita los objetivos
  escaneables, alineado con un uso responsable de la herramienta.

## 5. Mapa de requisitos → implementación

| Requisito de la práctica | Dónde se resuelve                          |
|--------------------------|--------------------------------------------|
| Base de datos            | `core/database.py` + modelos (Paso 3)      |
| API / webhook            | `api/` (propia) + `discovery/` (consumo)   |
| Aplicación web           | `dashboard/app.py`                         |
| GitHub con historial     | Commits por fase                           |
| Reporte con portada      | `reporting/generator.py`                   |

## 6. Hoja de ruta

1. **Paso 1 — Arquitectura + esqueleto** ✅
2. **Paso 2 — Motor de descubrimiento**
3. **Paso 3 — Base de datos + modelos**
4. **Paso 4 — API REST completa + APIs externas**
5. **Paso 5 — Capa IA (triaje + consulta NL)**
6. **Paso 6 — Dashboard completo**
7. **Paso 7 — Generador de informes**
