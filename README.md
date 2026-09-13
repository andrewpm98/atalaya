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
5. **Informa** — genera un informe ejecutivo con portada (PDF/DOCX).

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
      │to (scan)   │   │ (triaje)   │   │ (persist.) │          │ (PDF/DOCX)   │
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
| Reporte con portada    | Informe generado por la propia herramienta             |

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
- [ ] **Paso 3** — Base de datos + modelos
- [ ] **Paso 4** — API REST completa + APIs externas
- [ ] **Paso 5** — Capa IA (triaje + consulta NL)
- [ ] **Paso 6** — Dashboard completo
- [ ] **Paso 7** — Generador de informes

## Aviso legal

Atalaya realiza reconocimiento sobre infraestructura. **Úsalo solo sobre
dominios que te pertenezcan o para los que tengas autorización explícita.**
La variable `SCAN_ALLOWLIST` permite restringir los objetivos permitidos.

## Licencia

MIT — ver [`LICENSE`](LICENSE).
