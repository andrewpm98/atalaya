# Atalaya — contexto del proyecto

Plataforma de **Attack Surface Management (ASM) con triaje por IA**. Entrega
de la Práctica 1 de un Máster en Ciberseguridad e IA. Desarrollo en solitario.

---

## Requisitos obligatorios de la entrega

El enunciado es explícito: **si falta uno de estos puntos, la práctica está
suspensa**. Cualquier decisión de diseño debe respetarlos.

| Requisito | Cómo se cubre | Estado |
|---|---|---|
| Base de datos | PostgreSQL + SQLAlchemy async | ⬜ Motor configurado, modelos pendientes |
| API o webhook | API REST propia **y** consumo de APIs externas | 🔨 Estructura lista, endpoints en 501 |
| Aplicación web | Dashboard Streamlit | 🔨 Versión mínima |
| GitHub con historial | Commits por unidad lógica | ✅ 10 commits |
| Reporte con portada | Informe generado por la herramienta | ⬜ Paso 7 |

**El historial de commits se evalúa.** No agrupar trabajo de varias fases en
un commit único; el desarrollo progresivo es parte de lo que se califica.

---

## Qué hace la herramienta

Recibe un dominio y ejecuta cuatro fases:

1. **Descubrimiento** — subdominios (Certificate Transparency + DNS), puertos,
   cabeceras de seguridad HTTP, configuración TLS.
2. **Persistencia** — activos y hallazgos en base de datos, para comparar
   escaneos en el tiempo.
3. **Triaje por IA** — un LLM prioriza hallazgos, explica impacto real y
   propone remediación. **Es el componente diferencial del proyecto.**
4. **Consulta e informe** — preguntas en lenguaje natural e informe ejecutivo.

---

## Estado del código

### Implementado y verificado

```
src/atalaya/
├── config.py                    Configuración desde entorno (.env)
├── cli.py                       CLI con subcomando `subdomains`
├── core/
│   ├── database.py              Engine async + Base declarativa (sin modelos)
│   ├── exceptions.py            AtalayaError, UnauthorizedTargetError, ...
│   ├── authorization.py         ensure_authorized() — SCAN_ALLOWLIST
│   └── netutils.py              classify_ip() — 10 alcances de red
├── discovery/
│   ├── models.py                SubdomainRecord, SubdomainScanResult
│   └── subdomains.py            Enumeración completa (crt.sh + DNS)
└── api/main.py                  FastAPI operativo, /health responde
```

Validado sobre `github.com`: 117 subdominios descubiertos, 61 activos,
55 objetivos de escaneo, 19 segundos. **70 tests en verde.**

### Pendiente (stubs con contrato definido)

| Fichero | Fase | Qué falta |
|---|---|---|
| `discovery/ports.py` | Paso 2 | Escaneo asíncrono de puertos |
| `discovery/headers.py` | Paso 2 | Cabeceras de seguridad HTTP |
| `discovery/tls.py` | Paso 2 | Certificados y versión TLS |
| `core/database.py` | Paso 3 | Modelos Scan / Asset / Finding |
| `api/routes/*.py` | Paso 4 | 6 endpoints devuelven 501 a propósito |
| `ai/provider.py`, `ai/triage.py` | Paso 5 | Capa de IA |
| `dashboard/app.py` | Paso 6 | Panel completo |
| `reporting/generator.py` | Paso 7 | Informe con portada |

Los stubs **no son código muerto**: fijan qué recibe y devuelve cada pieza.
Respeta esas firmas salvo que haya razón para cambiarlas, y si cambias una,
dilo.

---

## Hoja de ruta

1. ~~Paso 1 — Arquitectura y esqueleto~~ ✅
2. **Paso 2 — Motor de descubrimiento** — subdominios ✅ · puertos, cabeceras, TLS ⬜
3. Paso 3 — Modelos de BD y persistencia
4. Paso 4 — Endpoints REST completos
5. Paso 5 — Capa de IA (triaje + consulta NL)
6. Paso 6 — Dashboard completo
7. Paso 7 — Informe con portada

**Orden en discusión:** se valora adelantar el Paso 3 (persistencia) antes de
completar el resto del descubrimiento, para que los módulos nuevos nazcan ya
guardando resultados en lugar de requerir adaptación posterior.

**Plazo:** entrega a finales de septiembre. Priorizar cerrar los cinco
requisitos obligatorios sobre pulir cualquiera de ellos.

---

## Convenciones del proyecto

### Código

- Python 3.11+, **todo asíncrono** (la carga está dominada por espera de red).
- Type hints en todas las firmas. `from __future__ import annotations`.
- Docstrings en español, explicando **por qué**, no solo qué.
- Pydantic para datos que cruzan una frontera (entrada externa, respuesta API).
- Línea máxima 100 caracteres (`ruff`).

### Manejo de errores

Principio establecido y aplicado en `subdomains.py`: **degradación controlada**.

- Una fuente externa caída **no aborta el escaneo**: se reintenta con backoff
  y, si falla, se registra en `result.errors` y se continúa.
- Las funciones que procesan un elemento de una colección (un host, un puerto)
  **nunca lanzan excepción**: reflejan el fallo en el estado del resultado.
- Las excepciones propias (`core/exceptions.py`) se reservan para condiciones
  que sí deben detener la operación: objetivo inválido o no autorizado.

### Tests

- **Deterministas y sin red.** Las fuentes externas se sustituyen por dobles:
  HTTP con `httpx.MockTransport`, DNS sustituyendo la función del resolver.
- Un fallo en la suite debe indicar siempre un problema del código, nunca una
  caída de servicio.
- Cubrir casos límite y los de seguridad, no solo el camino feliz.
- Ejecutar `pytest -q` antes de dar por terminado cualquier cambio.

### Commits

Convención `feat:` / `fix:` / `chore:` / `docs:` / `build:`, con ámbito:

```
feat(discovery): escaneo asíncrono de puertos con detección de servicios
fix(netutils): excluir multicast de las direcciones enrutables
```

Un commit por unidad lógica. No mezclar fases.

---

## Restricciones de seguridad — no negociables

Esta es una herramienta de reconocimiento. El proyecto se califica también por
cómo trata esto.

1. **Toda fase de descubrimiento pasa por `ensure_authorized()`** antes de
   tocar la red. Sin excepciones.
2. **Solo se escanean direcciones enrutables.** Usa
   `SubdomainScanResult.scan_targets()`, nunca `unique_ips()`. Sin ese filtro,
   un objetivo `127.0.0.1` haría que la herramienta escanee la propia máquina
   que la ejecuta, y `0.0.0.0` produciría conexiones sin destino.
3. **Nada de secretos en el código.** Todo por `.env`, que está en
   `.gitignore`. Solo se versiona `.env.example`.
4. **Comparación de dominios con el punto separador.** `endswith("ejemplo.com")`
   aceptaría `ejemplo.com.evil.net`, que un atacante puede registrar para
   inyectar activos ajenos en el inventario. Hay un test que lo cubre.
5. **Escaneo de puertos: intrusividad acotada.** Cuando se implemente, limitar
   concurrencia y ritmo. Un escaneo agresivo puede degradar el servicio del
   objetivo y es indistinguible de un ataque.
6. **Nunca verificar explotabilidad.** La herramienta señala patrones de riesgo
   (p. ej. un nombre apuntando a hosting no reclamado); no comprueba si son
   explotables. Eso excede el reconocimiento y requiere autorización expresa.

---

## Decisiones ya tomadas (no reabrir sin motivo)

| Decisión | Motivo |
|---|---|
| FastAPI | Async nativo, validación Pydantic, OpenAPI automático |
| PostgreSQL, no SQLite en producción | Concurrencia de escritura durante escaneos |
| No Neo4j por ahora | El modelo es tabular; un segundo motor añade coste sin valor en plazo |
| Streamlit, no React | El plazo no permite invertirlo en frontend |
| Capa IA tras interfaz `LLMProvider` | El modelo es configuración, no dependencia rígida |
| Triaje IA **después** de persistir | La IA clasifica y explica sobre evidencia verificada; no descubre |
| Endpoints en 501, no ausentes | El contrato de la API se fija en diseño y se rellena por fases |

---

## Deuda técnica conocida

- **Sin consulta de registros CNAME.** En el escaneo de `github.com` unos 50
  hosts quedaron en `no_answer`: existen pero sin A/AAAA, probablemente con
  CNAME. Importa porque **un CNAME apuntando a un recurso no reclamado es la
  señal característica del subdomain takeover**. Incorporar cuando la capa IA
  lo necesite.
- **Fuente única de enumeración** (crt.sh). `SHODAN_API_KEY` ya está previsto
  en la configuración para ampliar cobertura.
- **Sin detección de comodines DNS.** Un dominio que resuelve cualquier
  subdominio inexistente inflaría el recuento de activos.
- **API sin autenticación.** Asumible en local; bloqueante si se despliega con
  IP pública.
- **Variabilidad del DNS.** Dos escaneos del mismo dominio no dan resultados
  idénticos (timeouts, balanceo, caché). Es normal, y refuerza la necesidad de
  persistir escaneos para distinguir un cambio real de una fluctuación.

---

## Comandos

```bash
pip install -e ".[dev]"              # instalar con dependencias de desarrollo
pytest -q                            # tests (deben pasar los 70)
uvicorn atalaya.api.main:app --reload # API en :8000, docs en /docs
streamlit run dashboard/app.py       # dashboard en :8501
atalaya subdomains ejemplo.com       # CLI de enumeración
ruff check src tests                 # linter
docker compose up --build            # stack completo
```

**Dominio de pruebas:** `scanme.nmap.org`, mantenido por el autor de Nmap
explícitamente para reconocimiento autorizado.

---

## Cómo quiero trabajar

- Explica el **porqué** de las decisiones, no solo el qué. El proyecto se
  defiende oralmente y necesito entender cada pieza.
- Análisis directo y con datos. Si algo no funciona o es mala idea, dilo.
- Ejecuta los tests antes de dar nada por terminado.
- Al terminar una tarea: qué has cambiado, cómo probarlo, qué commit hacer.
- Si detectas un defecto en lo ya implementado, señálalo aunque no sea el
  encargo. Ya ocurrió una vez con un falso positivo (`0.0.0.0` contado como
  activo) y corregirlo a tiempo evitó que contaminara la fase siguiente.
