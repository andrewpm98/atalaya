# Memoria técnica — Paso 1: Arquitectura y esqueleto del proyecto

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 1 de 7 — Diseño arquitectónico y andamiaje del repositorio
**Estado:** Completado y verificado

---

## 1. Resumen ejecutivo

El Paso 1 no produce funcionalidad visible para el usuario final: produce **la estructura que hace posible todo lo demás**. Se ha definido la arquitectura completa del sistema, se ha levantado el esqueleto del repositorio con todos los módulos cableados entre sí, y se ha verificado que la aplicación arranca y responde.

El resultado tangible es un repositorio de 38 ficheros con:

- Una API REST operativa (FastAPI) que arranca, responde y se autodocumenta.
- La capa de persistencia configurada (SQLAlchemy asíncrono sobre PostgreSQL).
- Los contratos de los cuatro módulos de descubrimiento, la capa de IA y el generador de informes.
- Una aplicación web inicial (Streamlit) que ya verifica el estado de la API.
- Orquestación con Docker Compose para levantar todo el stack con un comando.
- Documentación de arquitectura y 7 commits de historial real en Git.
- Dos pruebas automatizadas que pasan correctamente.

La decisión de fondo del Paso 1 es **cerrar la estructura antes de escribir lógica**. Cada requisito obligatorio de la práctica tiene ya un lugar reservado en el código, de modo que ninguno pueda quedarse fuera por olvido cuando el desarrollo avance.

---

## 2. Qué es la herramienta y por qué esta

### 2.1 El problema

Cuando una organización crece, va dejando activos expuestos en Internet sin llevar un control centralizado: subdominios de proyectos antiguos, servidores de pruebas que nunca se apagaron, servicios con certificados caducados, paneles de administración accesibles. Ese conjunto es la **superficie de exposición** (*attack surface*), y el problema no es solo que exista, sino que **nadie tiene un inventario fiable de ella**.

Existen escáneres que enumeran activos, pero generan un volumen de resultados tan grande y tan ruidoso que el informe acaba sin leerse. El cuello de botella real no es detectar, es **priorizar y entender**.

### 2.2 La propuesta

Atalaya recibe un dominio y ejecuta cuatro fases:

1. **Descubrimiento.** Enumera subdominios mediante registros de Certificate Transparency y resolución DNS; detecta puertos y servicios abiertos; analiza las cabeceras de seguridad HTTP; e inspecciona la configuración TLS y los certificados.
2. **Persistencia.** Guarda activos y hallazgos en base de datos, lo que permite comparar escaneos a lo largo del tiempo y detectar cambios en la exposición.
3. **Triaje por IA.** Un modelo de lenguaje recibe los hallazgos ya estructurados y devuelve, para cada uno, una severidad razonada, una explicación del impacto real en lenguaje comprensible y una propuesta de remediación.
4. **Consulta e informe.** El usuario puede preguntar en lenguaje natural sobre su superficie de exposición, y la herramienta genera un informe ejecutivo con portada.

### 2.3 Por qué es una elección defendible

El elemento diferencial no es el escaneo, que es tecnología conocida, sino **la capa de interpretación**. La herramienta traduce un volcado técnico en decisiones accionables.

Frente a las alternativas que se barajaron:

| Alternativa | Motivo de descarte |
|---|---|
| Analizador de ofertas de empleo + CV | Depende de *scraping* frágil de plataformas de terceros; escaso contenido de ciberseguridad |
| Detección en mamografías | Proyecto de *machine learning* de varios meses; inviable en el plazo disponible en solitario |
| Herramienta de phishing | Fricción ética y legal; difícil de acotar de forma responsable |
| **ASM con triaje por IA** | **Reutiliza trabajo previo, combina ciberseguridad e IA, y es una categoría real de producto** |

Además, ASM es una categoría de mercado existente (Tenable ASM, CyCognito, Detectify), lo que convierte el proyecto en una pieza de portfolio verificable y no en un ejercicio académico cerrado en sí mismo.

---

## 3. Arquitectura del sistema

### 3.1 Visión de conjunto

```
        ┌─────────────┐     REST      ┌──────────────┐
        │  Dashboard  │ ◀───────────▶ │     API      │
        │ (Streamlit) │               │  (FastAPI)   │
        └─────────────┘               └──────┬───────┘
                                             │
            ┌────────────────┬───────────────┼───────────────┐
            ▼                ▼               ▼               ▼
     ┌─────────────┐  ┌────────────┐  ┌────────────┐  ┌─────────────┐
     │Descubrimient│  │  Capa IA   │  │ PostgreSQL │  │  Informes   │
     │o (scan)     │  │  (triaje)  │  │(persistenc)│  │ (PDF/DOCX)  │
     └──────┬──────┘  └─────┬──────┘  └────────────┘  └─────────────┘
            │               │
     APIs externas      LLM (Claude)
   (crt.sh, OSV, Shodan)
```

### 3.2 Flujo de datos

```
dominio objetivo
   │  POST /scans
   ▼
[Descubrimiento]  subdominios → puertos → cabeceras → TLS
   │  hallazgos en bruto
   ▼
[PostgreSQL]  se persisten activos y hallazgos
   │
   ▼
[Capa IA]  triaje: severidad + impacto + remediación
   │
   ├──▶ [Dashboard]  visualización y consulta en lenguaje natural
   └──▶ [Informes]   PDF/DOCX con portada
```

### 3.3 Componentes

| Componente | Ubicación | Responsabilidad |
|---|---|---|
| API | `src/atalaya/api/` | Expone la API REST y orquesta el resto de módulos |
| Configuración | `src/atalaya/config.py` | Centraliza los ajustes leídos del entorno |
| Persistencia | `src/atalaya/core/database.py` | Motor asíncrono de base de datos y sesiones |
| Descubrimiento | `src/atalaya/discovery/` | Cuatro técnicas independientes de reconocimiento |
| Capa IA | `src/atalaya/ai/` | Abstracción del LLM y lógica de triaje |
| Informes | `src/atalaya/reporting/` | Generación del informe ejecutivo |
| Aplicación web | `dashboard/app.py` | Interfaz de usuario final |
| Orquestación | `docker-compose.yml`, `docker/` | Levantado del stack completo |

---

## 4. Bloque de entendimiento: los conceptos, explicados

Esta sección existe para que cada decisión del proyecto pueda explicarse sin recurrir a fórmulas memorizadas.

### 4.1 Qué es una API y qué es un *endpoint*

Una **API** (Interfaz de Programación de Aplicaciones) es el conjunto de puertas por las que un programa puede pedirle cosas a otro. No es una pantalla: es un contrato entre máquinas.

Un **endpoint** es cada una de esas puertas concreta, identificada por una dirección. En Atalaya, `/scans` es el endpoint para trabajar con escaneos.

La distinción importante es que **la API es independiente de la interfaz**. El dashboard de Streamlit consume la API, pero también podría hacerlo un script en la terminal, otra aplicación o un agente automatizado. Por eso el profesor insistió en que la API es obligatoria: es lo que convierte una herramienta cerrada en una pieza integrable.

### 4.2 REST, y qué significan GET y POST

**REST** es el estilo arquitectónico más extendido para diseñar APIs sobre HTTP. Su idea central es que todo se modela como **recursos** (escaneos, activos, hallazgos) sobre los que se ejecutan **verbos** estándar:

- **GET** — solicitar información, sin modificar nada. `GET /assets` significa "devuélveme la lista de activos".
- **POST** — enviar datos para que el servidor ejecute una acción o cree algo. `POST /scans` significa "lanza un escaneo nuevo".

Existen otros verbos (PUT, PATCH, DELETE) que se incorporarán si el modelo lo requiere. La ventaja de REST es la previsibilidad: cualquier desarrollador entiende la API sin manual porque sigue convenciones conocidas.

### 4.3 Códigos de estado HTTP

Cada respuesta lleva un número que indica qué ha ocurrido. Los relevantes aquí:

- **200 OK** — la petición se procesó correctamente.
- **404 Not Found** — el recurso solicitado no existe.
- **500 Internal Server Error** — el servidor falló de forma no controlada.
- **501 Not Implemented** — el endpoint existe y está declarado, pero su lógica aún no está construida.

Los endpoints de escaneos, activos y hallazgos devuelven hoy **501 de forma deliberada**. Esta es una decisión de diseño, no una carencia: el contrato de la API queda fijado y públicamente visible desde el primer día, y cada fase posterior lo rellena. La diferencia entre un 501 intencionado y un 500 accidental es precisamente la diferencia entre un proyecto planificado y uno improvisado.

### 4.4 OpenAPI y Swagger UI

Al abrir `http://localhost:8000/docs` aparece una página interactiva que nadie ha programado. FastAPI la genera automáticamente: analiza el código, deduce qué endpoints existen, qué parámetros aceptan y qué devuelven, y construye la documentación.

Esa página se apoya en **OpenAPI**, un estándar abierto para describir APIs. El fichero `/openapi.json` es esa descripción en formato legible por máquinas, y sirve como **evidencia formal de la existencia de la API** durante la defensa.

### 4.5 Programación asíncrona (`async`)

Un escaneo pasa la mayor parte del tiempo **esperando**: esperando a que responda un servidor DNS, a que se establezca una conexión TCP, a que llegue un certificado. En un modelo tradicional, el programa se queda bloqueado en cada espera.

La programación **asíncrona** permite que, mientras una operación espera, el programa atienda otras. Aplicado a Atalaya: en lugar de comprobar 200 subdominios uno detrás de otro, se lanzan en paralelo y se recogen según van respondiendo. La diferencia en tiempo de escaneo es de órdenes de magnitud.

Por eso todo el proyecto —API, base de datos y descubrimiento— está construido sobre `async`. No es una moda: es el patrón correcto para una carga de trabajo dominada por la espera de red.

### 4.6 ORM y base de datos

Un **ORM** (Mapeo Objeto-Relacional) permite trabajar con las tablas de la base de datos como si fueran objetos del lenguaje, en lugar de escribir SQL a mano. Se utiliza **SQLAlchemy 2.0** en modo asíncrono.

Las ventajas concretas: evita la construcción manual de consultas —y con ello una clase entera de vulnerabilidades de inyección SQL—, y desacopla el código del motor de base de datos, lo que permite desarrollar sobre SQLite y desplegar sobre PostgreSQL sin reescribir nada.

El modelo de datos previsto es:

- **Scan** — un escaneo concreto: dominio objetivo, fecha, estado.
- **Asset** — un activo descubierto: subdominio o host, IP, puertos.
- **Finding** — un hallazgo: tipo, evidencia, severidad, remediación.

Con las relaciones `Scan 1─N Asset` y `Asset 1─N Finding`.

### 4.7 Variables de entorno y gestión de secretos

Las claves de API, credenciales de base de datos y parámetros de configuración **no están en el código**. Se leen de variables de entorno mediante un fichero `.env`, que está explícitamente excluido del control de versiones en `.gitignore`.

El repositorio incluye `.env.example`: una plantilla con las variables necesarias y sin valores reales. Es la práctica estándar, y en un proyecto de ciberseguridad es además una cuestión de coherencia: subir una clave a un repositorio es uno de los errores de exposición más frecuentes que la propia herramienta pretende ayudar a detectar.

### 4.8 Entorno virtual (`venv`)

Un entorno virtual es una instalación de Python aislada para un proyecto concreto. Evita que las dependencias de un proyecto interfieran con las de otro y garantiza que la aplicación se ejecute con las versiones esperadas. Es el motivo por el que la puesta en marcha comienza creando `.venv`.

### 4.9 Docker y contenedores

Un **contenedor** empaqueta la aplicación junto con todo lo que necesita para funcionar. Resuelve el problema clásico de "en mi máquina funciona": el contenedor se comporta igual en cualquier sistema.

**Docker Compose** coordina varios contenedores relacionados. En este proyecto levanta tres servicios —base de datos PostgreSQL, API y dashboard— conectados entre sí, con un único comando. Esto facilita tanto la demostración como un despliegue posterior en servidor.

### 4.10 Control de versiones e historial de commits

Un **commit** es una instantánea del proyecto con una descripción de qué cambió. El conjunto de commits forma el **historial**, que documenta la evolución del trabajo.

El repositorio tiene 7 commits que separan unidades lógicas de trabajo, siguiendo la convención *Conventional Commits* (`feat:`, `chore:`, `docs:`, `build:`). Esto responde a un requisito explícito de la práctica —"GitHub con History"— y demuestra un desarrollo progresivo frente a un volcado único de código.

---

## 5. Decisiones de diseño y su justificación

| Decisión | Alternativa considerada | Justificación |
|---|---|---|
| **FastAPI** | Flask, Django | Soporte asíncrono nativo, validación automática con Pydantic y documentación OpenAPI generada sin coste adicional |
| **PostgreSQL** | SQLite, MongoDB | Motor relacional realista, con concurrencia; el modelo de datos es claramente relacional. SQLite queda como alternativa de desarrollo |
| **SQLAlchemy asíncrono** | SQL directo | Coherencia con la arquitectura asíncrona y protección frente a inyección SQL |
| **Capa IA tras interfaz `LLMProvider`** | Llamadas directas al SDK | El modelo pasa a ser un detalle de configuración; se puede sustituir sin tocar la lógica de negocio |
| **Módulos de descubrimiento independientes** | Un único escáner monolítico | Permite añadir, desactivar o probar técnicas de forma aislada |
| **Streamlit** | React, plantillas HTML | Prioriza el tiempo disponible; permite construir la aplicación web sin invertir el plazo en desarrollo frontend |
| **Docker Compose** | Instalación manual | Reproducibilidad y facilidad de demostración y despliegue |
| **`SCAN_ALLOWLIST`** | Sin restricción | Salvaguarda de autorización incorporada desde el diseño |

Un punto merece subrayarse: la arquitectura **estructura el contexto antes de entregárselo al modelo de lenguaje**. La IA no recibe un volcado en bruto, sino hallazgos ya normalizados y persistidos. Esto responde al principio de que la calidad de la salida de un modelo depende directamente de la calidad del contexto que recibe, y es la razón de que el triaje se sitúe después de la persistencia y no antes.

---

## 6. Estructura del repositorio

```
atalaya/
├── README.md                      Presentación y puesta en marcha
├── LICENSE                        Licencia MIT
├── pyproject.toml                 Metadatos y dependencias
├── Makefile                       Comandos abreviados
├── docker-compose.yml             Orquestación de los tres servicios
├── .env.example                   Plantilla de configuración
├── .gitignore                     Exclusiones (incluye .env)
│
├── docker/
│   ├── Dockerfile.api             Imagen de la API
│   └── Dockerfile.dashboard       Imagen del dashboard
│
├── docs/
│   └── ARQUITECTURA.md            Documento de arquitectura
│
├── src/atalaya/
│   ├── config.py                  Configuración desde entorno
│   ├── cli.py                     Interfaz de línea de comandos
│   ├── core/database.py           Motor y sesiones de BD
│   ├── api/
│   │   ├── main.py                Aplicación FastAPI
│   │   └── routes/                scans, assets, findings
│   ├── discovery/                 subdomains, ports, headers, tls
│   ├── ai/                        provider, triage
│   └── reporting/generator.py     Informe ejecutivo
│
├── dashboard/app.py               Aplicación web
└── tests/test_health.py           Pruebas de humo
```

Los módulos de `discovery`, `ai` y `reporting` contienen actualmente funciones declaradas con su firma, documentación y una marca `TODO` que indica la fase en que se implementan. No son código muerto: son **contratos** que fijan qué recibe y qué devuelve cada pieza, de modo que los módulos puedan desarrollarse de forma independiente.

---

## 7. Trazabilidad: requisitos de la práctica

| Requisito obligatorio | Resolución en Atalaya | Estado tras Paso 1 |
|---|---|---|
| **Base de datos** | PostgreSQL con SQLAlchemy; entidades Scan, Asset, Finding | Motor configurado; modelos en Paso 3 |
| **API o webhook** | API REST propia **y** consumo de APIs externas (crt.sh, OSV, Shodan) | Estructura operativa y documentada |
| **Aplicación web** | Dashboard Streamlit | Versión inicial funcional |
| **GitHub con historial** | 7 commits por unidad lógica | Cumplido |
| **Reporte con portada** | Generador de informes integrado en la herramienta | Contrato definido; Paso 7 |

El requisito de la API se cubre por partida doble, lo cual es relevante porque el enunciado admitía ambas formas: Atalaya **ofrece** una API REST propia y **consume** APIs de terceros durante el descubrimiento.

---

## 8. Verificación realizada

No se da por válido nada que no se haya comprobado.

1. **Arranque de la aplicación.** La API se inicia sin errores y responde en `/health` con `{"status": "ok", "version": "0.1.0"}`.
2. **Pruebas automatizadas.** Dos pruebas de humo (`tests/test_health.py`) verifican los endpoints `/health` y `/`. Ambas pasan.
3. **Documentación automática.** Swagger UI se genera correctamente en `/docs` y muestra las cuatro secciones con sus endpoints.
4. **Comportamiento esperado de los contratos.** Los endpoints pendientes devuelven 501, no 500, confirmando que están declarados correctamente.
5. **Integridad del repositorio.** Árbol de trabajo limpio, 7 commits, sin ficheros sensibles ni artefactos de compilación versionados.

### Historial de commits

```
docs: documento de arquitectura y hoja de ruta por fases
feat(dashboard): panel Streamlit inicial + tests de humo de la API
feat: contratos de descubrimiento, capa IA y generación de informes
feat(api): esqueleto FastAPI con /health y routers de scans/assets/findings
feat(core): configuración por entorno y motor de BD asíncrono (SQLAlchemy)
build: docker-compose (postgres, api, dashboard) y entorno de desarrollo
chore: estructura inicial del proyecto (licencia, readme, pyproject)
```

---

## 9. Consideraciones legales y éticas

Atalaya realiza reconocimiento sobre infraestructura de red. Aunque las técnicas empleadas en el Paso 2 son de naturaleza pasiva o de baja intrusividad —consulta de registros públicos de Certificate Transparency, resolución DNS, conexiones a puertos e inspección de certificados—, su uso sobre infraestructura ajena sin autorización puede constituir una infracción.

Por ello el diseño incorpora desde el inicio:

- La variable **`SCAN_ALLOWLIST`**, que restringe los dominios sobre los que la herramienta acepta operar.
- Un **aviso legal explícito** en el README.
- El compromiso de realizar todas las pruebas sobre **dominios propios o entornos de laboratorio autorizados**.

Incorporar el control de autorización en la fase de diseño, y no como un añadido posterior, es coherente con el propio objeto del proyecto.

---

## 10. Limitaciones actuales

Declaradas de forma explícita, porque conviene anticiparlas antes de que se pregunten por ellas:

- **No hay funcionalidad de escaneo todavía.** El Paso 1 entrega estructura verificada, no capacidad operativa.
- **Los modelos de base de datos no están definidos.** Existe el motor, no las tablas.
- **La capa de IA es una interfaz sin implementación.**
- **No hay autenticación en la API.** Es asumible mientras el despliegue sea local; si se publica en un servidor con IP pública, pasa a ser un requisito previo ineludible.
- **El dashboard es mínimo.** Comprueba el estado de la API y poco más.

Todas estas limitaciones corresponden a fases posteriores ya planificadas.

---

## 11. Bloque de defensa: preguntas previsibles

### Sobre la elección del proyecto

**¿Por qué esta herramienta y no otra de las propuestas?**
Porque combina las dos disciplinas del máster en un mismo artefacto y porque su valor diferencial —el triaje por IA— ataca un problema real: los escáneres generan más ruido del que un equipo puede procesar. Además reutiliza un desarrollo propio previo de análisis de cabeceras HTTP, lo que permitía alcanzar profundidad técnica dentro del plazo disponible.

**¿No es esto lo mismo que Nmap o Shodan?**
No. Nmap escanea puertos y Shodan indexa dispositivos expuestos; ambos son fuentes de datos. Atalaya se sitúa una capa por encima: correlaciona activos, los persiste para poder comparar en el tiempo y añade una capa de interpretación que prioriza y explica. De hecho, Shodan está contemplado como fuente consumida, no como competidor.

### Sobre la arquitectura

**¿Por qué FastAPI y no Flask o Django?**
Por tres razones concretas: soporte asíncrono nativo, que es determinante en una carga de trabajo dominada por la espera de red; validación automática de datos mediante Pydantic; y generación automática de documentación OpenAPI, que además sirve como evidencia formal de la API.

**¿Por qué PostgreSQL y no SQLite?**
SQLite no gestiona bien la concurrencia de escritura, y un escaneo asíncrono escribe muchos hallazgos en paralelo. PostgreSQL es además el motor realista en un despliegue de producción. SQLite se mantiene como alternativa de desarrollo, algo que el ORM permite sin cambiar código.

**¿Por qué no una base de datos de grafos como Neo4j?**
Es una opción razonable si el objetivo prioritario fuera el análisis relacional entre activos, y se contempla como evolución futura. Para el alcance actual, el modelo es claramente tabular —escaneos, activos y hallazgos con relaciones jerárquicas simples— y un motor relacional lo cubre con menos complejidad operativa. Introducir un segundo motor sin necesidad funcional añadiría coste sin aportar valor dentro del plazo.

**¿Por qué hay endpoints que devuelven 501?**
Porque el contrato de la API se fija en el diseño y se implementa por fases. Un 501 indica que el endpoint existe y está declarado pero su lógica está pendiente; sería un problema si devolviera 500, que señalaría un fallo no controlado. Fijar el contrato desde el principio permite que el dashboard y las pruebas se desarrollen contra una interfaz estable.

### Sobre la capa de IA

**¿Qué aporta la IA que no pueda hacerse con reglas?**
Un sistema de reglas puede clasificar un hallazgo como "certificado caducado". Lo que no puede hacer es razonar sobre la combinación de hallazgos en un contexto concreto ni redactar una explicación de impacto comprensible para un responsable no técnico. El triaje por IA correlaciona señales y produce una priorización justificada, no una simple etiqueta.

**¿Cómo se evita que el modelo invente información?**
El modelo no descubre nada: recibe exclusivamente hallazgos ya verificados, normalizados y persistidos, y su función es clasificar y explicar sobre esa evidencia. Esta es precisamente la razón de que el triaje se sitúe después de la persistencia en el flujo. Cada hallazgo conserva su evidencia técnica original, de forma que toda afirmación del modelo es contrastable contra el dato que la originó.

**¿Qué ocurre si el proveedor de IA falla o cambia?**
La capa está aislada tras la interfaz `LLMProvider`. El proveedor y el modelo son parámetros de configuración en el fichero `.env`, no dependencias incrustadas en la lógica de negocio.

### Sobre seguridad y legalidad

**¿Es legal escanear dominios de terceros?**
Depende de la técnica y de la jurisdicción. La consulta de registros de Certificate Transparency y la resolución DNS son consultas a fuentes públicas. El escaneo de puertos sobre infraestructura ajena sin autorización sí puede ser problemático. Por eso el proyecto incorpora la salvaguarda `SCAN_ALLOWLIST` desde el diseño y todas las pruebas se realizan sobre dominios propios o entornos autorizados.

**¿Cómo se protegen las credenciales?**
No hay secretos en el código. Se cargan desde variables de entorno mediante un fichero `.env` excluido del control de versiones; el repositorio solo contiene una plantilla sin valores.

**¿La API no está expuesta sin autenticación?**
En despliegue local no supone riesgo. Si se publica en un servidor con IP pública, la autenticación pasa a ser requisito previo. Está identificado como tal y documentado entre las limitaciones.

### Preguntas de comprensión

**Explica qué es una API con tus palabras.**
Es el conjunto de puertas por las que otro programa puede pedirle cosas al mío, con un contrato definido de qué se envía y qué se devuelve. No es la interfaz visual: es la capa que permite que la herramienta se integre con otros sistemas en lugar de quedar aislada.

**¿Qué diferencia hay entre GET y POST?**
GET solicita información sin modificar el estado del sistema. POST envía datos para que el servidor ejecute una acción o cree un recurso. `GET /assets` devuelve los activos; `POST /scans` lanza un escaneo nuevo.

**¿Por qué todo el código es asíncrono?**
Porque el escaneo consiste en esperar respuestas de red. De forma síncrona, comprobar doscientos subdominios significa esperar doscientas veces de manera consecutiva. De forma asíncrona se lanzan en paralelo y se procesan según responden, reduciendo el tiempo total en órdenes de magnitud.

**¿Qué es el fichero `/openapi.json`?**
La descripción formal de la API en formato estándar OpenAPI, generada automáticamente a partir del código. Documenta todos los endpoints, sus parámetros y sus respuestas de forma legible por máquinas.

---

## 12. Próximos pasos

| Fase | Contenido | Requisito que consolida |
|---|---|---|
| **Paso 2** | Motor de descubrimiento: subdominios, puertos, cabeceras, TLS | Consumo de APIs externas |
| **Paso 3** | Modelos de base de datos y persistencia | Base de datos |
| **Paso 4** | Implementación completa de los endpoints REST | API |
| **Paso 5** | Capa de IA: triaje y consulta en lenguaje natural | Componente diferencial |
| **Paso 6** | Dashboard completo | Aplicación web |
| **Paso 7** | Generador de informes con portada | Reporte |

---

## 13. Conclusión del Paso 1

El Paso 1 entrega una base verificada sobre la que construir: la aplicación arranca, las pruebas pasan, la documentación se genera y el historial de control de versiones refleja un desarrollo progresivo.

La aportación principal de esta fase no es código funcional, sino **una arquitectura en la que cada requisito obligatorio tiene asignado un lugar concreto**. Ese es el criterio que reduce el riesgo de llegar al cierre del plazo descubriendo que falta una pieza exigida, que es el modo habitual en que se suspende este tipo de entregas.
