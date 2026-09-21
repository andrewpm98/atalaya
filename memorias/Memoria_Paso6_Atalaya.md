# Memoria técnica — Paso 6: Dashboard completo

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 6 de 7 — Aplicación web (Streamlit) sobre la API completa
**Estado:** Completado y verificado

---

## 1. Resumen ejecutivo

El Paso 6 cierra el requisito obligatorio de **aplicación web**: hasta ahora
el dashboard (Paso 1) solo comprobaba el estado de la API. Esta fase lo
convierte en el cliente completo de todo lo construido en los Pasos 2 a 5 —
lanzar escaneos, explorar activos y hallazgos, triar con IA y preguntar en
lenguaje natural— sin tocar la base de datos ni los módulos de `core` o
`discovery` directamente: el dashboard es, deliberadamente, un cliente HTTP
más de la API, igual que lo sería un script externo.

Resultados tangibles:

- `dashboard/app.py` reescrito con tres pestañas: **Nuevo escaneo**,
  **Escaneos** (listado, detalle, triaje) y **Preguntar** (consulta NL).
- Cliente HTTP propio (`api_get`/`api_post`) con degradación controlada: un
  fallo de la API se muestra en la propia página (`st.error`), nunca
  interrumpe el script con una excepción de Python.
- Botón de triaje que refresca el detalle del escaneo en la misma ejecución,
  sin depender de `st.rerun()`.
- **10 pruebas automatizadas nuevas** (124 en total: 114 + 10), usando
  `streamlit.testing.v1.AppTest` — sin navegador y sin una API real
  escuchando durante los tests.
- Un commit, hasta 30 en el repositorio.

---

## 2. Qué se ha construido

### 2.1 Componentes

| Fichero | Responsabilidad | Estado |
|---|---|---|
| `dashboard/app.py` | Panel completo: nuevo escaneo, listado/detalle, triaje, consulta NL | Reescrito (230 líneas añadidas) |
| `tests/test_dashboard.py` | 10 pruebas de la interfaz vía `AppTest` | Nuevo (329 líneas) |

### 2.2 Estructura de la página

```
Barra lateral
 └─ Estado del sistema — GET /health, con degradación si la API no responde

Pestaña "Nuevo escaneo"
 └─ Formulario (dominio, checkbox "Verificar por DNS") → POST /scans

Pestaña "Escaneos"
 ├─ Tabla de escaneos — GET /scans
 ├─ Selector de escaneo → GET /scans/{id}
 └─ Detalle: métricas, botón de triaje, activos con sus hallazgos

Pestaña "Preguntar"
 └─ Formulario (dominio, pregunta) → POST /findings/ask
```

### 2.3 Flujo del triaje desde el dashboard

```
Detalle de un escaneo con N hallazgos "unknown"
   │
   ▼
[botón "🧠 Triar con IA (N pendiente(s))"]
   │
   ▼
POST /scans/{id}/triage
   │  {"triaged": k, "errors": [...]}
   ▼
st.success / st.warning (si hubo fallos)
   │
   ▼
GET /scans/{id}   ← recarga en la misma ejecución
   │
   ▼
render_scan_detail(scan_actualizado)   métricas y severidades al día
```

---

## 3. Bloque de entendimiento: los conceptos

### 3.1 Por qué el dashboard no usa `async`

El resto del proyecto es asíncrono porque el descubrimiento lanza decenas de
operaciones de red en paralelo (Paso 2): ahí `async` reduce el tiempo total
en órdenes de magnitud. El dashboard no tiene ese patrón: Streamlit
reejecuta el script completo en cada interacción del usuario y en cada
ejecución solo hay, como mucho, una petición HTTP pendiente a la vez. Envolver
esa única llamada en `asyncio.run()` añadiría la complejidad de gestionar un
bucle de eventos sin nada que paralelizar — se usa `httpx.Client` síncrono,
la herramienta que corresponde a la carga de trabajo real de esta capa.

### 3.2 El modelo de ejecución de Streamlit y por qué importa aquí

Streamlit no mantiene un estado de sesión implícito entre interacciones del
usuario del modo en que lo haría un framework de página única: cada clic,
cada tecla en un formulario, **reejecuta el script completo de arriba a
abajo**. Esto tiene una consecuencia directa en el diseño del dashboard: no
existen controladores de eventos aislados (`onClick`), sino un guion
imperativo que se relee entero, y cualquier dato que deba sobrevivir entre
ejecuciones debe guardarse explícitamente en `st.session_state`.

### 3.3 Degradación controlada aplicada a la interfaz de usuario

El mismo principio que rige el descubrimiento (Paso 2) y el triaje (Paso 5)
se traslada aquí en su propia forma: **un fallo de la API nunca debe tumbar
la página**. `api_get`/`api_post` capturan `httpx.HTTPError` (la API no
responde) y comprueban el código de estado (la API respondió con un error),
y en ambos casos devuelven `None` tras mostrar `st.error` con el detalle —
nunca dejan escapar una excepción hacia el resto del script. Cada llamador
comprueba `if resultado is not None:` antes de seguir, el mismo patrón que
`resolve_hostname` (Paso 2) o `triage_finding` (Paso 5) aplican a su propio
nivel: ningún fallo puntual debe abortar el resto de lo que la página puede
seguir mostrando.

### 3.4 Por qué el triaje se refresca sin `st.rerun()`

Tras `POST /scans/{id}/triage`, el dashboard necesita mostrar dos cosas a la
vez: el mensaje de éxito de la llamada que se acaba de hacer, y las
severidades actualizadas de los hallazgos. La forma obvia de refrescar datos
en Streamlit es `st.rerun()` — forzar una nueva ejecución completa del
script —, pero eso tiene un efecto colateral: al reiniciar la ejecución, los
mensajes `st.success`/`st.warning` que se acaban de emitir se pierden antes
de que el usuario llegue a verlos, porque pertenecían a la ejecución
anterior.

La solución adoptada es más simple: dentro de la **misma** ejecución, tras
procesar el `POST`, se hace un `GET /scans/{id}` adicional y se reasigna la
variable local `scan` con el resultado. El resto de la función
(`render_scan_detail`) sigue leyendo de esa variable ya actualizada. No hay
recarga de página, solo una relectura de datos antes de renderizar el resto
del componente.

### 3.5 Formularios (`st.form`) frente a widgets sueltos

Tanto "Nuevo escaneo" como "Preguntar" usan `st.form`: agrupa varios campos
para que **no** se reejecute el script en cada tecla, solo al enviar. La
alternativa —un `st.text_input` suelto— dispararía una petición
potencialmente cara (un escaneo, una llamada a un LLM) en un estado
intermedio si el usuario, por ejemplo, pulsara Enter por accidente en un
campo aún incompleto. El formulario retiene los valores hasta que
`st.form_submit_button` se pulsa explícitamente.

---

## 4. Decisiones de diseño

| Decisión | Justificación |
|---|---|
| El dashboard consume solo la API REST, nunca `core`/`discovery` directamente | Es un cliente más de la API, en igualdad de condiciones que la CLI o cualquier integración externa (`docs/ARQUITECTURA.md`, 2.6) |
| `httpx.Client` síncrono, no `asyncio.run()` por llamada | Streamlit ya serializa la interacción del usuario en un script que se reejecuta completo; no hay nada que paralelizar en una sola petición HTTP (sección 3.1) |
| `api_get`/`api_post` nunca lanzan excepción, devuelven `None` y muestran `st.error` | Mismo criterio de degradación controlada que el resto del proyecto; un fallo puntual de la API no debe tumbar el resto de la página |
| Triaje: relectura del escaneo en la misma ejecución, no `st.rerun()` | `st.rerun()` descartaría los mensajes de éxito/aviso antes de que el usuario los vea (sección 3.4) |
| `st.form` para "Nuevo escaneo" y "Preguntar" | Evita disparar una petición cara (escaneo, llamada a IA) en un estado intermedio del formulario |
| Iconos de severidad (`_SEVERITY_ICON`) como diccionario fijo, no lógica condicional dispersa | Una sola fuente de verdad para la representación visual de cada severidad, reutilizada en `render_finding` |

---

## 5. Validación

### 5.1 Pruebas automatizadas

**10 pruebas nuevas, 124 en total (114 + 10), todas en verde:**

| Bloque | Nº | Qué cubre |
|---|---|---|
| Arranque y degradación | 3 | Sin API disponible (`ConnectError`), listado vacío, error de la API mostrado sin excepción |
| Nuevo escaneo | 2 | Éxito con resumen, dominio vacío no llama a la API |
| Escaneos: listado, detalle y triaje | 3 | Métricas y activos del detalle, triaje refresca sin `rerun`, triaje con fallos muestra los errores |
| Preguntar | 2 | Respuesta mostrada, 404 sin escaneo previo mostrado como error |

Se usa `streamlit.testing.v1.AppTest`, que ejecuta el script en un entorno
controlado e inspecciona los elementos renderizados (`at.tabs[i].success`,
`.error`, `.metric`, `.dataframe`...) sin un navegador real. `httpx.Client`
se sustituye por `_fake_client`, un doble que responde según ruta y método —
mismo criterio de determinismo que `httpx.MockTransport` en el Paso 2: un
fallo aquí debe indicar siempre un problema en `dashboard/app.py`, nunca que
la API real esté caída, por lo que ninguna prueba la levanta.

Un detalle del doble merece explicarse: `get_map` acepta una respuesta fija
o una **lista** de respuestas, que se consumen en orden. Es lo que permite
probar `test_triage_refresca_sin_rerun`: la misma ruta `GET /scans/1` debe
devolver el escaneo *sin* triar en la carga inicial y *con* la severidad
actualizada tras el `POST` de triaje, dentro de la misma ejecución del
script.

### 5.2 Verificación manual

Se lanzó `streamlit run dashboard/app.py` contra la API real (`uvicorn`) en
ejecución, con `scanme.nmap.org` como dominio de prueba: el flujo completo
—lanzar el escaneo, ver el detalle en la pestaña "Escaneos", triar (sin
`ANTHROPIC_API_KEY`, lo que ejercitó el aviso de error) y preguntar en
lenguaje natural— se recorrió de extremo a extremo en el navegador.

---

## 6. Consideraciones legales y éticas

Esta fase no añade superficie de exposición nueva: el dashboard no
interactúa con ningún objetivo de reconocimiento, solo con la propia API de
Atalaya. La consideración relevante es que el formulario de "Nuevo escaneo"
es ahora el punto de entrada más accesible para lanzar un escaneo — sigue
pasando íntegramente por `ensure_authorized()`/`SCAN_ALLOWLIST` en el
servidor, sin ninguna comprobación adicional ni distinta en el cliente, lo
que evita que exista una vía para eludir la salvaguarda desde la interfaz
web.

---

## 7. Limitaciones actuales

- **Sin autenticación en el dashboard**, coherente con la ausencia de
  autenticación ya declarada en la API (Paso 1, Paso 4): asumible en local.
- **Sin paginación en el listado de escaneos.** Hereda el límite de
  `list_scans` (por defecto 50); con un histórico muy grande, la tabla
  crecería sin control de scroll o filtrado adicional.
- **La consulta NL no recuerda el historial de preguntas.** Cada pregunta es
  independiente; no hay una conversación con memoria de turnos anteriores.
- **El triaje se lanza sobre todo el escaneo, no por hallazgo individual.**
  No hay forma de triar selectivamente un único hallazgo desde la interfaz.

---

## 8. Bloque de defensa: preguntas previsibles

### Sobre la arquitectura del dashboard

**¿Por qué el dashboard no accede directamente a la base de datos?**
Porque entonces dejaría de ser un cliente de la API y pasaría a duplicar su
lógica de negocio con otro camino de acceso a los mismos datos. Consumir
solo la API REST demuestra, además, que la API es autosuficiente: cualquier
otra interfaz (una CLI, una integración de terceros) podría sustituir al
dashboard sin tocar el backend.

**¿Por qué Streamlit reejecuta el script entero en cada interacción, y qué
implicación tiene?**
Es su modelo de ejecución: no hay controladores de eventos aislados, el
guion completo se relee de arriba a abajo tras cada clic. La implicación
práctica es que cualquier dato que deba sobrevivir entre ejecuciones —el PDF
ya descargado, por ejemplo— debe guardarse explícitamente en
`st.session_state`, porque las variables locales del script no persisten
por sí solas.

**¿Por qué no se usa `st.rerun()` tras triar?**
Porque descartaría los mensajes de éxito o aviso de esa misma llamada antes
de que el usuario llegara a verlos: `st.rerun()` reinicia la ejecución desde
cero. En su lugar, se relee el escaneo (`GET /scans/{id}`) dentro de la
misma ejecución y se sigue renderizando con los datos ya actualizados.

### Sobre las pruebas

**¿Cómo se prueba una interfaz Streamlit sin abrir un navegador?**
Con `streamlit.testing.v1.AppTest`, que ejecuta el script en un entorno
controlado y expone los elementos renderizados como objetos inspeccionables
(botones, métricas, mensajes) sobre los que se puede simular un clic o una
entrada de texto y volver a ejecutar.

**¿Por qué las pruebas no llaman a la API real?**
Mismo criterio que el resto del proyecto: un doble de `httpx.Client`
responde según la ruta pedida, así un fallo en la suite señala siempre un
problema en `dashboard/app.py`, nunca que la API esté caída o que el modelo
de IA no esté disponible.

### Preguntas de comprensión

**¿Qué es `st.session_state` y por qué hace falta aquí?**
Es el mecanismo de Streamlit para conservar datos entre ejecuciones del
script, que de otro modo se perderían en cada reejecución. Se usa, por
ejemplo, para guardar los bytes del informe PDF ya descargado de la API
antes de que aparezca el botón de descarga definitivo (ver memoria del Paso
7).

---

## 9. Estado de los requisitos de la práctica

| Requisito | Estado tras el Paso 6 |
|---|---|
| **Aplicación web** | ✅ Dashboard completo: escaneos, triaje IA, consulta NL |
| **GitHub con historial** | ✅ 30 commits publicados (1 de esta fase) |
| **API o webhook** | ✅ Sin cambios de fondo en esta fase |
| **Base de datos** | ✅ Sin cambios en esta fase |
| **Reporte con portada** | ⬜ Paso 7 |

---

## 10. Próximos pasos

| Fase | Contenido |
|---|---|
| **Paso 7** | Generador de informes con portada (PDF), expuesto por API y por un botón de descarga en este mismo dashboard |
| **Paso 2 (resto)** | Puertos, cabeceras HTTP y TLS, ya reflejados en el detalle de activos del dashboard en cuanto persistan |

---

## 11. Conclusión del Paso 6

El Paso 6 entrega el cliente completo de la API construida en los pasos
anteriores, cerrando el requisito de aplicación web sin introducir ningún
atajo de acceso a datos que no pase por la propia API. La aportación que
vale la pena subrayar no es el número de pestañas, sino la forma en que se
resolvió refrescar el triaje sin perder los mensajes de la interacción que
lo disparó — una solución específica del modelo de ejecución de Streamlit,
verificada con una prueba que reproduce exactamente la secuencia de
peticiones que hace la página real.
