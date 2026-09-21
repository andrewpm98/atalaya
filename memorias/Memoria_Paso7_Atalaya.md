# Memoria técnica — Paso 7: Generador de informes con portada

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 7 de 7 — Informe ejecutivo PDF, API y dashboard
**Estado:** Completado y verificado. Cierra los siete pasos de la hoja de ruta y los
cinco requisitos obligatorios de la entrega.

---

## 1. Resumen ejecutivo

El Paso 7 cierra el último requisito obligatorio pendiente: **reporte con
portada**. Convierte un escaneo ya persistido y triado en un informe
ejecutivo en PDF —portada con el dominio y la fecha, resumen con contadores
por severidad, y el detalle de cada activo y hallazgo con impacto y
remediación— generado por la propia herramienta, no por un servicio externo.

Resultados tangibles:

- `reporting/generator.py`: `build_report_context()`, `render_html()`
  (Jinja2, puro y síncrono) y `generate_report()` (conversión a PDF con
  `xhtml2pdf`, en un hilo aparte).
- `reporting/templates/report.html`: plantilla con portada de página
  completa, resumen ejecutivo y detalle por activo, con CSS deliberadamente
  simple por las limitaciones del motor de renderizado a PDF.
- `GET /scans/{id}/report`: expone el generador por API, regenerando el PDF
  en cada descarga.
- Botón de descarga en la pestaña "Escaneos" del dashboard, en dos pasos por
  una restricción de `st.download_button`.
- **13 pruebas automatizadas nuevas** (137 en total: 124 + 13), todas
  deterministas: 9 sobre el generador, 2 sobre el endpoint (una de ellas de
  extremo a extremo, con un PDF real) y 2 sobre el botón del dashboard.
- Cuatro commits, hasta 34 en el repositorio en el momento de cerrar esta fase.

Con este paso, **los cinco requisitos obligatorios de la práctica y los
siete pasos de la hoja de ruta quedan cerrados** (ver sección 9).

---

## 2. Qué se ha construido

### 2.1 Componentes

| Fichero | Responsabilidad | Estado |
|---|---|---|
| `src/atalaya/reporting/generator.py` | `build_report_context`, `render_html`, `generate_report` | Reescrito (155 líneas añadidas) |
| `src/atalaya/reporting/templates/report.html` | Plantilla Jinja2 del informe (portada, resumen, detalle) | Nuevo (281 líneas) |
| `src/atalaya/api/routes/scans.py` | `GET /scans/{id}/report` | Ampliado |
| `dashboard/app.py` | Botón "Generar informe PDF" + botón de descarga | Ampliado |
| `src/atalaya/config.py`, `.env.example` | `reports_dir` (`REPORTS_DIR`) | Ampliado |
| `tests/test_reporting.py` | 9 pruebas del generador | Nuevo (167 líneas) |
| `tests/test_api_scans.py` | 2 pruebas del endpoint (incluida una end-to-end) | Ampliado |
| `tests/test_dashboard.py` | 2 pruebas del botón de descarga | Ampliado |

### 2.2 Flujo de generación

```
GET /scans/{id}/report
   │
   ▼
[repository.get_scan]         escaneo + activos + hallazgos, precargados
   │  404 si no existe
   ▼
[build_report_context]        selecciona campos, precalcula contadores por
   │                          severidad y ordena hallazgos (crítica → sin triar)
   ▼
[render_html]                 Jinja2 puro, sin xhtml2pdf — fácil de probar
   │  HTML completo
   ▼
[asyncio.to_thread(_html_to_pdf_bytes)]   xhtml2pdf (pisa), CPU-bound,
   │                                       fuera del loop de eventos
   ▼
reports/atalaya_informe_{dominio}_{id}.pdf   (sobrescribe si ya existía)
   │
   ▼
FileResponse   200 OK, application/pdf
```

### 2.3 Flujo de descarga desde el dashboard

```
Pestaña "Escaneos" → detalle de un escaneo
   │
   ▼
[botón "📄 Generar informe PDF"]
   │
   ▼
GET /scans/{id}/report   (bytes crudos, no JSON)
   │
   ▼
st.session_state["report_bytes_{id}"] = pdf_bytes
   │
   ▼
[aparece "⬇️ Descargar informe PDF"]   st.download_button con los bytes ya en mano
```

---

## 3. Bloque de entendimiento: los conceptos

### 3.1 Por qué xhtml2pdf y no WeasyPrint ni reportlab/platypus

Se valoraron tres opciones para convertir contenido a PDF:

| Opción | Motivo de descarte / elección |
|---|---|
| **WeasyPrint** | Motor de renderizado con mejor soporte CSS, pero depende de Pango, Cairo y GTK — bibliotecas del sistema ausentes en un Windows sin ese runtime instalado. Habría añadido una dependencia de infraestructura fuera del control del propio proyecto |
| **reportlab + platypus** | Python puro, sin dependencias del sistema, pero exige construir el documento con una API de bajo nivel (flowables, tablas por código) en vez de una plantilla declarativa |
| **xhtml2pdf (elegido)** | Python puro — mismo criterio que descarta WeasyPrint — y convierte **HTML ya renderizado** a PDF, lo que permite reutilizar Jinja2 (la misma herramienta de plantillas que ya usa el proyecto en otras fronteras de presentación) en vez de una API de documento distinta |

La contrapartida, documentada en el propio código: `xhtml2pdf` no
implementa CSS moderno de forma fiable (flexbox, grid, `border-collapse`),
lo que condiciona directamente el CSS de `report.html` (sección 3.3).

### 3.2 `render_html` separado de `generate_report`: dos causas de fallo distintas

El renderizado se divide deliberadamente en dos funciones con
responsabilidades distintas:

- `render_html(scan)` — Jinja2 puro y **síncrono**: construye el contexto y
  produce una cadena HTML. No puede fallar por trabajo de CPU intensivo ni
  por I/O; sus únicos fallos posibles son errores de la propia plantilla o
  de datos ausentes.
- `generate_report(scan)` — llama a `render_html`, y además convierte ese
  HTML a PDF (`xhtml2pdf`, trabajo de CPU no trivial) y lo escribe a disco.

Separarlas permite probar el **contenido** del informe (qué texto aparece,
en qué orden, qué campos se incluyen) sin pagar el coste de generar un PDF
real en cada caso — de las 9 pruebas del generador, 6 cubren `render_html` y
solo 3 llegan a invocar `xhtml2pdf`.

### 3.3 Por qué el CSS de la plantilla usa tablas en vez de flexbox/grid

`xhtml2pdf` no soporta de forma fiable las técnicas modernas de maquetado
CSS. La portada necesita centrar verticalmente su contenido en una página
completa; la forma habitual (`display: flex; align-items: center`) no
produce el resultado esperado con este motor. La plantilla resuelve el
centrado vertical con una tabla de una sola celda y `vertical-align:
middle` — la técnica que sí es fiable en HTML para tablas desde mucho antes
de que existiera flexbox, y la que la propia documentación de `xhtml2pdf`
recomienda para salidas predecibles. Es una limitación del motor elegido,
no una preferencia estética: **el código del CSS documenta explícitamente
por qué**, para que no se intente "modernizar" sin conocer la razón.

### 3.4 `asyncio.to_thread`: por qué la conversión a PDF no bloquea el loop de eventos

`pisa.CreatePDF` es una función síncrona que hace trabajo de CPU real
(interpretar el HTML, maquetar, rasterizar el PDF). Llamarla directamente
dentro de una ruta `async` de FastAPI bloquearía el bucle de eventos durante
toda esa conversión: mientras se genera un informe, ninguna otra petición
concurrente a la API podría avanzar, sin importar si es una operación de
red rápida como `GET /scans`.

`asyncio.to_thread()` ejecuta esa función síncrona en un hilo del *executor*
por defecto, liberando el bucle de eventos para atender otras corrutinas
mientras tanto. Es la misma razón por la que el resto del proyecto es
asíncrono (Paso 1) llevada a su caso límite: aquí el cuello de botella no es
la espera de red, sino el cómputo, y la solución no es paralelizar con
`await` sobre I/O sino delegar el cómputo a un hilo aparte.

### 3.5 Regenerar en cada descarga, no servir una copia cacheada

`download_report` llama a `generate_report(scan)` en **cada** petición, en
vez de comprobar primero si ya existe un PDF en `reports/` y servirlo tal
cual. La alternativa —cachear— parece más eficiente, pero es incorrecta en
este proyecto: un escaneo puede triarse con IA (Paso 5) **después** de
generarse un primer informe, y ese triaje cambia la severidad, el impacto y
la remediación de los hallazgos que el PDF debe reflejar. Servir una copia
cacheada arriesgaría entregar un informe desactualizado sin que quien lo
descarga tenga forma de saberlo. El coste de regenerar (típicamente
milisegundos para el volumen de datos de un escaneo) es aceptable frente al
riesgo de un informe silenciosamente obsoleto.

### 3.6 Por qué el fichero en disco es determinista por escaneo

`_report_path(scan)` construye siempre la misma ruta para el mismo escaneo:
`reports/atalaya_informe_{dominio}_{id}.pdf`. Regenerar el informe
**sobrescribe** ese fichero en vez de crear una copia nueva con una marca de
tiempo en el nombre. Es una decisión de higiene de disco: sin ella, cada
clic en "descargar" desde el dashboard (o cada llamada a la API) acumularía
una copia más, la mayoría idénticas o casi idénticas entre sí, sin que nada
las diferencie salvo el instante exacto de creación. Un informe por
escaneo, siempre al día, es el invariante que se prefiere mantener.

### 3.7 Por qué `generate_report` recibe un `Scan` y no un `scan_id`

El stub original de `CLAUDE.md` (Paso 1) preveía
`generate_report(scan_id: int, fmt: str = "pdf") -> Path`. Se cambió a
recibir un `Scan` ya cargado, por el mismo motivo que llevó a
`ai/query.py::ask()` a recibir un `Scan` en vez de un `scan_id` y una sesión
(Paso 5): quien llama al generador —el endpoint `GET /scans/{id}/report`—
ya resolvió el escaneo vía `repository.get_scan()`, con sus activos y
hallazgos precargados mediante `selectinload`. Si `generate_report`
aceptara un `scan_id`, necesitaría abrir su propia sesión de base de datos y
repetir esa misma consulta, acoplando el módulo de informes a la capa de
persistencia sin necesidad y duplicando trabajo ya hecho.

---

## 4. Decisiones de diseño

| Decisión | Justificación |
|---|---|
| `xhtml2pdf`, no WeasyPrint | Python puro; sin dependencia de Pango/Cairo/GTK, ausentes en Windows sin ese runtime (sección 3.1) |
| `xhtml2pdf`, no `reportlab`/`platypus` | Reutiliza Jinja2, ya usado en el proyecto, en vez de una API de documento de bajo nivel |
| `render_html` separado de `generate_report` | Permite probar el contenido del informe sin generar un PDF real en cada caso (sección 3.2) |
| CSS con tablas para el centrado, no flexbox/grid | `xhtml2pdf` no soporta esas técnicas de forma fiable; documentado en el propio CSS |
| Conversión a PDF en `asyncio.to_thread` | `pisa.CreatePDF` es CPU-bound; ejecutarla en el loop de eventos bloquearía otras peticiones concurrentes (sección 3.4) |
| Regenerar en cada descarga, no cachear | Un escaneo puede triarse después de generar un primer informe; servir una copia cacheada arriesgaría un informe desactualizado (sección 3.5) |
| Ruta de fichero determinista por escaneo, sobrescribe en cada regeneración | Evita acumular copias casi idénticas en disco por cada descarga (sección 3.6) |
| `generate_report(scan: Scan)`, no `scan_id: int` | Mismo criterio que `ai/query.py::ask()`: el llamador ya tiene el escaneo cargado con sus relaciones; evita una sesión de BD duplicada dentro del generador (sección 3.7) |
| Parámetro `fmt` del stub original conservado, con `ValueError` si no es `"pdf"` | Punto de extensión explícito (un futuro DOCX), no código muerto ni una rama silenciosamente ignorada |
| Botón de descarga en dos pasos en el dashboard | `st.download_button` necesita los bytes ya en mano al renderizarse; no puede generarlos en su propio clic (igual razón que motivó el patrón de dos pasos del triaje en el Paso 6) |

---

## 5. Validación

### 5.1 Pruebas automatizadas

**13 pruebas nuevas, 137 en total (124 + 13), todas en verde:**

| Fichero | Nº | Qué cubre |
|---|---|---|
| `tests/test_reporting.py` | 9 | Contadores por severidad, orden descendente de hallazgos, portada con el dominio, escaneo sin activos no falla, hallazgo sin triar marcado como pendiente, incidencias del escaneo visibles, PDF válido escrito a disco, regeneración determinista (mismo fichero, no acumula copias), `fmt` no soportado lanza `ValueError` |
| `tests/test_api_scans.py` | 2 | Descarga end-to-end (escaneo real → informe real → respuesta HTTP con cabecera `application/pdf` y contenido que empieza por `%PDF`), 404 si el escaneo no existe |
| `tests/test_dashboard.py` | 2 | El botón "Generar informe PDF" habilita la descarga con los bytes recibidos; un fallo de la API deja sin botón de descarga y muestra el error |

La prueba end-to-end de `test_api_scans.py` es la más representativa: no
sustituye `xhtml2pdf` por un doble, ejecuta la conversión real contra un
directorio temporal (`monkeypatch` sobre `settings.reports_dir`) y verifica
que el fichero resultante es un PDF real (`content.startswith(b"%PDF")`),
no solo que el código no lanzó una excepción.

### 5.2 Verificación manual

Se descargó el informe de un escaneo de `scanme.nmap.org` tanto vía `curl`
contra la API real en ejecución como desde el botón del dashboard, y se
abrió el PDF resultante para confirmar visualmente la portada, el resumen
por severidad y el detalle de activos — no solo que el fichero fuera un PDF
válido según sus cabeceras, sino que el contenido renderizado fuera legible
y coherente con los datos del escaneo.

---

## 6. Consideraciones legales y éticas

El informe expone exactamente los mismos datos que ya persiste la base de
datos —hostnames, IPs, hallazgos, severidad, impacto y remediación—, sin
añadir información nueva ni realizar ninguna acción sobre el objetivo. La
única consideración nueva de esta fase es que el PDF se escribe **a disco**
en `reports/`: es información de reconocimiento sobre un dominio de
terceros persistida en un segundo lugar además de la base de datos, por lo
que hereda la misma salvaguarda de fondo que ya protege la persistencia
(Paso 3, `SCAN_ALLOWLIST`) — el informe solo puede generarse sobre un
escaneo que ya pasó por esa comprobación al crearse.

---

## 7. Limitaciones actuales

- **Solo PDF.** El parámetro `fmt` del stub original se conserva como punto
  de extensión (`ValueError` explícito si no es `"pdf"`), pero no hay una
  segunda implementación (por ejemplo, DOCX) que lo demuestre.
- **Sin histórico de informes.** Cada regeneración sobrescribe el PDF
  anterior del mismo escaneo; no es posible recuperar una versión previa del
  informe una vez sobrescrita.
- **El informe no distingue quién lo generó ni cuándo se entregó**, más allá
  de la fecha de generación (`generated_at`) impresa en la propia portada.
  No hay un registro de descargas.
- **Sin marca de agua ni control de confidencialidad real.** La plantilla
  incluye una leyenda "confidencial" textual, pero no ningún mecanismo
  técnico (cifrado del PDF, contraseña) que la haga cumplir.

---

## 8. Bloque de defensa: preguntas previsibles

### Sobre la elección de xhtml2pdf

**¿Por qué no WeasyPrint, que tiene mejor soporte de CSS?**
Porque depende de bibliotecas del sistema (Pango, Cairo, GTK) ausentes en un
Windows sin ese runtime instalado, y el entorno de desarrollo de este
proyecto es Windows. `xhtml2pdf` es Python puro: se instala como cualquier
otra dependencia del `pyproject.toml`, sin requisitos de sistema operativo
adicionales.

**¿Qué contrapartida tiene esa elección?**
Un soporte de CSS más limitado: sin flexbox ni grid fiables, sin
`border-collapse` consistente. El maquetado de la plantilla se adapta a esa
limitación usando tablas para el centrado en vez de pelear contra el motor,
documentado explícitamente en el propio CSS para que no se intente
"modernizarlo" sin conocer la razón.

### Sobre el diseño del generador

**¿Por qué separar `render_html` de `generate_report`?**
Porque tienen perfiles de fallo distintos: `render_html` es Jinja2 puro y
síncrono, solo puede fallar por datos ausentes o un error de plantilla;
`generate_report` añade una conversión a PDF que sí hace trabajo de CPU real
y puede fallar por motivos propios del renderizador. Separarlas permite
probar el contenido del informe sin pagar el coste de generar un PDF en cada
caso, igual que `ai/triage.py` separa la construcción del contexto de la
llamada al proveedor de IA.

**¿Por qué la conversión a PDF se ejecuta en un hilo aparte?**
Porque `pisa.CreatePDF` bloquea en CPU. Ejecutarla directamente dentro de
una ruta `async` de FastAPI congelaría el bucle de eventos durante toda la
conversión, impidiendo que la API atienda cualquier otra petición
concurrente mientras tanto. `asyncio.to_thread` delega ese trabajo a un
hilo del *executor*, liberando el bucle de eventos.

**¿Por qué se regenera el PDF en cada descarga en vez de servir una copia
guardada?**
Porque un escaneo puede triarse con IA después de haberse generado un
primer informe, y ese triaje cambia severidad, impacto y remediación de los
hallazgos. Servir una copia cacheada sin comprobar nada arriesgaría entregar
un informe desactualizado sin que quien lo descarga tenga forma de saberlo.

**¿Por qué `generate_report` recibe un objeto `Scan` y no un `scan_id`?**
Porque quien la llama —el endpoint— ya resolvió el escaneo con sus activos y
hallazgos precargados vía `repository.get_scan()`. Aceptar un `scan_id` en
su lugar obligaría al generador a abrir su propia sesión de base de datos y
repetir esa consulta, acoplando el módulo de informes a la capa de
persistencia sin necesidad — mismo criterio que ya se aplicó en `ai/query.py`
en el Paso 5.

### Sobre las pruebas

**¿Cómo se prueba un PDF sin abrirlo visualmente en cada ejecución?**
Comprobando que el contenido generado empieza por la cabecera estándar de
todo fichero PDF (`%PDF`) y que el fichero existe y no está vacío. Es una
verificación automática de que el proceso de conversión no falló
silenciosamente; la revisión del contenido renderizado (que la portada, el
resumen y el detalle sean correctos) se hizo una vez de forma manual,
abriendo el PDF real.

**¿Qué demuestra la prueba de extremo a extremo que las demás no
demuestran?**
Que la cadena completa —persistir un escaneo real, generarle un informe real
con `xhtml2pdf` de verdad, y servirlo por HTTP con las cabeceras
correctas— funciona sin ningún doble de por medio. Las otras 9 pruebas del
generador usan objetos `Scan`/`Asset`/`Finding` construidos a mano, más
rápidas pero que no ejercitan la ruta HTTP ni la escritura a un directorio
real gestionado por la configuración de la aplicación.

### Preguntas de comprensión

**¿Qué problema resuelve `asyncio.to_thread`?**
Permite ejecutar una función síncrona que consume CPU (aquí,
`pisa.CreatePDF`) sin bloquear el bucle de eventos de `asyncio`, delegándola
a un hilo aparte. Es el mecanismo adecuado cuando el cuello de botella es
cómputo, a diferencia de `await` sobre una operación de red, que es el
patrón que domina el resto del proyecto.

**¿Por qué el informe muestra "Pendiente de triaje por IA" en vez de dejar
el campo vacío para un hallazgo sin triar?**
Porque un hallazgo con `severity="unknown"` no tiene `impact` ni
`remediation` todavía (son `None` hasta que la capa de IA los rellena, Paso
5). Dejar esos campos en blanco sin explicación confundiría a quien lea el
informe sobre si es un dato ausente por error o un hallazgo aún no
procesado; el mensaje explícito distingue ambos casos.

---

## 9. Estado de los requisitos de la práctica

| Requisito | Estado tras el Paso 7 |
|---|---|
| **Reporte con portada** | ✅ PDF real (Jinja2 + xhtml2pdf), vía API y dashboard |
| **Base de datos** | ✅ Sin cambios en esta fase |
| **API o webhook** | ✅ Sin cambios de fondo; `GET /scans/{id}/report` añadido |
| **Aplicación web** | ✅ Sin cambios de fondo; botón de descarga añadido |
| **GitHub con historial** | ✅ 34 commits publicados (4 de esta fase) |

**Con el cierre de este paso, los cinco requisitos obligatorios de la
práctica y los siete pasos de la hoja de ruta quedan completos.** El
histórico de commits recoge, después de esta fase, trabajo adicional sobre
el resto del Paso 2 (puertos, cabeceras HTTP y TLS) que amplía la cobertura
de descubrimiento sin corresponder a una fase nueva de la hoja de ruta
original.

---

## 10. Próximos pasos

Con los siete pasos cerrados, el trabajo restante hasta la entrega es
robustecer lo ya construido y preparar la defensa oral, no nuevas fases
(ver `CLAUDE.md`, "Hoja de ruta"). La deuda técnica conocida —fuente única
de enumeración, sin CNAME, sin autenticación, informe sin histórico de
versiones, entre otras— queda documentada como candidata a esa fase de
robustecimiento, priorizada según lo que aporte más a la defensa.

---

## 11. Conclusión del Paso 7

El Paso 7 entrega el último requisito obligatorio pendiente y cierra la
hoja de ruta completa del proyecto: un informe ejecutivo real, generado por
la propia herramienta a partir de datos persistidos y triados, no una
maqueta ni un documento estático. La decisión que más vale la pena
subrayar no es la elección de `xhtml2pdf` en sí, sino el criterio que la
sostiene y que ya atraviesa todo el proyecto desde el Paso 2: elegir la
herramienta que funciona dentro de las restricciones reales del entorno de
desarrollo (Python puro, sin dependencias de sistema en Windows) sobre la
que ofrece mejores prestaciones en abstracto, y documentar la contrapartida
en vez de descubrirla más tarde sin explicación.
