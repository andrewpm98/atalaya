# Memoria técnica — Paso 2: Motor de descubrimiento (módulo de subdominios)

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Paso 2 de 7 — Motor de descubrimiento, submódulo de subdominios
**Estado:** Completado y verificado sobre datos reales

---

## 1. Resumen ejecutivo

El Paso 2 convierte la estructura levantada en el Paso 1 en capacidad operativa real. Se ha implementado por completo el primer módulo de descubrimiento: la enumeración de subdominios mediante registros de Certificate Transparency, con verificación posterior por DNS.

Resultados tangibles de la fase:

- Módulo de enumeración funcional, validado contra infraestructura real.
- Clasificación de direcciones IP por alcance de red, que evita falsos positivos.
- Salvaguarda de autorización operativa sobre cada escaneo.
- Interfaz de línea de comandos para ejecutar y demostrar el módulo.
- **70 pruebas automatizadas**, todas deterministas y sin dependencia de red.
- Tres commits adicionales, hasta un total de 10 en el repositorio.

La validación se realizó sobre `github.com`, con este resultado: **117 subdominios descubiertos, 61 activos y alcanzables, 55 direcciones IP válidas como objetivo de escaneo**, en 19 segundos.

Esa diferencia entre 117 y 61 es el hallazgo que justifica el diseño del módulo: **el 48% de lo que la organización certificó en algún momento ya no resuelve**. Un enumerador que se limitara a consultar Certificate Transparency reportaría 117 activos, y más de la mitad serían inexistentes.

---

## 2. Qué se ha construido

### 2.1 Componentes

| Fichero | Responsabilidad | Estado |
|---|---|---|
| `src/atalaya/discovery/subdomains.py` | Enumeración y verificación de subdominios | Nuevo (305 líneas) |
| `src/atalaya/discovery/models.py` | Modelos de resultado (Pydantic) | Nuevo |
| `src/atalaya/core/netutils.py` | Clasificación de IPs por alcance de red | Nuevo |
| `src/atalaya/core/authorization.py` | Salvaguarda de autorización de objetivos | Nuevo |
| `src/atalaya/core/exceptions.py` | Jerarquía de excepciones propia | Nuevo |
| `src/atalaya/cli.py` | Subcomando `subdomains` | Ampliado |
| `src/atalaya/config.py` | Parámetros de crt.sh y DNS | Ampliado |
| `tests/test_subdomains.py` | 46 pruebas del módulo | Nuevo |
| `tests/test_netutils.py` | 24 pruebas de clasificación de IPs | Nuevo |

### 2.2 Flujo de ejecución

```
dominio
   │
   ▼
[ensure_authorized]   valida el formato y comprueba SCAN_ALLOWLIST
   │
   ▼
[fetch_crtsh]         GET a crt.sh + reintentos con backoff exponencial
   │  JSON de certificados
   ▼
[parse_crtsh_payload] extrae los SAN y el common_name de cada certificado
   │
   ▼
[normalize_hostname]  minúsculas · sin punto final · expande comodines
   │                  descarta correos y nombres fuera de alcance
   │  conjunto de candidatos únicos
   ▼
[resolve_hostname]    consulta A + AAAA, concurrente y acotada
   │
   ▼
[classify_ip]         determina el alcance de cada dirección resuelta
   │
   ▼
SubdomainScanResult   registros + resumen + incidencias
```

---

## 3. Bloque de entendimiento: los conceptos

### 3.1 Certificate Transparency

Certificate Transparency (CT) es un estándar definido en el **RFC 6962**. Obliga a las autoridades de certificación a publicar en registros públicos y auditables cada certificado TLS que emiten. Nació como respuesta a incidentes de emisión fraudulenta de certificados: si toda emisión queda registrada, un certificado ilegítimo puede detectarse.

Su efecto secundario es relevante para el reconocimiento: **cuando una organización solicita un certificado para `interno.empresa.com`, ese nombre queda publicado**. Consultar los registros de CT revela subdominios sin enviar un solo paquete a la infraestructura objetivo.

`crt.sh` es un servicio público, mantenido por Sectigo, que indexa esos registros y permite consultarlos por dominio.

### 3.2 Enumeración pasiva frente a activa

La distinción es central en el proyecto, y tiene implicaciones tanto técnicas como legales.

| | Pasiva | Activa |
|---|---|---|
| **Método** | Consultar fuentes públicas de terceros | Enviar tráfico al objetivo |
| **Ejemplo** | Certificate Transparency, registros WHOIS | Fuerza bruta de nombres DNS, escaneo de puertos |
| **Huella** | Nula sobre el objetivo | Queda registrada en sus logs |
| **Cobertura** | Solo lo que se haya certificado | Puede encontrar lo no certificado |

El módulo implementado es **estrictamente pasivo** en su fase de recolección. La verificación DNS posterior consulta resolvers públicos, no la infraestructura del objetivo, por lo que tampoco genera tráfico dirigido.

Esta elección es deliberada: ofrece una cobertura muy alta con la menor intrusividad posible, lo que resulta coherente con una herramienta pensada para inventariar la superficie propia de una organización.

### 3.3 Por qué no basta con Certificate Transparency

CT refleja lo que **se certificó alguna vez**, no lo que está **activo hoy**. Un subdominio puede aparecer en los registros y haber dejado de existir años atrás.

Esto genera dos categorías distintas:

- **Superficie histórica** — nombres que aparecen en CT pero ya no resuelven. Útiles para entender la evolución de la organización; no son activos atacables.
- **Superficie real** — nombres que resuelven a una dirección alcanzable. Son los activos que deben inventariarse y analizarse.

La fase de verificación DNS es la que separa ambas. En la prueba sobre `github.com`, esa separación redujo el inventario de 117 a 61.

### 3.4 Registros DNS A y AAAA

El sistema DNS traduce nombres a direcciones. Dos tipos de registro interesan aquí:

- **A** — asocia un nombre a una dirección IPv4 (`140.82.121.4`).
- **AAAA** — asocia un nombre a una dirección IPv6 (`2606:50c0:8000::153`).

Se consultan ambos porque un host puede ser alcanzable únicamente por IPv6, y omitirlo dejaría fuera parte de la superficie.

Existen otros tipos relevantes que **no se consultan todavía**, y se documentan como mejora en la sección 9.

### 3.5 Concurrencia acotada por semáforo

Resolver 117 nombres de forma secuencial supondría esperar 117 veces. De forma concurrente, se lanzan todas las consultas y se recogen según responden.

Ahora bien, la concurrencia ilimitada es contraproducente: lanzar mil consultas simultáneas satura el resolver, que empieza a descartar peticiones por *rate limiting*, y los resultados se degradan.

Un **semáforo** resuelve esto limitando cuántas operaciones pueden estar en vuelo a la vez. El módulo usa un límite de 50, configurable mediante `DNS_CONCURRENCY`.

El efecto medido: 8 hosts resueltos en 0,05 segundos, y los 117 de `github.com` en 19 segundos incluyendo la consulta a crt.sh.

### 3.6 Degradación controlada

`crt.sh` es un servicio gratuito y notoriamente inestable: puede devolver errores 502 o 504 bajo carga. Una herramienta que abortara ante ese fallo sería inservible en la práctica.

El módulo aplica dos mecanismos:

1. **Reintentos con backoff exponencial** — hasta tres intentos, esperando 1, 2 y 4 segundos. Un fallo transitorio no invalida el escaneo.
2. **Degradación controlada** — si tras los reintentos la fuente sigue sin responder, el escaneo **continúa** y el fallo se registra como incidencia trazable en el campo `errors` del resultado.

Este comportamiento se verificó de forma accidental pero útil durante el desarrollo: en el entorno de construcción, crt.sh devolvía 403 por restricciones de red. La herramienta reintentó tres veces, registró la incidencia y continuó, resolviendo correctamente el dominio raíz.

El mismo principio se aplica a la resolución DNS: `resolve_hostname` **nunca lanza excepción**. Cualquier fallo se refleja en el estado del registro, de modo que un host problemático no puede abortar la enumeración completa.

### 3.7 Alcance de las direcciones IP

Que un nombre resuelva no significa que exista un host alcanzable. Casos habituales:

| Alcance | Rango | Significado |
|---|---|---|
| `public` | Enrutable en Internet | Activo real, objetivo válido |
| `unspecified` | `0.0.0.0`, `::` | Registro anulado deliberadamente |
| `loopback` | `127.0.0.0/8`, `::1` | Bucle local, nunca un host remoto |
| `private` | RFC 1918, RFC 4193 | Direccionamiento interno |
| `cgnat` | `100.64.0.0/10` | RFC 6598, espacio compartido |
| `link_local` | `169.254.0.0/16`, `fe80::/10` | No enrutable |
| `multicast` | `224.0.0.0/4`, `ff00::/8` | No es un host individual |
| `documentation` | RFC 5737, RFC 3849 | Rangos reservados para ejemplos |
| `invalid` | — | Entrada malformada |

Solo las direcciones públicas se consideran objetivos válidos. Esta clasificación tiene dos consecuencias prácticas que se detallan en la sección 5.

---

## 4. Decisiones de diseño

| Decisión | Justificación |
|---|---|
| Certificate Transparency como fuente primaria | Máxima cobertura con intrusividad nula |
| Reintentos con backoff ante fallo de crt.sh | El servicio es gratuito e inestable; un 502 puntual no debe invalidar el escaneo |
| Degradación controlada en lugar de excepción | Si una fuente cae, el escaneo continúa y el fallo queda registrado |
| `resolve_hostname` nunca lanza excepción | Un host problemático no puede abortar la enumeración |
| Semáforo sobre la concurrencia DNS | Evita la saturación del resolver y el descarte por *rate limiting* |
| Expansión de comodines (`*.x.com` → `x.com`) | Un comodín no es un host; conservarlo generaría un activo inexistente |
| Verificación estricta de sufijo | `ejemplo.com.evil.net` no pertenece a `ejemplo.com`; comprobar el sufijo sin el punto separador sería explotable |
| Modelos Pydantic | Validan entrada externa no confiable y sirven como esquema de respuesta de la API (Paso 4) |
| Clasificación de IPs por alcance | Evita falsos positivos y protege las fases posteriores |
| Autorización centralizada | Ninguna fase puede ejecutarse sobre un objetivo no autorizado |

### 4.1 Normalización: por qué es necesaria

Los datos procedentes de CT son ruidosos. El módulo debe tratar:

- **Comodines** — `*.api.ejemplo.com` no es un host; se expande a `api.ejemplo.com`.
- **Mayúsculas** — `API.Ejemplo.com` y `api.ejemplo.com` son el mismo host.
- **Punto final** — `ejemplo.com.` es la forma absoluta del mismo nombre.
- **Duplicados** — un mismo nombre aparece en decenas de certificados sucesivos.
- **Direcciones de correo** — ocasionalmente presentes en los campos SAN.
- **Nombres fuera de alcance** — la consulta puede devolver dominios no relacionados.

Sin normalización, el inventario contendría entradas duplicadas, hosts inexistentes y nombres ajenos a la organización analizada.

### 4.2 La verificación de sufijo como control de seguridad

Merece mención aparte porque es un control de seguridad, no una simple validación.

Comprobar si un nombre pertenece a un dominio mediante `nombre.endswith(dominio)` es **incorrecto y explotable**: la cadena `ejemplo.com.evil.net` termina en `ejemplo.com` sin pertenecer a ese dominio. Un atacante podría registrar ese nombre para introducir activos ajenos en el inventario de un tercero.

La comprobación correcta exige el punto separador: `nombre == dominio or nombre.endswith("." + dominio)`. El módulo lo implementa así y existe una prueba específica que lo verifica.

---

## 5. Corrección realizada: clasificación de direcciones

Esta sección documenta un defecto detectado durante la validación y su corrección, por ser ilustrativa del método de trabajo.

### 5.1 Detección

La primera ejecución sobre `github.com` produjo esta línea:

```
jobs.github.com    active    0.0.0.0
```

`0.0.0.0` es la dirección **no especificada**: no identifica ningún host. Es la técnica habitual para anular un nombre sin retirar su registro DNS. GitHub Jobs cerró en 2021 y el registro quedó apuntando ahí.

La implementación inicial lo contabilizaba como activo, lo cual era incorrecto.

### 5.2 Alcance del problema

El defecto tenía dos consecuencias, la segunda más grave que la primera:

1. **Inventario inflado** — se contabilizaban como activos hosts inexistentes.
2. **Contaminación de fases posteriores** — el método que alimenta el escaneo de puertos devolvía esas direcciones. Un objetivo `127.0.0.1` habría provocado que la herramienta **escaneara la máquina que la ejecuta**, y un `0.0.0.0` intentos de conexión sin destino.

La segunda consecuencia motivó corregirlo antes de continuar: el defecto se habría propagado al siguiente módulo.

### 5.3 Solución

Se creó el módulo `core/netutils.py`, que clasifica cada dirección en uno de diez alcances, y se incorporó un estado nuevo:

- **`unroutable`** — el nombre resuelve, pero solo a direcciones no alcanzables. Se distingue así de `nxdomain` (el nombre no existe) y de `active` (existe y es alcanzable).

Además, `scan_targets()` sustituye a `unique_ips()` como entrada de las fases posteriores, devolviendo exclusivamente direcciones enrutables.

### 5.4 Dos trampas encontradas en la implementación

Al construir la clasificación aparecieron dos comportamientos contraintuitivos de la biblioteca estándar de Python, ambos documentados en el código:

1. **`ipaddress.is_global` devuelve `True` para direcciones multicast.** Apoyarse solo en esa propiedad habría clasificado `224.0.0.1` como objetivo válido.
2. **Python clasifica los rangos de documentación (`192.0.2.0/24`, RFC 5737) como privados.** Esto obligó a reescribir varias pruebas que empleaban esas direcciones como ejemplo, ya que pasaron a considerarse correctamente no enrutables.

Por ambos motivos, la clasificación sigue un **orden explícito de comprobación** en lugar de delegar en una única propiedad.

### 5.5 Hallazgo derivado: direccionamiento interno expuesto

La corrección habilitó una capacidad no prevista inicialmente. Un subdominio público que resuelve a una dirección privada (`10.x`, `192.168.x`) no es un activo alcanzable, pero **revela estructura de red interna**: nombres de host internos, esquema de direccionamiento y segmentación.

Es un hallazgo por derecho propio. Se marca mediante la propiedad `leaks_internal_addressing`, la interfaz de línea de comandos lo destaca en una sección específica, y la capa de IA lo tratará como hallazgo en el Paso 5.

---

## 6. Validación

### 6.1 Pruebas automatizadas

**70 pruebas, todas en verde.** Distribución:

| Bloque | Nº | Qué cubre |
|---|---|---|
| Normalización de hostnames | 13 | Comodines, mayúsculas, puntos finales, correos, fuera de alcance |
| Parseo de crt.sh | 3 | SAN multilínea, deduplicación, entradas malformadas |
| Cliente HTTP | 3 | Respuesta correcta, degradación ante error, JSON inválido |
| Orquestación | 4 | Flujo completo, inclusión del dominio raíz, marcado de activos |
| Autorización | 6 | Allowlist, sufijos engañosos, dominios inválidos |
| Modelos | 8 | Cálculo de resumen, serialización, alcance de IPs |
| Clasificación de IPs | 33 | Los diez alcances, casos límite, particionado |

**Todas las pruebas son deterministas.** Las fuentes externas se sustituyen por dobles: el cliente HTTP mediante `httpx.MockTransport` y el resolver DNS mediante sustitución de la función. Un fallo en la suite indica siempre un problema en el código, nunca una caída de red.

Este criterio es deliberado. Una prueba que dependa de crt.sh fallaría cada vez que el servicio esté caído, lo que entrenaría a ignorar los fallos de la suite.

### 6.2 Incidencia durante el desarrollo

Al ejecutar la suite por primera vez, dos pruebas fallaron con `RecursionError`. La causa estaba en las propias pruebas: la sustitución de `asyncio.sleep` para eliminar las esperas creaba una función que se invocaba a sí misma.

Se corrigió capturando una referencia a la función original antes de sustituirla. Se documenta porque ilustra el valor de ejecutar las pruebas: el defecto estaba en el código de verificación, que sin ejecución habría pasado inadvertido.

### 6.3 Validación sobre infraestructura real

| Objetivo | Descubiertos | Activos | Objetivos de escaneo | Duración |
|---|---|---|---|---|
| `scanme.nmap.org` | 1 | 1 | 1 | 1,0 s |
| `github.com` | 117 | 61 | 55 | 18,9 s |

`scanme.nmap.org` es un servicio que su propietario, autor de Nmap, mantiene explícitamente para pruebas de reconocimiento autorizadas.

### 6.4 Observación sobre la variabilidad del DNS

Dos ejecuciones consecutivas sobre `github.com` no producen resultados idénticos: algunos hosts alternan entre `active` y `no_answer`. Las causas son propias del funcionamiento del DNS —tiempos de espera agotados, balanceo de carga, estado de la caché del resolver— y no constituyen un defecto.

Se documenta porque tiene una implicación de diseño: **el inventario debe entenderse como una fotografía en un instante dado, no como una verdad absoluta**. Esto refuerza la decisión de persistir los escaneos en base de datos (Paso 3), ya que comparar ejecuciones sucesivas permite distinguir un cambio real de una fluctuación transitoria.

---

## 7. Análisis de los resultados obtenidos

El escaneo de `github.com` ilustra qué tipo de información produce la herramienta. Los datos proceden exclusivamente de fuentes públicas.

### 7.1 Superficie de preproducción

Aparecen numerosos entornos que no son de producción:

- `examregistration-uat`, `examadmin-uat`, `examregistration-uat-api` — entornos UAT (*User Acceptance Testing*)
- `codespaces-ppe`, `workspaces-ppe` — PPE (*Pre-Production Environment*)
- `graphql-stage`, `stg.github.com`, `staging-lab` — entornos de staging
- `review-lab`, `proxima-review-lab`, `render-lab`, `lab-sandbox` — laboratorios

Los entornos de preproducción suelen recibir menos atención en materia de seguridad que los de producción, pese a manejar en ocasiones datos equivalentes. Su identificación es uno de los objetivos habituales de un inventario de superficie.

### 7.2 Patrón de interés: nombres apuntando a hosting estático

Numerosos subdominios resuelven al rango `185.199.108-111`, correspondiente a GitHub Pages. Entre ellos, `vpn-ca.iad.github.com`, cuyo nombre sugiere una función de infraestructura —autoridad certificadora de VPN— pero apunta a un servicio de alojamiento estático.

Cuando un nombre apunta a una plataforma de hosting y el recurso correspondiente no está reclamado, aparece el patrón conocido como *subdomain takeover*. **No se ha verificado que sea el caso aquí, ni se ha intentado**: hacerlo excedería el reconocimiento pasivo y requeriría autorización.

Se documenta como ejemplo del tipo de correlación que la capa de IA deberá señalar en el Paso 5: la combinación de un nombre con semántica sensible y un destino de hosting genérico es exactamente la señal que un analista investigaría.

### 7.3 Ausencia de direccionamiento interno

No se detectaron subdominios resolviendo a direcciones privadas, lo que indica una gestión correcta en ese aspecto.

---

## 8. Consideraciones legales y éticas

### 8.1 Naturaleza de las técnicas empleadas

La fase de recolección es **estrictamente pasiva**: consulta registros públicos de Certificate Transparency a través de un servicio de terceros. No se envía tráfico a la infraestructura analizada.

La verificación DNS consulta resolvers públicos, no los servidores del objetivo. No genera registros en los sistemas de la organización analizada.

### 8.2 Salvaguarda implementada

El módulo `core/authorization.py` centraliza el control. Toda enumeración comienza por `ensure_authorized()`, que valida el formato del dominio y comprueba la variable `SCAN_ALLOWLIST`. Si el dominio no está autorizado, se lanza `UnauthorizedTargetError` y el escaneo no llega a iniciarse.

La comprobación contempla dominios y sus subdominios, y rechaza sufijos engañosos mediante la verificación estricta descrita en 4.2.

### 8.3 Objetivos utilizados en la validación

- `scanme.nmap.org` — mantenido explícitamente por su propietario para pruebas autorizadas.
- `github.com` — empleado únicamente con técnicas pasivas sobre información pública, sin envío de tráfico a su infraestructura.

---

## 9. Limitaciones actuales

Declaradas de forma explícita:

- **Fuente única.** Solo se consulta crt.sh. Otras fuentes pasivas (Shodan, SecurityTrails, VirusTotal) ampliarían la cobertura. `SHODAN_API_KEY` ya está previsto en la configuración.
- **No se consultan registros CNAME.** En el escaneo de `github.com`, unos 50 hosts quedaron en estado `no_answer`: existen en DNS pero sin registros A/AAAA. Muchos tendrán probablemente un CNAME apuntando a un servicio externo. Es una carencia relevante, porque **un CNAME apuntando a un recurso no reclamado es la señal característica del *subdomain takeover***. Se incorporará cuando la capa de IA requiera ese dato.
- **Sin persistencia.** Cada escaneo se pierde al terminar la ejecución. Se resuelve en el Paso 3.
- **Sin detección de comodines DNS.** Algunos dominios resuelven cualquier subdominio inexistente, lo que puede inflar el recuento de activos.
- **Sin exposición por API.** El módulo se ejecuta por línea de comandos. Se integra en el Paso 4.
- **Enumeración limitada a lo certificado.** Un subdominio que nunca tuvo certificado no aparece. Es la contrapartida inherente al enfoque pasivo.

---

## 10. Bloque de defensa: preguntas previsibles

### Sobre la técnica

**¿Por qué Certificate Transparency y no fuerza bruta de subdominios?**
Porque CT ofrece cobertura muy alta sin enviar un solo paquete al objetivo. La fuerza bruta genera miles de consultas, queda registrada y solo encuentra los nombres que estén en el diccionario empleado. CT encuentra nombres que ningún diccionario contendría, porque proceden de certificados realmente emitidos. Ambas técnicas son complementarias; la pasiva es la que corresponde priorizar en una herramienta de inventario.

**¿Es legal esto?**
La fase de recolección consulta registros públicos a través de un servicio de terceros: no hay interacción con la infraestructura analizada. La verificación DNS consulta resolvers públicos. Aun así, el proyecto incorpora `SCAN_ALLOWLIST` desde el diseño, y la validación se realizó sobre un dominio mantenido explícitamente para pruebas y sobre información pública.

**¿Por qué verificar por DNS si CT ya da los nombres?**
Porque CT refleja lo que se certificó alguna vez, no lo que está activo. En la prueba real, de 117 nombres solo 61 resolvían: el 48% era superficie histórica. Sin esa verificación, el inventario sería mayoritariamente ficticio.

**¿Qué pasa si crt.sh está caído?**
Se reintenta tres veces con backoff exponencial. Si sigue sin responder, el escaneo continúa y el fallo se registra como incidencia en el resultado. Este comportamiento se verificó durante el desarrollo, cuando crt.sh devolvió 403 por restricciones del entorno de construcción: la herramienta degradó correctamente.

### Sobre la implementación

**¿Por qué un semáforo en las consultas DNS?**
Porque la concurrencia ilimitada satura el resolver, que empieza a descartar peticiones por *rate limiting*, y los resultados se degradan. El semáforo limita las operaciones simultáneas a un valor configurable, por defecto 50.

**¿Por qué `resolve_hostname` no lanza excepciones?**
Porque un único host problemático no debe abortar la enumeración completa. Cualquier fallo se refleja en el estado del registro, que puede ser `timeout`, `error`, `nxdomain` o `no_answer`. Así el resultado es siempre completo y cada incidencia queda trazada.

**¿Por qué comprobar el sufijo con el punto separador?**
Porque es un control de seguridad. Usar `endswith("ejemplo.com")` aceptaría `ejemplo.com.evil.net`, un nombre que un atacante puede registrar para introducir activos ajenos en el inventario. La comprobación correcta exige el punto, y hay una prueba específica que lo verifica.

**¿Por qué modelos Pydantic y no diccionarios?**
Por tres razones: validan datos externos no confiables, sirven directamente como esquema de respuesta en FastAPI sin conversión intermedia, y sus campos anticipan las columnas de la entidad `Asset` en la base de datos.

### Sobre la corrección realizada

**¿Qué era el problema de `0.0.0.0`?**
Un nombre que resuelve a esa dirección no apunta a ningún host: es la forma habitual de anular un registro DNS sin borrarlo. La implementación inicial lo contaba como activo. Se detectó en la validación sobre datos reales, con el caso de `jobs.github.com`.

**¿Por qué corregirlo antes de continuar y no después?**
Porque el método que alimenta el escaneo de puertos devolvía esas direcciones. Un objetivo `127.0.0.1` habría hecho que la herramienta escaneara la propia máquina que la ejecuta. El defecto se habría propagado al siguiente módulo con consecuencias peores que un simple recuento erróneo.

**¿Por qué una IP privada es un hallazgo si no es alcanzable?**
Porque revela estructura de red interna: nombres de host, esquema de direccionamiento y segmentación. No permite atacar directamente ese activo, pero aporta información de valor para quien prepare un ataque. Por eso se marca aparte en lugar de descartarse.

**¿No bastaba con `ipaddress.is_global`?**
No, y comprobarlo fue necesario. Esa propiedad devuelve verdadero para direcciones multicast, y Python clasifica los rangos de documentación como privados. Por eso la clasificación sigue un orden explícito de comprobación en lugar de delegar en una única propiedad.

### Sobre las pruebas

**¿Por qué las pruebas no consultan crt.sh de verdad?**
Porque fallarían cada vez que el servicio estuviera caído, y eso entrena a ignorar los fallos de la suite. Las fuentes externas se sustituyen por dobles, de modo que un fallo indique siempre un problema en el código. La validación contra servicios reales se hace aparte, de forma manual y documentada.

**¿Cómo se sustituyen esas fuentes?**
El cliente HTTP mediante `httpx.MockTransport`, que intercepta las peticiones y devuelve respuestas controladas. El resolver DNS mediante sustitución de la función correspondiente durante la prueba.

**¿Por qué dos ejecuciones del mismo dominio dan resultados distintos?**
Por el funcionamiento normal del DNS: tiempos de espera agotados, balanceo de carga y estado de la caché. El inventario es una fotografía en un instante dado. Es precisamente uno de los motivos por los que los escaneos deben persistirse: comparar ejecuciones permite distinguir un cambio real de una fluctuación.

### Preguntas de comprensión

**Explica qué es Certificate Transparency.**
Un estándar que obliga a las autoridades de certificación a publicar en registros públicos auditables cada certificado TLS que emiten. Se creó para detectar emisiones fraudulentas. Como efecto secundario, permite descubrir subdominios de una organización sin interactuar con su infraestructura.

**¿Qué diferencia hay entre `nxdomain`, `no_answer` y `unroutable`?**
`nxdomain` significa que el nombre no existe en DNS. `no_answer` que existe pero no tiene registros A o AAAA, por ejemplo si solo tiene registros de correo. `unroutable` que sí resuelve a direcciones, pero ninguna es alcanzable desde Internet.

**¿Qué es un comodín en un certificado y por qué se expande?**
Un certificado comodín como `*.ejemplo.com` cubre cualquier subdominio de primer nivel. El nombre `*.ejemplo.com` no identifica ningún host concreto, por lo que conservarlo introduciría un activo inexistente en el inventario. Se expande al dominio base, que sí es un host real.

---

## 11. Estado de los requisitos de la práctica

| Requisito | Estado tras el Paso 2 |
|---|---|
| **GitHub con historial** | ✅ 10 commits publicados |
| **API o webhook** | 🔨 Estructura operativa; consumo de crt.sh implementado |
| **Aplicación web** | 🔨 Dashboard inicial funcional |
| **Base de datos** | ⬜ Motor configurado; modelos en el Paso 3 |
| **Reporte con portada** | ⬜ Paso 7 |

El consumo de crt.sh consolida parcialmente el requisito de API: el enunciado admitía tanto ofrecer como consumir una API, y esta fase implementa la segunda vertiente.

---

## 12. Próximos pasos

| Fase | Contenido |
|---|---|
| **Paso 2 (resto)** | Puertos, cabeceras HTTP y TLS |
| **Paso 3** | Modelos de base de datos y persistencia de escaneos |
| **Paso 4** | Implementación completa de los endpoints REST |
| **Paso 5** | Capa de IA: triaje y consulta en lenguaje natural |
| **Paso 6** | Dashboard completo |
| **Paso 7** | Generador de informes con portada |

Se valora alterar el orden y abordar la persistencia antes que el resto de módulos de descubrimiento, de modo que estos nazcan ya guardando sus resultados en lugar de requerir una adaptación posterior.

---

## 13. Conclusión del Paso 2

El Paso 2 entrega el primer módulo de descubrimiento plenamente operativo, validado sobre infraestructura real y respaldado por 70 pruebas automatizadas.

Más allá del código, la fase deja tres aportaciones que conviene destacar:

1. **Una distinción conceptual útil** entre superficie histórica y superficie real, que resultó ser casi la mitad del inventario en el caso analizado.
2. **Un defecto detectado y corregido sobre datos reales** antes de que se propagara al siguiente módulo, junto con la capacidad adicional que esa corrección habilitó.
3. **Un criterio de calidad establecido**: pruebas deterministas, degradación controlada ante fallos externos y validación manual documentada frente a servicios reales.
