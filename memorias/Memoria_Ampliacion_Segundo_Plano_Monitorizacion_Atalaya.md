# Memoria técnica — Ampliación: escaneo en segundo plano y monitorización

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación 14, iniciada el 13/10/2026. Prepara la
defensa (dossier y guía de la herramienta), saca el escaneo de la petición
HTTP y añade la vigilancia programada.
**Estado:** En curso. Bloques 2 y 3 completos y subidos a `origin/main` el
13/10/2026. Netlas (bloque 3b), evaluada y descartada el 14/10/2026. Bloque 4
(vigilancia) completo el 14/10/2026, por API y con su panel en el dashboard:
683 tests, `ruff` y `mypy` a cero. Pendiente el cierre (bloque 5); ver §9.

---

## 1. Resumen ejecutivo

1. **Dossier de defensa y guía de la herramienta**, dos documentos vivos en
   Claude Docs. El dossier reúne en un sitio lo que estaba repartido entre
   doce memorias; la guía explica la herramienta a quien llega de fuera.
2. **`POST /scans` en segundo plano.** La API responde 202 al momento y el
   escaneo corre aparte; el dashboard lo sigue sin bloquearse.
3. **Un defecto anterior**, encontrado al prototipar: en Windows, cada
   petición del dashboard a la API tardaba 2 segundos.
4. **Netlas, medida y descartada** como segunda fuente de subdominios: más
   ruido que activos con el plan gratuito.
5. **Vigilancia programada.** Un monitor repite el escaneo de un dominio cada
   cierto tiempo y avisa por webhook cuando cambia la superficie o cuando el
   escaneo falla. Es la carencia más grande que tenía la herramienta como
   ASM, y cumple de forma literal el requisito «API o webhook».

---

## 2. Bloque 2: el material de defensa

**El dossier** tiene diez secciones: presentación de dos minutos,
arquitectura con un diagrama, los cinco requisitos en la demo, el guion de la
demo con plan B sin red, cifras, decisiones, las seis restricciones de
seguridad, límites, checklist del día y un banco de preguntas.

**Un cambio de enfoque a mitad.** La primera versión del banco eran las 120
preguntas de las memorias, casi todas técnicas. El usuario lo corrigió: en la
defensa espera preguntas sobre la herramienta, no sobre el código. El banco
principal pasó a ser funcional (qué es, para quién, qué encuentra, qué aporta
la IA, frente a qué alternativas, límites, uso responsable, preguntas trampa)
y lo técnico quedó en un anexo.

**El mejor argumento salió de los datos.** Para «¿por qué IA y no reglas?»:
en github.com, la falta de protección contra clickjacking aparece en 32
subdominios triados; el modelo la dejó en baja en 29 y la subió a media en 3
(`vscode-auth`, `api.security` y `octocaptcha.review-lab`). El impacto que
redactó para `vscode-auth` habla de que es un servicio de autenticación OAuth.

**Tres respuestas de las memorias estaban superadas** (autenticación en el
Paso 1, PostgreSQL sin probar en el Paso 3 y `ai/query.py` en el Paso 7). Se
corrigieron con una nota «Estado posterior», que es la excepción que CLAUDE.md
permite en los bloques de defensa.

**La guía de la herramienta** es el documento corto: qué es, objetivos, cómo
funciona, qué encuentra, la IA, cómo se usa, ventajas, límites, seguridad y
qué viene después. Sin código y sin cifras que caduquen.

---

## 3. Bloque 3: el escaneo en segundo plano (`ce2a048`, `35cb462`)

**El problema.** El escaneo corría dentro de la petición: 19 s para
github.com y minutos para un dominio grande. La conexión quedaba abierta todo
ese tiempo y el dashboard, con un timeout de 120 s, daba por fallido un
escaneo que seguía corriendo.

**El diseño**, acordado antes de escribir código:

- `POST /scans` valida y autoriza el dominio **antes** de crear nada: un
  dominio no autorizado es un 403 inmediato, no un escaneo `failed`.
- Crea el escaneo en `running`, responde **202** con `Location: /scans/{id}` y
  deja el trabajo a `core/scan_runner.py::run_scan`, con su propia sesión de
  base de datos (la de la petición se cierra al responder).
- `run_scan` no deja nunca un escaneo en `running`: termina en `completed` o
  en `failed` con el motivo.
- Al arrancar, la API cierra como fallidos los escaneos que una parada dejó a
  medias.
- `?wait=true` conserva el comportamiento anterior.

**Lo que el diseño no preveía.** Hasta ahora ningún escaneo quedaba «en
curso» ni «fallido»: el escaneo síncrono o terminaba o no se guardaba. Ya
pasó con los hosts `wildcard` que un estado nuevo se cuela sin revisar a
quién afecta, así que se repasaron todos los que leen el estado de un
escaneo. Comparar con uno en curso daría todos sus hostnames por
«desaparecidos»; triarlo diría «0 triados» como si estuviera hecho. Ahora
triar, pedir el informe o preguntar por un escaneo en curso da **409**, y
comparar exige que los dos estén completados.

**Cuatro detalles que se defienden solos:**

- **Nunca a medias.** Activos y hallazgos se guardan en una sola transacción
  al final: quien consulta mientras corre ve el escaneo vacío. El primer test
  de esto pasaba por la razón equivocada, porque la base de datos en memoria
  comparte una conexión entre sesiones y cada una ve lo que la otra no ha
  confirmado; se pasó a una base de datos en fichero.
- **Sin secretos en los errores.** De una excepción inesperada solo se guarda
  el tipo: su texto podría llevar una URL con la clave de Shodan, y `errors`
  llega al dashboard, al modelo y al PDF. Un test lo comprueba con una clave
  falsa en el mensaje.
- **Una carga perezosa escondida.** Con `?wait=true`, la ruta relee el escaneo
  tras `expire_all()`, y leer después `scan.id` disparaba una consulta fuera
  del contexto asíncrono (el `MissingGreenlet` del Paso 4). Se guarda el id
  antes.
- **La API sigue respondiendo durante el escaneo.** Se midió `/health` y el
  detalle del escaneo cada 0,7 s mientras corría: nada se bloquea.

**El dashboard**, con maqueta de capturas reales aprobada antes de cerrarlo:
un aviso «En curso» que se actualiza cada 2 s en un fragmento de Streamlit
(el resto del panel sigue usable), el detalle de un escaneo en curso que se
completa solo, el motivo de uno fallido y «Comparar con» solo entre
completados.

---

## 4. El defecto de `localhost` (`c8043a0`)

Al capturar la maqueta, el aviso «en curso» tardaba 6 segundos en aparecer
cuando la API respondía en 0,27. No era la API: en Windows, `localhost`
resuelve antes a IPv6, uvicorn solo escucha en IPv4 y la conexión rechazada
tardaba unos 2 segundos en caer a `127.0.0.1`. Cada interacción del dashboard
hace varias peticiones.

| Dashboard contra | Carga inicial | Cambiar de escaneo |
|---|---|---|
| `localhost` (antes) | 9,7 s | 6,4 s |
| `127.0.0.1` (ahora) | 2,9 s | 0,3 s |

Afectaba a todo el dashboard en local desde el principio; en Docker no (la
URL es `http://api:8000`).

**Una lección de proceso.** El commit del dashboard entró con un aviso de
`ruff`: la comprobación iba en una tubería (`| tail -1`) que ocultaba su
código de salida. Se corrigió en un commit aparte (`2ff066c`).

---

## 5. Bloque 3b: Netlas, evaluada y descartada (14/10/2026)

**La propuesta.** crt.sh es en la práctica la única fuente de subdominios:
Shodan exige un plan de pago para `/dns/domain` y el usuario no quiere
pagarlo. Netlas tiene un plan gratuito (Community) con búsqueda de dominios
por API, y se propuso como segunda fuente.

**Antes de escribir código, se midió.** Peticiones sin clave a
`app.netlas.io/api/domains/` el 14/10/2026:

| Prueba | Resultado |
|---|---|
| Nombres bajo `*.github.com` (`domains_count`) | 38.035, frente a 117 de crt.sh |
| Los 7 primeros devueltos (`smpp`, `mylive`, `myname`, `myme`, `mgmg`, `kanri`, `www.upload`) | Ninguno resuelve a una dirección (`NoAnswer` los 7) |
| Orden | Por fecha de indexación, no por relevancia |
| Sin clave | Responde, pero la cuota diaria se agotó en 4 peticiones (`daily_request_limit_exceeded`) |
| Plan Community (página de precios y licencia) | 50 peticiones/día, 2.500 resultados/mes, 200 por descarga; solo uso personal no comercial |

**Por qué se descartó.** En un dominio grande, Netlas no aporta 38.000
subdominios sino, como mucho, los 200 más recientes, y la muestra apunta a
nombres recogidos por DNS pasivo (erratas, intentos de fuerza bruta de
terceros) más que a activos. Cada uno entraría en el inventario como
`no_answer` y pasaría por la consulta de CNAME del takeover: más volumen y
más ruido, justo la carencia de señal/ruido que ya tiene la herramienta. Con
2.500 resultados al mes caben unos doce escaneos de un dominio grande. Filtrar
en la consulta por nombres con registro A (`a:*`) podría limpiar el ruido,
pero exigía una cuenta para comprobarlo y no cambiaba la cuota.

Se priorizó la monitorización (bloque 4), la carencia más grande como ASM. La
medición queda como respuesta a «¿por qué solo crt.sh?».

---

## 6. Bloque 4: la vigilancia programada (`7de68a2`, `c8e03b1`)

**El problema.** Un ASM se define por vigilar en el tiempo, y Atalaya solo
escaneaba cuando alguien lo pedía. El diff con `cambiados` ya decía qué había
cambiado entre dos escaneos; faltaba el disparador.

**El diseño acordado** (12/10/2026): una tabla `monitors`, un bucle en el
arranque de la API que lanza los escaneos que tocan con el mismo `run_scan`
de `POST /scans`, un diff **sin IA** (no gasta crédito ni depende del
proveedor) y un `POST` al webhook si hay nuevos, desaparecidos o cambiados.
Autorización al crear y en cada ejecución, protección contra SSRF, mínimo de
una hora entre escaneos y auditoría de cada aviso.

**Tres decisiones del usuario** sobre lo que el diseño no cubría: avisar
también de los fallos (evento `escaneo_fallido`, porque en vigilancia el peor
fallo es el silencioso), firmar los avisos con HMAC si el monitor tiene
secreto, y hacer la API primero y el panel del dashboard después, con maqueta.

**Lo que salió al pensarlo con datos:**

- **Un aviso perdido no debe perder el cambio.** Si cada ejecución comparase
  con la anterior, un webhook caído haría que el cambio no se avisara nunca:
  la siguiente compararía contra un escaneo que ya lo incluye. Cada monitor
  guarda una **línea base** que solo avanza cuando el aviso llega.
- **crt.sh caído no es «sus hosts desaparecieron».** Una fuente caída deja
  un escaneo «completado» sin los hosts que aportaba, y el diff los daría por
  desaparecidos. Se mira fuente a fuente: si crt.sh o Shodan aportaron hosts
  a la línea base y ninguno ahora, esa fuente cayó y se avisa como fallo. La
  primera versión miraba «0 activos» y era un error, que destapó la prueba
  completa (ver más abajo). No servía mirar si el escaneo tenía incidencias:
  con clave de Shodan, su 403 aparece en todos (se vio en la prueba real).
- **El límite de varios procesos se resolvió en vez de documentarse.** Cada
  ejecución se «reclama» actualizando su próxima hora solo si nadie lo hizo
  antes; de dos procesos, solo uno gana.

**SSRF, más allá de lo que pedía el plan.** El plan pedía resolver el host
del webhook y rechazar direcciones internas. Eso solo no basta: si se valida
resolviendo el nombre y luego el cliente HTTP lo resuelve otra vez, un DNS
malicioso puede responder una IP pública la primera vez y `127.0.0.1` la
segunda (*DNS rebinding*). Por eso, al enviar, se conecta a la IP ya validada
y el nombre va en la cabecera `Host` y en el SNI, con el certificado
verificado contra él. Antes de escribirlo se comprobó contra un servidor real
que la verificación sigue funcionando: con un nombre que el certificado no
cubre, la conexión se rechaza.

**Dos trampas encontradas al comprobarlo:**

- La primera prueba negativa «pasó» por la razón equivocada: httpx reutiliza
  las conexiones por IP aunque cambie el SNI, y la segunda petición viajó por
  la conexión de la primera, ya verificada. Con un cliente nuevo, falla como
  debe. De ahí la regla del código: un cliente nuevo por intento.
- Fijar la IP desactiva el *happy eyeballs* de httpx. Si el resolvedor da
  primero una IPv6 y la máquina no tiene IPv6, el aviso no llegaría nunca.
  Ahora se prueban las direcciones validadas en orden, pero solo si la
  anterior no llegó a conectar (una vez conectado, repetir podría duplicar el
  aviso). Es el mismo tipo de fallo que el de `localhost` en Windows (§4).

**La URL del webhook es un secreto.** Las de Slack o Discord llevan el token
en la ruta. La API la devuelve como `https://host/…`, el log de auditoría
igual, y de un error de red solo se guarda el tipo (su texto lleva la URL).

**El panel del dashboard** (`88bc65d`), con maqueta de capturas reales
aprobada antes de cerrarlo (https://claude.ai/artifact/EnvuSwUbnQ71ukn97VyaZz): una pestaña «Vigilancia» con la tabla
de monitores, que se refresca sola cada 10 s y muestra el resultado de la
última ejecución en un chip (pendiente, escaneando, sin cambios, avisado,
atención), pausar/reanudar, borrar con confirmación y un formulario de alta.
La firma va activada por defecto y, si no se da un secreto propio, el panel
genera uno y lo enseña una sola vez: añadido fuera del plan y aprobado en la
maqueta, porque si no firmar exigía inventarse 16 caracteres a mano.

La maqueta pasó por tres rondas antes de enseñarse, por fallos vistos en las
propias capturas: tras crear un monitor, la lista seguía diciendo «0
monitores» (se pintaba antes de procesar el formulario) y el formulario no se
vaciaba. Lo segundo es una trampa de Streamlit: borrar el valor del estado no
vacía el campo, porque el navegador reenvía el suyo; hacen falta claves
nuevas tras cada alta.

---

## 7. Verificación

**Tests:** de 583 a 669. Bloque 3, +22: 17 del escaneo en segundo plano (202, 400 y
403 sin crear nada, fallo con motivo y sin secretos, autorización al ejecutar,
409 en triaje, informe, comparación y preguntas, atomicidad, recuperación al
arrancar y arranque con la base de datos caída) y 5 del dashboard (aviso en
curso, resumen, fallo, detalle en curso y fallido, comparación solo entre
completados). Cinco mutaciones hacen fallar los tests que las cubren.
Bloque 4, +66: 34 del webhook (SSRF con ocho tipos de dirección interna,
IP fijada con `Host` y SNI, revalidación al enviar, sin redirecciones, firma,
paso a la siguiente dirección solo sin conexión, token fuera de errores y
auditoría), 27 de los monitores (línea base, aviso repetido, fallos, fuente
caída total o parcial, fuente que nunca aportó, allowlist al ejecutar,
planificación, reclamo concurrente, bucle,
`lifespan` y rutas) y 5 del test de autenticación, que recorre las rutas
nuevas. Siete mutaciones (avanzar la base sin entregar, quitar el guardia de
fuente caída, volver al criterio de «0 activos», reclamar sin condición, no
reautorizar, no fijar la IP, seguir redirecciones) hacen fallar su test. Panel, +12 (estados de la tabla, escape
de lo que llega de la API, alta con secreto generado o propio o sin firma,
rechazo de la API conservando el formulario, pausa, borrado con
confirmación y cancelación); cuatro mutaciones (sin escape, borrar sin
confirmar, el error antes que «escaneando», no recargar tras el alta) hacen
fallar cada una su test.

**Pruebas reales:**

| Prueba | Resultado |
|---|---|
| `POST /scans` contra `scanme.nmap.org` | 202 en 0,27 s; completado en unos 8 s |
| Triar mientras corre | 409 «aún está en curso» |
| Dominio no autorizado | 403 en 0,2 s y ningún escaneo creado |
| API parada a mitad de un escaneo y reiniciada | `failed`: «interrumpido: la API se detuvo antes de que terminara» |
| `?wait=true` | 201 con el escaneo completo en 7 s |
| Comparar con el escaneo interrumpido | 409 «está fallido» |
| Dashboard en Chromium con escaneos reales | Aviso en 0,2 s; el detalle pasa solo de «en curso» a completo |

**Pruebas reales del bloque 4** (14/10/2026), con `scanme.nmap.org` y un
receptor público (webhook.site). Para que hubiera un cambio que avisar, se
alteró a mano la línea base: el puerto 80 dejó de constar como abierto.

| Prueba | Resultado |
|---|---|
| Webhook a `https://localhost/…` y a `https://169.254.169.254/…` | 400 (`loopback`, `link_local`) y auditoría «Webhook rechazado (SSRF)» |
| Webhook `http://` · dominio fuera de la allowlist | 400 · 403 |
| Monitor nuevo (local, SQLite) | Ejecutado 37 s después; un solo `POST` con evento `cambios`, puerto 80 en `puertos_nuevos`, firma HMAC válida, `Host: webhook.site` |
| Segunda ejecución sin cambios | Escaneo #3, línea base al #3, ningún aviso nuevo |
| Log de la API | Creación y entrega auditadas con `https://webhook.site/…`; el token, 0 veces |
| Stack Docker (PostgreSQL 16.15) | Migración aplicada al arrancar; mismo aviso, firmado; reclamo concurrente `[True, False]` |
| `GET /config/status` en Docker (pendiente del bloque 3) | «sin .env · 29 campos desde variables de entorno», «PostgreSQL 16.15 · migraciones al día» |
| `POST /scans` en Docker (pendiente del bloque 3) | 202 en 0,06 s; `completed` a los 11 s |

**La prueba completa** (14/10/2026, a petición del usuario): stack Docker con
`SCAN_ALLOWLIST=scanme.nmap.org` por un override fuera del repositorio, 9
fases y evidencias publicadas en una página
(https://claude.ai/artifact/9xemMd7makz8RuyUJSNtjw). Los cambios se simularon en la
línea base (puerto 80 cerrado, hosts `simulado-*`) y se deshicieron al acabar;
el turno de cada ejecución se adelantó en la base de datos para no esperar
una hora.

| Fase | Resultado |
|---|---|
| A · rechazos | 10 de 10 con su motivo: `http`, `localhost`, `127.0.0.1.nip.io` (resuelve de verdad a `127.0.0.1` en el contenedor), metadatos `169.254.169.254`, `10.0.0.5.nip.io`, credenciales en la URL, host inexistente (400); dominio fuera de la allowlist (403); intervalo 0 y secreto corto (422) |
| B · primera ejecución | 16 s tras crearlo; aviso `cambios` (1 desaparecido, 1 con cambios), firma válida |
| C · sin cambios | Ningún aviso; la base avanza |
| D · receptor caído | Con 503: `last_error` y la base quieta (#7); con 200: aviso del **#9 frente al #7**, el cambio no se perdió |
| E · crt.sh caído | **Destapó el defecto**: el escaneo sale con 1 activo (la raíz), no con 0, y el guardia no saltaba. Corregido (`f541101`) y repetido: `escaneo_fallido` «crt.sh no aportó ningún subdominio y en la línea base aportó 1» |
| F · fuera de la allowlist | Ningún escaneo creado (11 → 11); `escaneo_fallido` con `scan_id: null` |
| G · pausa | 75 s con el turno vencido sin ejecutarse; al reanudar, ejecución en la siguiente vuelta; reclamo concurrente `[True, False]` |
| H/I · auditoría | 10 líneas en un solo contenedor (SSRF, creación, NO entregado 503, entregado, borrado); token y secreto, 0 veces en el log; 7 avisos recibidos, 7 firmas válidas |

**Un error de método, también.** Recrear el contenedor de la API para
cambiar su configuración (fases E y F) borra sus logs, y con ellos la
auditoría de las fases anteriores. Se repitió lo necesario en una fase sin
reinicios (I) y se guardó el log al momento.

---

## 8. Límites

- **Vigilancia: el diff no separa señal de ruido.** Un timeout o una
  fluctuación de DNS sale como cambio: un dominio grande puede avisar en casi
  cada ejecución.
- **Un aviso fallido no se reintenta al momento**; se repite, acumulado, en la
  siguiente ejecución.
- **La URL del webhook y su secreto se guardan en claro** en la base de datos
  (hacen falta para enviar y firmar), como las claves en `.env`.
- **El panel no edita un monitor** (se borra y se crea otro) ni guarda un
  historial de avisos: la API solo guarda el último resultado.
- **El trabajo vive en el proceso de la API.** Con varios procesos sobre la
  misma base de datos, uno que arranca cerraría los escaneos de otro. Se
  despliega con uno. (La vigilancia no repite ejecuciones entre procesos:
  cada una se reclama, §6.)
- ~~**Sin probar en el stack Docker real**, como `GET /config/status`.~~
  *Estado posterior:* ambos verificados con el stack levantado el
  14/10/2026 (§7).
- **El seguimiento depende de tener el panel abierto**; si se cierra, el
  escaneo termina igual y aparece en «Escaneos».

---

## 9. Lo que queda de la fase

1. **Cierre**: dossier y guía al día (con la restricción #7), guion de la
   demo recorrido en `replay`, decidir si la vigilancia entra en la demo y
   `push`.

---

## 10. Commits

| Commit | Contenido |
|---|---|
| `a0e7803`, `7b96ba2` | docs: dossier de defensa, respuestas de las memorias al día y enfoque funcional |
| `ce2a048` | feat(api): `POST /scans` en segundo plano (202) |
| `c8043a0` | fix(dashboard): la API en `127.0.0.1` y no en `localhost` |
| `35cb462` | feat(dashboard): seguimiento del escaneo en segundo plano |
| `2ff066c` | style(dashboard): aviso de `ruff` que entró en el anterior |
| `1fc0e7f` | docs: el bloque 3 en CLAUDE.md, ARQUITECTURA, README y esta memoria |
| `5acc66f` | docs: Netlas, evaluada y descartada como segunda fuente |
| `7de68a2` | feat(core): avisos por webhook protegidos contra SSRF |
| `c8e03b1` | feat(api): vigilancia programada con aviso por webhook (`/monitors`) |
| `6d171c4` | docs: la vigilancia en CLAUDE.md, ARQUITECTURA, README y esta memoria |
| `f541101` | fix(monitor): la fuente caída, por lo que aporta y no por 0 activos |
| `ddb0ccd` | docs: la prueba completa y la corrección del guardia |
| `88bc65d` | feat(dashboard): panel de vigilancia (pestaña «Vigilancia») |
| (este) | docs: el panel de vigilancia y el estado al cierre del 14/10/2026 |

---

## 11. Bloque de defensa: preguntas previsibles

**¿Por qué el escaneo va en segundo plano?**
Porque dura de segundos a minutos. Dentro de la petición, la conexión quedaba
abierta y un cliente con timeout lo daba por fallido aunque siguiera. Ahora la
API responde al momento y el panel sigue usable.

**¿Qué pasa si se apaga la API a mitad de un escaneo?**
El escaneo no se queda «en curso» para siempre: al volver a arrancar, la API
lo marca como fallido con el motivo. Se probó parándola de verdad.

**¿Y si escaneo un dominio no autorizado?**
Se rechaza al momento, antes de crear nada. Y si la lista cambia entre la
petición y la ejecución, la ejecución vuelve a comprobarla.

**¿Por qué no se puede comparar con un escaneo en curso?**
Porque todavía no tiene activos: todos saldrían como «desaparecidos». La API
lo rechaza y el panel no lo ofrece.

**¿Se puede ver un escaneo a medias?**
No: todo lo que encuentra se guarda de una vez al terminar. Mientras corre se
ve vacío y «en curso».

**¿Por qué el dashboard iba lento en Windows?**
Por un detalle de red: `localhost` prueba antes IPv6 y la API solo escucha en
IPv4, así que cada petición perdía 2 segundos. Se midió y se corrigió: la
carga bajó de 9,7 a 2,9 segundos.

**¿Por qué solo crt.sh? ¿No probaste otras fuentes?**
Sí. Shodan está integrada, pero su búsqueda de subdominios exige un plan de
pago. Netlas tiene un plan gratuito y la medí antes de integrarla: para
github.com tiene 38.000 nombres, pero los que miré no resolvían a ninguna
dirección, y el plan gratuito da como mucho 200 por consulta y 2.500 al mes.
Habría metido más ruido que activos, así que preferí dedicar el tiempo a la
vigilancia programada.

**¿La herramienta vigila sola o hay que lanzarla a mano?**
Vigila sola. Le dices un dominio, cada cuánto y a qué dirección avisar, y
repite el escaneo con esa frecuencia. Si aparece un subdominio, desaparece
otro o uno que ya existía abre un puerto, manda un aviso. En la prueba real
detectó un puerto nuevo en scanme.nmap.org y el aviso llegó en segundos.

**¿Y si falla el escaneo? ¿Me entero?**
Sí, con un aviso distinto. Una vigilancia que falla en silencio es peor que
no tenerla: una semana sin avisos se leería como «nada ha cambiado».

**¿Y si el receptor del aviso está caído?**
El cambio no se pierde. La herramienta solo da un cambio por avisado cuando
el aviso llega; si no, lo vuelve a mandar en la siguiente ejecución, junto con
lo que haya cambiado entretanto.

**¿No puede dar falsas alarmas?**
La más grave sí la evita: si la fuente de subdominios se cae, el escaneo sale
sin sus subdominios y parecería que han desaparecido. Eso se avisa como fallo
de la fuente, no como cambio. Y lo sé porque la prueba real me pilló una
primera versión que no lo hacía bien: la corregí y la volví a probar. Lo que no distingue es una fluctuación pequeña
(un servidor que no respondió a tiempo) de un cambio real; por eso lo ausente
se llama «desaparecido» y no «cerrado».

**¿Usa IA para los avisos?**
No, a propósito. El aviso dice qué cambió, que es un cálculo exacto; no
depende de que el proveedor de IA responda ni gasta crédito. La valoración con
IA del cambio sigue disponible desde el panel, a demanda.

**Si me dejan poner una URL de aviso, ¿no puedo hacer que la herramienta ataque
su propia red?**
Es el riesgo principal de un webhook (SSRF) y está cubierto. Solo se admiten
direcciones públicas y con cifrado: una URL hacia la propia máquina, la red
interna o el servicio de metadatos de la nube se rechaza, y queda registrado.
Se comprueba al crear el monitor y otra vez al enviar, y al enviar se conecta
a la dirección que se comprobó, para que no se pueda cambiar entre medias.

**¿Cómo sabe el receptor que el aviso viene de verdad de Atalaya?**
Si se configura un secreto, cada aviso va firmado, como hacen GitHub o Stripe.
El receptor recalcula la firma y descarta lo que no cuadre.

**¿Cada cuánto se puede escanear?**
Como mucho una vez por hora, y un solo monitor por dominio. Un escaneo hace
cientos de conexiones al objetivo: repetirlo cada pocos minutos sería un
barrido continuo, que el objetivo no distinguiría de un ataque.
