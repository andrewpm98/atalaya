# Memoria técnica — Ampliación: escaneo en segundo plano y monitorización

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación 14, iniciada el 13/10/2026. Prepara la
defensa (dossier y guía de la herramienta), saca el escaneo de la petición
HTTP y, en el siguiente bloque, añadirá la vigilancia programada.
**Estado:** En curso. Bloques 2 y 3 completos y subidos a `origin/main` el
13/10/2026: 605 tests, `ruff` y `mypy` a cero. Pendientes la decisión sobre
Netlas, la monitorización (bloque 4) y el cierre (bloque 5); ver §7.

---

## 1. Resumen ejecutivo

1. **Dossier de defensa y guía de la herramienta**, dos documentos vivos en
   Claude Docs. El dossier reúne en un sitio lo que estaba repartido entre
   doce memorias; la guía explica la herramienta a quien llega de fuera.
2. **`POST /scans` en segundo plano.** La API responde 202 al momento y el
   escaneo corre aparte; el dashboard lo sigue sin bloquearse.
3. **Un defecto anterior**, encontrado al prototipar: en Windows, cada
   petición del dashboard a la API tardaba 2 segundos.

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

## 5. Verificación

**Tests:** de 583 a 605 (+22): 17 del escaneo en segundo plano (202, 400 y
403 sin crear nada, fallo con motivo y sin secretos, autorización al ejecutar,
409 en triaje, informe, comparación y preguntas, atomicidad, recuperación al
arrancar y arranque con la base de datos caída) y 5 del dashboard (aviso en
curso, resumen, fallo, detalle en curso y fallido, comparación solo entre
completados). Cinco mutaciones hacen fallar los tests que las cubren.

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

---

## 6. Límites

- **El trabajo vive en el proceso de la API.** Con varios procesos sobre la
  misma base de datos, uno que arranca cerraría los escaneos de otro. Se
  despliega con uno.
- **Sin probar en el stack Docker real**, como `GET /config/status`.
- **El seguimiento depende de tener el panel abierto**; si se cierra, el
  escaneo termina igual y aparece en «Escaneos».

---

## 7. Lo que queda de la fase

1. **Decidir Netlas** como segunda fuente de subdominios (el usuario no quiere
   pagar el plan de Shodan). Plan gratuito con búsqueda DNS, pero sin
   confirmar que permita la API: antes, una prueba con su clave real.
2. **Bloque 4: monitorización** con escaneos programados y aviso por webhook,
   protegido contra SSRF. Reutilizará `run_scan`.
3. **Verificar en Docker** el escaneo en segundo plano y `/config/status`.
4. **Cierre**: documentación, preguntas de defensa y guion de la demo.

---

## 8. Commits

| Commit | Contenido |
|---|---|
| `a0e7803`, `7b96ba2` | docs: dossier de defensa, respuestas de las memorias al día y enfoque funcional |
| `ce2a048` | feat(api): `POST /scans` en segundo plano (202) |
| `c8043a0` | fix(dashboard): la API en `127.0.0.1` y no en `localhost` |
| `35cb462` | feat(dashboard): seguimiento del escaneo en segundo plano |
| `2ff066c` | style(dashboard): aviso de `ruff` que entró en el anterior |
| (este) | docs: el bloque 3 en CLAUDE.md, ARQUITECTURA, README y esta memoria |

---

## 9. Bloque de defensa: preguntas previsibles

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
