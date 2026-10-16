# Memoria técnica — Ampliación: vigilancia con menos ruido

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación 15, del 15 al 16/10/2026. Pedida por el
usuario al cerrar la fase 14 («reduce el ruido»): que la vigilancia programada
no convierta cada fluctuación de un escaneo en una alerta.
**Estado:** Cerrada el 16/10/2026, con la que se cierra también la
herramienta. 704 tests, `ruff` y `mypy` a cero. Ningún prompt cambió: la demo
en `replay` sigue intacta.

---

## 1. Resumen ejecutivo

1. **Un cambio solo se avisa si se ve en dos escaneos seguidos**, cambio a
   cambio (un host, su estado, un puerto, un tipo de hallazgo) y en las dos
   direcciones. Lo visto una sola vez queda «por confirmar»; si el escaneo
   siguiente no lo repite, se descarta como ruido sin avisar.
2. **La confirmación se adelanta a una hora**, el intervalo mínimo, para que
   un monitor diario no avise de cada cambio real un día tarde.
3. **Nada se pierde**: se compara contra lo ya avisado, y lo no avisado (por
   confirmar, o confirmado con el aviso fallido) se guarda con su valor
   anterior.
4. **Probado en real**: un servidor lento produjo 9 cambios falsos y ninguno
   llegó al receptor; un cambio persistente llegó firmado al segundo escaneo.
   Con los mismos escaneos, la versión anterior habría enviado 3 avisos, 2 de
   ellos falsos.
5. **El panel** dice qué espera confirmación y cuánto ruido se descartó, con
   maqueta aprobada antes de commitearlo.

---

## 2. El problema, y lo que se pudo medir

La fase 14 dejó escrito un límite: «un timeout o una fluctuación de DNS sale
como cambio: un dominio grande puede avisar en casi cada ejecución». Antes de
diseñar se buscaron datos para medirlo.

**Lo que había no lo confirmaba.** En los escaneos guardados, los tres últimos
de `scanme.nmap.org` son idénticos, y entre los dos de github.com (una semana
de diferencia) hay cuatro cambios que parecen reales: un subdominio nuevo, un
HSTS acortado, un certificado que entra en la ventana de caducidad y una CSP
que desaparece. No hay escaneos repetidos de un dominio grande con
autorización, así que **cuánto ruido hay en uno sigue sin medirse**, y así
consta ahora en CLAUDE.md: la frase era una hipótesis.

**Lo que sí se comprobó, en el código, es cómo nace el ruido:**

| Medición que falla | Lo que sale en el diff |
|---|---|
| Un puerto no contesta a tiempo | El puerto «desaparece» |
| El DNS de un host da timeout | Cambia su estado y pierde sus puertos y hallazgos |
| HTTPS y HTTP no contestan | Desaparecen todos sus hallazgos de cabeceras |
| HTTPS no contesta y HTTP sí | **Aparece** un `sin_https` que no existe (`discovery/headers.py`) |

La última fila decidió el diseño: el ruido también hace aparecer cosas.
Desconfiar solo de lo que desaparece no bastaba.

---

## 3. El diseño (`5f3b4b6`, antes del código)

Se escribió en ARQUITECTURA §12 y en CLAUDE.md, en un commit de
documentación aparte y antes del código, como se hace con los cambios de
criterio.

**Cambios atómicos.** El diff se descompone en piezas: un host que aparece o
desaparece, un cambio de estado, un puerto, un tipo de hallazgo. Cada una se
confirma por separado, para que un puerto que fluctúa no retrase el aviso de
un subdominio nuevo. De un host que aparece cuenta que existe, no su detalle:
es el mismo cambio aunque sus puertos difieran entre los dos escaneos.

**Confirmación.** Un cambio se confirma cuando la ejecución anterior vio el
mismo cambio, hacia el mismo valor. Un estado que pasa de `active` a `timeout`
y luego a `nxdomain` son dos observaciones distintas: no se confirma hasta
que una se repita.

**La referencia es lo ya avisado.** Aquí estuvo lo difícil. Con la base fija
en un escaneo (como en la fase 14), lo visto una sola vez tenía dos destinos
malos: si la base avanzaba al escaneo nuevo, el cambio quedaba absorbido sin
avisar; si no avanzaba, lo ya avisado se repetía en cada ejecución. La
solución: la base pasa siempre al último escaneo comparado, y cada cambio no
avisado se guarda **con su valor anterior** (`monitors.pending_changes`).
Deshaciendo esos cambios sobre la base se obtiene exactamente lo que el
receptor ya sabe. Se descartaron dos alternativas equivalentes pero más
pesadas: guardar el estado avisado entero en JSON, o una lista de «ya
entregados» con la base fija.

**Un aviso perdido sigue sin perder el cambio.** La regla del bloque 4 se
mantiene: si el webhook falla, lo confirmado se queda pendiente, y en la
ejecución siguiente se confirma otra vez y se reenvía.

**Confirmación adelantada.** Esperar al turno normal retrasaría un día cada
aviso de un monitor diario. Si una ejecución deja cambios nuevos y antes no
había nada pendiente, el siguiente escaneo se adelanta a una hora. Solo en
esa transición: en un dominio que fluctúa sin parar, lo pendiente no llega a
vaciarse y no se adelanta, así que como mucho hay un escaneo de más por
turno. El mínimo de una hora de la restricción #5 no cambia.

---

## 4. La implementación (`f3abebb`)

- `core/change_confirmation.py`: puro cálculo, sin base de datos ni red,
  como `diff_scans`. Lo comparable de un escaneo, los cambios atómicos, la
  referencia, la confirmación y la vuelta a la forma del diff para el aviso.
- `core/monitor_runner.py`: la comparación pasa por la confirmación; el
  aviso añade `por_confirmar` y `descartados`, y su resumen dice «confirmados
  en los escaneos #a y #b».
- Migración `8fd664bfa9de`: `pending_changes` (JSON) y `last_discarded`, con
  valor por defecto en la base de datos para los monitores que ya existían.
- La API devuelve los dos contadores, no el detalle.

**Un detalle que salió con los datos reales.** El test de «deshacer los
cambios devuelve la referencia» se escribió con los dos escaneos reales de
github.com y falló: entre una semana y otra, el triaje dio otra severidad al
mismo hallazgo en dos hosts. La severidad no es un cambio (el diff compara por
tipo), así que la referencia se queda con la más reciente; el test exige
igualdad en lo que sí cuenta como cambio.

---

## 5. La prueba real (15/10/2026)

API real (uvicorn) contra un PostgreSQL 16 desechable, escaneos reales de
`scanme.nmap.org` por la red y un receptor real en webhook.site. Evidencias
publicadas: https://claude.ai/artifact/FHzmxcBAEx8YQ75UpgGx79.

| Escaneo | Qué se hizo | Resultado | Siguiente |
|---|---|---|---|
| #1 | Monitor nuevo | Referencia, sin aviso | 24 h |
| #2 | Timeouts de 1 ms en puertos y cabeceras (servidor lento) | 9 cambios por confirmar, 0 avisos | 1 h, adelantado |
| #3 | Timeouts normales | Los 9 descartados como ruido, 0 avisos | 24 h |
| #4 | El 80 cerrado en la referencia (simulado) | 1 cambio por confirmar, 0 avisos | 1 h, adelantado |
| #5 | Sin tocar nada | Confirmado: 1 aviso, firma HMAC válida, HTTP 200 | 24 h |

**Antes y después.** Aplicando el diff de la versión anterior a esos cinco
escaneos: 3 avisos (los 9 «desaparecidos» del #2, su «reaparición» en el #3 y
el puerto del #4), 2 de ellos falsos. Ahora, 1 aviso, real, un escaneo más
tarde.

**Qué se simuló, y por qué.** El servidor lento, reiniciando la API con
timeouts de 1 ms: las conexiones de verdad no llegan a completarse, que es lo
que provoca un servidor lento o una red congestionada. El cambio persistente,
marcando el 80 como cerrado en la referencia, como en la prueba del bloque 4,
porque scanme.nmap.org no cambia. Y los turnos, adelantados en la base de
datos para no esperar entre ejecuciones; el adelanto a una hora sí es el que
calculó el monitor.

---

## 6. El panel (`835ad18`)

Con la confirmación, «sin cambios» escondía dos cosas: que hay cambios
esperando y cuánto ruido se descartó. La maqueta se hizo con el dashboard
real contra la API de la prueba, con el mismo monitor en tres momentos
reales, y el usuario la aprobó antes del commit:

1. Estado «por confirmar», con el acento en línea discontinua: provisional,
   ni alerta (ámbar) ni escaneo en marcha (acento continuo).
2. «confirma lo pendiente» bajo el próximo turno cuando se adelantó.
3. «sin cambios» dice cuántos cambios se descartaron como ruido.
4. «avisado» dice que se confirmó en dos escaneos y cuántos esperan.
5. Fuera del plan, visto al revisar las capturas: con cambios pendientes no
   se escribe «compara con el escaneo #N», porque la referencia es ese escaneo
   sin esos cambios y la frase engañaría.

---

## 7. Verificación

**Tests:** de 687 a 704. 16 de la confirmación: la equivalencia con
`diff_scans` y el deshacer exacto sobre los dos escaneos reales de github.com,
los cambios atómicos de un timeout, confirmar y descartar, el estado que
cambia hacia otro valor, el host nuevo con puertos distintos, el subconjunto
que enseña el estado avisado, el JSON de ida y vuelta, y a nivel del monitor
un timeout realista que se descarta, las dos direcciones, cambio a cambio, el
adelanto y la fuente caída. Tres tests anteriores se reescribieron con el
criterio nuevo, conservando su intención. Uno más del panel.

**Mutaciones:** ocho cambios del diseño hacen fallar algún test cada uno
(avisar sin confirmar, absorber lo confirmado no entregado, adelantar siempre,
no adelantar nunca, comparar el host con su detalle, no deshacer los puertos,
base fija como antes, no contar los descartados).

**Migración:** en SQLite (base de datos nueva, copia de la de desarrollo y una
con un monitor creado antes) y en PostgreSQL 16 real, con subida, bajada,
vuelta a subir y `alembic check` sin diferencias con los modelos. El 16/10 se
aplicó sola al levantar el stack Docker del usuario, sobre sus 23 escaneos.

---

## 8. Límites

- **Una fluctuación que dure dos escaneos seguidos sí se avisa.**
- **Cada aviso llega un escaneo tarde**: una hora con la confirmación
  adelantada.
- **El ruido de un dominio grande sigue sin medirse**: no hay escaneos
  repetidos de uno con autorización.
- **Los avisos no distinguen importancia**: un `csp_missing` que desaparece
  y un 3389 que se abre van igual. Queda como mejora posible.

---

## 9. Lecciones de proceso

- **Medir antes de diseñar**, aunque el dato no acompañe: los escaneos
  guardados no mostraban el ruido que se daba por hecho, y eso se dijo en vez
  de inventar una cifra. La necesidad salió del código.
- **Los datos reales en los tests vuelven a pagar**: la severidad que cambia
  entre escaneos no habría salido con casos fabricados.
- **Tres trampas del entorno**, apuntadas en CLAUDE.md: la terminal convertía
  la barra invertida de un heredoc en un carácter de control (se coló un
  retroceso en un test); el Playwright del entorno buscaba otra versión de
  Chromium; y `example.com` no resuelve con el DNS del usuario, así que la
  API rechazó ese webhook con un 400, que es lo correcto.

---

## 10. Commits

| Commit | Contenido |
|---|---|
| `5f3b4b6` | docs: diseño de la confirmación de cambios, antes del código |
| `f3abebb` | feat(monitor): confirmar cada cambio en dos escaneos antes de avisar |
| `5066eee` | style(core): una línea de más de 100 caracteres |
| `996ca70` | docs: la confirmación en el README y el estado de la fase |
| `e5e7349` | docs: estado al cierre de la sesión del 15/10/2026 |
| `835ad18` | feat(dashboard): lo pendiente de confirmar y lo descartado en «Vigilancia» |
| `1327551` | docs: el panel aprobado y el estado al cierre del 15/10/2026 |
| (este) | docs: cierre de la fase 15 y de la herramienta |

---

## 11. Bloque de defensa: preguntas previsibles

**¿Por qué la vigilancia no avisa en cuanto ve un cambio?**
Porque un escaneo es una medición y a veces falla. Un servidor que tarda en
contestar hace «desaparecer» sus puertos; avisar de eso es una falsa alarma.
Por eso un cambio se avisa cuando se ve en dos escaneos seguidos.

**¿No llega tarde un aviso importante?**
Un escaneo tarde: cuando aparece algo nuevo, el siguiente escaneo se adelanta
a una hora para confirmarlo. Es el precio de no avisar de cada timeout.

**¿Cómo sabes que funciona?**
Lo probé con escaneos reales: simulé un servidor lento y salieron 9 cambios
falsos. Ninguno llegó al receptor, y los 9 se descartaron en el escaneo
siguiente. Un cambio que sí persistía llegó firmado al segundo escaneo. Con la
versión anterior, esos mismos escaneos habrían dado 3 avisos, 2 falsos.

**¿Por qué confirmar también lo que aparece?**
Porque el ruido también hace aparecer cosas. Si HTTPS no contesta a tiempo y
HTTP sí, la herramienta vería un sitio «sin HTTPS» que no existe.

**¿Cuánto ruido había antes?**
En un dominio grande no lo he podido medir: no tengo escaneos repetidos de uno
con autorización. Lo que sí sé es cómo se produce, y en la prueba real la
versión anterior habría enviado dos avisos falsos de tres.

**¿No escanea más el objetivo por confirmar?**
Como mucho un escaneo más por turno, y nunca a menos de una hora del
anterior, que es el mínimo que ya tenía la herramienta.

**¿Qué pasa si el receptor está caído cuando se confirma un cambio?**
El cambio se queda pendiente y se vuelve a enviar en la ejecución siguiente;
no se pierde.

**¿Qué significa «por confirmar» en el panel?**
Que el último escaneo vio algo distinto una sola vez. Si el siguiente lo
repite, se avisa; si no, se descarta como ruido y el panel dice cuántos
descartó.
