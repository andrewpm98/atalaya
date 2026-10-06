# Memoria técnica — Ampliación: diff de activos comunes y reutilización del triaje

**Proyecto:** Atalaya — Plataforma de Attack Surface Management (ASM) con triaje por IA
**Asignatura:** Práctica 1 — Máster en Ciberseguridad e Inteligencia Artificial
**Fase documentada:** Ampliación posterior al cierre pre-entrega (06/10/2026).
Dos mejoras de producto y una revisión crítica de la herramienta, de la que
salen las carencias que quedan anotadas para las siguientes sesiones.
**Estado:** Completa, en local (pendiente de `push`). 472 tests, `ruff` y
`mypy` a cero, cada commit verificado en verde por separado.

---

## 1. Resumen ejecutivo

La sesión empezó con una pregunta: qué queda por hacer. Con los cinco
requisitos obligatorios y los siete pasos cerrados, lo pendiente era deuda
técnica, y de toda la lista solo una entrada contradecía algo que la
herramienta dice hacer: **el diff solo comparaba hostnames**. Un activo que
ya existía y abría un puerto, o perdía HSTS, salía como «sin cambios». Es
justo lo que un ASM debe vigilar en el tiempo.

1. **Diff de activos comunes.** El diff devuelve ahora `cambiados`: los
   activos presentes en los dos escaneos que cambiaron de estado, de puertos
   abiertos o de hallazgos. En los dos escaneos reales de github.com de la
   demo aparecen 3 cambios que antes eran invisibles.
2. **Reutilización del triaje entre escaneos.** Un re-escaneo volvía a pagar
   el triaje de todo lo que no había cambiado. Ahora se copia el triaje de un
   hallazgo de otro escaneo cuando el prompt sería idéntico. En la demo,
   triar el segundo escaneo pasa de 211 a 154 llamadas al modelo (27 %).

La propuesta inicial para el punto 2 (deduplicar prompts idénticos dentro
del mismo lote) **se descartó al medirla**: ahorraba un 0 %. Se documenta en
la sección 4.1 porque es el ejemplo más claro de la sesión de por qué se
mide antes de implementar.

---

## 2. Criterio de la fase

- **No cambiar ningún prompt sin necesidad.** El crédito de la API de
  Anthropic está agotado desde esta sesión, y cualquier cambio de prompt deja
  obsoleta la grabación de la demo (`demo/ai_recordings.json`). El diff tuvo
  que cambiar el prompt del comparador y se regrabó antes de agotarse el
  crédito (2 llamadas). La reutilización del triaje se diseñó para **no**
  cambiar ninguno.
- **El contrato de la API no se rompe.** Ambos cambios añaden campos, no
  quitan ni cambian el significado de los existentes.
- **`ai/triage.py` no se toca**, como desde el Paso 5.

---

## 3. Diff de activos comunes (`272b4c6`, `1ade547`, `a696096`)

### 3.1 El cálculo

`core/repository.py::diff_scans()` sigue devolviendo `nuevos`,
`desaparecidos` y `comunes`, y añade `cambiados`: por cada activo común con
algún cambio, estado anterior y actual, puertos nuevos y desaparecidos, y
hallazgos nuevos y desaparecidos con su severidad. Tres decisiones:

| Decisión | Motivo |
|---|---|
| Hallazgos comparados por `finding_type`, no por evidencia | La evidencia cambia sin que cambie el problema: «el certificado caduca en 27 días» pasa a «20 días» la semana siguiente. Comparando el texto, todo certificado saldría cambiado en cada escaneo. Cada técnica emite como mucho un hallazgo por tipo y host, así que el tipo identifica el hallazgo. |
| IPs no comparadas | Con CDN y balanceo, la IP varía entre escaneos sin que cambie la exposición. Comparándolas, casi todo host tras un balanceador saldría cambiado. |
| «Desaparecido», no «cerrado» ni «resuelto» | Si la sonda de cabeceras no obtiene respuesta, no hay cabeceras que evaluar y el hallazgo tampoco aparece. El cálculo no distingue una corrección de un timeout, y el nombre no afirma más de lo que sabe. |

La severidad de cada hallazgo es la del escaneo donde está: el actual para
los nuevos y el previo para los desaparecidos. Un hallazgo que desaparece se
valora por lo grave que era.

`comunes` sigue completo, así que un cliente anterior recibe lo mismo; «sin
cambios» es `comunes` menos los hostnames de `cambiados`.

### 3.2 El comparador de IA

`ai/diff_analyst.py` recibe los cambios de cada activo con **solo los campos
que cambiaron** (en un dominio grande, repetir estados iguales y listas
vacías infla el prompt sin aportar). El prompt añade dos advertencias: un
puerto o hallazgo desaparecido puede ser una sonda sin respuesta, y un
hallazgo `unknown` aún no se ha triado.

Como el contexto lleva la severidad de los hallazgos cambiados, el diff de
la demo tiene ahora **dos grabaciones**, antes y después del triaje en
directo (26 en total). La regrabación costó 2 llamadas reales; el triaje
salió entero de la caché.

### 3.3 El dashboard

«Comparar con» muestra cuatro recuentos (Nuevos, Desaparecidos, Cambiados,
Sin cambios) y una fila por activo cambiado, con chips `+`/`−` para estado,
puertos y hallazgos y el filo con el color de su severidad. El hostname se
escapa: viene del DNS y lo controla el objetivo.

### 3.4 Resultado sobre los datos reales

github.com, escaneo del 21/09 frente al del 28/09: 1 activo nuevo, 0
desaparecidos, 117 comunes, de los que **3 cambian**:

| Activo | Cambio |
|---|---|
| `maintainers.github.com` | + `hsts_max_age_bajo` |
| `vpn-ca.iad.github.com` | + `certificado_proximo_a_caducar` |
| `copilot-billing-preview.github.com` | − `csp_missing` |

La valoración del modelo trata el `csp_missing` desaparecido como mejora
probable sin darla por segura, y los dos nuevos como pendientes de triar.
**Defecto de la grabación:** la valoración posterior al triaje escribe
«`vpn-ca.github.com` (IAD)» en vez de `vpn-ca.iad.github.com`. Es un descuido
del modelo, no del código; regrabarlo cuesta una llamada cuando haya crédito.

---

## 4. Reutilización del triaje (`02e644b`, `1a1f99e`)

### 4.1 La propuesta que se descartó al medirla

La propuesta de partida era deduplicar prompts idénticos dentro de un mismo
lote de triaje, con la premisa de que «falta X-Frame-Options» sale igual en
decenas de hosts y cada uno paga su llamada.

La premisa es cierta para la **evidencia** y falsa para el **prompt**. El
contexto del triaje (`build_finding_context`) incluye el activo: hostname,
IPs, estado, fuentes y puertos. Medido sobre la demo:

| | Hallazgos | Prompts únicos | Ahorro de deduplicar dentro del lote |
|---|---|---|---|
| Escaneo #1 | 204 | 204 | 0 % |
| Escaneo #2 | 211 | 211 | 0 % |

Dentro de un escaneo no puede repetirse un prompt: cada técnica emite como
mucho un hallazgo por tipo y host. En cambio, de los 211 hallazgos del #2
solo hay **11 combinaciones distintas de tipo + evidencia**
(`permissions_policy_missing` aparece 59 veces con el mismo texto).

Había tres caminos, y se eligió el primero:

1. **Reutilizar entre escaneos ante el mismo prompt exacto.** 57 de los 211
   prompts del #2 son idénticos a uno del #1. No cambia ningún prompt.
2. Deduplicar dentro del lote, como se proponía: 0 % de ahorro.
3. Quitar el activo del prompt y agrupar por tipo + evidencia: de 211 a 11
   llamadas, pero el modelo dejaría de ver el host (no pesa igual el
   clickjacking en `vpn-ca.iad.github.com` que en una página estática) y
   habría que regrabar la demo sin crédito.

### 4.2 La implementación

`ai/triage_reuse.py::reuse_previous_triage()` compara la huella canónica
del contexto de cada hallazgo pendiente con la de los ya triados de otros
escaneos del dominio (`core/repository.py::list_triaged_findings()`, del
más reciente al más antiguo: si hay varios triajes del mismo contexto, gana
el último). El resto del prompt (prefijo, prompt de sistema, herramienta) es
constante, así que **mismo contexto significa mismo prompt**: se reutiliza
la respuesta a la misma pregunta exacta, nunca a una parecida. Es el mismo
criterio que `replay`.

- `?force=true` no reutiliza: forzar es volver a preguntar al modelo actual.
- Si todo se reutiliza, no se instancia el proveedor: funciona sin clave.
- `TriageResponse` añade `reused` y `model_calls`, y la API registra
  «N hallazgos triados con M llamadas al modelo (K reutilizados, ahorro del
  X %)». El dashboard lo dice en el mensaje de éxito.
- Vive fuera de `ai/triage.py`: no cambia cómo se tría un hallazgo, solo
  cuántas veces hace falta preguntarlo.

### 4.3 El límite: las IPs

El ahorro se queda en el 27 % por las IPs. De los 203 hallazgos del #2 que
ya existían en el #1 (mismo host y tipo), solo 57 tienen el prompt idéntico;
en el resto ha cambiado algún campo del contexto, típicamente la IP de un
host tras CDN o balanceador. Quitar las IPs del prompt ahorraría más, pero
cambia lo que ve el modelo y obliga a regrabar. Queda como deuda.

---

## 5. Verificación

1. **Suite:** de 441 a **472 tests** (+11 del diff, +20 de la reutilización),
   `ruff` y `mypy` a cero. Entre los nuevos, un test parametrizado comprueba,
   campo a campo del contexto, que la huella de reutilización cambia
   exactamente cuando cambia el prompt real que se envía al modelo.
2. **Cada commit, por separado:** los seis primeros commits se ejecutaron en
   un worktree aislado, importando el paquete de ese worktree: 448, 450, 452,
   452, 471 y 472 tests en verde.
3. **Demo en `replay`, por HTTP contra una API real** sobre una BD temporal
   recién sembrada: las cuatro preguntas, el informe, el diff en los dos
   órdenes, el triaje en directo y de nuevo todo, con **cero respuestas sin
   grabación**. El triaje en directo hace 8 llamadas y no reutiliza nada,
   como debe: los 8 pendientes no existían en el #1.
4. **Ahorro medido con el código real:** el #2 triado desde cero con el #1
   triado da 57 reutilizados y 154 llamadas.
5. **Dashboard capturado** con `_shot.py --diff`: los 3 cambiados con sus
   chips y la valoración grabada.

---

## 6. Los límites deliberados, y por qué no se quitan

La revisión de la deuda técnica obligó a separar lo que **no se puede**
quitar de lo que **no se debe** quitar. Casi ningún límite es imposible
técnicamente; la defensa debe decirlo así.

| Límite | ¿Se puede quitar? | Por qué no se quita |
|---|---|---|
| Puertos: solo `COMMON_PORTS`, sin banner grabbing | Sí | Restricción #5: un barrido completo puede degradar al objetivo y no se distingue de un ataque; el banner grabbing ya interactúa con el servicio |
| Cabeceras: solo la portada, sin CORS | Sí, rastreando el sitio | Rastrear es otra actividad, mucho más intrusiva; CORS solo tiene sentido en rutas de API que la portada no enlaza |
| Takeover nunca «confirmado» | Sí, reclamando el recurso | Restricción #6: reclamarlo es el ataque |
| Tabla de takeover no exhaustiva | Parcialmente | Una huella frágil da falsos positivos, y un falso «alta sospecha» es peor que no decir nada |
| Verificación de takeover solo en hosts que no resuelven | Sí | Otra técnica, con más falsos positivos: un host activo hacia GitHub Pages casi siempre es legítimo |
| TLS: un error de cadena por host | Sí, validando a mano | OpenSSL se detiene en el primero; el segundo no cambia la conclusión y una validación propia puede discrepar del navegador |
| TLS solo en el 443 | Sí, y es barato | Prioridad: es el único límite que merece la pena cerrar |
| Re-triaje sin botón | Sí, trivial | Fricción intencionada: cientos de llamadas de pago con un clic |

---

## 7. Carencias detectadas en la revisión crítica

Como trabajo de máster la herramienta está por encima de lo pedido. Como
producto de ASM tiene carencias de fondo, anotadas en CLAUDE.md («Deuda
técnica conocida») para las próximas sesiones:

1. **Sin monitorización continua.** Los escaneos se lanzan a mano: no hay
   escaneos programados ni alertas. El ASM se define por vigilar en el
   tiempo, y el diff ampliado es la pieza que faltaba para alertar («ayer no
   tenía el 22 abierto»), pero nadie lo dispara. Es la carencia más grande.
2. **Una sola fuente efectiva de enumeración.** Con el plan gratuito, Shodan
   no aporta nada: en la práctica todo sale de crt.sh, frente a las decenas de
   fuentes de subfinder o amass. La calidad del inventario limita todo lo que
   viene después.
3. **Señal/ruido.** En github.com, 194 de los 211 hallazgos son `low`, casi
   todo higiene de cabeceras. La reutilización reduce el coste de triarlos,
   no su volumen.
4. **`POST /scans` es síncrono.** El escaneo entero corre dentro de la
   petición HTTP: 19 s para github.com, pero minutos para un dominio grande.
   Lo normal sería lanzarlo como tarea y consultar su estado.

Y dos riesgos para la defensa oral:

- **Seis agentes pueden parecer «agentes por moda»:** el prompter enruta
  entre solo dos destinos. La respuesta (cada agente tiene una forma de
  salida y un criterio de fallo distintos) conviene llevarla preparada.
- **El volumen de documentación:** la defensa evalúa lo que se sabe
  explicar. Las decisiones centrales (allowlist, IA después de persistir,
  `LLMProvider`, `risk_score` por bandas, `replay` que no inventa,
  excepción de la restricción #6) deben poder defenderse sin papeles.

---

## 8. Estado final y commits

| Commit | Tipo | Contenido |
|---|---|---|
| `272b4c6` | feat(core) | `diff_scans()` con `cambiados`; esquemas de la API |
| `1ade547` | feat(ai) | `diff_analyst` valora los cambios; demo regrabada |
| `a696096` | feat(dashboard) | Activos cambiados en «Comparar con» |
| `aec86af` | docs | Diff de activos comunes |
| `02e644b` | feat(ai) | Reutilización del triaje entre escaneos |
| `1a1f99e` | feat(dashboard) | El triaje informa de lo reutilizado |
| `14d43d5` | docs | Reutilización del triaje |

Más los commits de documentación de cierre de la sesión (esta memoria,
subagentes y CLAUDE.md). Todo en local, pendiente de `push`.

---

## 9. Bloque de defensa: preguntas previsibles

### Sobre el diff

**¿Por qué no se comparan las IPs?**
Porque con CDN y balanceo cambian entre escaneos sin que cambie nada de lo
expuesto. Si contaran, casi todo host tras un balanceador saldría como
cambiado, y el cambio real quedaría enterrado en ruido.

**¿Por qué los hallazgos se comparan por tipo y no por evidencia?**
Porque la evidencia lleva datos que varían solos: los días que faltan para
que caduque un certificado cambian cada semana. Comparar el texto marcaría
como cambiado un problema que es el mismo.

**Si un hallazgo desaparece, ¿está resuelto?**
No necesariamente, por eso se llama «desaparecido». Un timeout de la sonda
deja el mismo rastro que una corrección. El cálculo no puede distinguirlos y
el prompt del comparador pide al modelo que no lo dé por corregido sin
evidencia.

### Sobre la reutilización del triaje

**¿No es peligroso copiar el triaje de otro hallazgo?**
Solo se copia cuando el prompt sería idéntico byte a byte: misma pregunta
exacta al modelo, así que se reutiliza la respuesta que ya dio a esa misma
pregunta. Es el mismo criterio que `replay`: nunca una respuesta «parecida».
Un test comprueba, campo a campo, que la huella cambia exactamente cuando
cambia el prompt real.

**¿Por qué no agrupar por tipo de hallazgo, que ahorraría un 95 %?**
Porque habría que quitar el activo del prompt, y el activo cambia la
severidad: no pesa igual el clickjacking en un servidor de la VPN que en una
página estática. Además cambiaría todos los prompts.

**¿Por qué no deduplicar dentro del mismo escaneo?**
Porque no hay nada que deduplicar: el contexto lleva el host, y cada técnica
emite como mucho un hallazgo por tipo y host. Se midió: 211 hallazgos, 211
prompts distintos.

**¿Y si cambio de modelo?**
`?force=true` no reutiliza nada: vuelve a preguntar al modelo actual por
todos los hallazgos.

### Sobre la herramienta en conjunto

**¿Qué le falta para ser un ASM de verdad?**
Monitorización continua: escaneos programados y alertas cuando el diff
cambia. Las piezas existen (persistencia, diff con cambios de los activos
comunes); falta el disparador. Y más fuentes de enumeración: hoy, en la
práctica, solo crt.sh.
