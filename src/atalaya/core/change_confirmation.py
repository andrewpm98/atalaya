"""Confirmación de cambios de la vigilancia: un cambio solo se avisa si se ve
en dos ejecuciones seguidas del monitor.

Un escaneo es una medición, y una medición falla. Un puerto que no contesta a
tiempo «desaparece»; un host cuyo DNS da timeout pierde sus puertos y sus
hallazgos; y si HTTPS no responde pero HTTP sí, *aparece* un `sin_https` que
no existe (`discovery/headers.py`). Avisar de cada diferencia entre dos
escaneos convierte cada timeout en una alerta. Por eso:

- El diff se descompone en **cambios atómicos**: un host que aparece o
  desaparece, un cambio de estado, un puerto, un tipo de hallazgo. Cada uno
  se confirma por separado: un puerto que fluctúa no retrasa el aviso de un
  subdominio nuevo.
- Un cambio se **confirma** cuando la ejecución anterior vio el mismo cambio
  frente al mismo valor avisado. En las dos direcciones: el ruido también
  hace aparecer cosas.
- Lo visto una sola vez queda **por confirmar**; si la ejecución siguiente no
  lo repite, se **descarta** como ruido sin avisar.

La comparación es siempre contra lo que el receptor ya sabe (la
*referencia*): el último escaneo comparado con los cambios aún no avisados
deshechos, porque cada uno guarda su valor anterior. Así la base puede pasar
a cada escaneo sin absorber lo que no se avisó. Ver ARQUITECTURA §12.

Puro cálculo, sin base de datos ni red, como `diff_scans`. Qué cuenta como
cambio es lo mismo que allí (estado, puertos abiertos y tipos de hallazgo,
no las IPs ni la evidencia), y un test lo exige: el monitor y el diff que se
pide a mano no pueden discrepar.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from atalaya.core.models import Asset, Scan
from atalaya.core.repository import AssetChange, FindingRef, ScanDiff

#: Un host tal como se compara: `{"status": str, "ports": [int], "findings":
#: {tipo: severidad}}`. Diccionarios y listas, no objetos, porque los cambios
#: pendientes se guardan en JSON con el estado anterior del host.
HostState = dict[str, Any]
Snapshot = dict[str, HostState]

Kind = Literal["host", "status", "port", "finding"]


def host_state(asset: Asset) -> HostState:
    return {
        "status": asset.status,
        "ports": sorted(set(asset.open_ports)),
        "findings": {f.finding_type: f.severity.value for f in asset.findings},
    }


def snapshot(scan: Scan) -> Snapshot:
    """Lo comparable de un escaneo. Requiere `assets` y sus `findings`
    cargados, como `diff_scans`."""
    return {asset.hostname: host_state(asset) for asset in scan.assets}


@dataclass(frozen=True)
class Change:
    """Un cambio atómico frente a la referencia.

    `before`/`after` según `kind`: el estado completo del host o `None`
    (`host`), el texto del estado (`status`), si el puerto está abierto
    (`port`), la severidad del hallazgo o `None` (`finding`). `item` es el
    puerto o el tipo de hallazgo.
    """

    kind: Kind
    host: str
    item: int | str | None
    before: Any
    after: Any

    def token(self) -> tuple[Any, ...]:
        """Lo que la ejecución siguiente tiene que repetir para confirmarlo:
        qué cambió y hacia dónde. De un host o un hallazgo cuenta la
        presencia, no el detalle: un subdominio nuevo es el mismo cambio
        aunque sus puertos difieran entre los dos escaneos, y el diff compara
        hallazgos por tipo, no por severidad."""
        if self.kind in ("host", "finding"):
            return (self.kind, self.host, self.item, self.after is not None)
        return (self.kind, self.host, self.item, self.after)

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "host": self.host,
            "item": self.item,
            "before": self.before,
            "after": self.after,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Change:
        return cls(
            kind=cast("Kind", data["kind"]),
            host=data["host"],
            item=data["item"],
            before=data["before"],
            after=data["after"],
        )


def changes_between(reference: Snapshot, current: Snapshot) -> list[Change]:
    """Cambios atómicos de `reference` a `current`, en orden estable.

    De un host que aparece o desaparece sale un solo cambio, sin detallar sus
    puertos ni hallazgos (como `nuevos`/`desaparecidos` en `diff_scans`).
    """
    changes = [
        Change("host", host, None, None, copy.deepcopy(current[host]))
        for host in sorted(current.keys() - reference.keys())
    ]
    changes += [
        Change("host", host, None, copy.deepcopy(reference[host]), None)
        for host in sorted(reference.keys() - current.keys())
    ]
    for host in sorted(reference.keys() & current.keys()):
        before, after = reference[host], current[host]
        if before["status"] != after["status"]:
            changes.append(Change("status", host, None, before["status"], after["status"]))
        ports_before, ports_after = set(before["ports"]), set(after["ports"])
        changes += [
            Change("port", host, port, port in ports_before, port in ports_after)
            for port in sorted(ports_before ^ ports_after)
        ]
        found_before, found_after = before["findings"], after["findings"]
        changes += [
            Change("finding", host, kind, found_before.get(kind), found_after.get(kind))
            for kind in sorted(found_before.keys() ^ found_after.keys())
        ]
    return changes


def reference(base: Snapshot, pending: list[Change]) -> Snapshot:
    """Lo ya avisado: `base` (el último escaneo comparado) con los cambios
    pendientes deshechos.

    Todos los pendientes salen de una misma comparación (ver
    `core/monitor_runner.py`), así que nunca hay a la vez un cambio de host y
    uno de sus puertos o hallazgos: estos solo se calculan para hosts comunes.

    La severidad de un hallazgo que sigue presente no se deshace: no es un
    cambio, y la referencia se queda con la del escaneo más reciente (en los
    escaneos reales de la demo, el triaje dio otra severidad al mismo
    hallazgo en dos hosts entre una semana y la siguiente).
    """
    ref = copy.deepcopy(base)
    for change in pending:
        if change.kind != "host":
            continue
        if change.before is None:
            ref.pop(change.host, None)
        else:
            ref[change.host] = copy.deepcopy(change.before)
    for change in pending:
        state = ref.get(change.host)
        if change.kind == "host" or state is None:
            continue
        if change.kind == "status":
            state["status"] = change.before
        elif change.kind == "port":
            ports = set(state["ports"])
            if change.before:
                ports.add(cast("int", change.item))
            else:
                ports.discard(cast("int", change.item))
            state["ports"] = sorted(ports)
        elif change.before is None:
            state["findings"].pop(change.item, None)
        else:
            state["findings"][cast("str", change.item)] = change.before
    return ref


@dataclass
class Confirmation:
    """Resultado de una ejecución: qué se avisa, qué espera y qué se descartó."""

    #: Vistos también en la ejecución anterior: se avisan.
    confirmed: list[Change] = field(default_factory=list)
    #: Vistos por primera vez: esperan a la siguiente ejecución.
    unconfirmed: list[Change] = field(default_factory=list)
    #: Pendientes que esta ejecución no repitió: ruido, no se avisan nunca.
    discarded: int = 0


def confirm(changes: list[Change], pending: list[Change]) -> Confirmation:
    previos = {change.token() for change in pending}
    actuales = {change.token() for change in changes}
    return Confirmation(
        confirmed=[c for c in changes if c.token() in previos],
        unconfirmed=[c for c in changes if c.token() not in previos],
        discarded=len(previos - actuales),
    )


def as_scan_diff(changes: list[Change], ref: Snapshot, current: Snapshot) -> ScanDiff:
    """Agrupa cambios atómicos con la forma de `diff_scans` (la del aviso y la
    de la API).

    Con todos los cambios entre dos escaneos, el resultado es idéntico al de
    `diff_scans` sobre esos escaneos. Con un subconjunto (los confirmados), el
    estado que no cambió se muestra como el de la referencia: es lo que el
    receptor ya conoce.
    """
    por_host: dict[str, AssetChange] = {}
    for change in changes:
        if change.kind == "host":
            continue
        asset = por_host.get(change.host)
        if asset is None:
            estado = ref[change.host]["status"]
            asset = AssetChange(hostname=change.host, estado_anterior=estado, estado_actual=estado)
            por_host[change.host] = asset
        if change.kind == "status":
            asset.estado_anterior, asset.estado_actual = change.before, change.after
        elif change.kind == "port":
            destino = asset.puertos_nuevos if change.after else asset.puertos_desaparecidos
            destino.append(cast("int", change.item))
        elif change.after is not None:
            asset.hallazgos_nuevos.append(FindingRef(cast("str", change.item), change.after))
        else:
            asset.hallazgos_desaparecidos.append(FindingRef(cast("str", change.item), change.before))
    for asset in por_host.values():
        asset.puertos_nuevos.sort()
        asset.puertos_desaparecidos.sort()
        asset.hallazgos_nuevos.sort(key=lambda ref: ref.finding_type)
        asset.hallazgos_desaparecidos.sort(key=lambda ref: ref.finding_type)
    return ScanDiff(
        nuevos=sorted(c.host for c in changes if c.kind == "host" and c.after is not None),
        desaparecidos=sorted(c.host for c in changes if c.kind == "host" and c.after is None),
        comunes=sorted(ref.keys() & current.keys()),
        cambiados=[por_host[host] for host in sorted(por_host)],
    )
