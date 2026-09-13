"""Clasificación de direcciones IP según su alcance de red.

Una resolución DNS correcta no implica un activo alcanzable. Existen varios
casos en los que un nombre resuelve sin que exista un host que analizar:

- ``0.0.0.0`` / ``::`` — dirección no especificada. Es la técnica habitual
  para **anular** un nombre sin retirar el registro DNS: el servicio se
  retiró pero la entrada sigue publicada.
- ``127.0.0.0/8`` — bucle local; nunca apunta a un host remoto.
- Rangos privados (RFC 1918, RFC 4193) — no enrutables en Internet. Un nombre
  **público** que resuelve a una IP privada no es un activo alcanzable, pero
  sí constituye una filtración de direccionamiento interno, que es un hallazgo
  por derecho propio.
- CGNAT (RFC 6598), enlace local, multicast, documentación y reservados.

Distinguir estos casos evita dos errores: contar activos que no existen e
inyectar objetivos inválidos en las fases posteriores de escaneo.

Nota de implementación: no basta con `ipaddress.is_global`. Las direcciones
multicast lo devuelven como verdadero, y los rangos de documentación se
marcan como privados. Por eso la clasificación sigue un orden explícito.
"""

from __future__ import annotations

import ipaddress
from enum import Enum

#: Rangos reservados para documentación y ejemplos (RFC 5737, RFC 3849).
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),    # documentación IPv6
)

#: Espacio compartido para CGNAT (RFC 6598).
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class IpScope(str, Enum):
    """Alcance de una dirección IP."""

    PUBLIC = "public"                # enrutable en Internet: objetivo válido
    PRIVATE = "private"              # RFC 1918 / RFC 4193
    LOOPBACK = "loopback"            # 127.0.0.0/8, ::1
    UNSPECIFIED = "unspecified"      # 0.0.0.0, :: — nombre anulado
    LINK_LOCAL = "link_local"        # 169.254.0.0/16, fe80::/10
    CGNAT = "cgnat"                  # 100.64.0.0/10
    MULTICAST = "multicast"          # 224.0.0.0/4, ff00::/8
    DOCUMENTATION = "documentation"  # RFC 5737 / RFC 3849
    RESERVED = "reserved"            # otros rangos reservados
    INVALID = "invalid"              # no es una dirección IP válida

    @property
    def is_routable(self) -> bool:
        """True solo si la dirección puede alcanzarse desde Internet."""
        return self is IpScope.PUBLIC


def classify_ip(address: str) -> IpScope:
    """Clasifica una dirección IP según su alcance.

    El orden de comprobación es deliberado: los casos particulares se
    evalúan antes que los generales, porque varias propiedades de
    `ipaddress` se solapan entre sí.
    """
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return IpScope.INVALID

    if ip.is_unspecified:
        return IpScope.UNSPECIFIED
    if ip.is_loopback:
        return IpScope.LOOPBACK
    if ip.is_link_local:
        return IpScope.LINK_LOCAL
    if ip.is_multicast:
        return IpScope.MULTICAST
    if any(ip in network for network in _DOCUMENTATION_NETWORKS):
        return IpScope.DOCUMENTATION
    if ip.version == 4 and ip in _CGNAT_NETWORK:
        return IpScope.CGNAT
    if ip.is_private:
        return IpScope.PRIVATE
    if ip.is_reserved:
        return IpScope.RESERVED
    if ip.is_global:
        return IpScope.PUBLIC
    return IpScope.RESERVED


def is_routable(address: str) -> bool:
    """Indica si la dirección es alcanzable desde Internet."""
    return classify_ip(address).is_routable


def partition_ips(addresses: list[str]) -> tuple[list[str], list[str]]:
    """Separa direcciones en ``(enrutables, no_enrutables)``, ordenadas."""
    routable = sorted({a for a in addresses if is_routable(a)})
    non_routable = sorted({a for a in addresses if not is_routable(a)})
    return routable, non_routable
