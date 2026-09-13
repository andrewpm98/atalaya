"""Pruebas de la clasificación de direcciones IP por alcance.

Cubre los casos que motivaron el módulo: nombres anulados con 0.0.0.0,
direccionamiento interno filtrado y rangos especiales que no deben tratarse
como objetivos de escaneo.
"""

from __future__ import annotations

import pytest

from atalaya.core.netutils import IpScope, classify_ip, is_routable, partition_ips


@pytest.mark.parametrize(
    ("address", "esperado"),
    [
        # Enrutables: objetivos válidos
        ("140.82.121.3", IpScope.PUBLIC),
        ("8.8.8.8", IpScope.PUBLIC),
        ("2600:3c01::f03c:91ff:fe18:bb2f", IpScope.PUBLIC),
        # Nombre anulado deliberadamente
        ("0.0.0.0", IpScope.UNSPECIFIED),
        ("::", IpScope.UNSPECIFIED),
        # Bucle local
        ("127.0.0.1", IpScope.LOOPBACK),
        ("::1", IpScope.LOOPBACK),
        # Direccionamiento interno (RFC 1918 / RFC 4193)
        ("10.0.0.1", IpScope.PRIVATE),
        ("172.16.0.1", IpScope.PRIVATE),
        ("192.168.1.1", IpScope.PRIVATE),
        ("fd00::1", IpScope.PRIVATE),
        # Rangos especiales
        ("100.64.0.1", IpScope.CGNAT),
        ("169.254.1.1", IpScope.LINK_LOCAL),
        ("fe80::1", IpScope.LINK_LOCAL),
        ("224.0.0.1", IpScope.MULTICAST),
        ("192.0.2.1", IpScope.DOCUMENTATION),
        ("198.51.100.1", IpScope.DOCUMENTATION),
        ("203.0.113.1", IpScope.DOCUMENTATION),
        ("2001:db8::1", IpScope.DOCUMENTATION),
        # Entrada inválida
        ("no-es-una-ip", IpScope.INVALID),
        ("", IpScope.INVALID),
        ("999.999.999.999", IpScope.INVALID),
    ],
)
def test_classify_ip(address: str, esperado: IpScope) -> None:
    assert classify_ip(address) is esperado


def test_solo_las_publicas_son_enrutables() -> None:
    assert is_routable("140.82.121.3")
    for address in ("0.0.0.0", "127.0.0.1", "10.0.0.1", "224.0.0.1", "no-es-ip"):
        assert not is_routable(address), address


def test_multicast_no_se_considera_enrutable() -> None:
    """`ipaddress.is_global` devuelve True para multicast: no debe bastar."""
    assert not is_routable("224.0.0.1")


def test_rangos_de_documentacion_no_son_objetivos() -> None:
    """Las IPs de ejemplo no deben inyectarse en el escaneo de puertos."""
    assert not is_routable("192.0.2.1")


def test_partition_separa_y_ordena() -> None:
    enrutables, no_enrutables = partition_ips(
        ["10.0.0.1", "140.82.121.3", "0.0.0.0", "8.8.8.8", "140.82.121.3"]
    )
    assert enrutables == ["140.82.121.3", "8.8.8.8"]
    assert no_enrutables == ["0.0.0.0", "10.0.0.1"]


def test_partition_con_lista_vacia() -> None:
    assert partition_ips([]) == ([], [])
