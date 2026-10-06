"""Tests unitaires du parseur de paquets."""

import sys
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    Ether,
    ICMP,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
)
from scapy.layers.inet6 import ICMPv6ND_RA


# Ajoute le dossier backend au chemin d'import de Python.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.analysis.packet_parser import parse_packet


def test_parse_tcp_flags_and_does_not_infer_https_from_port() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20", ttl=57)
        / TCP(sport=51000, dport=443, flags="S")
    )

    result = parse_packet(packet)

    assert result["protocol"] == "TCP"
    assert result["transport_protocol"] == "TCP"
    assert result["application_protocol"] == "Non identifié"
    assert result["source_ip"] == "192.0.2.10"
    assert result["destination_ip"] == "198.51.100.20"
    assert result["source_port"] == 51000
    assert result["destination_port"] == 443
    assert result["tcp_flags"] == ["SYN"]
    assert result["ttl"] == 57
    assert result["ip_version"] == 4
    assert result["packet_length_bytes"] == len(packet)


def test_parse_udp_dns_when_dns_layer_is_present() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.org"))
    )

    result = parse_packet(packet)

    assert result["protocol"] == "DNS"
    assert result["transport_protocol"] == "UDP"
    assert result["application_protocol"] == "DNS"
    assert result["source_port"] == 53000
    assert result["destination_port"] == 53


def test_parse_ipv6_udp() -> None:
    packet = (
        Ether()
        / IPv6(src="2001:db8::10", dst="2001:db8::20", hlim=42)
        / UDP(sport=12000, dport=12001)
    )

    result = parse_packet(packet)

    assert result["source_ip"] == "2001:db8::10"
    assert result["destination_ip"] == "2001:db8::20"
    assert result["ip_version"] == 6
    assert result["ttl"] == 42
    assert result["transport_protocol"] == "UDP"


def test_parse_icmpv6_router_advertisement() -> None:
    packet = (
        Ether()
        / IPv6(src="fe80::1", dst="ff02::1")
        / ICMPv6ND_RA()
    )

    result = parse_packet(packet)

    assert result["protocol"] == "ICMPv6"
    assert result["transport_protocol"] == "ICMPv6"
    assert result["ip_version"] == 6
    assert result["source_ip"] == "fe80::1"
    assert result["destination_ip"] == "ff02::1"


def test_parse_arp_addresses() -> None:
    packet = Ether() / ARP(psrc="192.0.2.10", pdst="192.0.2.1")

    result = parse_packet(packet)

    assert result["protocol"] == "ARP"
    assert result["source_ip"] == "192.0.2.10"
    assert result["destination_ip"] == "192.0.2.1"
    assert result["source_port"] is None


def test_parse_icmp() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.1")
        / ICMP()
    )

    result = parse_packet(packet)

    assert result["protocol"] == "ICMP"
    assert result["transport_protocol"] == "ICMP"


def test_unknown_packet_is_not_misclassified() -> None:
    packet = Ether() / Raw(load=b"\x01\x02\x03")

    result = parse_packet(packet)

    assert result["protocol"] == "Inconnu"
    assert result["application_protocol"] == "Non identifié"
    assert result["source_ip"] is None
    assert result["destination_ip"] is None