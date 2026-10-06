"""Extraction des faits observables depuis un paquet Scapy."""

from datetime import datetime, timezone
from uuid import uuid4

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def _timestamp(packet) -> str:
    """Formate l'heure fournie par Scapy sans lui substituer l'heure actuelle."""
    packet_time = getattr(packet, "time", None)

    if packet_time is None:
        return "Non disponible"

    try:
        return datetime.fromtimestamp(
            float(packet_time),
            tz=timezone.utc,
        ).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return "Non disponible"


def _tcp_flags(packet) -> list[str]:
    """Convertit les indicateurs TCP observés en noms lisibles."""
    if not packet.haslayer(TCP):
        return []

    observed_flags = str(packet[TCP].flags)

    return [
        name
        for abbreviation, name in TCP_FLAG_NAMES.items()
        if abbreviation in observed_flags
    ]


def _has_icmpv6_layer(packet) -> bool:
    """Indique si Scapy a décodé un message ICMPv6."""
    for layer in packet.layers():
        layer_name = getattr(layer, "__name__", "")

        if (
            layer_name.startswith("ICMPv6")
            and not layer_name.startswith("ICMPv6NDOpt")
        ):
            return True

    return False


def parse_packet(packet) -> dict:
    """Retourne un résumé du paquet sans conserver son contenu applicatif."""
    source_ip = None
    destination_ip = None
    ip_version = None
    ttl = None

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        ip_version = 4
        ttl = int(ip_layer.ttl) if ip_layer.ttl is not None else None

    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        ip_version = 6
        ttl = int(ip_layer.hlim) if ip_layer.hlim is not None else None

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        source_ip = arp_layer.psrc or None
        destination_ip = arp_layer.pdst or None

    transport_protocol = None
    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        transport_protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)

    elif packet.haslayer(UDP):
        transport_protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    elif packet.haslayer(ICMP):
        transport_protocol = "ICMP"

    elif _has_icmpv6_layer(packet):
        transport_protocol = "ICMPv6"

    elif packet.haslayer(ARP):
        transport_protocol = "ARP"

    if packet.haslayer(DNS):
        application_protocol = "DNS"
        protocol = "DNS"
    else:
        application_protocol = "Non identifié"
        protocol = transport_protocol or "Inconnu"

    try:
        packet_length_bytes = len(packet)
    except (TypeError, ValueError):
        packet_length_bytes = None

    return {
        "packet_id": str(uuid4()),
        "timestamp": _timestamp(packet),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "transport_protocol": transport_protocol,
        "application_protocol": application_protocol,
        "packet_length_bytes": packet_length_bytes,
        "tcp_flags": _tcp_flags(packet),
        "ttl": ttl,
        "ip_version": ip_version,
    }