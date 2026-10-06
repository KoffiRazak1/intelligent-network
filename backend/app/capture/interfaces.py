"""Découverte des interfaces réseau disponibles avec Scapy."""


class InterfaceDiscoveryError(Exception):
    """Erreur compréhensible lors de la découverte des interfaces."""


def list_network_interfaces() -> list[dict[str, str]]:
    """Retourne les interfaces détectées et leurs adresses disponibles."""
    try:
        from scapy.all import conf

        interfaces = conf.ifaces
        interfaces.reload()
    except ImportError as error:
        raise InterfaceDiscoveryError(
            "Scapy n'est pas installé. Installe les dépendances du projet."
        ) from error
    except Exception as error:
        raise InterfaceDiscoveryError(
            "Impossible de lire les interfaces réseau. "
            "Vérifie que Scapy et le pilote Npcap sont installés."
        ) from error

    results = []

    for interface in interfaces.values():
        interface_id = str(
            getattr(interface, "network_name", "")
            or getattr(interface, "name", "")
        ).strip()

        if not interface_id:
            continue

        name = str(
            getattr(interface, "description", "")
            or getattr(interface, "name", "")
            or interface_id
        ).strip()

        ipv4 = str(getattr(interface, "ip", "") or "Non disponible")
        mac = str(getattr(interface, "mac", "") or "Non disponible")

        results.append(
            {
                "id": interface_id,
                "name": name,
                "ipv4": ipv4,
                "mac": mac,
            }
        )

    return sorted(results, key=lambda item: item["name"].lower())