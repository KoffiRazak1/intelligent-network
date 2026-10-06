"""Regroupe les paquets réseau en communications bidirectionnelles."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Mapping


class FlowTracker:
    """Suit les communications à partir des résumés de paquets."""

    def __init__(self, max_flows: int = 2_000) -> None:
        if max_flows < 1:
            raise ValueError("max_flows doit être supérieur à zéro.")

        self.max_flows = max_flows
        self._flows: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
        self._lock = Lock()

    @staticmethod
    def _endpoint(address: Any, port: Any) -> tuple[str, int | None]:
        """Normalise une extrémité réseau."""
        normalized_port = int(port) if port is not None else None
        return str(address or "Inconnu"), normalized_port

    @staticmethod
    def _timestamp(value: Any) -> str:
        """Convertit l'horodatage en texte ISO."""
        if isinstance(value, datetime):
            return value.isoformat()

        if value:
            return str(value)

        return datetime.now(timezone.utc).isoformat()

    def add_packet(self, packet: Mapping[str, Any]) -> dict[str, Any] | None:
        """Ajoute un paquet et renvoie la communication mise à jour.

        Les champs attendus sont ceux renvoyés par le parseur :
        source_ip, destination_ip, source_port, destination_port,
        transport_protocol, protocol, packet_length_bytes et timestamp.
        """
        source = self._endpoint(
            packet.get("source_ip"),
            packet.get("source_port"),
        )
        destination = self._endpoint(
            packet.get("destination_ip"),
            packet.get("destination_port"),
        )

        protocol = str(
            packet.get("transport_protocol")
            or packet.get("protocol")
            or "Inconnu"
        ).upper()

        # L'ordre des extrémités est normalisé : A→B et B→A
        # sont donc comptés dans la même communication.
        endpoints = tuple(sorted((source, destination)))
        key = (protocol, *endpoints)

        timestamp = self._timestamp(packet.get("timestamp"))
        packet_size = max(0, int(packet.get("packet_length_bytes") or 0))

        with self._lock:
            flow = self._flows.get(key)

            if flow is None:
                flow = {
                    "flow_id": len(self._flows) + 1,
                    "protocol": protocol,
                    "endpoint_a": {
                        "ip": endpoints[0][0],
                        "port": endpoints[0][1],
                    },
                    "endpoint_b": {
                        "ip": endpoints[1][0],
                        "port": endpoints[1][1],
                    },
                    "packet_count": 0,
                    "bytes_total": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
                self._flows[key] = flow

                # Évite que la mémoire augmente sans limite.
                while len(self._flows) > self.max_flows:
                    self._flows.popitem(last=False)

            flow["packet_count"] += 1
            flow["bytes_total"] += packet_size
            flow["last_seen"] = timestamp

            # Place la communication récemment active à la fin.
            self._flows.move_to_end(key)

            return flow.copy()

    def get_flows(self, limit: int = 100) -> list[dict[str, Any]]:
        """Renvoie les communications les plus récemment actives."""
        if limit < 1:
            return []

        with self._lock:
            recent_flows = list(self._flows.values())[-limit:]

            # Copies indépendantes pour éviter toute modification externe.
            return [flow.copy() for flow in reversed(recent_flows)]

    def clear(self) -> None:
        """Efface les communications suivies."""
        with self._lock:
            self._flows.clear()