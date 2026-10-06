"""Détection de balayages de ports et de rafales de tentatives TCP SYN."""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4


class AlertDetector:
    """Repère des séries inhabituelles de tentatives de connexion TCP."""

    def __init__(
        self,
        threshold: int = 12,
        window_seconds: int = 60,
        cooldown_seconds: int = 60,
        max_tracked_pairs: int = 2_000,
        syn_burst_threshold: int = 50,
        syn_burst_window_seconds: int = 10,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold doit être au moins égal à 2.")
        if window_seconds < 1:
            raise ValueError("window_seconds doit être supérieur à zéro.")
        if cooldown_seconds < 1:
            raise ValueError("cooldown_seconds doit être supérieur à zéro.")
        if max_tracked_pairs < 1:
            raise ValueError("max_tracked_pairs doit être supérieur à zéro.")
        if syn_burst_threshold < 2:
            raise ValueError("syn_burst_threshold doit être au moins égal à 2.")
        if syn_burst_window_seconds < 1:
            raise ValueError(
                "syn_burst_window_seconds doit être supérieur à zéro."
            )

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.max_tracked_pairs = max_tracked_pairs
        self.syn_burst_threshold = syn_burst_threshold
        self.syn_burst_window = timedelta(
            seconds=syn_burst_window_seconds
        )

        self._attempts: OrderedDict[
            tuple[str, str],
            deque[tuple[datetime, int]],
        ] = OrderedDict()

        self._last_alert_time: dict[
            tuple[str, str, str],
            datetime,
        ] = {}

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """Convertit l'horodatage d'un paquet en date UTC."""
        if isinstance(value, datetime):
            parsed = value
        elif value:
            try:
                parsed = datetime.fromisoformat(
                    str(value).replace("Z", "+00:00")
                )
            except ValueError:
                parsed = datetime.now(timezone.utc)
        else:
            parsed = datetime.now(timezone.utc)

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _parse_flags(value: Any) -> set[str]:
        """Accepte les indicateurs TCP sous forme de liste ou de texte."""
        if isinstance(value, str):
            flags = value.replace(",", " ").split()
        elif isinstance(value, (list, tuple, set)):
            flags = value
        else:
            flags = []

        return {str(flag).strip().upper() for flag in flags if str(flag).strip()}

    def _make_alert(
        self,
        *,
        rule_name: str,
        title: str,
        description: str,
        source_ip: str,
        destination_ip: str,
        timestamp: datetime,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """Construit une alerte avec les champs attendus par le tableau."""
        return {
            "alert_id": str(uuid4()),
            "timestamp": timestamp.isoformat(),
            "severity": "WARNING",
            "title": title,
            "description": description,
            "detection": title,
            "rule_name": rule_name,
            "protocol": "TCP",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "evidence": evidence,
            "status": "À examiner",
        }

    def inspect_packet(
        self,
        packet: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Examine un résumé de paquet TCP et signale une activité inhabituelle."""
        protocol = str(
            packet.get("transport_protocol")
            or packet.get("protocol")
            or ""
        ).strip().upper()

        if protocol != "TCP":
            return None

        flags = self._parse_flags(packet.get("tcp_flags"))

        # Seules les demandes de connexion initiales sont comptabilisées.
        if "SYN" not in flags or "ACK" in flags:
            return None

        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        destination_port = packet.get("destination_port")

        if not source_ip or not destination_ip or destination_port is None:
            return None

        try:
            port = int(destination_port)
        except (TypeError, ValueError):
            return None

        if not 0 <= port <= 65535:
            return None

        timestamp = self._parse_timestamp(packet.get("timestamp"))
        source = str(source_ip)
        destination = str(destination_ip)
        pair = (source, destination)

        attempts = self._attempts.get(pair)
        if attempts is None:
            attempts = deque()
            self._attempts[pair] = attempts

        attempts.append((timestamp, port))

        # Garde seulement les tentatives nécessaires à la règle la plus longue.
        longest_window = max(self.window, self.syn_burst_window)
        cutoff = timestamp - longest_window

        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()

        self._attempts.move_to_end(pair)

        while len(self._attempts) > self.max_tracked_pairs:
            removed_pair, _ = self._attempts.popitem(last=False)
            for alert_key in list(self._last_alert_time):
                if alert_key[:2] == removed_pair:
                    self._last_alert_time.pop(alert_key, None)

        scan_cutoff = timestamp - self.window
        scan_ports = {
            attempt_port
            for attempt_time, attempt_port in attempts
            if attempt_time >= scan_cutoff
        }

        burst_cutoff = timestamp - self.syn_burst_window
        burst_attempts = [
            attempt
            for attempt in attempts
            if attempt[0] >= burst_cutoff
        ]

        rule_name: str | None = None
        title = ""
        description = ""
        evidence: dict[str, Any] = {}

        if len(scan_ports) >= self.threshold:
            rule_name = "tcp_multiport_scan"
            title = "Tentatives TCP sur plusieurs ports"
            description = (
                f"{source} a tenté de joindre {len(scan_ports)} ports "
                f"différents sur {destination} en "
                f"{self.window.seconds} secondes. "
                "Cette activité mérite une vérification."
            )
            evidence = {
                "distinct_destination_ports": len(scan_ports),
                "threshold": self.threshold,
                "window_seconds": self.window.seconds,
            }

        elif len(burst_attempts) >= self.syn_burst_threshold:
            rule_name = "tcp_syn_burst"
            title = "Rafale de tentatives TCP"
            description = (
                f"{source} a envoyé {len(burst_attempts)} demandes TCP SYN "
                f"vers {destination} en "
                f"{self.syn_burst_window.seconds} secondes. "
                "Vérifie si cette activité est attendue."
            )
            evidence = {
                "syn_attempts": len(burst_attempts),
                "threshold": self.syn_burst_threshold,
                "window_seconds": self.syn_burst_window.seconds,
            }

        if rule_name is None:
            return None

        alert_key = (source, destination, rule_name)
        previous_alert = self._last_alert_time.get(alert_key)

        if (
            previous_alert is not None
            and timestamp - previous_alert < self.cooldown
        ):
            return None

        self._last_alert_time[alert_key] = timestamp

        return self._make_alert(
            rule_name=rule_name,
            title=title,
            description=description,
            source_ip=source,
            destination_ip=destination,
            timestamp=timestamp,
            evidence=evidence,
        )

    def clear(self) -> None:
        """Efface les tentatives et les délais de répétition mémorisés."""
        self._attempts.clear()
        self._last_alert_time.clear()