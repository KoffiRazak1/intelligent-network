"""Démarrage et arrêt d'une capture Scapy en arrière-plan."""

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Iterator

from app.analysis.alert_detector import AlertDetector
from app.analysis.flow_tracker import FlowTracker
from app.analysis.packet_parser import parse_packet
from app.storage.history_store import HistoryStore


logger = logging.getLogger(__name__)

MAX_RECENT_PACKETS = 200
MAX_RECENT_ALERTS = 200
ARCHIVE_BATCH_SIZE = 100


class CaptureManagerError(Exception):
    """Erreur de capture pouvant être présentée proprement par l'API."""


class CaptureAlreadyActive(CaptureManagerError):
    """Une capture est déjà active ou en cours de démarrage."""


class InterfaceSelectionError(CaptureManagerError):
    """L'interface choisie n'est pas disponible."""


class CaptureManager:
    """Gère la capture, les résumés, les alertes et l'historique."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._archive_lock = threading.Lock()

        self._sniffer: Any | None = None
        self._started_monotonic: float | None = None
        self._current_session_id: int | None = None

        self._recent_packets: deque[dict[str, Any]] = deque(
            maxlen=MAX_RECENT_PACKETS
        )
        self._recent_alerts: deque[dict[str, Any]] = deque(
            maxlen=MAX_RECENT_ALERTS
        )

        self._pending_archive_packets: list[
            tuple[int, dict[str, Any]]
        ] = []
        self._archive_sequence = 0

        self._flow_tracker = FlowTracker()
        self._alert_detector = AlertDetector()
        self._history_store = HistoryStore()

        recovered_count = self._history_store.recover_interrupted_sessions()
        if recovered_count:
            logger.info(
                "%s ancienne(s) session(s) marquée(s) comme interrompue(s).",
                recovered_count,
            )

        self._state: dict[str, Any] = {
            "status": "IDLE",
            "session_id": None,
            "interface_id": None,
            "interface_name": None,
            "packet_count": 0,
            "bytes_captured": 0,
            "started_at": None,
            "message": "Aucune capture n'a été démarrée.",
        }

    def _flush_archive_packets_locked(self, session_id: int) -> None:
        """Écrit les paquets en attente. L'appelant détient déjà le verrou."""
        if not self._pending_archive_packets:
            return

        batch = list(self._pending_archive_packets)

        self._history_store.save_packet_summaries(
            session_id=session_id,
            packets=batch,
        )

        del self._pending_archive_packets[: len(batch)]

    def _flush_archive_packets(self, session_id: int) -> None:
        """Écrit en base le lot de résumés en attente."""
        with self._archive_lock:
            self._flush_archive_packets_locked(session_id)

    def _archive_packet(
        self,
        session_id: int,
        packet_summary: dict[str, Any],
    ) -> None:
        """Place un résumé dans le lot et l'enregistre par groupes."""
        with self._archive_lock:
            self._archive_sequence += 1
            self._pending_archive_packets.append(
                (self._archive_sequence, packet_summary)
            )

            if len(self._pending_archive_packets) >= ARCHIVE_BATCH_SIZE:
                try:
                    self._flush_archive_packets_locked(session_id)
                except Exception:
                    logger.exception(
                        "Impossible d'enregistrer un lot de paquets."
                    )

    def _record_packet(self, packet: Any) -> None:
        """Compte le paquet, le résume et examine les alertes."""
        try:
            packet_size = len(packet)
        except (TypeError, ValueError):
            packet_size = 0

        try:
            packet_summary = parse_packet(packet)
        except Exception:
            logger.exception("Impossible d'analyser un paquet capturé.")
            packet_summary = None

        with self._lock:
            self._state["packet_count"] += 1
            self._state["bytes_captured"] += packet_size

            if packet_summary is not None:
                self._recent_packets.appendleft(packet_summary)

            session_id = self._current_session_id

        if packet_summary is None:
            return

        if session_id is not None:
            self._archive_packet(session_id, packet_summary)

        try:
            self._flow_tracker.add_packet(packet_summary)
        except Exception:
            logger.exception(
                "Impossible de mettre à jour les communications réseau."
            )

        try:
            alert = self._alert_detector.inspect_packet(packet_summary)
        except Exception:
            logger.exception(
                "Impossible d'examiner le paquet pour les alertes."
            )
            return

        if alert is not None:
            with self._lock:
                self._recent_alerts.appendleft(alert)

            logger.warning(
                "Alerte réseau : %s (%s vers %s)",
                alert["title"],
                alert["source_ip"],
                alert["destination_ip"],
            )

    def _finish_history_session(
        self,
        session_id: int,
        status: str,
    ) -> None:
        """Enregistre les résumés en attente et clôt la session."""
        try:
            self._flush_archive_packets(session_id)
        except Exception:
            logger.exception(
                "Impossible d'archiver tous les résumés de paquets."
            )
            with self._lock:
                self._state["message"] += (
                    " Certains résumés de paquets n'ont pas pu être archivés."
                )

        with self._lock:
            session_state = dict(self._state)

        try:
            self._history_store.finish_session(
                session_id=session_id,
                status=status,
                ended_at=datetime.now(timezone.utc).isoformat(),
                packet_count=session_state["packet_count"],
                bytes_captured=session_state["bytes_captured"],
            )
        except Exception:
            logger.exception(
                "Impossible d'enregistrer la fin de la session historique."
            )
            with self._lock:
                self._state["message"] += (
                    " La session n'a pas pu être enregistrée dans l'historique."
                )

    def start(self, interface_id: str) -> dict[str, Any]:
        """Démarre une capture sur une interface Scapy existante."""
        try:
            from scapy.all import AsyncSniffer, conf

            interface = conf.ifaces.dev_from_networkname(interface_id)
        except ValueError as error:
            raise InterfaceSelectionError(
                "L'interface choisie n'est plus disponible. Actualise la liste."
            ) from error
        except Exception as error:
            logger.exception("Scapy n'a pas pu préparer la capture.")
            raise CaptureManagerError(
                "Impossible de préparer la capture. Vérifie Scapy, Npcap "
                "et les permissions."
            ) from error

        with self._lock:
            if self._state["status"] in {"STARTING", "RUNNING", "STOPPING"}:
                raise CaptureAlreadyActive("Une capture est déjà active.")

            self._recent_packets.clear()
            self._recent_alerts.clear()
            self._flow_tracker.clear()
            self._alert_detector.clear()

            started_at = datetime.now(timezone.utc).isoformat()

            self._state = {
                "status": "STARTING",
                "session_id": None,
                "interface_id": interface_id,
                "interface_name": interface.description or interface.name,
                "packet_count": 0,
                "bytes_captured": 0,
                "started_at": started_at,
                "message": "Démarrage de la capture…",
            }
            self._started_monotonic = time.monotonic()

            sniffer = AsyncSniffer(
                iface=interface,
                prn=self._record_packet,
                store=False,
                promisc=False,
            )
            self._sniffer = sniffer

        with self._archive_lock:
            self._pending_archive_packets.clear()
            self._archive_sequence = 0

        try:
            session_id = self._history_store.create_session(
                interface_id=interface_id,
                interface_name=interface.description or interface.name,
                started_at=started_at,
            )
        except Exception as error:
            logger.exception("Impossible de créer la session historique.")

            with self._lock:
                self._state["status"] = "ERROR"
                self._state["message"] = (
                    "Impossible d'enregistrer la session. Vérifie l'accès "
                    "au dossier de données de l'application."
                )
                self._sniffer = None
                self._started_monotonic = None

            raise CaptureManagerError(self._state["message"]) from error

        with self._lock:
            self._current_session_id = session_id
            self._state["session_id"] = session_id

        try:
            sniffer.start()
        except Exception as error:
            logger.exception("Le démarrage de la capture a échoué.")

            with self._lock:
                self._state["status"] = "ERROR"
                self._state["message"] = (
                    "La capture n'a pas pu démarrer. Vérifie les permissions "
                    "et l'interface sélectionnée."
                )
                self._sniffer = None
                self._started_monotonic = None
                self._current_session_id = None

            self._finish_history_session(session_id, "ERROR")
            raise CaptureManagerError(self._state["message"]) from error

        with self._lock:
            self._state["status"] = "RUNNING"
            self._state["message"] = "Capture en cours."

        logger.info("Capture démarrée sur l'interface %s", interface.name)
        return self.get_status()

    def stop(self) -> dict[str, Any]:
        """Arrête la capture et retourne son dernier état."""
        with self._lock:
            if self._state["status"] not in {"STARTING", "RUNNING"}:
                raise CaptureManagerError("Aucune capture n'est en cours.")

            sniffer = self._sniffer
            self._state["status"] = "STOPPING"
            self._state["message"] = "Arrêt de la capture…"

        try:
            if sniffer is not None and sniffer.running:
                sniffer.stop()
        except Exception as error:
            logger.exception("L'arrêt de la capture a échoué.")

            with self._lock:
                self._state["status"] = "ERROR"
                self._state["message"] = (
                    "La capture a rencontré une erreur pendant son arrêt."
                )
                self._sniffer = None
                self._started_monotonic = None
                session_id = self._current_session_id
                self._current_session_id = None

            if session_id is not None:
                self._finish_history_session(session_id, "ERROR")

            raise CaptureManagerError(self._state["message"]) from error

        with self._lock:
            self._state["status"] = "STOPPED"
            self._state["message"] = "Capture arrêtée."
            self._sniffer = None
            self._started_monotonic = None
            session_id = self._current_session_id
            self._current_session_id = None
            packet_count = self._state["packet_count"]

        if session_id is not None:
            self._finish_history_session(session_id, "STOPPED")

        logger.info("Capture arrêtée : %s paquets observés", packet_count)
        return self.get_status()

    def get_status(self) -> dict[str, Any]:
        """Retourne une copie sûre de l'état courant."""
        with self._lock:
            if (
                self._state["status"] == "RUNNING"
                and self._sniffer is not None
                and not self._sniffer.running
                and self._started_monotonic is not None
                and time.monotonic() - self._started_monotonic > 1
            ):
                self._state["status"] = "ERROR"
                self._state["message"] = (
                    "La capture s'est interrompue. Consulte le terminal "
                    "pour les détails techniques."
                )
                self._sniffer = None

            return dict(self._state)

    def get_recent_packets(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retourne les paquets récents, du plus nouveau au plus ancien."""
        safe_limit = max(1, min(limit, MAX_RECENT_PACKETS))

        with self._lock:
            return list(self._recent_packets)[:safe_limit]

    def get_recent_flows(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retourne les communications récemment actives."""
        return self._flow_tracker.get_flows(limit)

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retourne les alertes récentes."""
        safe_limit = max(1, min(limit, MAX_RECENT_ALERTS))

        with self._lock:
            return list(self._recent_alerts)[:safe_limit]

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retourne les sessions enregistrées dans SQLite."""
        return self._history_store.list_sessions(limit)

    def history_session_exists(self, session_id: int) -> bool:
        """Indique si une session existe dans l'historique."""
        return self._history_store.has_session(session_id)

    def iter_session_packets(
        self,
        session_id: int,
    ) -> Iterator[dict[str, Any]]:
        """Prépare puis lit les résumés d'une session."""
        with self._lock:
            current_session_id = self._current_session_id

        if current_session_id == session_id:
            self._flush_archive_packets(session_id)

        return self._history_store.iter_packet_summaries(session_id)


capture_manager = CaptureManager()