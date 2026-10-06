"""Routes API liées aux interfaces, à la capture et aux données réseau."""

import csv
import io
import logging
from pathlib import PurePosixPath
from collections.abc import Iterator

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.capture.interfaces import (
    InterfaceDiscoveryError,
    list_network_interfaces,
)
from app.capture.packet_capture import (
    CaptureAlreadyActive,
    CaptureManagerError,
    InterfaceSelectionError,
    capture_manager,
)
from app.analysis.packet_parser import parse_packet
from app.config import get_settings


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Capture"])
MAX_PCAP_BYTES = 25 * 1024 * 1024
MAX_PCAP_PACKETS = 50_000


class StartCaptureRequest(BaseModel):
    """Données nécessaires pour démarrer une capture."""

    interface_id: str = Field(min_length=1, max_length=500)


@router.post("/capture/import")
def import_capture(file: UploadFile = File(...)) -> dict:
    """Analyse un fichier PCAP/PCAPNG fourni par l'utilisateur."""
    if capture_manager.get_status()["status"] in {
        "STARTING",
        "RUNNING",
        "STOPPING",
    }:
        raise HTTPException(
            status_code=409,
            detail="Arrête la capture en cours avant d’importer un fichier.",
        )

    filename = PurePosixPath((file.filename or "capture.pcap").replace("\\", "/")).name
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=415,
            detail="Choisis un fichier .pcap ou .pcapng.",
        )

    try:
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)
    except (OSError, AttributeError) as error:
        raise HTTPException(status_code=400, detail="Fichier illisible.") from error

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Le fichier est vide.")
    if file_size > MAX_PCAP_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Le fichier dépasse la limite de 25 Mo.",
        )

    try:
        from scapy.utils import PcapReader

        summaries = []
        with PcapReader(file.file) as reader:
            for packet in reader:
                if len(summaries) >= MAX_PCAP_PACKETS:
                    raise HTTPException(
                        status_code=413,
                        detail="Le fichier dépasse la limite de 50 000 paquets.",
                    )
                summaries.append(parse_packet(packet))
    except HTTPException:
        raise
    except Exception as error:
        logger.info("Fichier de capture refusé (%s).", type(error).__name__)
        raise HTTPException(
            status_code=422,
            detail="Le fichier n'est pas une capture PCAP/PCAPNG valide.",
        ) from error
    finally:
        file.file.close()

    if not summaries:
        raise HTTPException(
            status_code=422,
            detail="La capture ne contient aucun paquet analysable.",
        )

    try:
        status = capture_manager.import_summaries(filename, summaries)
    except CaptureAlreadyActive as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        logger.exception("Impossible d'analyser le fichier de capture importé.")
        raise HTTPException(
            status_code=503,
            detail="L'analyse a échoué côté serveur.",
        ) from error

    return {
        "message": "Capture analysée.",
        "session_id": status.get("session_id"),
        "packet_count": status["packet_count"],
        "bytes_captured": status["bytes_captured"],
    }


@router.get("/interfaces")
def get_interfaces() -> dict:
    """Retourne les interfaces réseau détectées."""
    if not get_settings().capture_enabled:
        return {
            "count": 0,
            "interfaces": [],
            "message": (
                "La capture réseau est désactivée sur le service Railway. "
                "Un service cloud ne peut pas accéder à la carte Wi-Fi de ton PC."
            ),
        }
    try:
        interfaces = list_network_interfaces()
    except InterfaceDiscoveryError as error:
        logger.warning("Découverte des interfaces impossible : %s", error)
        raise HTTPException(status_code=503, detail=str(error)) from error

    message = None
    if not interfaces:
        message = (
            "Aucune interface n'a été détectée. "
            "Vérifie les adaptateurs réseau et Npcap."
        )

    return {
        "count": len(interfaces),
        "interfaces": interfaces,
        "message": message,
    }


@router.post("/capture/start")
def start_capture(request: StartCaptureRequest) -> dict:
    """Démarre une capture sur l'interface demandée."""
    if not get_settings().capture_enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "La capture locale est désactivée sur le service Railway. "
                "Lance la capture depuis le PC qui possède l'interface réseau."
            ),
        )
    try:
        return capture_manager.start(request.interface_id)
    except CaptureAlreadyActive as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except InterfaceSelectionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except CaptureManagerError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@router.post("/capture/stop")
def stop_capture() -> dict:
    """Arrête la capture en cours."""
    try:
        return capture_manager.stop()
    except CaptureManagerError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.get("/capture/status")
def get_capture_status() -> dict:
    """Retourne l'état et les compteurs de la capture."""
    return capture_manager.get_status()


@router.get("/packets")
def get_packets(
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    """Retourne les résumés récents des paquets."""
    packets = capture_manager.get_recent_packets(limit)

    return {
        "count": len(packets),
        "packets": packets,
    }


@router.get("/flows")
def get_flows(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    """Retourne les communications réseau regroupées."""
    flows = capture_manager.get_recent_flows(limit)

    return {
        "count": len(flows),
        "flows": flows,
    }


@router.get("/alerts")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    """Retourne les alertes récentes de la session."""
    alerts = capture_manager.get_recent_alerts(limit)

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


@router.get("/history")
def get_capture_history(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    """Retourne les sessions de capture enregistrées."""
    sessions = capture_manager.get_history(limit)

    return {
        "count": len(sessions),
        "sessions": sessions,
    }


@router.get("/history/{session_id}/packets.csv")
def export_session_packets(session_id: int) -> StreamingResponse:
    """Télécharge en CSV tous les résumés de paquets d'une session."""
    if session_id < 1 or not capture_manager.history_session_exists(session_id):
        raise HTTPException(
            status_code=404,
            detail="Session de capture introuvable.",
        )

    try:
        packets = capture_manager.iter_session_packets(session_id)
    except Exception as error:
        logger.exception(
            "Impossible de préparer l'export de la session %s.",
            session_id,
        )
        raise HTTPException(
            status_code=503,
            detail="Impossible de préparer l'export de cette session.",
        ) from error

    def csv_rows() -> Iterator[str]:
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";", lineterminator="\r\n")

        writer.writerow(
            [
                "Horodatage",
                "Adresse source",
                "Port source",
                "Adresse destination",
                "Port destination",
                "Protocole",
                "Protocole transport",
                "Protocole application",
                "Indicateurs TCP",
                "Taille en octets",
                "TTL",
                "Version IP",
                "Identifiant paquet",
            ]
        )
        yield "\ufeff" + output.getvalue()

        for packet in packets:
            output.seek(0)
            output.truncate(0)

            flags = packet.get("tcp_flags") or []
            if isinstance(flags, list):
                flags = ", ".join(str(flag) for flag in flags)

            writer.writerow(
                [
                    packet.get("timestamp", ""),
                    packet.get("source_ip", ""),
                    packet.get("source_port", ""),
                    packet.get("destination_ip", ""),
                    packet.get("destination_port", ""),
                    packet.get("protocol", ""),
                    packet.get("transport_protocol", ""),
                    packet.get("application_protocol", ""),
                    flags,
                    packet.get("packet_length_bytes", ""),
                    packet.get("ttl", ""),
                    packet.get("ip_version", ""),
                    packet.get("packet_id", ""),
                ]
            )
            yield output.getvalue()

    return StreamingResponse(
        csv_rows(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="capture-{session_id}-paquets.csv"'
            )
        },
    )
