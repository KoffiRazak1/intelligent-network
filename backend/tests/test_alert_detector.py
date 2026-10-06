from app.analysis.alert_detector import AlertDetector


def make_syn_packet(port: int, second: int) -> dict:
    return {
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "source_port": 50000 + second,
        "destination_port": port,
        "protocol": "TCP",
        "transport_protocol": "TCP",
        "tcp_flags": ["SYN"],
        "timestamp": f"2026-10-06T10:00:{second:02d}+00:00",
    }


def test_alerts_after_threshold_of_distinct_ports() -> None:
    detector = AlertDetector(threshold=3, window_seconds=30)

    assert detector.inspect_packet(make_syn_packet(22, 0)) is None
    assert detector.inspect_packet(make_syn_packet(80, 1)) is None

    alert = detector.inspect_packet(make_syn_packet(443, 2))

    assert alert is not None
    assert alert["severity"] == "WARNING"
    assert alert["source_ip"] == "192.168.1.10"
    assert alert["destination_ip"] == "192.168.1.20"
    assert alert["evidence"]["distinct_destination_ports"] == 3


def test_same_destination_port_does_not_increase_distinct_port_count() -> None:
    detector = AlertDetector(threshold=3, window_seconds=30)

    assert detector.inspect_packet(make_syn_packet(80, 0)) is None
    assert detector.inspect_packet(make_syn_packet(80, 1)) is None
    assert detector.inspect_packet(make_syn_packet(80, 2)) is None


def test_non_syn_tcp_packets_are_ignored() -> None:
    detector = AlertDetector(threshold=2)

    packet = make_syn_packet(80, 0)
    packet["tcp_flags"] = ["SYN", "ACK"]

    assert detector.inspect_packet(packet) is None


def test_non_tcp_packets_are_ignored() -> None:
    detector = AlertDetector(threshold=2)

    packet = make_syn_packet(80, 0)
    packet["protocol"] = "UDP"
    packet["transport_protocol"] = "UDP"

    assert detector.inspect_packet(packet) is None


def test_old_attempts_expire_from_the_time_window() -> None:
    detector = AlertDetector(threshold=2, window_seconds=5)

    assert detector.inspect_packet(make_syn_packet(22, 0)) is None

    later_packet = make_syn_packet(443, 10)
    assert detector.inspect_packet(later_packet) is None