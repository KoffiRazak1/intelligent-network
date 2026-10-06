from app.analysis.flow_tracker import FlowTracker


def test_packets_in_both_directions_are_grouped_into_one_flow() -> None:
    tracker = FlowTracker()

    tracker.add_packet(
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "source_port": 50000,
            "destination_port": 443,
            "transport_protocol": "TCP",
            "protocol": "TCP",
            "packet_length_bytes": 100,
            "timestamp": "2026-10-05T20:00:00+00:00",
        }
    )

    flow = tracker.add_packet(
        {
            "source_ip": "192.168.1.20",
            "destination_ip": "192.168.1.10",
            "source_port": 443,
            "destination_port": 50000,
            "transport_protocol": "TCP",
            "protocol": "TCP",
            "packet_length_bytes": 250,
            "timestamp": "2026-10-05T20:00:01+00:00",
        }
    )

    assert flow is not None
    assert flow["packet_count"] == 2
    assert flow["bytes_total"] == 350
    assert flow["first_seen"] == "2026-10-05T20:00:00+00:00"
    assert flow["last_seen"] == "2026-10-05T20:00:01+00:00"
    assert len(tracker.get_flows()) == 1


def test_different_protocols_create_separate_flows() -> None:
    tracker = FlowTracker()

    common_packet = {
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "source_port": 12345,
        "destination_port": 53,
        "packet_length_bytes": 80,
        "timestamp": "2026-10-05T20:00:00+00:00",
    }

    tracker.add_packet({**common_packet, "transport_protocol": "UDP"})
    tracker.add_packet({**common_packet, "transport_protocol": "TCP"})

    assert len(tracker.get_flows()) == 2


def test_max_flows_limits_memory() -> None:
    tracker = FlowTracker(max_flows=2)

    for last_octet in (20, 21, 22):
        tracker.add_packet(
            {
                "source_ip": "192.168.1.10",
                "destination_ip": f"192.168.1.{last_octet}",
                "source_port": 50000,
                "destination_port": 443,
                "transport_protocol": "TCP",
                "packet_length_bytes": 100,
            }
        )

    assert len(tracker.get_flows(limit=10)) == 2


def test_clear_removes_all_flows() -> None:
    tracker = FlowTracker()

    tracker.add_packet(
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "source_port": 50000,
            "destination_port": 443,
            "transport_protocol": "TCP",
            "packet_length_bytes": 100,
        }
    )

    tracker.clear()

    assert tracker.get_flows() == []