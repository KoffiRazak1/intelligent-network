from app.storage.history_store import HistoryStore


def test_create_session_stores_initial_metadata(tmp_path) -> None:
    store = HistoryStore(tmp_path / "history.db")

    session_id = store.create_session(
        interface_id="interface-test",
        interface_name="Adaptateur de test",
        started_at="2026-10-06T10:00:00+00:00",
    )

    sessions = store.list_sessions()

    assert len(sessions) == 1
    assert sessions[0]["id"] == session_id
    assert sessions[0]["interface_name"] == "Adaptateur de test"
    assert sessions[0]["status"] == "RUNNING"
    assert sessions[0]["packet_count"] == 0
    assert sessions[0]["bytes_captured"] == 0
    assert sessions[0]["ended_at"] is None


def test_finish_session_updates_status_and_counters(tmp_path) -> None:
    store = HistoryStore(tmp_path / "history.db")
    session_id = store.create_session(
        interface_id="interface-test",
        interface_name="Adaptateur de test",
        started_at="2026-10-06T10:00:00+00:00",
    )

    store.finish_session(
        session_id=session_id,
        status="STOPPED",
        ended_at="2026-10-06T10:05:00+00:00",
        packet_count=125,
        bytes_captured=64000,
    )

    session = store.list_sessions()[0]

    assert session["status"] == "STOPPED"
    assert session["ended_at"] == "2026-10-06T10:05:00+00:00"
    assert session["packet_count"] == 125
    assert session["bytes_captured"] == 64000


def test_sessions_are_returned_newest_first_and_limit_is_applied(
    tmp_path,
) -> None:
    store = HistoryStore(tmp_path / "history.db")

    first_id = store.create_session(
        interface_id="interface-1",
        interface_name="Première interface",
        started_at="2026-10-06T10:00:00+00:00",
    )
    second_id = store.create_session(
        interface_id="interface-2",
        interface_name="Deuxième interface",
        started_at="2026-10-06T11:00:00+00:00",
    )

    sessions = store.list_sessions(limit=1)

    assert len(sessions) == 1
    assert sessions[0]["id"] == second_id
    assert sessions[0]["id"] != first_id


def test_finish_unknown_session_raises_key_error(tmp_path) -> None:
    store = HistoryStore(tmp_path / "history.db")

    try:
        store.finish_session(
            session_id=999,
            status="STOPPED",
            ended_at="2026-10-06T10:05:00+00:00",
            packet_count=0,
            bytes_captured=0,
        )
    except KeyError as error:
        assert "999" in str(error)
    else:
        raise AssertionError("Une session inconnue aurait dû être refusée.")