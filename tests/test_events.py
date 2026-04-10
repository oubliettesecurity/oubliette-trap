"""Tests for TrapEvent storage."""
import pytest
from oubliette.intel.events import EventStore
from oubliette.models import TrapEvent


@pytest.fixture
def store(tmp_path):
    return EventStore(db_path=str(tmp_path / "test.db"))


class TestEventStore:
    def test_save_and_retrieve(self, store):
        event = TrapEvent(
            session_id="sess-001", source_ip="10.0.0.1",
            tool_name="list_services", arguments={"filter": "all"},
            response_sent={"services": []}, deception_profile="default",
        )
        store.save(event)
        events = store.get_by_session("sess-001")
        assert len(events) == 1
        assert events[0]["tool_name"] == "list_services"

    def test_get_all(self, store):
        for i in range(3):
            store.save(TrapEvent(
                session_id=f"sess-{i}", source_ip="10.0.0.1",
                tool_name="whoami", arguments={},
                response_sent={}, deception_profile="default",
            ))
        events = store.get_all(limit=10)
        assert len(events) == 3

    def test_get_by_source_ip(self, store):
        store.save(TrapEvent(
            session_id="s1", source_ip="10.0.0.1",
            tool_name="t", arguments={}, response_sent={}, deception_profile="default",
        ))
        store.save(TrapEvent(
            session_id="s2", source_ip="10.0.0.2",
            tool_name="t", arguments={}, response_sent={}, deception_profile="default",
        ))
        events = store.get_by_source_ip("10.0.0.1")
        assert len(events) == 1

    def test_count(self, store):
        store.save(TrapEvent(
            session_id="s1", source_ip="1.2.3.4",
            tool_name="t", arguments={}, response_sent={}, deception_profile="default",
        ))
        assert store.count() == 1
