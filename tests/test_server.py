"""Tests for the honeypot MCP server wiring."""
import pytest
from oubliette.server import OublietteTrap


class TestOublietteTrap:
    def test_create_with_defaults(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        assert trap.profile is not None
        assert len(trap.profile.get_tool_names()) >= 10

    def test_handle_tool_call(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        result = trap.handle_tool_call(
            tool_name="list_services", arguments={},
            session_id="test-sess", source_ip="10.0.0.1",
        )
        assert "services" in result

    def test_records_event(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        trap.handle_tool_call(
            tool_name="whoami", arguments={},
            session_id="test-sess", source_ip="10.0.0.1",
        )
        assert trap.event_store.count() == 1

    def test_fingerprints_after_enough_calls(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        for tool in ["list_services", "get_environment", "whoami", "get_credentials"]:
            trap.handle_tool_call(tool_name=tool, arguments={}, session_id="test-sess", source_ip="10.0.0.1")
        session = trap.sessions["test-sess"]
        assert session.call_count == 4

    def test_active_probes_when_enabled(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path), active_probes=True)
        result = trap.handle_tool_call(
            tool_name="list_services", arguments={},
            session_id="test-sess", source_ip="10.0.0.1",
        )
        result_str = str(result)
        assert "_trace_id" in result_str or "_system_note" in result_str or "required_ack_format" in result_str

    def test_get_classification(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        for tool in ["list_services", "get_environment", "whoami", "get_credentials"]:
            trap.handle_tool_call(tool_name=tool, arguments={}, session_id="s1", source_ip="10.0.0.1")
        classification = trap.get_classification("s1")
        assert classification is not None
        assert hasattr(classification, "agent_type")
