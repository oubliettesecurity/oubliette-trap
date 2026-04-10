"""Tests for DeceptionSession -- per-agent state and breadcrumb tracking."""
import pytest
from oubliette.deception.session import DeceptionSession


class TestDeceptionSession:
    def test_create(self):
        s = DeceptionSession(session_id="sess-001", source_ip="10.0.0.1")
        assert s.session_id == "sess-001"
        assert s.tools_called == []
        assert s.breadcrumbs_seen == []

    def test_record_tool_call(self):
        s = DeceptionSession(session_id="sess-001", source_ip="10.0.0.1")
        s.record_tool_call("list_services", {"filter": "all"})
        assert s.tools_called == ["list_services"]
        assert s.call_count == 1
        assert len(s.call_timestamps) == 1

    def test_tracks_breadcrumbs(self):
        s = DeceptionSession(session_id="sess-001", source_ip="10.0.0.1")
        s.record_tool_call("list_services", {})
        s.add_breadcrumb("internal_api_call", "payment-api")
        s.record_tool_call("internal_api_call", {"service": "payment-api"})
        assert "internal_api_call:payment-api" in s.breadcrumbs_followed

    def test_escalation_depth(self):
        s = DeceptionSession(session_id="sess-001", source_ip="10.0.0.1")
        s.record_tool_call("list_services", {})
        s.record_tool_call("get_credentials", {})
        s.record_tool_call("admin_panel", {})
        assert s.escalation_depth >= 2

    def test_inter_call_timings(self):
        s = DeceptionSession(session_id="sess-001", source_ip="10.0.0.1")
        s.record_tool_call("list_services", {})
        s.record_tool_call("whoami", {})
        assert len(s.inter_call_timings_ms) == 1

    def test_to_dict(self):
        s = DeceptionSession(session_id="sess-001", source_ip="10.0.0.1")
        s.record_tool_call("whoami", {})
        d = s.to_dict()
        assert d["session_id"] == "sess-001"
        assert d["call_count"] == 1
        assert "tools_called" in d
