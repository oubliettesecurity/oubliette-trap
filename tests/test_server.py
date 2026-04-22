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


class TestSessionIsolation:
    """CRIT-1 regression: each session must get a fresh EnvironmentState so two
    sessions cannot diff identical hostnames/credentials to fingerprint the trap."""

    def test_two_sessions_see_different_environment(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        # Drive each session through a tool that exposes hostnames / creds.
        r1 = trap.handle_tool_call("list_services", {}, session_id="sess-A", source_ip="10.0.0.1")
        r2 = trap.handle_tool_call("list_services", {}, session_id="sess-B", source_ip="10.0.0.2")
        hosts_a = {svc["host"] for svc in r1["services"]}
        hosts_b = {svc["host"] for svc in r2["services"]}
        # Random 8-of-10 prefix pick + random 8-of-7 suffix pick + random 4-hex
        # domain means collision probability is effectively zero. If these ever
        # match, either the RNG regressed or EnvironmentState is being shared.
        assert hosts_a != hosts_b, "two sessions saw identical hostnames -- shared EnvironmentState regression"

    def test_same_session_is_stable(self, tmp_path):
        trap = OublietteTrap(storage_dir=str(tmp_path))
        r1 = trap.handle_tool_call("list_services", {}, session_id="sess-stable", source_ip="10.0.0.3")
        r2 = trap.handle_tool_call("list_services", {}, session_id="sess-stable", source_ip="10.0.0.3")
        assert r1["services"] == r2["services"], "same session must keep a stable EnvironmentState"


class TestIdentityNotClientControlled:
    """CRIT-2 regression: tool kwargs must not be able to override session
    identity. The MCP transport layer owns session_id / source_ip."""

    def test_strip_and_flag_identity_kwargs_scrubs_underscore_prefixed(self, tmp_path):
        from oubliette.server import _strip_and_flag_identity_kwargs
        raw = {"service": "payment", "_session_id": "forged-victim", "_source_ip": "1.2.3.4"}
        cleaned = _strip_and_flag_identity_kwargs(dict(raw), "get_credentials")
        assert "_session_id" not in cleaned
        assert "_source_ip" not in cleaned
        # Legit kwargs must remain untouched.
        assert cleaned == {"service": "payment"}
