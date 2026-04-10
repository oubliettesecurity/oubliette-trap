"""Tests for active probe injection and detection."""
import pytest
from oubliette.fingerprint.probes import (
    ProbeInjector, inject_canary, inject_instruction_trap,
    inject_format_compliance, check_for_probe_response,
)
from oubliette.deception.session import DeceptionSession


class TestCanaryProbes:
    def test_inject_canary(self):
        response = {"data": {"username": "admin"}}
        modified, probe_id = inject_canary(response)
        assert "_trace_id" in modified or probe_id in str(modified)

    def test_detect_canary_in_arguments(self):
        response = {"data": {"token": "abc123"}}
        modified, probe_id = inject_canary(response)
        canary_value = probe_id.split(":", 1)[1]
        result = check_for_probe_response(probe_id, {"token": canary_value})
        assert result is True

    def test_no_false_positive(self):
        result = check_for_probe_response("canary:CANARY-abc123", {"query": "select * from users"})
        assert result is False


class TestInstructionTraps:
    def test_inject_instruction(self):
        response = {"services": []}
        modified, probe_id = inject_instruction_trap(response)
        resp_str = str(modified)
        assert "verify_access" in resp_str or "confirm" in resp_str.lower()

    def test_detect_instruction_compliance(self):
        _, probe_id = inject_instruction_trap({"data": {}})
        code = probe_id.split(":")[1]
        result = check_for_probe_response(probe_id, {"code": code})
        assert result is True


class TestFormatCompliance:
    def test_inject_format_request(self):
        response = {"result": "ok"}
        modified, probe_id = inject_format_compliance(response)
        assert "required_ack_format" in str(modified)

    def test_detect_format_compliance(self):
        _, probe_id = inject_format_compliance({"data": {}})
        code = probe_id.split(":")[1]
        result = check_for_probe_response(probe_id, {"ack": f"RECV-{code}"})
        assert result is True


class TestProbeInjector:
    def test_injector_selects_probe(self):
        injector = ProbeInjector()
        session = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        response = {"data": {"key": "value"}}
        modified, probe_ids = injector.inject(response, session)
        assert len(probe_ids) >= 1
        assert len(session.probes_sent) >= 1
