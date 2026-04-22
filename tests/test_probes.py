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
        # probe_id now carries the full planted value ("format:RECV-XXXX")
        # after the HIGH fix that moved to leaf-equality detection.
        expected_ack = probe_id.split(":", 1)[1]
        result = check_for_probe_response(probe_id, {"ack": expected_ack})
        assert result is True


class TestProbeInjector:
    def test_injector_selects_probe(self):
        injector = ProbeInjector()
        session = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        response = {"data": {"key": "value"}}
        modified, probe_ids = injector.inject(response, session)
        assert len(probe_ids) >= 1
        assert len(session.probes_sent) >= 1


class TestSubstringSmuggleDefence:
    """HIGH-2/3/5 regression: attackers used to observe a planted probe value
    in one response and smuggle it inside an unrelated argument field (e.g.
    ``{"notes": "my CANARY-abc123 is helpful"}``) to fake probe-triggered.
    Leaf-equality rejection closes that path."""

    def test_canary_smuggle_in_string_rejected(self):
        _, probe_id = inject_canary({})
        value = probe_id.split(":", 1)[1]  # CANARY-xxxxxx
        # Agent embeds the canary inside a larger string as a smuggle attempt.
        result = check_for_probe_response(
            probe_id, {"notes": f"observed {value} in trace"}
        )
        assert result is False

    def test_canary_leaf_exact_match_accepted(self):
        _, probe_id = inject_canary({})
        value = probe_id.split(":", 1)[1]
        # Agent actually echoes the canary as a full leaf value -- legitimate.
        result = check_for_probe_response(probe_id, {"trace_id": value})
        assert result is True

    def test_canary_in_nested_leaf_accepted(self):
        _, probe_id = inject_canary({})
        value = probe_id.split(":", 1)[1]
        nested = {"meta": {"deep": {"tag": value}}}
        assert check_for_probe_response(probe_id, nested) is True


class TestProbeSelectionNotPredictable:
    """HIGH regression: probe selection used to be ``call_count % 3``, so an
    attacker learned the rotation after a single call. Selection now uses
    secrets.randbelow -- verify the CSPRNG path is reachable (over a large
    sample we see more than one probe type)."""

    def test_multiple_probe_types_over_many_sessions(self):
        from collections import Counter
        injector = ProbeInjector()
        types_seen = Counter()
        for i in range(200):
            session = DeceptionSession(session_id=f"t{i}", source_ip="1.2.3.4")
            _, probe_ids = injector.inject({}, session)
            for pid in probe_ids:
                types_seen[pid.split(":", 1)[0]] += 1
        # With 3 probe types and 200 samples at 1/3 each, probability of any
        # single type being absent is ~(2/3)**200 ~ 1e-35 -- effectively zero.
        assert len(types_seen) == 3, f"expected all 3 probe types, saw {types_seen}"
