"""Tests for passive fingerprinting signals."""
import pytest
from oubliette.fingerprint.passive import PassiveSignals, compute_passive_signals
from oubliette.deception.session import DeceptionSession


class TestTimingSignals:
    def test_regular_timing_detected(self):
        s = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        s.inter_call_timings_ms = [200, 195, 205, 198, 202, 201, 199]
        signals = compute_passive_signals(s)
        assert signals.timing_regularity > 0.7

    def test_irregular_timing_detected(self):
        s = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        s.inter_call_timings_ms = [3500, 800, 12000, 2100, 450, 8000]
        signals = compute_passive_signals(s)
        assert signals.timing_regularity < 0.3

    def test_fast_timing_detected(self):
        s = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        s.inter_call_timings_ms = [10, 10, 11, 10, 10, 10]
        signals = compute_passive_signals(s)
        assert signals.avg_timing_ms < 50


class TestEnumerationPattern:
    def test_systematic_enumeration(self):
        s = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        for tool in ["list_services", "get_environment", "whoami",
                      "get_credentials", "query_database", "admin_panel"]:
            s.record_tool_call(tool, {})
        signals = compute_passive_signals(s)
        assert signals.category_coverage >= 4

    def test_narrow_focus(self):
        s = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        for _ in range(5):
            s.record_tool_call("get_credentials", {})
        signals = compute_passive_signals(s)
        assert signals.category_coverage == 1


class TestBreadcrumbFollowing:
    def test_breadcrumb_follow_rate(self):
        s = DeceptionSession(session_id="t", source_ip="1.2.3.4")
        s.add_breadcrumb("internal_api_call", "payment-api")
        s.add_breadcrumb("ssh_connect", "db-prod.internal")
        s.record_tool_call("internal_api_call", {"service": "payment-api"})
        signals = compute_passive_signals(s)
        assert signals.breadcrumb_follow_rate == 0.5
