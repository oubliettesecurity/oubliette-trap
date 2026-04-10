"""Tests for rule-based agent classifier."""
import pytest
from oubliette.fingerprint.classifier import classify_agent
from oubliette.fingerprint.passive import PassiveSignals
from oubliette.models import AgentType


class TestClassifier:
    def test_classify_llm_agent(self):
        signals = PassiveSignals(avg_timing_ms=250, timing_regularity=0.85, category_coverage=4, unique_tools=8, total_calls=12, breadcrumb_follow_rate=0.8, escalation_depth=2)
        result = classify_agent(signals, probes_triggered=2, probes_sent=3)
        assert result.agent_type == AgentType.LLM_AGENT
        assert result.confidence >= 0.7

    def test_classify_script(self):
        signals = PassiveSignals(avg_timing_ms=15, timing_regularity=0.95, category_coverage=1, unique_tools=1, total_calls=20, breadcrumb_follow_rate=0.0, escalation_depth=0)
        result = classify_agent(signals, probes_triggered=0, probes_sent=3)
        assert result.agent_type == AgentType.SCRIPT
        assert result.confidence >= 0.7

    def test_classify_human(self):
        signals = PassiveSignals(avg_timing_ms=5000, timing_regularity=0.15, category_coverage=2, unique_tools=3, total_calls=4, breadcrumb_follow_rate=0.3, escalation_depth=1)
        result = classify_agent(signals, probes_triggered=0, probes_sent=2)
        assert result.agent_type == AgentType.HUMAN
        assert result.confidence >= 0.5

    def test_low_data_returns_unknown(self):
        signals = PassiveSignals(total_calls=1)
        result = classify_agent(signals, probes_triggered=0, probes_sent=0)
        assert result.agent_type == AgentType.UNKNOWN

    def test_probe_response_boosts_llm_confidence(self):
        signals = PassiveSignals(avg_timing_ms=300, timing_regularity=0.6, category_coverage=3, unique_tools=5, total_calls=8, breadcrumb_follow_rate=0.5)
        no_probes = classify_agent(signals, probes_triggered=0, probes_sent=3)
        with_probes = classify_agent(signals, probes_triggered=2, probes_sent=3)
        assert with_probes.confidence > no_probes.confidence
