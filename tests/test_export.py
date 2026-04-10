"""Tests for intelligence export (STIX, CEF, JSON)."""
import json
import pytest
from oubliette.intel.export import export_stix, export_cef, export_json
from oubliette.models import TrapEvent, AgentClassification, AgentType, AgentProfile


@pytest.fixture
def sample_events():
    return [
        TrapEvent(
            session_id="sess-001", source_ip="10.0.0.1",
            tool_name="list_services", arguments={},
            response_sent={"services": []}, deception_profile="default",
            fingerprint=AgentClassification(agent_type=AgentType.LLM_AGENT, confidence=0.85),
        ),
        TrapEvent(
            session_id="sess-001", source_ip="10.0.0.1",
            tool_name="get_credentials", arguments={"service": "payment-api"},
            response_sent={"credentials": []}, deception_profile="default",
            fingerprint=AgentClassification(agent_type=AgentType.LLM_AGENT, confidence=0.85),
        ),
    ]


@pytest.fixture
def sample_profile():
    return AgentProfile(
        behavioral_signature="abc123",
        classification=AgentClassification(agent_type=AgentType.LLM_AGENT, confidence=0.85),
        session_count=3,
        tools_targeted=["list_services", "get_credentials"],
        ttps=["AML.T0043", "AML.T0044"],
    )


class TestStixExport:
    def test_produces_valid_bundle(self, sample_events, sample_profile):
        bundle = export_stix(sample_events, [sample_profile])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 1

    def test_includes_threat_actor(self, sample_events, sample_profile):
        bundle = export_stix(sample_events, [sample_profile])
        types = [obj["type"] for obj in bundle["objects"]]
        assert "threat-actor" in types


class TestCefExport:
    def test_produces_cef_lines(self, sample_events):
        lines = export_cef(sample_events)
        assert len(lines) == 2
        assert all(line.startswith("CEF:") for line in lines)

    def test_includes_tool_name(self, sample_events):
        lines = export_cef(sample_events)
        assert "list_services" in lines[0]


class TestJsonExport:
    def test_produces_valid_json(self, sample_events, sample_profile):
        output = export_json(sample_events, [sample_profile])
        data = json.loads(output)
        assert "events" in data
        assert "profiles" in data
        assert len(data["events"]) == 2
