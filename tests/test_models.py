"""Tests for core data models."""
import pytest
from oubliette.models import (
    AgentType, AgentClassification,
    TrapEvent, AgentProfile,
)


class TestAgentClassification:
    def test_create(self):
        c = AgentClassification(
            agent_type=AgentType.LLM_AGENT,
            confidence=0.85,
            model_family="claude",
            capabilities=["tool_enumeration", "credential_theft"],
        )
        assert c.agent_type == AgentType.LLM_AGENT
        assert c.confidence == 0.85
        assert c.model_family == "claude"
        assert "tool_enumeration" in c.capabilities
        assert c.behavioral_signature == ""

    def test_to_dict(self):
        c = AgentClassification(
            agent_type=AgentType.SCRIPT,
            confidence=0.95,
        )
        d = c.to_dict()
        assert d["agent_type"] == "script"
        assert d["confidence"] == 0.95

    def test_unknown_default(self):
        c = AgentClassification()
        assert c.agent_type == AgentType.UNKNOWN
        assert c.confidence == 0.0


class TestTrapEvent:
    def test_create(self):
        e = TrapEvent(
            session_id="sess-001",
            source_ip="10.0.0.1",
            tool_name="list_services",
            arguments={"filter": "all"},
            response_sent={"services": []},
            deception_profile="default",
        )
        assert e.event_id.startswith("EVT-")
        assert e.session_id == "sess-001"
        assert e.tool_name == "list_services"
        assert e.timestamp != ""

    def test_to_dict(self):
        e = TrapEvent(
            session_id="sess-002",
            source_ip="10.0.0.2",
            tool_name="whoami",
            arguments={},
            response_sent={"user": "admin"},
            deception_profile="cloud-api",
        )
        d = e.to_dict()
        assert d["session_id"] == "sess-002"
        assert "event_id" in d
        assert "timestamp" in d


class TestAgentProfile:
    def test_create(self):
        p = AgentProfile(behavioral_signature="abc123")
        assert p.profile_id.startswith("AGT-")
        assert p.session_count == 0
        assert p.tools_targeted == []

    def test_record_session(self):
        p = AgentProfile(behavioral_signature="abc123")
        p.record_session(
            tools=["list_services", "get_credentials"],
            classification=AgentClassification(
                agent_type=AgentType.LLM_AGENT,
                confidence=0.9,
            ),
        )
        assert p.session_count == 1
        assert "list_services" in p.tools_targeted
        assert p.last_seen != ""
