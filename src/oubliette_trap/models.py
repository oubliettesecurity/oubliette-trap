"""Core data models for the Oubliette deception platform."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class AgentType(Enum):
    UNKNOWN = "unknown"
    LLM_AGENT = "llm_agent"
    SCRIPT = "script"
    HUMAN = "human"
    COMPROMISED_AGENT = "compromised_agent"


@dataclass
class AgentClassification:
    """Result of fingerprinting an interacting entity."""

    agent_type: AgentType = AgentType.UNKNOWN
    confidence: float = 0.0
    model_family: str = "unknown"
    capabilities: list[str] = field(default_factory=list)
    behavioral_signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_type": self.agent_type.value,
            "confidence": self.confidence,
            "model_family": self.model_family,
            "capabilities": self.capabilities,
            "behavioral_signature": self.behavioral_signature,
        }


@dataclass
class TrapEvent:
    """A single interaction with the honeypot."""

    session_id: str
    source_ip: str
    tool_name: str
    arguments: dict[str, Any]
    response_sent: dict[str, Any]
    deception_profile: str
    event_id: str = field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    fingerprint: AgentClassification = field(default_factory=AgentClassification)
    breadcrumbs_followed: list[str] = field(default_factory=list)
    probes_triggered: list[str] = field(default_factory=list)
    mitre_atlas_mapping: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "response_sent": self.response_sent,
            "deception_profile": self.deception_profile,
            "fingerprint": self.fingerprint.to_dict(),
            "breadcrumbs_followed": self.breadcrumbs_followed,
            "probes_triggered": self.probes_triggered,
            "mitre_atlas_mapping": self.mitre_atlas_mapping,
        }


@dataclass
class AgentProfile:
    """Aggregated behavioral profile of an agent across sessions."""

    behavioral_signature: str
    profile_id: str = field(default_factory=lambda: f"AGT-{uuid.uuid4().hex[:8].upper()}")
    classification: AgentClassification = field(default_factory=AgentClassification)
    first_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen: str = ""
    session_count: int = 0
    tools_targeted: list[str] = field(default_factory=list)
    capability_assessment: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)

    def record_session(
        self,
        tools: list[str],
        classification: AgentClassification,
    ) -> None:
        """Update profile with data from a new session."""
        self.session_count += 1
        self.last_seen = datetime.now(UTC).isoformat()
        self.classification = classification
        for tool in tools:
            if tool not in self.tools_targeted:
                self.tools_targeted.append(tool)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "behavioral_signature": self.behavioral_signature,
            "classification": self.classification.to_dict(),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "session_count": self.session_count,
            "tools_targeted": self.tools_targeted,
            "capability_assessment": self.capability_assessment,
            "ttps": self.ttps,
        }
