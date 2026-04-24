"""Intelligence export -- STIX 2.1, CEF, and JSON formats."""

from __future__ import annotations

from typing import Any

import json
import uuid
from datetime import UTC, datetime

from oubliette.models import AgentProfile, TrapEvent


def export_stix(events: list[TrapEvent], profiles: list[AgentProfile]) -> dict[str, Any]:
    objects: list[dict[str, Any]] = []

    identity_id = "identity--oubliette-trap"
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": datetime.now(UTC).isoformat() + "Z",
            "modified": datetime.now(UTC).isoformat() + "Z",
            "name": "Oubliette Agent Deception Platform",
            "identity_class": "system",
        }
    )

    for profile in profiles:
        ta_id = f"threat-actor--{uuid.uuid4()}"
        first = profile.first_seen if profile.first_seen.endswith("Z") else profile.first_seen + "Z"
        last = profile.last_seen or profile.first_seen
        last = last if last.endswith("Z") else last + "Z"
        objects.append(
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": ta_id,
                "created": first,
                "modified": last,
                "name": f"Agent {profile.profile_id}",
                "description": f"Classified as {profile.classification.agent_type.value} (confidence: {profile.classification.confidence})",
                "threat_actor_types": ["unknown"],
                "labels": [profile.classification.agent_type.value],
            }
        )

    for event in events:
        ts = event.timestamp if event.timestamp.endswith("Z") else event.timestamp + "Z"
        # MED-01 fix (2026-04-22 audit): STIX 2.1 requires observed-data to
        # reference at least one SCO via ``object_refs`` OR carry inline SCOs
        # in ``objects``. The previous ``object_refs: []`` was invalid and
        # OpenCTI / MISP silently dropped the observation. Emit an inline
        # ipv4-addr SCO for the source IP so each event carries a valid
        # reference; the tool name / session ID remain as x_ extension fields.
        sco_id = f"ipv4-addr--{uuid.uuid4()}"
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{uuid.uuid4()}",
                "created": ts,
                "modified": ts,
                "first_observed": event.timestamp,
                "last_observed": event.timestamp,
                "number_observed": 1,
                "object_refs": [sco_id],
                "x_oubliette_tool_name": event.tool_name,
                "x_oubliette_session_id": event.session_id,
                "x_oubliette_source_ip": event.source_ip,
                "x_oubliette_agent_type": event.fingerprint.agent_type.value,
            }
        )
        objects.append(
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": sco_id,
                "value": event.source_ip,
            }
        )

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _cef_escape_ext(value: object) -> str:
    """Escape a value for CEF extension fields per ArcSight CEF spec.

    MED-02 fix (2026-04-22 audit): session_id and source_ip were attacker-
    controllable (via CRIT-2, now fixed) and flowed unescaped into the CEF
    extension string. Without escaping, an attacker could have injected
    ``src=... dst=attacker act=Block`` as fake CEF fields and steered SIEM
    correlation. Escape backslash, pipe, equals, CR, LF per spec.
    """
    s = str(value) if value is not None else ""
    # Order matters: escape backslashes first.
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    s = s.replace("=", "\\=")
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s


def _cef_escape_header(value: object) -> str:
    """CEF header escaping: pipe and backslash only (no equals)."""
    s = str(value) if value is not None else ""
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    s = s.replace("\r", " ").replace("\n", " ")
    return s


def export_cef(events: list[TrapEvent]) -> list[str]:
    lines = []
    for event in events:
        severity = _cef_severity(event)
        name = f"AgentTrap:{_cef_escape_header(event.tool_name)}"
        ext = (
            f"src={_cef_escape_ext(event.source_ip)} "
            f"cs1={_cef_escape_ext(event.session_id)} cs1Label=SessionID "
            f"cs2={_cef_escape_ext(event.fingerprint.agent_type.value)} cs2Label=AgentType "
            f"cs3={_cef_escape_ext(event.deception_profile)} cs3Label=Profile "
            f"msg={_cef_escape_ext(event.tool_name)}"
        )
        line = f"CEF:0|Oubliette|Trap|0.1.0|{_cef_escape_header(event.tool_name)}|{name}|{severity}|{ext}"
        lines.append(line)
    return lines


def export_json(events: list[TrapEvent], profiles: list[AgentProfile]) -> str:
    return json.dumps(
        {
            "events": [e.to_dict() for e in events],
            "profiles": [p.to_dict() for p in profiles],
            "exported_at": datetime.now(UTC).isoformat(),
        },
        indent=2,
    )


def _cef_severity(event: TrapEvent) -> int:
    tool = event.tool_name
    if tool in ("modify_permissions", "create_user", "admin_panel"):
        return 8
    if tool in ("get_credentials", "vault_read", "rotate_api_key"):
        return 7
    if tool in ("ssh_connect", "internal_api_call", "deploy_service"):
        return 6
    if tool in ("query_database", "read_config", "list_secrets"):
        return 5
    return 3
