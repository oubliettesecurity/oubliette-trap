"""Intelligence export -- STIX 2.1, CEF, and JSON formats."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from oubliette.models import AgentProfile, TrapEvent


def export_stix(events: list[TrapEvent], profiles: list[AgentProfile]) -> dict:
    objects = []

    identity_id = "identity--oubliette-trap"
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": datetime.now(timezone.utc).isoformat() + "Z",
        "modified": datetime.now(timezone.utc).isoformat() + "Z",
        "name": "Oubliette Agent Deception Platform", "identity_class": "system",
    })

    for profile in profiles:
        ta_id = f"threat-actor--{uuid.uuid4()}"
        first = profile.first_seen if profile.first_seen.endswith("Z") else profile.first_seen + "Z"
        last = (profile.last_seen or profile.first_seen)
        last = last if last.endswith("Z") else last + "Z"
        objects.append({
            "type": "threat-actor", "spec_version": "2.1", "id": ta_id,
            "created": first, "modified": last,
            "name": f"Agent {profile.profile_id}",
            "description": f"Classified as {profile.classification.agent_type.value} (confidence: {profile.classification.confidence})",
            "threat_actor_types": ["unknown"],
            "labels": [profile.classification.agent_type.value],
        })

    for event in events:
        ts = event.timestamp if event.timestamp.endswith("Z") else event.timestamp + "Z"
        objects.append({
            "type": "observed-data", "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": ts, "modified": ts,
            "first_observed": event.timestamp, "last_observed": event.timestamp,
            "number_observed": 1, "object_refs": [],
            "x_oubliette_tool_name": event.tool_name,
            "x_oubliette_session_id": event.session_id,
            "x_oubliette_source_ip": event.source_ip,
            "x_oubliette_agent_type": event.fingerprint.agent_type.value,
        })

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def export_cef(events: list[TrapEvent]) -> list[str]:
    lines = []
    for event in events:
        severity = _cef_severity(event)
        name = f"AgentTrap:{event.tool_name}"
        ext = (
            f"src={event.source_ip} "
            f"cs1={event.session_id} cs1Label=SessionID "
            f"cs2={event.fingerprint.agent_type.value} cs2Label=AgentType "
            f"cs3={event.deception_profile} cs3Label=Profile "
            f"msg={event.tool_name}"
        )
        line = f"CEF:0|Oubliette|Trap|0.1.0|{event.tool_name}|{name}|{severity}|{ext}"
        lines.append(line)
    return lines


def export_json(events: list[TrapEvent], profiles: list[AgentProfile]) -> str:
    return json.dumps({
        "events": [e.to_dict() for e in events],
        "profiles": [p.to_dict() for p in profiles],
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


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
