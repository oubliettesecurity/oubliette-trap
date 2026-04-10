"""DeceptionSession -- tracks per-agent state within a deception environment."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

_TOOL_CATEGORIES = {
    "list_services": "discovery", "get_environment": "discovery", "whoami": "discovery",
    "get_credentials": "credential", "rotate_api_key": "credential", "vault_read": "credential",
    "query_database": "data", "read_config": "data", "list_secrets": "data",
    "internal_api_call": "lateral", "ssh_connect": "lateral", "deploy_service": "lateral",
    "admin_panel": "escalation", "modify_permissions": "escalation", "create_user": "escalation",
}

_CATEGORY_DEPTH = {"discovery": 0, "credential": 1, "data": 1, "lateral": 2, "escalation": 3}


@dataclass
class DeceptionSession:
    """Tracks an agent's journey through the deception environment."""
    session_id: str
    source_ip: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tools_called: list[str] = field(default_factory=list)
    call_timestamps: list[float] = field(default_factory=list)
    inter_call_timings_ms: list[float] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    escalation_depth: int = 0
    breadcrumbs_planted: list[str] = field(default_factory=list)
    breadcrumbs_seen: list[str] = field(default_factory=list)
    breadcrumbs_followed: list[str] = field(default_factory=list)
    probes_sent: list[str] = field(default_factory=list)
    probes_triggered: list[str] = field(default_factory=list)
    argument_history: list[dict] = field(default_factory=list)

    @property
    def call_count(self) -> int:
        return len(self.tools_called)

    def record_tool_call(self, tool_name: str, arguments: dict) -> None:
        now = time.monotonic()
        if self.call_timestamps:
            gap_ms = (now - self.call_timestamps[-1]) * 1000
            self.inter_call_timings_ms.append(gap_ms)
        self.call_timestamps.append(now)
        self.tools_called.append(tool_name)
        self.argument_history.append({"tool": tool_name, "args": arguments})

        for bc in self.breadcrumbs_planted:
            bc_tool, bc_value = bc.split(":", 1)
            if tool_name == bc_tool:
                arg_str = str(arguments)
                if bc_value in arg_str:
                    if bc not in self.breadcrumbs_followed:
                        self.breadcrumbs_followed.append(bc)

        category = _TOOL_CATEGORIES.get(tool_name, "unknown")
        if category not in self.categories_seen:
            self.categories_seen.append(category)
        depth = _CATEGORY_DEPTH.get(category, 0)
        if depth > self.escalation_depth:
            self.escalation_depth = depth

    def add_breadcrumb(self, tool_name: str, value: str) -> None:
        bc = f"{tool_name}:{value}"
        if bc not in self.breadcrumbs_planted:
            self.breadcrumbs_planted.append(bc)

    def record_probe_sent(self, probe_id: str) -> None:
        self.probes_sent.append(probe_id)

    def record_probe_triggered(self, probe_id: str) -> None:
        if probe_id not in self.probes_triggered:
            self.probes_triggered.append(probe_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "created_at": self.created_at,
            "call_count": self.call_count,
            "tools_called": self.tools_called,
            "categories_seen": self.categories_seen,
            "escalation_depth": self.escalation_depth,
            "breadcrumbs_planted": len(self.breadcrumbs_planted),
            "breadcrumbs_followed": self.breadcrumbs_followed,
            "probes_sent": len(self.probes_sent),
            "probes_triggered": self.probes_triggered,
        }
