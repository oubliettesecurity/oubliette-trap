"""Passive fingerprinting -- behavioral signals collected without agent awareness."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from oubliette.deception.session import DeceptionSession


@dataclass
class PassiveSignals:
    """Computed behavioral signals from a deception session."""
    avg_timing_ms: float = 0.0
    timing_regularity: float = 0.0
    category_coverage: int = 0
    unique_tools: int = 0
    total_calls: int = 0
    breadcrumb_follow_rate: float = 0.0
    escalation_depth: int = 0
    avg_argument_length: float = 0.0


def compute_passive_signals(session: DeceptionSession) -> PassiveSignals:
    """Extract passive behavioral signals from a deception session."""
    signals = PassiveSignals()
    signals.total_calls = session.call_count
    signals.unique_tools = len(set(session.tools_called))
    signals.category_coverage = len(session.categories_seen)
    signals.escalation_depth = session.escalation_depth

    timings = session.inter_call_timings_ms
    if timings:
        signals.avg_timing_ms = statistics.mean(timings)
        if len(timings) >= 2:
            mean = statistics.mean(timings)
            stdev = statistics.stdev(timings)
            cv = stdev / mean if mean > 0 else 1.0
            signals.timing_regularity = max(0.0, min(1.0, 1.0 - cv))

    planted = len(session.breadcrumbs_planted)
    if planted > 0:
        signals.breadcrumb_follow_rate = len(session.breadcrumbs_followed) / planted

    if session.argument_history:
        lengths = [len(str(a.get("args", {}))) for a in session.argument_history]
        signals.avg_argument_length = statistics.mean(lengths)

    return signals
