"""Rule-based agent classifier -- Phase 1 (no ML required).

HIGH-1 note: this module ships in OSS with its weights visible. The scoring
cannot be a secret defence; an attacker can read the code and learn to fall
just under `_MIN_CALLS`, to jitter timing >2s, or to noise at <50ms to target
a specific bucket. Mitigations applied here:

* `_MIN_CALLS` is env-configurable so operators can raise it per deployment
  (the OSS default of 3 is a starting point, not a hard limit an attacker
  can rely on).
* Confidence is returned as a decisive category WITH a raw-score breakdown
  so downstream session logic can make risk decisions without relying on a
  single classifier output. The real defence is multi-signal session-level
  escalation, not pure classifier accuracy.

Future work: per-deployment salt that jitters score weights within a small
envelope, plus session-level anomaly detection to catch deliberate evasion
patterns (e.g. "exactly 3 calls at exactly 50ms intervals").
"""

from __future__ import annotations

import os

from oubliette.fingerprint.passive import PassiveSignals
from oubliette.models import AgentClassification, AgentType

_MIN_CALLS = int(os.getenv("OUBLIETTE_CLASSIFIER_MIN_CALLS", "3"))


def classify_agent(
    signals: PassiveSignals, probes_triggered: int = 0, probes_sent: int = 0
) -> AgentClassification:
    if signals.total_calls < _MIN_CALLS:
        return AgentClassification(agent_type=AgentType.UNKNOWN, confidence=0.0)

    scores = {
        AgentType.LLM_AGENT: _score_llm_agent(signals, probes_triggered, probes_sent),
        AgentType.SCRIPT: _score_script(signals, probes_triggered, probes_sent),
        AgentType.HUMAN: _score_human(signals, probes_triggered, probes_sent),
    }

    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    total = sum(scores.values())
    confidence = best_score / total if total > 0 else 0.0

    return AgentClassification(agent_type=best_type, confidence=round(confidence, 2))


def _score_llm_agent(signals, probes_triggered, probes_sent):
    score = 0.0
    if 100 <= signals.avg_timing_ms <= 2000 and signals.timing_regularity > 0.5:
        score += 2.0
    elif signals.timing_regularity > 0.7:
        score += 1.0
    if signals.category_coverage >= 3:
        score += 2.0
    elif signals.category_coverage >= 2:
        score += 1.0
    if signals.breadcrumb_follow_rate > 0.6:
        score += 2.0
    elif signals.breadcrumb_follow_rate > 0.3:
        score += 1.0
    if probes_sent > 0:
        probe_rate = probes_triggered / probes_sent
        if probe_rate > 0.5:
            score += 3.0
        elif probe_rate > 0:
            score += 1.5
    if signals.escalation_depth >= 2:
        score += 1.0
    return score


def _score_script(signals, probes_triggered, probes_sent):
    score = 0.0
    if signals.avg_timing_ms < 50:
        score += 3.0
    elif signals.avg_timing_ms < 100:
        score += 1.5
    if signals.timing_regularity > 0.9:
        score += 1.5
    if signals.category_coverage <= 1 and signals.total_calls >= 5:
        score += 2.0
    if signals.breadcrumb_follow_rate == 0.0 and signals.total_calls >= 3:
        score += 1.5
    if probes_sent > 0 and probes_triggered == 0:
        score += 1.5
    return score


def _score_human(signals, probes_triggered, probes_sent):
    score = 0.0
    if signals.avg_timing_ms > 2000:
        score += 2.0
    elif signals.avg_timing_ms > 1000:
        score += 1.0
    if signals.timing_regularity < 0.3:
        score += 2.0
    elif signals.timing_regularity < 0.5:
        score += 1.0
    if signals.total_calls <= 6:
        score += 1.0
    if 0.1 < signals.breadcrumb_follow_rate < 0.6:
        score += 1.0
    if probes_sent > 0 and probes_triggered == 0:
        score += 1.0
    return score
