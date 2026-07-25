"""Lightweight, explainable temporal behavioral drift scoring.

This module intentionally has no dependency on Step 3 detection results.  The
temporal score is an additional intelligence layer and does not alter the
existing event risk score or alert ranking.

Labels are deliberately absent from the telemetry query used by
``calculate_temporal_drift``.  The evaluation helper reads labels only after
all temporal scores have been calculated.
"""

import json
import math
from datetime import datetime
from statistics import mean
from typing import Any


RECENT_EVENT_COUNT = 10

# The six independent sequence-level signals sum to 100.
SIGNAL_WEIGHTS = {
    "resource_expansion": 20,
    "activity_frequency": 15,
    "behavioral_deviation_accumulation": 20,
    "authentication_failure_increase": 15,
    "session_duration_deviation": 15,
    "device_location_diversity": 15,
}

# Documented operating thresholds for the 0-100 temporal score.
STATUS_ELEVATED_THRESHOLD = 35
STATUS_HIGH_DRIFT_THRESHOLD = 65

TELEMETRY_COLUMNS = """
    entity_id, entity_type, timestamp, source_ip, geo_location, resource_accessed,
    auth_method, auth_success, session_duration, device_fingerprint, department
"""


def _clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _days_between(start: datetime, end: datetime) -> float:
    return max((end - start).total_seconds() / 86400.0, 1.0 / 24.0)


def _profile_deviation_count(event: dict[str, Any], profile: dict[str, Any]) -> int:
    """Count profile deviations using only fields present in the event/profile."""
    hour = _parse_timestamp(event["timestamp"]).hour
    normal_hours = profile.get("normal_hours", list(range(24)))
    known_devices = {str(device) for device in profile.get("known_devices", [])}
    common_resources = {str(resource) for resource in profile.get("common_resources", [])}
    preferred_auth = str(profile.get("preferred_auth", ""))
    ip_prefix = str(profile.get("ip_prefix", ""))

    deviations = [
        hour not in normal_hours,
        str(event["device_fingerprint"]) not in known_devices,
        str(event["geo_location"]) != str(profile.get("primary_location", "")),
        bool(ip_prefix) and not str(event["source_ip"]).startswith(ip_prefix),
        str(event["resource_accessed"]) not in common_resources,
        str(event["auth_method"]) != preferred_auth,
        _session_deviation(event["session_duration"], profile) > 0,
    ]
    return sum(bool(deviation) for deviation in deviations)


def _session_deviation(duration: float, profile: dict[str, Any]) -> float:
    """Return normalized distance outside the profile's normal duration range."""
    minimum = float(profile.get("session_dur_min", duration))
    maximum = float(profile.get("session_dur_max", duration))
    span = max(maximum - minimum, 1.0)
    if duration < minimum:
        return _clamp((minimum - duration) / span)
    if duration > maximum:
        return _clamp((duration - maximum) / span)
    return 0.0


def _signal(score: float, **details: Any) -> dict[str, Any]:
    normalized = round(_clamp(score), 4)
    return {
        "score": normalized,
        "weighted_points": round(normalized * details.pop("weight", 0), 2),
        **details,
        "triggered": normalized >= 0.35,
    }


def _resource_signal(recent: list[dict[str, Any]], history: list[dict[str, Any]], profile: dict[str, Any]) -> dict[str, Any]:
    recent_resources = {str(row["resource_accessed"]) for row in recent}
    historical_resources = {str(row["resource_accessed"]) for row in history}
    if not historical_resources:
        historical_resources = {str(resource) for resource in profile.get("common_resources", [])}
    new_resources = recent_resources - historical_resources
    denominator = max(2.0, len(historical_resources) * 0.4)
    score = len(new_resources) / denominator if historical_resources else 0.0
    return _signal(
        score,
        weight=SIGNAL_WEIGHTS["resource_expansion"],
        recent_distinct_resources=len(recent_resources),
        historical_distinct_resources=len(historical_resources),
        new_resources=len(new_resources),
    )


def _frequency_signal(recent: list[dict[str, Any]], history: list[dict[str, Any]]) -> dict[str, Any]:
    if len(recent) < 2 or len(history) < 2:
        return _signal(0.0, weight=SIGNAL_WEIGHTS["activity_frequency"], recent_events=len(recent))
    recent_span = _days_between(_parse_timestamp(recent[0]["timestamp"]), _parse_timestamp(recent[-1]["timestamp"]))
    history_span = _days_between(_parse_timestamp(history[0]["timestamp"]), _parse_timestamp(history[-1]["timestamp"]))
    recent_rate = (len(recent) - 1) / recent_span
    historical_rate = (len(history) - 1) / history_span
    rate_ratio = recent_rate / max(historical_rate, 1e-9)
    score = _clamp((rate_ratio - 1.0) / 2.0)
    return _signal(
        score,
        weight=SIGNAL_WEIGHTS["activity_frequency"],
        recent_events=len(recent),
        recent_events_per_day=round(recent_rate, 4),
        historical_events_per_day=round(historical_rate, 4),
        rate_ratio=round(rate_ratio, 4),
    )


def _deviation_signal(recent: list[dict[str, Any]], history: list[dict[str, Any]], profile: dict[str, Any]) -> dict[str, Any]:
    recent_average = mean(_profile_deviation_count(row, profile) for row in recent) if recent else 0.0
    historical_average = mean(_profile_deviation_count(row, profile) for row in history) if history else 0.0
    recent_normalized = recent_average / 7.0
    increase = _clamp((recent_average - historical_average) / 3.0)
    score = 0.6 * recent_normalized + 0.4 * increase
    return _signal(
        score,
        weight=SIGNAL_WEIGHTS["behavioral_deviation_accumulation"],
        recent_average_deviations=round(recent_average, 4),
        historical_average_deviations=round(historical_average, 4),
    )


def _failure_signal(recent: list[dict[str, Any]], history: list[dict[str, Any]]) -> dict[str, Any]:
    recent_rate = mean(not bool(row["auth_success"]) for row in recent) if recent else 0.0
    historical_rate = mean(not bool(row["auth_success"]) for row in history) if history else 0.0
    score = _clamp((recent_rate - historical_rate) * 2.5)
    return _signal(
        score,
        weight=SIGNAL_WEIGHTS["authentication_failure_increase"],
        recent_failure_rate=round(recent_rate, 4),
        historical_failure_rate=round(historical_rate, 4),
    )


def _session_signal(recent: list[dict[str, Any]], history: list[dict[str, Any]], profile: dict[str, Any]) -> dict[str, Any]:
    recent_average = mean(_session_deviation(float(row["session_duration"]), profile) for row in recent) if recent else 0.0
    historical_average = mean(_session_deviation(float(row["session_duration"]), profile) for row in history) if history else 0.0
    increase = _clamp((recent_average - historical_average) * 2.0)
    score = 0.6 * _clamp(recent_average) + 0.4 * increase
    return _signal(
        score,
        weight=SIGNAL_WEIGHTS["session_duration_deviation"],
        recent_average_deviation=round(recent_average, 4),
        historical_average_deviation=round(historical_average, 4),
    )


def _diversity_signal(recent: list[dict[str, Any]], history: list[dict[str, Any]]) -> dict[str, Any]:
    def diversity(rows: list[dict[str, Any]]) -> float:
        if not rows:
            return 0.0
        devices = len({str(row["device_fingerprint"]) for row in rows}) / len(rows)
        locations = len({str(row["geo_location"]) for row in rows}) / len(rows)
        return (devices + locations) / 2.0

    recent_value = diversity(recent)
    historical_value = diversity(history)
    score = _clamp((recent_value - historical_value) * 2.0)
    return _signal(
        score,
        weight=SIGNAL_WEIGHTS["device_location_diversity"],
        recent_diversity=round(recent_value, 4),
        historical_diversity=round(historical_value, 4),
        recent_distinct_devices=len({str(row["device_fingerprint"]) for row in recent}),
        recent_distinct_locations=len({str(row["geo_location"]) for row in recent}),
    )


def _status(score: float) -> str:
    if score >= STATUS_HIGH_DRIFT_THRESHOLD:
        return "High Drift"
    if score >= STATUS_ELEVATED_THRESHOLD:
        return "Elevated"
    return "Stable"


def calculate_temporal_drift(conn, entity_id: str) -> dict[str, Any] | None:
    """Calculate temporal drift for one identity without reading ground truth."""
    identity = conn.execute(
        "SELECT entity_id, profile FROM identities WHERE entity_id = ?",
        (entity_id,),
    ).fetchone()
    if identity is None:
        return None

    # Do not add label here: this is the complete scoring telemetry input.
    rows = conn.execute(
        f"""
        SELECT {TELEMETRY_COLUMNS}
        FROM events
        WHERE entity_id = ?
        ORDER BY timestamp ASC, rowid ASC
        """,
        (entity_id,),
    ).fetchall()
    events = [dict(row) for row in rows]
    profile = json.loads(identity["profile"])
    recent = events[-RECENT_EVENT_COUNT:]
    history = events[:-RECENT_EVENT_COUNT]

    signals = {
        "resource_expansion": _resource_signal(recent, history, profile),
        "activity_frequency": _frequency_signal(recent, history),
        "behavioral_deviation_accumulation": _deviation_signal(recent, history, profile),
        "authentication_failure_increase": _failure_signal(recent, history),
        "session_duration_deviation": _session_signal(recent, history, profile),
        "device_location_diversity": _diversity_signal(recent, history),
    }
    score = round(sum(signal["weighted_points"] for signal in signals.values()))
    reasons_by_signal = {
        "resource_expansion": "Resource access expanded beyond historical baseline",
        "activity_frequency": "Activity frequency exceeded historical behavior",
        "behavioral_deviation_accumulation": "Behavioral deviations accumulated across recent activity",
        "authentication_failure_increase": "Authentication failures increased in recent activity",
        "session_duration_deviation": "Session-duration deviation increased in recent activity",
        "device_location_diversity": "Device/location diversity increased",
    }
    reasons = [
        reasons_by_signal[name]
        for name, signal in signals.items()
        if signal["triggered"]
    ]

    return {
        "entity_id": entity_id,
        "temporal_drift_score": score,
        "temporal_status": _status(score),
        "temporal_reasons": reasons,
        "temporal_signals": signals,
        "recent_event_count": len(recent),
        "historical_event_count": len(history),
    }


def calculate_all_temporal_drift(conn) -> dict[str, dict[str, Any]]:
    """Calculate all identity scores before any offline label evaluation."""
    identity_rows = conn.execute("SELECT entity_id FROM identities ORDER BY entity_id").fetchall()
    results = {}
    for row in identity_rows:
        result = calculate_temporal_drift(conn, row["entity_id"])
        if result is not None:
            results[row["entity_id"]] = result
    return results


def evaluate_temporal_attack_association(conn, scores: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Post-hoc evaluation: labels are read only after scores are complete."""
    rows = conn.execute(
        "SELECT entity_id, label FROM events WHERE label IN (?, ?, ?)",
        ("lateral_movement", "low_slow_exfiltration", "insider_drift"),
    ).fetchall()
    by_attack: dict[str, dict[str, Any]] = {}
    for attack in ("lateral_movement", "low_slow_exfiltration", "insider_drift"):
        attack_entities = {row["entity_id"] for row in rows if row["label"] == attack}
        attack_scores = [scores[eid]["temporal_drift_score"] for eid in attack_entities if eid in scores]
        high_drift = sum(score >= STATUS_HIGH_DRIFT_THRESHOLD for score in attack_scores)
        by_attack[attack] = {
            "identity_count": len(attack_scores),
            "high_drift_identities": high_drift,
            "high_drift_rate": round(high_drift / len(attack_scores), 4) if attack_scores else 0.0,
            "mean_temporal_drift_score": round(mean(attack_scores), 2) if attack_scores else 0.0,
        }
    return by_attack