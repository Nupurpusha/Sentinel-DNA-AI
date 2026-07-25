"""Lightweight, explainable temporal behavioral drift scoring.

This module intentionally has no dependency on Step 3 detection results.  The
temporal score is an additional intelligence layer and does not alter the
existing event risk score or alert ranking.

Labels are deliberately absent from the telemetry query used by
``calculate_temporal_drift``.  The evaluation helper reads labels only after
all temporal scores have been calculated.
"""

import json
from datetime import datetime
from statistics import mean
from typing import Any

from baseline import MINIMUM_HISTORY_EVENTS, baseline_status

ROLLING_WINDOW_SIZES = (10, 25, 50)
SEGMENT_SIZE = 10

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
        "triggered": normalized >= 0.25,
    }


def _window_pair(events: list[dict[str, Any]], size: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return a recent window and the immediately preceding baseline window."""
    recent = events[-size:]
    baseline = events[-(2 * size):-size]
    if len(baseline) < max(5, size // 2):
        baseline = events[:-size]
    return recent, baseline


def _rate(rows: list[dict[str, Any]]) -> float:
    if len(rows) < 2:
        return 0.0
    span = _days_between(_parse_timestamp(rows[0]["timestamp"]), _parse_timestamp(rows[-1]["timestamp"]))
    return (len(rows) - 1) / span


def _resource_window_score(recent: list[dict[str, Any]], baseline: list[dict[str, Any]], profile: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    recent_resources = [str(row["resource_accessed"]) for row in recent]
    baseline_resources = {str(row["resource_accessed"]) for row in baseline}
    if not baseline_resources:
        baseline_resources = {str(resource) for resource in profile.get("common_resources", [])}
    recent_distinct = set(recent_resources)
    new_resources = recent_distinct - baseline_resources
    counts = {resource: recent_resources.count(resource) for resource in new_resources}
    repeated_new = sum(count for count in counts.values() if count >= 2)
    expansion = len(new_resources) / max(2.0, len(baseline_resources) * 0.25)
    repetition = repeated_new / max(len(recent_resources), 1)
    score = _clamp(0.7 * expansion + 0.3 * repetition)
    return score, {
        "recent_distinct_resources": len(recent_distinct),
        "baseline_distinct_resources": len(baseline_resources),
        "new_resources": len(new_resources),
        "repeated_new_resource_accesses": repeated_new,
    }


def _frequency_window_score(recent: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    recent_rate = _rate(recent)
    baseline_rate = _rate(baseline)
    ratio = recent_rate / max(baseline_rate, 1e-9)
    score = _clamp((ratio - 1.0) / 1.5)
    return score, {
        "recent_events_per_day": round(recent_rate, 4),
        "baseline_events_per_day": round(baseline_rate, 4),
        "rate_ratio": round(ratio, 4),
    }


def _deviation_window_score(recent: list[dict[str, Any]], baseline: list[dict[str, Any]], profile: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    recent_average = mean(_profile_deviation_count(row, profile) for row in recent) if recent else 0.0
    baseline_average = mean(_profile_deviation_count(row, profile) for row in baseline) if baseline else 0.0
    level = _clamp(recent_average / 5.0)
    increase = _clamp((recent_average - baseline_average) / 2.0)
    return _clamp(0.55 * level + 0.45 * increase), {
        "recent_average_deviations": round(recent_average, 4),
        "baseline_average_deviations": round(baseline_average, 4),
    }


def _failure_window_score(recent: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    recent_rate = mean(not bool(row["auth_success"]) for row in recent) if recent else 0.0
    baseline_rate = mean(not bool(row["auth_success"]) for row in baseline) if baseline else 0.0
    increase = _clamp((recent_rate - baseline_rate) * 3.0)
    sustained = _clamp(recent_rate * 1.5)
    return _clamp(0.65 * increase + 0.35 * sustained), {
        "recent_failure_rate": round(recent_rate, 4),
        "baseline_failure_rate": round(baseline_rate, 4),
    }


def _session_window_score(recent: list[dict[str, Any]], baseline: list[dict[str, Any]], profile: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    recent_average = mean(_session_deviation(float(row["session_duration"]), profile) for row in recent) if recent else 0.0
    baseline_average = mean(_session_deviation(float(row["session_duration"]), profile) for row in baseline) if baseline else 0.0
    increase = _clamp((recent_average - baseline_average) * 2.0)
    return _clamp(0.65 * recent_average + 0.35 * increase), {
        "recent_average_deviation": round(recent_average, 4),
        "baseline_average_deviation": round(baseline_average, 4),
    }


def _diversity_window_score(recent: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    def diversity(rows: list[dict[str, Any]]) -> float:
        if not rows:
            return 0.0
        devices = len({str(row["device_fingerprint"]) for row in rows}) / len(rows)
        locations = len({str(row["geo_location"]) for row in rows}) / len(rows)
        return (devices + locations) / 2.0

    recent_value = diversity(recent)
    baseline_value = diversity(baseline)
    growth = _clamp((recent_value - baseline_value) * 2.0)
    sustained = _clamp(recent_value * 0.75)
    return _clamp(0.7 * growth + 0.3 * sustained), {
        "recent_diversity": round(recent_value, 4),
        "baseline_diversity": round(baseline_value, 4),
        "recent_distinct_devices": len({str(row["device_fingerprint"]) for row in recent}),
        "recent_distinct_locations": len({str(row["geo_location"]) for row in recent}),
    }


SIGNAL_CALCULATORS = {
    "resource_expansion": _resource_window_score,
    "activity_frequency": _frequency_window_score,
    "behavioral_deviation_accumulation": _deviation_window_score,
    "authentication_failure_increase": _failure_window_score,
    "session_duration_deviation": _session_window_score,
    "device_location_diversity": _diversity_window_score,
}


def _rolling_signal(
    events: list[dict[str, Any]],
    profile: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    """Aggregate three recent-vs-prior windows with persistence and trend."""
    calculator = SIGNAL_CALCULATORS[name]
    window_scores: dict[str, float] = {}
    window_details: dict[str, dict[str, Any]] = {}
    for size in ROLLING_WINDOW_SIZES:
        recent, baseline = _window_pair(events, size)
        raw_score, details = calculator(recent, baseline, profile) if name in {
            "resource_expansion", "behavioral_deviation_accumulation",
            "session_duration_deviation",
        } else calculator(recent, baseline)
        window_scores[str(size)] = round(raw_score, 4)
        window_details[str(size)] = details

    available_scores = [window_scores[str(size)] for size in ROLLING_WINDOW_SIZES if len(events) >= size * 2]
    if not available_scores:
        available_scores = list(window_scores.values())
    weighted_recent = sum(
        window_scores[str(size)] * weight
        for size, weight in ((10, 0.5), (25, 0.3), (50, 0.2))
    )
    persistent_windows = sum(score >= 0.25 for score in available_scores)
    persistence = persistent_windows / len(available_scores)

    # Consecutive 10-event segments expose a genuine direction of travel
    # without treating a one-event spike as a trend.
    segment_scores: list[float] = []
    segment_count = min(5, len(events) // SEGMENT_SIZE)
    for segment_index in range(segment_count - 1):
        end = len(events) - segment_index * SEGMENT_SIZE
        recent = events[end - SEGMENT_SIZE:end]
        baseline = events[end - 2 * SEGMENT_SIZE:end - SEGMENT_SIZE]
        raw_score, _ = calculator(recent, baseline, profile) if name in {
            "resource_expansion", "behavioral_deviation_accumulation",
            "session_duration_deviation",
        } else calculator(recent, baseline)
        segment_scores.append(raw_score)
    segment_scores.reverse()
    segment_persistence = (
        sum(score >= 0.25 for score in segment_scores) / len(segment_scores)
        if segment_scores else 0.0
    )
    trend = 0.0
    if len(segment_scores) >= 3:
        trend = _clamp((segment_scores[-1] - mean(segment_scores[:-1])) / 0.35)

    final_score = _clamp(
        0.50 * weighted_recent
        + 0.25 * persistence
        + 0.15 * segment_persistence
        + 0.10 * trend
    )
    return {
        "score": round(final_score, 4),
        "weighted_points": round(final_score * SIGNAL_WEIGHTS[name], 2),
        "window_scores": window_scores,
        "window_details": window_details,
        "persistent_windows": persistent_windows,
        "available_windows": len(available_scores),
        "segment_scores": [round(score, 4) for score in segment_scores],
        "segment_persistence": round(segment_persistence, 4),
        "trend": round(trend, 4),
        "triggered": final_score >= 0.25,
    }


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
    history_event_count = len(events)
    profile = json.loads(identity["profile"])
    if history_event_count < MINIMUM_HISTORY_EVENTS:
        return {
            "entity_id": entity_id,
            "baseline_status": baseline_status(history_event_count),
            "history_event_count": history_event_count,
            "minimum_history_events": MINIMUM_HISTORY_EVENTS,
            "temporal_drift_score": 0,
            "temporal_status": "Stable",
            "temporal_reasons": [],
            "temporal_signals": {},
            "temporal_scoring_reliable": False,
            "recent_event_count": history_event_count,
            "historical_event_count": 0,
            "rolling_window_sizes": list(ROLLING_WINDOW_SIZES),
        }

    signals = {
        name: _rolling_signal(events, profile, name)
        for name in SIGNAL_CALCULATORS
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
        "baseline_status": baseline_status(history_event_count),
        "history_event_count": history_event_count,
        "minimum_history_events": MINIMUM_HISTORY_EVENTS,
        "temporal_drift_score": score,
        "temporal_status": _status(score),
        "temporal_reasons": reasons,
        "temporal_signals": signals,
        "temporal_scoring_reliable": True,
        "recent_event_count": min(len(events), max(ROLLING_WINDOW_SIZES)),
        "historical_event_count": max(0, len(events) - max(ROLLING_WINDOW_SIZES)),
        "rolling_window_sizes": list(ROLLING_WINDOW_SIZES),
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