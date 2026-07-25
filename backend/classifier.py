"""
SentinelDNA — Step 6: Anomaly-Type Classifier

ABSOLUTE RULE: Ground-truth labels are NEVER used as inputs to classification,
scoring, or feature engineering.  They are consulted ONLY in evaluate_classifier()
for post-hoc accuracy metrics.

Classification uses deterministic evidence-based rules on behavioral features
already produced by Steps 2-3 (no new data collection required).

Target types
------------
  brute_force           — bot-speed repeated auth failures, single target
  credential_stuffing   — high failure rate from foreign IP/location, many targets
  impossible_travel     — successful auth from geographically impossible location
  lateral_movement      — unfamiliar resource access, normal device & location
  device_spoofing       — unknown device fingerprint, successful auth, normal context
  low_slow_exfiltration — off-hours successful access to unfamiliar resources
  insider_drift         — gradual temporal/resource behavioural shift, insider context
  unknown_anomaly       — insufficient evidence to assign a specific type
"""

from __future__ import annotations

import json
from typing import Any

import numpy as np
import pandas as pd

# ─── Tuning constants ─────────────────────────────────────────────────────────
# Minimum raw score for the winning type.  Below → unknown_anomaly.
MIN_WINNING_RAW: float = 0.30
# Minimum relative share of total score pool.  Below → unknown_anomaly.
MIN_CONFIDENCE_SHARE: float = 0.25

KNOWN_TYPES = [
    "brute_force",
    "credential_stuffing",
    "impossible_travel",
    "lateral_movement",
    "device_spoofing",
    "low_slow_exfiltration",
    "insider_drift",
]

ALL_TYPES = KNOWN_TYPES + ["unknown_anomaly"]


# ─── Per-type scoring functions ───────────────────────────────────────────────
# Each returns (raw_score: float, reasons: list[str]).
#
# Input: a feature dict produced by _engineer_features() — the 'label' key is
# present in the dict but is NEVER READ by any function in this module.
# Label independence is guaranteed by construction: no code path accesses it.

def _score_brute_force(row: dict) -> tuple[float, list[str]]:
    """High repeated auth failures, bot-speed short sessions, unfamiliar IP."""
    s, r = 0.0, []

    if row.get("auth_failed", 0):
        s += 0.35
        r.append("Authentication failed")

    fail_rate = float(row.get("recent_failure_rate", 0.0))
    if fail_rate > 0.60:
        s += 0.40
        r.append(f"Very high auth failure rate ({fail_rate:.0%})")
    elif fail_rate > 0.30:
        s += 0.20
        r.append(f"Elevated auth failure rate ({fail_rate:.0%})")

    dur = float(row.get("session_duration", 9_999.0))
    if dur < 10.0:
        s += 0.30
        r.append("Sub-10 s session (bot-speed attempt)")
    elif dur < 60.0:
        s += 0.10
        r.append("Unusually short session duration")

    if row.get("ip_unfamiliar", 0):
        s += 0.10
        r.append("Unfamiliar source IP")

    # Discount: foreign location shifts hypothesis to credential_stuffing
    if row.get("location_unfamiliar", 0):
        s -= 0.20

    return max(0.0, s), r


def _score_credential_stuffing(row: dict) -> tuple[float, list[str]]:
    """Auth failures from foreign IP/location — attack targets many identities."""
    s, r = 0.0, []

    if row.get("auth_failed", 0):
        s += 0.25
        r.append("Authentication failed")

    if row.get("location_unfamiliar", 0):
        s += 0.30
        r.append("Authentication from unfamiliar/foreign location")

    if row.get("ip_unfamiliar", 0):
        s += 0.25
        r.append("Unfamiliar source IP subnet")

    fail_rate = float(row.get("recent_failure_rate", 0.0))
    if fail_rate > 0.60:
        s += 0.30
        r.append(f"Very high auth failure rate ({fail_rate:.0%})")
    elif fail_rate > 0.30:
        s += 0.15
        r.append(f"Elevated auth failure rate ({fail_rate:.0%})")

    dur = float(row.get("session_duration", 9_999.0))
    if dur < 10.0:
        s += 0.15
        r.append("Short session duration")

    # Successful foreign auth is more likely impossible_travel
    if not row.get("auth_failed", 0):
        s -= 0.20

    return max(0.0, s), r


def _score_impossible_travel(row: dict) -> tuple[float, list[str]]:
    """Successful auth from a geographically implausible location."""
    s, r = 0.0, []

    if row.get("location_unfamiliar", 0):
        s += 0.45
        r.append("Authentication from unusual geographic location")

    if row.get("ip_unfamiliar", 0):
        s += 0.25
        r.append("Unfamiliar IP subnet (consistent with foreign origin)")

    if not row.get("auth_failed", 0):
        s += 0.25
        r.append("Successful authentication from unusual location")
    else:
        s -= 0.15  # failed foreign auth → credential_stuffing is more likely

    # Impossible_travel events re-use the identity's own device (credential reuse)
    if row.get("device_unknown", 0):
        s -= 0.10  # unknown device weakens impossible-travel hypothesis

    return max(0.0, s), r


def _score_lateral_movement(row: dict) -> tuple[float, list[str]]:
    """Post-compromise pivot: unfamiliar resource, normal device & location."""
    s, r = 0.0, []

    if row.get("resource_unfamiliar", 0):
        s += 0.45
        r.append("Access to resource outside established profile")

    if not row.get("auth_failed", 0):
        s += 0.15
        r.append("Successful authentication (attacker has valid credentials)")
    else:
        s -= 0.25  # lateral movement requires a working session

    if not row.get("device_unknown", 0):
        s += 0.10
        r.append("Familiar device (post-compromise session)")
    if not row.get("location_unfamiliar", 0):
        s += 0.10
        r.append("Normal geographic location (internal pivot)")
    if not row.get("ip_unfamiliar", 0):
        s += 0.05
        r.append("Familiar IP subnet")

    # Off-hours resource pivot shifts toward low_slow_exfiltration
    if row.get("is_outside_normal_hours", 0):
        s -= 0.10
    if row.get("location_unfamiliar", 0):
        s -= 0.15

    return max(0.0, s), r


def _score_device_spoofing(row: dict) -> tuple[float, list[str]]:
    """Unknown device fingerprint with successful auth in a normal context."""
    s, r = 0.0, []

    if row.get("device_unknown", 0):
        s += 0.55
        r.append("Unrecognised device fingerprint")

    if not row.get("auth_failed", 0):
        s += 0.20
        r.append("Successful authentication with unknown device")
    else:
        s -= 0.30  # unknown device + failure → more like brute_force

    if not row.get("location_unfamiliar", 0):
        s += 0.10
        r.append("Normal geographic location")
    if not row.get("ip_unfamiliar", 0):
        s += 0.10
        r.append("Familiar IP subnet (internal context)")

    # Foreign location + unknown device → shifts toward impossible_travel
    if row.get("location_unfamiliar", 0):
        s -= 0.20

    return max(0.0, s), r


def _score_low_slow_exfiltration(row: dict) -> tuple[float, list[str]]:
    """Off-hours successful access to unfamiliar resources — slow data extraction."""
    s, r = 0.0, []

    if row.get("is_outside_normal_hours", 0):
        s += 0.35
        r.append("Access outside normal working hours")

    if row.get("resource_unfamiliar", 0):
        s += 0.30
        r.append("Unfamiliar resource accessed (scope expansion)")

    if not row.get("auth_failed", 0):
        s += 0.15
        r.append("Successful authentication (insider has valid credentials)")
    else:
        s -= 0.25

    zscore = float(row.get("session_zscore", 0.0))
    if zscore > 2.0:
        s += 0.15
        r.append("Abnormally long session duration")

    # Insider pattern: known device and normal location
    if not row.get("device_unknown", 0) and not row.get("location_unfamiliar", 0):
        s += 0.10
        r.append("Familiar device and location (insider pattern)")

    return max(0.0, s), r


def _score_insider_drift(row: dict) -> tuple[float, list[str]]:
    """Gradual behavioural shift: slightly off-hours, mild resource drift, insider context."""
    s, r = 0.0, []

    if row.get("is_outside_normal_hours", 0):
        s += 0.30
        r.append("Access outside established working hours (temporal drift)")

    if not row.get("auth_failed", 0):
        s += 0.15
        r.append("Successful authentication")
    else:
        s -= 0.20

    if not row.get("device_unknown", 0):
        s += 0.15
        r.append("Familiar device (insider pattern)")
    else:
        s -= 0.10

    if not row.get("location_unfamiliar", 0):
        s += 0.10
        r.append("Local access (no geographic anomaly)")
    else:
        s -= 0.15

    if row.get("resource_unfamiliar", 0):
        s += 0.20
        r.append("Resource access shifting outside established scope")

    zscore = float(row.get("session_zscore", 0.0))
    if 1.0 < zscore <= 2.5:
        s += 0.10
        r.append("Moderately elevated session duration")

    return max(0.0, s), r


# ─── Scorer registry ──────────────────────────────────────────────────────────

_SCORERS: dict[str, Any] = {
    "brute_force":           _score_brute_force,
    "credential_stuffing":   _score_credential_stuffing,
    "impossible_travel":     _score_impossible_travel,
    "lateral_movement":      _score_lateral_movement,
    "device_spoofing":       _score_device_spoofing,
    "low_slow_exfiltration": _score_low_slow_exfiltration,
    "insider_drift":         _score_insider_drift,
}


# ─── Single-event classification ──────────────────────────────────────────────

def classify_event(row: dict) -> dict:
    """
    Classify a single event into an anomaly type.

    Parameters
    ----------
    row : dict
        Feature values from _engineer_features().  The 'label' key may be
        present but is NEVER READ — label independence is guaranteed by
        construction (no code path accesses row['label']).

    Returns
    -------
    dict with:
        predicted_anomaly_type    : str
        classification_confidence : float  (0.0–1.0)
        classification_reasons    : list[str]
    """
    raw_scores: dict[str, float] = {}
    reason_map: dict[str, list]  = {}

    for t, fn in _SCORERS.items():
        sc, rs = fn(row)
        raw_scores[t] = sc
        reason_map[t] = rs

    total     = sum(raw_scores.values())
    best_type = max(raw_scores, key=lambda k: raw_scores[k])
    best_raw  = raw_scores[best_type]

    confidence = (best_raw / total) if total > 0.0 else 0.0

    if best_raw < MIN_WINNING_RAW or confidence < MIN_CONFIDENCE_SHARE:
        return {
            "predicted_anomaly_type":    "unknown_anomaly",
            "classification_confidence": round(confidence, 3),
            "classification_reasons":    [
                "Insufficient evidence to assign a specific anomaly type"
            ],
        }

    return {
        "predicted_anomaly_type":    best_type,
        "classification_confidence": round(min(confidence, 1.0), 3),
        "classification_reasons":    reason_map[best_type],
    }


# ─── Batch classification ──────────────────────────────────────────────────────

def classify_all(scored_df: pd.DataFrame) -> pd.DataFrame:
    """
    Classify every event in scored_df and append three new columns.

    Only events with predicted_anomaly=1 OR risk_score ≥ 45 (Medium+) are
    actively classified; all others receive 'normal_activity' with no confidence.

    ABSOLUTE RULE: row['label'] is present in scored_df but is NEVER READ
    here or by classify_event().
    """
    types: list[str]         = []
    confidences: list        = []
    reasons_json: list[str]  = []

    for _, row in scored_df.iterrows():
        row_d     = row.to_dict()
        flagged   = bool(row_d.get("predicted_anomaly", 0)) or int(row_d.get("risk_score", 0)) >= 45

        if flagged:
            result = classify_event(row_d)
            types.append(result["predicted_anomaly_type"])
            confidences.append(result["classification_confidence"])
            reasons_json.append(json.dumps(result["classification_reasons"]))
        else:
            types.append("normal_activity")
            confidences.append(None)
            reasons_json.append(json.dumps([]))

    out = scored_df.copy()
    out["predicted_anomaly_type"]    = types
    out["classification_confidence"] = confidences
    out["classification_reasons"]    = reasons_json
    return out


# ─── Label-independence test ───────────────────────────────────────────────────

def run_classifier_leakage_test(scored_df: pd.DataFrame) -> bool:
    """
    Prove that shuffling ground-truth labels has zero effect on classification.

    Procedure
    ---------
    1. Draw a reproducible sample.
    2. Classify it → record predicted_anomaly_type and classification_confidence.
    3. Shuffle the 'label' column in the sample (labels never enter the classifier).
    4. Classify the identical feature data again.
    5. Verify all outputs are bit-for-bit identical.

    Returns True only if the test genuinely passes.
    """
    try:
        rng    = np.random.default_rng(seed=99)
        sample = scored_df.sample(min(300, len(scored_df)), random_state=42)

        def _run(df: pd.DataFrame) -> list[dict]:
            out = []
            for _, row in df.iterrows():
                row_d   = row.to_dict()
                flagged = (
                    bool(row_d.get("predicted_anomaly", 0))
                    or int(row_d.get("risk_score", 0)) >= 45
                )
                if flagged:
                    out.append(classify_event(row_d))
                else:
                    out.append({
                        "predicted_anomaly_type":    "normal_activity",
                        "classification_confidence": None,
                        "classification_reasons":    [],
                    })
            return out

        original = _run(sample)

        shuffled          = sample.copy()
        shuffled["label"] = rng.permutation(shuffled["label"].values)
        after             = _run(shuffled)

        return original == after

    except Exception as exc:
        print(f"Classifier label-independence test error: {exc}")
        return False


# ─── Post-hoc evaluation (labels used ONLY here) ──────────────────────────────

def evaluate_classifier(classified_df: pd.DataFrame) -> dict:
    """
    Measure classification accuracy against ground-truth labels.

    Labels are used ONLY in this function — never during classification.

    Scope: true anomalous events (label != 'normal').
    Returns a dict suitable for JSON serialisation and API exposure.
    """
    anomalous = classified_df[classified_df["label"] != "normal"].copy()
    if anomalous.empty:
        return {"error": "No anomalous events found for evaluation"}

    total_anomalous = len(anomalous)
    pred_types  = anomalous["predicted_anomaly_type"].tolist()
    true_types  = anomalous["label"].tolist()

    # Unknown rate: fraction of true anomalies typed as unknown
    unknown_count = sum(1 for t in pred_types if t == "unknown_anomaly")
    unknown_rate  = round(unknown_count / total_anomalous, 4)

    # Overall accuracy: exact match across all anomalous events
    exact = sum(1 for p, t in zip(pred_types, true_types) if p == t)
    overall_accuracy = round(exact / total_anomalous, 4)

    # Per-type precision / recall / F1
    all_attack_types = sorted(
        set(true_types) | (set(pred_types) - {"unknown_anomaly", "normal_activity"})
    )
    per_type: dict[str, dict] = {}
    for at in all_attack_types:
        tp = sum(1 for p, t in zip(pred_types, true_types) if p == at and t == at)
        fp = sum(1 for p, t in zip(pred_types, true_types) if p == at and t != at)
        fn = sum(1 for p, t in zip(pred_types, true_types) if p != at and t == at)
        prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        rec  = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1   = round(2 * prec * rec / (prec + rec), 4) if (prec + rec) > 0 else 0.0
        per_type[at] = {
            "precision":       prec,
            "recall":          rec,
            "f1_score":        f1,
            "true_positives":  tp,
            "false_positives": fp,
            "false_negatives": fn,
            "support":         tp + fn,
        }

    # Confusion matrix  (true_type rows → predicted_type cols)
    col_types = all_attack_types + ["unknown_anomaly"]
    confusion: dict[str, dict[str, int]] = {}
    for tt in all_attack_types:
        confusion[tt] = {
            pt: sum(1 for p, t in zip(pred_types, true_types) if t == tt and p == pt)
            for pt in col_types
        }

    # Top-1% classification accuracy
    top1_acc: float | None = None
    if "risk_score" in classified_df.columns:
        n_total   = len(classified_df)
        n_top1    = max(1, int(round(n_total * 0.01)))
        top1_df   = classified_df.nlargest(n_top1, "risk_score")
        top1_anom = top1_df[top1_df["label"] != "normal"]
        if len(top1_anom) > 0:
            correct  = sum(
                1 for _, r in top1_anom.iterrows()
                if r["predicted_anomaly_type"] == r["label"]
            )
            top1_acc = round(correct / len(top1_anom), 4)

    return {
        "total_anomalous_events":           total_anomalous,
        "overall_accuracy":                 overall_accuracy,
        "unknown_rate":                     unknown_rate,
        "per_type":                         per_type,
        "confusion_matrix":                 confusion,
        "top1_pct_classification_accuracy": top1_acc,
        "note": (
            "Labels used ONLY for post-hoc evaluation. "
            "Classification never reads ground-truth labels."
        ),
    }
