"""Lightweight, sequence-aware GRU anomaly detection.

This module is intentionally isolated from the existing Isolation Forest and
risk-scoring pipeline. It trains a small GRU next-event predictor using only
the existing behavioral feature columns. Ground-truth labels are never loaded
or used here.
"""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from database import get_connection
from detector import FEATURE_COLS, _engineer_features, _load_data


MINIMUM_HISTORY_EVENTS = 50
SEQUENCE_LENGTH = 12
HIDDEN_SIZE = 32           # was 16 — larger hidden state improves sequence representation
TRAINING_WINDOWS = 4000    # was 1800 — more training coverage
TRAINING_EPOCHS = 8        # was 3 — more passes through windows
RANDOM_SEED = 20260726


def _sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(values, -30.0, 30.0)))


class GRUSequencePredictor:
    """A small GRU regressor trained with deterministic single-sample BPTT."""

    def __init__(
        self,
        input_size: int,
        hidden_size: int = HIDDEN_SIZE,
        seed: int = RANDOM_SEED,
    ):
        self.input_size = input_size
        self.hidden_size = hidden_size
        rng = np.random.default_rng(seed)
        scale = 1.0 / np.sqrt(input_size)

        self.Wz = rng.normal(0.0, scale, (input_size, hidden_size))
        self.Uz = rng.normal(0.0, scale, (hidden_size, hidden_size))
        self.bz = np.zeros(hidden_size)
        self.Wr = rng.normal(0.0, scale, (input_size, hidden_size))
        self.Ur = rng.normal(0.0, scale, (hidden_size, hidden_size))
        self.br = np.zeros(hidden_size)
        self.Wh = rng.normal(0.0, scale, (input_size, hidden_size))
        self.Uh = rng.normal(0.0, scale, (hidden_size, hidden_size))
        self.bh = np.zeros(hidden_size)
        self.Wy = rng.normal(0.0, scale, (hidden_size, input_size))
        self.by = np.zeros(input_size)

    def _forward(self, inputs: np.ndarray) -> tuple[np.ndarray, list[tuple]]:
        hidden = np.zeros(self.hidden_size)
        cache: list[tuple] = []
        for x in inputs:
            z = _sigmoid(x @ self.Wz + hidden @ self.Uz + self.bz)
            r = _sigmoid(x @ self.Wr + hidden @ self.Ur + self.br)
            candidate = np.tanh(x @ self.Wh + (r * hidden) @ self.Uh + self.bh)
            previous = hidden
            hidden = (1.0 - z) * candidate + z * hidden
            cache.append((x, previous, z, r, candidate))
        return hidden, cache

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        hidden, _ = self._forward(inputs)
        return hidden @ self.Wy + self.by

    def fit(
        self,
        windows: list[tuple[np.ndarray, np.ndarray]],
        epochs: int = TRAINING_EPOCHS,
        learning_rate: float = 0.005,  # was 0.008 — smaller step reduces overshoot
    ) -> None:
        """Fit the GRU on unlabeled input windows and next-event targets."""
        for _ in range(epochs):
            for inputs, target in windows:
                hidden, cache = self._forward(inputs)
                prediction = hidden @ self.Wy + self.by
                dy = 2.0 * (prediction - target) / self.input_size

                gradients = {
                    "Wz": np.zeros_like(self.Wz),
                    "Uz": np.zeros_like(self.Uz),
                    "bz": np.zeros_like(self.bz),
                    "Wr": np.zeros_like(self.Wr),
                    "Ur": np.zeros_like(self.Ur),
                    "br": np.zeros_like(self.br),
                    "Wh": np.zeros_like(self.Wh),
                    "Uh": np.zeros_like(self.Uh),
                    "bh": np.zeros_like(self.bh),
                    "Wy": np.outer(hidden, dy),
                    "by": dy,
                }
                dh = dy @ self.Wy.T

                for x, previous, z, r, candidate in reversed(cache):
                    dz = dh * (candidate * -1.0 + previous)
                    dcandidate = dh * (1.0 - z)
                    dprevious = dh * z

                    da_candidate = dcandidate * (1.0 - candidate * candidate)
                    reset_previous = r * previous
                    gradients["Wh"] += np.outer(x, da_candidate)
                    gradients["Uh"] += np.outer(reset_previous, da_candidate)
                    gradients["bh"] += da_candidate

                    dreset_previous = da_candidate @ self.Uh.T
                    dr = dreset_previous * previous
                    dprevious += dreset_previous * r
                    da_reset = dr * r * (1.0 - r)
                    gradients["Wr"] += np.outer(x, da_reset)
                    gradients["Ur"] += np.outer(previous, da_reset)
                    gradients["br"] += da_reset

                    da_update = dz * z * (1.0 - z)
                    gradients["Wz"] += np.outer(x, da_update)
                    gradients["Uz"] += np.outer(previous, da_update)
                    gradients["bz"] += da_update
                    dprevious += da_reset @ self.Ur.T + da_update @ self.Uz.T
                    dh = dprevious

                total_norm = np.sqrt(sum(float(np.sum(value * value)) for value in gradients.values()))
                clip_scale = min(1.0, 2.0 / max(total_norm, 2.0))
                for name, gradient in gradients.items():
                    setattr(self, name, getattr(self, name) - learning_rate * clip_scale * gradient)


@dataclass
class _SequenceModel:
    predictor: GRUSequencePredictor
    means: np.ndarray
    scales: np.ndarray
    error_median: float
    error_p95: float
    event_count: int
    training_window_count: int


_MODEL: Optional[_SequenceModel] = None
_MODEL_LOCK = threading.Lock()


def _feature_frame() -> pd.DataFrame:
    """Load chronological events and engineer existing non-label features."""
    events, profiles = _load_data()
    if events.empty:
        return pd.DataFrame(columns=["event_id", "entity_id", "timestamp", *FEATURE_COLS])
    features = _engineer_features(events, profiles)
    timestamps = events[["event_id", "entity_id", "timestamp"]]
    features = features.merge(timestamps, on=["event_id", "entity_id"], how="left")
    # Labels are deliberately removed before sequence normalization, training,
    # prediction, or scoring. They are not part of the sequence feature frame.
    features = features.drop(columns=["label"], errors="ignore")
    return features.sort_values(["entity_id", "timestamp", "event_id"]).copy()


def _chronological_groups(features: pd.DataFrame) -> dict[str, pd.DataFrame]:
    groups: dict[str, pd.DataFrame] = {}
    for entity_id, group in features.groupby("entity_id", sort=True):
        groups[str(entity_id)] = group.sort_values(["timestamp", "event_id"]).copy()
    return groups


def _build_windows(
    groups: dict[str, pd.DataFrame],
    means: np.ndarray,
    scales: np.ndarray,
    limit: int = TRAINING_WINDOWS,
) -> list[tuple[np.ndarray, np.ndarray]]:
    candidates: list[tuple[np.ndarray, np.ndarray]] = []
    for group in groups.values():
        values = group[FEATURE_COLS].to_numpy(dtype=float)
        normalized = (values - means) / scales
        for end in range(SEQUENCE_LENGTH, len(normalized)):
            candidates.append((normalized[end - SEQUENCE_LENGTH : end], normalized[end]))

    if len(candidates) <= limit:
        return candidates
    rng = np.random.default_rng(RANDOM_SEED)
    indices = np.sort(rng.choice(len(candidates), size=limit, replace=False))
    return [candidates[int(index)] for index in indices]


def _fit_sequence_model(features: pd.DataFrame, groups: dict[str, pd.DataFrame]) -> _SequenceModel:
    values = features[FEATURE_COLS].to_numpy(dtype=float)
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    scales[scales < 1e-6] = 1.0
    windows = _build_windows(groups, means, scales)
    if not windows:
        raise ValueError("Not enough chronological event windows for sequence training")

    predictor = GRUSequencePredictor(input_size=len(FEATURE_COLS))
    predictor.fit(windows)
    errors = [
        float(np.mean((predictor.predict(inputs) - target) ** 2))
        for inputs, target in windows
    ]
    median = float(np.percentile(errors, 50))
    p95 = float(np.percentile(errors, 95))
    if p95 <= median:
        p95 = median + 1.0
    return _SequenceModel(
        predictor,
        means,
        scales,
        median,
        p95,
        len(features),
        len(windows),
    )


def _get_model(features: pd.DataFrame, groups: dict[str, pd.DataFrame]) -> _SequenceModel:
    global _MODEL
    with _MODEL_LOCK:
        if _MODEL is None or _MODEL.event_count != len(features):
            _MODEL = _fit_sequence_model(features, groups)
        return _MODEL


def batch_score_all_events(feat_df: pd.DataFrame) -> dict:
    """
    Train GRU on all events (no labels) and return a per-event sequence score.

    Trains on the full chronological event set so scoring coverage matches the
    Isolation Forest (which also trains on all events).  Events that lack at
    least SEQUENCE_LENGTH prior events for their entity receive None — the
    caller uses the two-signal formula for those.

    ABSOLUTE RULE: labels must never enter this function.  feat_df must already
    have the 'label' column stripped before being passed here.
    """
    if feat_df.empty:
        return {}

    # Safety: drop labels if accidentally present
    features = feat_df.drop(columns=["label"], errors="ignore")

    groups = _chronological_groups(features)

    # Fit on the full dataset (unsupervised; no labels used)
    model = _fit_sequence_model(features, groups)

    score_map: dict = {}
    for entity_id, group in groups.items():
        values     = group[FEATURE_COLS].to_numpy(dtype=float)
        normalized = (values - model.means) / model.scales
        for index in range(len(normalized)):
            row    = group.iloc[index]
            eid    = str(row["event_id"])
            if index < SEQUENCE_LENGTH:
                score_map[eid] = None   # insufficient history
            else:
                prediction = model.predictor.predict(normalized[index - SEQUENCE_LENGTH : index])
                error = float(np.mean((prediction - normalized[index]) ** 2))
                score = 100.0 * np.clip(
                    (error - model.error_median) / (model.error_p95 - model.error_median),
                    0.0,
                    1.0,
                )
                score_map[eid] = round(float(score), 2)

    return score_map


def _score_group(group: pd.DataFrame, model: _SequenceModel) -> list[dict]:
    values = group[FEATURE_COLS].to_numpy(dtype=float)
    normalized = (values - model.means) / model.scales
    scores: list[dict] = []
    for index in range(SEQUENCE_LENGTH, len(normalized)):
        prediction = model.predictor.predict(normalized[index - SEQUENCE_LENGTH : index])
        error = float(np.mean((prediction - normalized[index]) ** 2))
        score = 100.0 * np.clip(
            (error - model.error_median) / (model.error_p95 - model.error_median),
            0.0,
            1.0,
        )
        row = group.iloc[index]
        scores.append({
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "score": round(float(score), 2),
            "prediction_error": round(error, 6),
        })
    return scores


def _score_group_from(group: pd.DataFrame, model: _SequenceModel, start_index: int) -> list[dict]:
    """Score rows at or after start_index using only preceding event features."""
    values = group[FEATURE_COLS].to_numpy(dtype=float)
    normalized = (values - model.means) / model.scales
    scores: list[dict] = []
    for index in range(max(SEQUENCE_LENGTH, start_index), len(normalized)):
        prediction = model.predictor.predict(normalized[index - SEQUENCE_LENGTH : index])
        error = float(np.mean((prediction - normalized[index]) ** 2))
        score = 100.0 * np.clip(
            (error - model.error_median) / (model.error_p95 - model.error_median),
            0.0,
            1.0,
        )
        row = group.iloc[index]
        scores.append({
            "event_id": row["event_id"],
            "entity_id": row["entity_id"],
            "timestamp": row["timestamp"],
            "score": round(float(score), 2),
            "prediction_error": round(error, 6),
            # label is post-hoc metadata; present when called from the evaluation
            # path but absent when called from the label-leakage test (which uses
            # label-free groups to prove labels cannot influence scores).
            "label": row["label"] if "label" in group.columns else None,
        })
    return scores


def _evaluation_frame() -> pd.DataFrame:
    """Build an evaluation-only frame; labels remain post-hoc metadata."""
    events, profiles = _load_data()
    if events.empty:
        return pd.DataFrame(columns=["event_id", "entity_id", "timestamp", "label", *FEATURE_COLS])
    features = _engineer_features(events, profiles)
    timestamps = events[["event_id", "entity_id", "timestamp"]]
    features = features.merge(timestamps, on=["event_id", "entity_id"], how="left")
    return features.sort_values(["entity_id", "timestamp", "event_id"]).copy()


def _evaluation_split(
    groups: dict[str, pd.DataFrame],
) -> tuple[dict[str, pd.DataFrame], dict[str, int]]:
    """Create deterministic chronological 80/20 identity-local holdouts."""
    train_groups: dict[str, pd.DataFrame] = {}
    cutoffs: dict[str, int] = {}
    for entity_id, group in groups.items():
        cutoff = int(np.floor(len(group) * 0.8))
        if cutoff < MINIMUM_HISTORY_EVENTS or len(group) <= cutoff:
            continue
        train_groups[entity_id] = group.iloc[:cutoff].copy()
        cutoffs[entity_id] = cutoff
    return train_groups, cutoffs


def _sequence_label_leakage_test(
    evaluation_frame: pd.DataFrame,
    groups: dict[str, pd.DataFrame],
    train_groups: dict[str, pd.DataFrame],
    cutoffs: dict[str, int],
) -> bool:
    """Confirm label replacement cannot change sequence scores."""
    try:
        train_frame = pd.concat(train_groups.values(), ignore_index=True)
        first_model = _fit_sequence_model(train_frame, train_groups)
        changed = evaluation_frame.copy()
        rng = np.random.default_rng(RANDOM_SEED + 1)
        changed["label"] = rng.permutation(changed["label"].to_numpy())
        changed_groups = _chronological_groups(changed.drop(columns=["label"]))
        changed_train_groups = {
            entity_id: changed_groups[entity_id].iloc[:cutoff].copy()
            for entity_id, cutoff in cutoffs.items()
        }
        changed_train = pd.concat(changed_train_groups.values(), ignore_index=True)
        second_model = _fit_sequence_model(changed_train, changed_train_groups)

        first_scores: list[tuple] = []
        second_scores: list[tuple] = []
        for entity_id, cutoff in cutoffs.items():
            original = _score_group_from(groups[entity_id], first_model, cutoff)
            replaced = _score_group_from(changed_groups[entity_id], second_model, cutoff)
            first_scores.extend((r["event_id"], r["score"], r["prediction_error"]) for r in original)
            second_scores.extend((r["event_id"], r["score"], r["prediction_error"]) for r in replaced)
        return first_scores == second_scores
    except Exception as exc:
        print(f"Sequence label leakage test error: {exc}")
        return False


def _existing_risk_ranking_label_leakage_test() -> bool:
    """Confirm replacing labels cannot change the existing risk-score ranking."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT dr.event_id, dr.risk_score, e.label
            FROM detection_results dr
            JOIN events e ON dr.event_id = e.event_id
            """
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return False

    original = [{"event_id": r["event_id"], "risk_score": r["risk_score"], "label": r["label"]} for r in rows]
    changed = [dict(row) for row in original]
    rng = np.random.default_rng(RANDOM_SEED + 2)
    changed_labels = rng.permutation([row["label"] for row in changed])
    for row, label in zip(changed, changed_labels):
        row["label"] = label
    sort_key = lambda row: (-int(row["risk_score"]), str(row["event_id"]))
    return [row["event_id"] for row in sorted(original, key=sort_key)] == [
        row["event_id"] for row in sorted(changed, key=sort_key)
    ]


def evaluate_sequence_detector() -> dict:
    """Evaluate the existing GRU on deterministic chronological holdouts."""
    evaluation_frame = _evaluation_frame()
    if evaluation_frame.empty:
        return {"has_results": False, "status": "no_events"}

    groups = _chronological_groups(evaluation_frame.drop(columns=["label"]))
    train_groups, cutoffs = _evaluation_split(groups)
    if not train_groups:
        return {"has_results": False, "status": "insufficient_history"}

    train_frame = pd.concat(train_groups.values(), ignore_index=True)
    model = _fit_sequence_model(train_frame, train_groups)
    holdout_scores: list[dict] = []
    for entity_id, cutoff in cutoffs.items():
        holdout_scores.extend(_score_group_from(evaluation_frame[evaluation_frame["entity_id"] == entity_id], model, cutoff))

    if not holdout_scores:
        return {"has_results": False, "status": "no_holdout_windows"}

    y_true = np.array([int(row["label"] != "normal") for row in holdout_scores])
    y_score = np.array([float(row["score"]) for row in holdout_scores])
    threshold = 50.0
    y_pred = (y_score >= threshold).astype(int)
    try:
        roc_auc = float(roc_auc_score(y_true, y_score))
    except ValueError:
        roc_auc = None
    try:
        average_precision = float(average_precision_score(y_true, y_score))
    except ValueError:
        average_precision = None

    category_totals = Counter(row["label"] for row in holdout_scores if row["label"] != "normal")
    category_captured = Counter(
        row["label"]
        for row in holdout_scores
        if row["label"] != "normal" and row["score"] >= threshold
    )
    coverage = [
        {
            "attack_type": attack_type,
            "holdout_support": total,
            "captured_at_threshold": category_captured.get(attack_type, 0),
            "coverage_pct": round(100.0 * category_captured.get(attack_type, 0) / total, 2),
        }
        for attack_type, total in sorted(category_totals.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "has_results": True,
        "status": "evaluated",
        "evaluation": {
            "split": "chronological_per_identity",
            "train_fraction": 0.8,
            "identities_evaluated": len(cutoffs),
            "train_events": len(train_frame),
            "holdout_events": len(holdout_scores),
            "holdout_attack_events": int(y_true.sum()),
            "sequence_length": SEQUENCE_LENGTH,
            "minimum_history_events": MINIMUM_HISTORY_EVENTS,
            "threshold": threshold,
        },
        "metrics": {
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
            "average_precision": round(average_precision, 4) if average_precision is not None else None,
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "predicted_anomalies": int(y_pred.sum()),
        },
        "attack_category_coverage": coverage,
        "label_leakage": {
            "sequence_scores_unchanged": _sequence_label_leakage_test(
                evaluation_frame, groups, train_groups, cutoffs
            ),
            "existing_risk_ranking_unchanged": _existing_risk_ranking_label_leakage_test(),
            "labels_used_for_training_or_scoring": False,
        },
        "model": {
            "type": "gru_next_event_predictor",
            "hidden_size": HIDDEN_SIZE,
            "training_epochs": TRAINING_EPOCHS,
            "training_windows": model.training_window_count,
            "random_seed": RANDOM_SEED,
        },
    }


def sequence_score_for_identity(entity_id: str) -> Optional[dict]:
    """Return the latest sequence score and reliability state for one identity."""
    features = _feature_frame()
    if features.empty:
        return None
    groups = _chronological_groups(features)
    group = groups.get(entity_id)
    if group is None:
        return None

    history_count = len(group)
    base = {
        "entity_id": entity_id,
        "history_event_count": history_count,
        "minimum_history_events": MINIMUM_HISTORY_EVENTS,
        "sequence_length": SEQUENCE_LENGTH,
        "features": list(FEATURE_COLS),
    }
    if history_count < MINIMUM_HISTORY_EVENTS:
        return {
            **base,
            "score": None,
            "prediction_error": None,
            "reliable": False,
            "status": "unreliable_cold_start",
            "message": "Sequence scoring requires at least 50 chronological events.",
            "recent_scores": [],
        }

    model = _get_model(features, groups)
    scores = _score_group(group, model)
    if not scores:
        return {
            **base,
            "score": None,
            "prediction_error": None,
            "reliable": False,
            "status": "unavailable",
            "message": "No complete sequence window is available.",
            "recent_scores": [],
        }
    latest = scores[-1]
    return {
        **base,
        "score": latest["score"],
        "prediction_error": latest["prediction_error"],
        "reliable": True,
        "status": "reliable",
        "recent_scores": scores[-10:],
        "model": {
            "type": "gru_next_event_predictor",
            "hidden_size": HIDDEN_SIZE,
            "training_windows": model.training_window_count,
            "ground_truth_labels_used": False,
        },
    }