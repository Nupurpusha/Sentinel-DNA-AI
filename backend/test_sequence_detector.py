"""Focused tests for the isolated sequence-aware GRU detector.

Tests are grouped into three layers:
  1. Unit tests for pure functions (no database required).
  2. Integration tests that exercise evaluate_sequence_detector() against the
     live SQLite database that ships with the repository.
  3. Label-leakage validation tests that confirm labels can never influence
     sequence scores or the existing Isolation Forest risk ranking.

Run with:
    cd backend && python -m unittest test_sequence_detector -v
"""

import sys
import os
import unittest
from collections import Counter

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from sequence_detector import (
    FEATURE_COLS,
    GRUSequencePredictor,
    MINIMUM_HISTORY_EVENTS,
    RANDOM_SEED,
    SEQUENCE_LENGTH,
    _chronological_groups,
    _evaluation_split,
    _fit_sequence_model,
    _score_group_from,
    _sequence_label_leakage_test,
    evaluate_sequence_detector,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _synthetic_group(
    entity_id: str,
    n: int,
    rng: np.random.Generator,
    label: str = "normal",
) -> pd.DataFrame:
    """Construct a minimal feature frame for one entity."""
    timestamps = pd.date_range("2025-01-01", periods=n, freq="h").astype(str)
    data = {
        "event_id": [f"{entity_id}_{i}" for i in range(n)],
        "entity_id": entity_id,
        "timestamp": timestamps,
        "label": label,
    }
    for col in FEATURE_COLS:
        data[col] = rng.uniform(0.0, 1.0, size=n)
    return pd.DataFrame(data)


def _synthetic_eval_frame(n_entities: int = 6, n_events: int = 120) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_SEED)
    groups = [_synthetic_group(f"e{i}", n_events, rng) for i in range(n_entities)]
    df = pd.concat(groups, ignore_index=True)
    return df.sort_values(["entity_id", "timestamp", "event_id"]).copy()


# ─── 1. Unit tests: pure functions, no database ───────────────────────────────

class TestGRUDeterminism(unittest.TestCase):
    """GRU weights and predictions must be identical across two same-seed runs."""

    def _make_windows(self):
        rng = np.random.default_rng(11)
        values = rng.normal(size=(SEQUENCE_LENGTH + 1, len(FEATURE_COLS)))
        return [(values[:SEQUENCE_LENGTH], values[SEQUENCE_LENGTH])]

    def test_weights_identical_after_fit(self):
        windows = self._make_windows()
        a = GRUSequencePredictor(len(FEATURE_COLS), seed=42)
        b = GRUSequencePredictor(len(FEATURE_COLS), seed=42)
        a.fit(windows, epochs=1)
        b.fit(windows, epochs=1)
        for name in ("Wz", "Uz", "bz", "Wr", "Ur", "br", "Wh", "Uh", "bh", "Wy", "by"):
            np.testing.assert_array_equal(
                getattr(a, name), getattr(b, name),
                err_msg=f"Weight matrix '{name}' differs between two same-seed runs.",
            )

    def test_prediction_identical_after_fit(self):
        windows = self._make_windows()
        x = windows[0][0]
        a = GRUSequencePredictor(len(FEATURE_COLS), seed=123)
        b = GRUSequencePredictor(len(FEATURE_COLS), seed=123)
        a.fit(windows, epochs=2)
        b.fit(windows, epochs=2)
        np.testing.assert_allclose(a.predict(x), b.predict(x))

    def test_different_seeds_produce_different_weights(self):
        windows = self._make_windows()
        a = GRUSequencePredictor(len(FEATURE_COLS), seed=1)
        b = GRUSequencePredictor(len(FEATURE_COLS), seed=2)
        # Before training the untrained weights must differ.
        any_different = any(
            not np.array_equal(getattr(a, n), getattr(b, n))
            for n in ("Wz", "Wr", "Wh")
        )
        self.assertTrue(any_different, "Different seeds should produce different weight matrices.")


class TestConstants(unittest.TestCase):
    """Invariant checks on module-level constants."""

    def test_cold_start_contract(self):
        self.assertEqual(MINIMUM_HISTORY_EVENTS, 50)

    def test_sequence_length_shorter_than_minimum_history(self):
        self.assertLess(SEQUENCE_LENGTH, MINIMUM_HISTORY_EVENTS)

    def test_feature_cols_non_empty(self):
        self.assertGreater(len(FEATURE_COLS), 0)

    def test_feature_cols_has_no_label(self):
        self.assertNotIn("label", FEATURE_COLS)


class TestChronologicalGroups(unittest.TestCase):
    """_chronological_groups must sort within each entity by (timestamp, event_id)."""

    def _shuffled_frame(self):
        rng = np.random.default_rng(0)
        frame = _synthetic_eval_frame(n_entities=3, n_events=20)
        return frame.sample(frac=1, random_state=0).reset_index(drop=True)

    def test_each_entity_appears_exactly_once(self):
        frame = _synthetic_eval_frame(n_entities=4, n_events=20)
        groups = _chronological_groups(frame)
        self.assertEqual(set(groups.keys()), {"e0", "e1", "e2", "e3"})

    def test_timestamps_non_decreasing_per_group(self):
        frame = self._shuffled_frame()
        groups = _chronological_groups(frame)
        for entity_id, group in groups.items():
            ts = group["timestamp"].tolist()
            self.assertEqual(
                ts, sorted(ts),
                msg=f"Entity {entity_id}: timestamps not in non-decreasing order.",
            )

    def test_all_events_preserved(self):
        frame = _synthetic_eval_frame(n_entities=3, n_events=30)
        groups = _chronological_groups(frame)
        total = sum(len(g) for g in groups.values())
        self.assertEqual(total, len(frame))


class TestEvaluationSplit(unittest.TestCase):
    """_evaluation_split must produce a deterministic chronological 80/20 split."""

    def _make_groups(self, n_events: int = 120) -> dict[str, pd.DataFrame]:
        frame = _synthetic_eval_frame(n_entities=4, n_events=n_events)
        return _chronological_groups(frame)

    def test_train_fraction_is_80_percent(self):
        groups = self._make_groups(120)
        train_groups, cutoffs = _evaluation_split(groups)
        for entity_id, cutoff in cutoffs.items():
            total = len(groups[entity_id])
            expected_cutoff = int(np.floor(total * 0.8))
            self.assertEqual(
                cutoff, expected_cutoff,
                msg=f"Entity {entity_id}: expected cutoff {expected_cutoff}, got {cutoff}.",
            )

    def test_train_rows_are_strictly_earlier(self):
        """The last training timestamp must be ≤ the first holdout timestamp."""
        groups = self._make_groups(120)
        train_groups, cutoffs = _evaluation_split(groups)
        for entity_id, cutoff in cutoffs.items():
            group = groups[entity_id]
            train_ts = group.iloc[: cutoff]["timestamp"].max()
            holdout_ts = group.iloc[cutoff:]["timestamp"].min()
            self.assertLessEqual(
                train_ts, holdout_ts,
                msg=f"Entity {entity_id}: training leaks into holdout window.",
            )

    def test_entities_below_minimum_history_excluded(self):
        """Entities with fewer events than MINIMUM_HISTORY_EVENTS must be skipped."""
        rng = np.random.default_rng(0)
        short = _synthetic_group("short", MINIMUM_HISTORY_EVENTS - 1, rng)
        long_ = _synthetic_group("long", MINIMUM_HISTORY_EVENTS * 2, rng)
        frame = pd.concat([short, long_], ignore_index=True)
        groups = _chronological_groups(frame)
        train_groups, cutoffs = _evaluation_split(groups)
        self.assertNotIn("short", cutoffs)
        self.assertIn("long", cutoffs)

    def test_deterministic_across_calls(self):
        """Two calls with identical input must produce identical cutoffs."""
        groups = self._make_groups(100)
        _, cutoffs_a = _evaluation_split(groups)
        _, cutoffs_b = _evaluation_split(groups)
        self.assertEqual(cutoffs_a, cutoffs_b)


class TestScoreGroupFrom(unittest.TestCase):
    """_score_group_from must score only holdout rows and handle missing labels."""

    def _make_model_and_group(self):
        rng = np.random.default_rng(RANDOM_SEED)
        frame = _synthetic_eval_frame(n_entities=1, n_events=200)
        groups = _chronological_groups(frame)
        train_groups, cutoffs = _evaluation_split(groups)
        entity_id = list(train_groups.keys())[0]
        train_frame = pd.concat(train_groups.values(), ignore_index=True)
        model = _fit_sequence_model(train_frame, train_groups)
        return model, groups[entity_id], cutoffs[entity_id]

    def test_scores_only_holdout_rows(self):
        model, group, cutoff = self._make_model_and_group()
        scores = _score_group_from(group, model, cutoff)
        # Every scored row must be at index ≥ max(SEQUENCE_LENGTH, cutoff).
        expected_count = len(group) - max(SEQUENCE_LENGTH, cutoff)
        self.assertEqual(len(scores), expected_count)

    def test_scores_in_range_0_to_100(self):
        model, group, cutoff = self._make_model_and_group()
        scores = _score_group_from(group, model, cutoff)
        for item in scores:
            self.assertGreaterEqual(item["score"], 0.0)
            self.assertLessEqual(item["score"], 100.0)

    def test_missing_label_does_not_crash(self):
        """Groups without a label column must not crash _score_group_from."""
        model, group, cutoff = self._make_model_and_group()
        group_no_label = group.drop(columns=["label"])
        scores = _score_group_from(group_no_label, model, cutoff)
        self.assertGreater(len(scores), 0)
        for item in scores:
            self.assertIsNone(item["label"])

    def test_scores_are_deterministic(self):
        model, group, cutoff = self._make_model_and_group()
        first = _score_group_from(group, model, cutoff)
        second = _score_group_from(group, model, cutoff)
        self.assertEqual(first, second)


# ─── 2. Integration: full evaluation pipeline against live database ───────────

class TestEvaluateSequenceDetector(unittest.TestCase):
    """Run evaluate_sequence_detector() and assert result structure and values."""

    @classmethod
    def setUpClass(cls):
        cls.result = evaluate_sequence_detector()

    def test_has_results(self):
        self.assertTrue(self.result.get("has_results"), self.result)

    def test_status_is_evaluated(self):
        self.assertEqual(self.result.get("status"), "evaluated")

    def test_evaluation_keys_present(self):
        required = {
            "split", "train_fraction", "identities_evaluated",
            "train_events", "holdout_events", "holdout_attack_events",
            "sequence_length", "minimum_history_events", "threshold",
        }
        self.assertTrue(required.issubset(self.result["evaluation"].keys()))

    def test_metrics_keys_present(self):
        required = {
            "roc_auc", "average_precision", "precision", "recall", "f1_score",
            "predicted_anomalies",
        }
        self.assertTrue(required.issubset(self.result["metrics"].keys()))

    def test_chronological_split_values(self):
        ev = self.result["evaluation"]
        self.assertEqual(ev["split"], "chronological_per_identity")
        self.assertAlmostEqual(ev["train_fraction"], 0.8)
        self.assertEqual(ev["sequence_length"], SEQUENCE_LENGTH)
        self.assertEqual(ev["minimum_history_events"], MINIMUM_HISTORY_EVENTS)

    def test_identities_evaluated_positive(self):
        self.assertGreater(self.result["evaluation"]["identities_evaluated"], 0)

    def test_holdout_events_smaller_than_train(self):
        ev = self.result["evaluation"]
        self.assertLess(ev["holdout_events"], ev["train_events"])

    # ── ROC-AUC / precision / recall / F1 ────────────────────────────────────

    def test_roc_auc_is_not_none(self):
        self.assertIsNotNone(self.result["metrics"]["roc_auc"])

    def test_roc_auc_above_random(self):
        """GRU must outperform random on the holdout — ROC-AUC > 0.5."""
        self.assertGreater(self.result["metrics"]["roc_auc"], 0.5)

    def test_precision_in_valid_range(self):
        p = self.result["metrics"]["precision"]
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)

    def test_recall_in_valid_range(self):
        r = self.result["metrics"]["recall"]
        self.assertGreaterEqual(r, 0.0)
        self.assertLessEqual(r, 1.0)

    def test_f1_in_valid_range(self):
        f = self.result["metrics"]["f1_score"]
        self.assertGreaterEqual(f, 0.0)
        self.assertLessEqual(f, 1.0)

    def test_f1_consistent_with_precision_recall(self):
        """F1 must equal the harmonic mean of precision and recall (±0.001)."""
        p = self.result["metrics"]["precision"]
        r = self.result["metrics"]["recall"]
        f = self.result["metrics"]["f1_score"]
        if p + r > 0:
            expected_f1 = 2 * p * r / (p + r)
            self.assertAlmostEqual(f, expected_f1, places=3)

    def test_predicted_anomalies_non_negative(self):
        self.assertGreaterEqual(self.result["metrics"]["predicted_anomalies"], 0)

    # ── Per-attack coverage ───────────────────────────────────────────────────

    def test_coverage_list_present(self):
        self.assertIn("attack_category_coverage", self.result)
        self.assertIsInstance(self.result["attack_category_coverage"], list)

    def test_coverage_items_have_required_keys(self):
        required = {"attack_type", "holdout_support", "captured_at_threshold", "coverage_pct"}
        for item in self.result["attack_category_coverage"]:
            self.assertTrue(required.issubset(item.keys()), msg=str(item))

    def test_coverage_pct_in_valid_range(self):
        for item in self.result["attack_category_coverage"]:
            self.assertGreaterEqual(item["coverage_pct"], 0.0)
            self.assertLessEqual(item["coverage_pct"], 100.0)

    def test_coverage_captured_le_support(self):
        for item in self.result["attack_category_coverage"]:
            self.assertLessEqual(
                item["captured_at_threshold"],
                item["holdout_support"],
                msg=f"captured > support for {item['attack_type']}",
            )

    def test_coverage_pct_arithmetic(self):
        """coverage_pct must equal captured / support × 100 (±0.1)."""
        for item in self.result["attack_category_coverage"]:
            expected = round(100.0 * item["captured_at_threshold"] / item["holdout_support"], 2)
            self.assertAlmostEqual(item["coverage_pct"], expected, places=1)

    def test_attack_support_totals_match_holdout_attack_events(self):
        """Sum of per-attack holdout_support must equal holdout_attack_events."""
        total_from_coverage = sum(
            item["holdout_support"] for item in self.result["attack_category_coverage"]
        )
        self.assertEqual(
            total_from_coverage,
            self.result["evaluation"]["holdout_attack_events"],
        )

    # ── Model metadata ────────────────────────────────────────────────────────

    def test_model_type_is_gru(self):
        self.assertEqual(self.result["model"]["type"], "gru_next_event_predictor")

    def test_model_seed_is_deterministic(self):
        self.assertEqual(self.result["model"]["random_seed"], RANDOM_SEED)


# ─── 3. Label-leakage validation ─────────────────────────────────────────────

class TestLabelLeakageValidation(unittest.TestCase):
    """Prove that labels cannot influence sequence scores or the IF risk ranking."""

    @classmethod
    def setUpClass(cls):
        cls.result = evaluate_sequence_detector()

    def test_leakage_section_present(self):
        self.assertIn("label_leakage", self.result)

    def test_labels_not_used_for_training_or_scoring(self):
        """The hard-coded invariant flag must always be False."""
        self.assertFalse(
            self.result["label_leakage"]["labels_used_for_training_or_scoring"]
        )

    def test_sequence_scores_unchanged_by_label_permutation(self):
        """
        Permuting labels must leave sequence scores byte-identical.

        This is the primary proof that labels cannot enter the GRU training
        or scoring path. A False here means labels are leaking.
        """
        self.assertTrue(
            self.result["label_leakage"]["sequence_scores_unchanged"],
            msg=(
                "sequence_scores_unchanged returned False. "
                "Labels must not influence GRU training or scoring."
            ),
        )

    def test_existing_risk_ranking_unchanged_by_label_permutation(self):
        """
        Permuting labels must leave the Isolation Forest risk ranking unchanged.
        """
        self.assertTrue(
            self.result["label_leakage"]["existing_risk_ranking_unchanged"],
            msg=(
                "existing_risk_ranking_unchanged returned False. "
                "Labels must not influence the Isolation Forest risk ranking."
            ),
        )

    def test_leakage_unit_with_synthetic_data(self):
        """
        Unit-level leakage proof using synthetic data (no database required).

        Train a model, score holdout events, shuffle labels, retrain, re-score.
        Scores must be numerically identical regardless of label values.
        """
        rng = np.random.default_rng(RANDOM_SEED)
        eval_frame = _synthetic_eval_frame(n_entities=6, n_events=120)

        groups = _chronological_groups(eval_frame.drop(columns=["label"]))
        train_groups, cutoffs = _evaluation_split(groups)
        self.assertGreater(len(cutoffs), 0, "No entities qualify for split in synthetic test.")

        result = _sequence_label_leakage_test(eval_frame, groups, train_groups, cutoffs)
        self.assertTrue(
            result,
            "Synthetic label-leakage test failed: label permutation changed sequence scores.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
