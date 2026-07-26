"""Focused tests for the isolated sequence-aware detector."""

import unittest

import numpy as np

from sequence_detector import (
    FEATURE_COLS,
    GRUSequencePredictor,
    MINIMUM_HISTORY_EVENTS,
    SEQUENCE_LENGTH,
)


class SequenceDetectorTests(unittest.TestCase):
    def test_gru_training_is_deterministic(self):
        rng = np.random.default_rng(11)
        values = rng.normal(size=(SEQUENCE_LENGTH + 1, len(FEATURE_COLS)))
        windows = [(values[:SEQUENCE_LENGTH], values[SEQUENCE_LENGTH])]

        first = GRUSequencePredictor(len(FEATURE_COLS), seed=123)
        second = GRUSequencePredictor(len(FEATURE_COLS), seed=123)
        first.fit(windows, epochs=1)
        second.fit(windows, epochs=1)

        np.testing.assert_allclose(
            first.predict(values[:SEQUENCE_LENGTH]),
            second.predict(values[:SEQUENCE_LENGTH]),
        )

    def test_sequence_constants_preserve_cold_start_contract(self):
        self.assertEqual(MINIMUM_HISTORY_EVENTS, 50)
        self.assertLess(SEQUENCE_LENGTH, MINIMUM_HISTORY_EVENTS)


if __name__ == "__main__":
    unittest.main()