"""Shared behavioral-baseline readiness metadata."""

MINIMUM_HISTORY_EVENTS = 50


def baseline_status(history_event_count: int) -> str:
    """Return whether enough unlabeled telemetry exists for a baseline."""
    return (
        "Established"
        if history_event_count >= MINIMUM_HISTORY_EVENTS
        else "Cold Start"
    )