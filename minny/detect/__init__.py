"""Streaming detector: signals, correlation, and replay (M3)."""

from minny.detect.correlator import Correlator, correlate
from minny.detect.events import DetectEvent, from_frame
from minny.detect.signals import Detector, RollingState

__all__ = [
    "Correlator",
    "correlate",
    "DetectEvent",
    "from_frame",
    "Detector",
    "RollingState",
]
