"""Streaming detector: signals, correlation, replay and rules (M3)."""

from minny.detect.correlator import Correlator, correlate
from minny.detect.events import DetectEvent, from_frame, from_mapping
from minny.detect.replay import Frame, InjectionQueue, Pipeline, ReplayEngine
from minny.detect.rules import RuleSet, parse_expression
from minny.detect.signals import Detector, RollingState

__all__ = [
    "Correlator",
    "correlate",
    "DetectEvent",
    "from_frame",
    "from_mapping",
    "Frame",
    "InjectionQueue",
    "Pipeline",
    "ReplayEngine",
    "RuleSet",
    "parse_expression",
    "Detector",
    "RollingState",
]
