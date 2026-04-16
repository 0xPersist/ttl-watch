"""ttl-watch: Multi-signal DNS anomaly detection engine."""

__version__ = "1.0.0"
__author__ = "NorthQuinn Inc."

from .engine import DomainCandidate, SignalResult, score_domain, DEFAULT_WEIGHTS
from .correlator import correlate_and_score

__all__ = [
    "DomainCandidate",
    "SignalResult",
    "score_domain",
    "correlate_and_score",
    "DEFAULT_WEIGHTS",
]
