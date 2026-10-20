"""Phase 2 hardware discovery infrastructure.

Collectors are opt-in extensions to the existing Phase 1 discovery pipeline.
"""
from .core import CollectionStatus, CollectorResult, DiscoveryContext, run_collector
from .probes import ProbeResult, run_probe

__all__ = [
    "CollectionStatus", "CollectorResult", "DiscoveryContext",
    "ProbeResult", "run_collector", "run_probe",
]
