# =============================================================================
# SVT System — Prometheus Metric Definitions (Single Source of Truth)
# =============================================================================
# All application metrics are defined here with a custom CollectorRegistry
# to avoid polluting the default registry with Python process metrics.
# =============================================================================

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

svt_tokens_generated_total = Counter(
    "svt_tokens_generated_total",
    "Total SVT tokens generated",
    ["issuer_id"],
    registry=REGISTRY,
)

svt_scans_total = Counter(
    "svt_scans_total",
    "Total scan verify calls",
    ["result"],  # ALLOW / WARN / DENY
    registry=REGISTRY,
)

svt_anomalies_total = Counter(
    "svt_anomalies_total",
    "Total anomalies flagged",
    ["rule"],  # scan_flood / geo_impossible / device_code_flood / ml_anomaly
    registry=REGISTRY,
)

svt_revocations_total = Counter(
    "svt_revocations_total",
    "Total token revocations",
    registry=REGISTRY,
)

scan_verify_duration_seconds = Histogram(
    "scan_verify_duration_seconds",
    "Scan verify endpoint latency",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25],
    registry=REGISTRY,
)
