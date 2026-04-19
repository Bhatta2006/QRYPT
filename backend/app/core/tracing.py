# =============================================================================
# SVT System — OpenTelemetry Tracing Configuration
# =============================================================================
# Called exactly once at app startup from main.py.
# Instruments FastAPI and injects trace/span IDs into structlog entries.
# =============================================================================

from __future__ import annotations

import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def _inject_trace_id(logger, method, event_dict):
    """Prepend OpenTelemetry trace_id and span_id into every structlog log entry."""
    span = trace.get_current_span()
    if span.is_recording():
        ctx = span.get_span_context()
        event_dict["trace_id"] = format(ctx.trace_id, "032x")
        event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


def configure_tracing(app):
    """
    Initialize OpenTelemetry tracing with OTLP gRPC exporter.

    Reads OTEL_EXPORTER_OTLP_ENDPOINT from environment.
    Instruments the FastAPI app and prepends trace context to structlog.
    """
    provider = TracerProvider()
    exporter = OTLPSpanExporter()  # reads OTEL_EXPORTER_OTLP_ENDPOINT from env
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)

    # Prepend trace_id injector to existing structlog processor chain
    current_config = structlog.get_config()
    existing_processors = list(current_config.get("processors", []))
    structlog.configure(
        processors=[_inject_trace_id, *existing_processors],
    )
