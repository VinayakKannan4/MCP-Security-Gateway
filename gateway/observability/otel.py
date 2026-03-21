"""OpenTelemetry setup — call configure_otel(app, settings) in main.py."""

from __future__ import annotations

import logging

from fastapi import FastAPI

from gateway.config import Settings

logger = logging.getLogger(__name__)

# Module-level imports so tests can patch via gateway.observability.otel.*
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


def configure_otel(app: FastAPI, settings: Settings) -> None:
    """Attach OTel tracing to the FastAPI app if OTEL_ENABLED=true.

    No-ops silently if otel_enabled is False so tests and local dev are unaffected.
    Uses OTLP gRPC exporter pointing at settings.otel_endpoint.
    """
    if not settings.otel_enabled:
        logger.debug("OTel disabled (OTEL_ENABLED=false) — skipping setup")
        return

    if not _OTEL_AVAILABLE:
        logger.warning("OTel packages not installed — skipping setup")
        return

    resource = Resource.create({"service.name": "mcp-security-gateway"})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)

    logger.info("OTel tracing configured (endpoint=%s)", settings.otel_endpoint)
