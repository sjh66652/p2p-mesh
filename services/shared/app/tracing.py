"""
OpenTelemetry tracing configuration.
Enable with OTEL_ENABLED=true environment variable.
"""

import os

def setup_tracing(service_name: str):
    """Initialize OpenTelemetry tracing if enabled."""
    if os.getenv("OTEL_ENABLED", "false").lower() != "true":
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        resource = Resource(attributes={SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)

        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4317")
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)

        import logging
        logging.getLogger("opentelemetry").info("Tracing enabled for %s -> %s", service_name, otlp_endpoint)

        return provider
    except ImportError:
        import logging
        logging.getLogger("opentelemetry").warning(
            "OpenTelemetry packages not installed. Install with: pip install opentelemetry-api "
            "opentelemetry-sdk opentelemetry-exporter-otlp opentelemetry-instrumentation-fastapi"
        )
        return None
