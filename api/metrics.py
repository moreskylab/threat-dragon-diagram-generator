from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# Prometheus Metrics
HTTP_REQUESTS_TOTAL = Counter(
    "dragon_gpt_http_requests_total",
    "Total HTTP requests received",
    ["method", "endpoint", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "dragon_gpt_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)

IN_FLIGHT_REQUESTS = Gauge(
    "dragon_gpt_in_flight_requests",
    "Number of active in-flight requests",
)

THREAT_MODELS_GENERATED_TOTAL = Counter(
    "dragon_gpt_threat_models_generated_total",
    "Total LLM threat models generated",
    ["model", "status"],
)

DIAGRAMS_RENDERED_TOTAL = Counter(
    "dragon_gpt_diagrams_rendered_total",
    "Total architecture diagrams rendered",
    ["format", "status"],
)


def get_latest_metrics() -> tuple[bytes, str]:
    """Export all registered Prometheus metrics."""
    return generate_latest(), CONTENT_TYPE_LATEST
