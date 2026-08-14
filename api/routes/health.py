import time
from datetime import datetime, timezone
from fastapi import APIRouter, Response
from api.config import settings
from api.schemas import HealthStatus
from api.metrics import get_latest_metrics

router = APIRouter(tags=["Health & Telemetry"])

START_TIME = time.time()


@router.get("/healthz", response_model=HealthStatus, summary="Liveness Probe")
@router.get("/livez", response_model=HealthStatus, include_in_schema=False)
def liveness() -> HealthStatus:
    """Kubernetes liveness probe indicating the application is running."""
    return HealthStatus(
        status="ok",
        version=settings.app_version,
        environment=settings.env,
        timestamp=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=round(time.time() - START_TIME, 2),
    )


@router.get("/readyz", response_model=HealthStatus, summary="Readiness Probe")
def readiness() -> HealthStatus:
    """Kubernetes readiness probe indicating the application is ready to serve traffic."""
    return HealthStatus(
        status="ready",
        version=settings.app_version,
        environment=settings.env,
        timestamp=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=round(time.time() - START_TIME, 2),
    )


@router.get("/metrics", summary="Prometheus Metrics Exporter")
def metrics() -> Response:
    """Prometheus telemetry metrics endpoint for scrapers."""
    data, content_type = get_latest_metrics()
    return Response(content=data, media_type=content_type)
