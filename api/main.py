import os
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
import uvicorn

from api.config import settings
from api.metrics import HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION_SECONDS, IN_FLIGHT_REQUESTS
from api.routes.health import router as health_router
from api.routes.templates import router as templates_router
from api.routes.threat_model import router as threat_model_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    print(f"[STARTUP] Starting {settings.app_name} v{settings.app_version} ({settings.env})")
    yield
    print("[SHUTDOWN] Stopping Dragon-GPT application server...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cloud-Native Automated Threat Modeling API for OWASP Threat Dragon Diagrams & LLMs.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prometheus_metrics_middleware(request: Request, call_next):
    """Middleware for Prometheus request metrics & latency tracking."""
    if not settings.enable_metrics or request.url.path in ("/metrics", "/healthz", "/readyz", "/livez"):
        return await call_next(request)

    IN_FLIGHT_REQUESTS.inc()
    start_time = time.time()
    endpoint = request.url.path
    method = request.method

    try:
        response: Response = await call_next(request)
        status_code = str(response.status_code)
    except Exception:
        status_code = "500"
        raise
    finally:
        latency = time.time() - start_time
        HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status_code=status_code).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=endpoint).observe(latency)
        IN_FLIGHT_REQUESTS.dec()

    return response


# Include Routers
app.include_router(health_router)
app.include_router(templates_router)
app.include_router(threat_model_router)

# Mount Static Web Studio UI if web directory exists
web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
static_dir = os.path.join(web_dir, "static")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/app", include_in_schema=False)
@app.get("/", include_in_schema=False)
def serve_ui():
    """Serve the Dragon-GPT Cloud Studio UI."""
    index_file = os.path.join(web_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return RedirectResponse(url="/docs")


def start():
    """CLI entry point to run the Cloud Native Dragon-GPT Server."""
    uvicorn.run(
        "api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    start()
