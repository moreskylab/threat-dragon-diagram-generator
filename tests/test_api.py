import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_healthz_endpoint():
    """Test Kubernetes liveness probe endpoint."""
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "uptime_seconds" in data


def test_readyz_endpoint():
    """Test Kubernetes readiness probe endpoint."""
    response = client.get("/readyz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"


def test_metrics_endpoint():
    """Test Prometheus metrics endpoint."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "dragon_gpt_http_requests_total" in response.text or "python_gc_objects_collected_total" in response.text


def test_list_templates():
    """Test template listing endpoint."""
    response = client.get("/api/v1/templates")
    assert response.status_code == 200
    templates = response.json()
    assert len(templates) >= 4
    template_ids = [t["id"] for t in templates]
    assert "ecommerce" in template_ids
    assert "microservices" in template_ids
    assert "k8s-cloudnative" in template_ids
    assert "payment-gateway" in template_ids


def test_get_template_details():
    """Test template detail and diagram generation."""
    response = client.get("/api/v1/templates/ecommerce")
    assert response.status_code == 200
    data = response.json()
    assert data["template_id"] == "ecommerce"
    assert "json_data" in data
    assert "svg_content" in data
    assert "<svg" in data["svg_content"]
    assert data["json_data"]["version"].startswith("2.")



def test_get_template_not_found():
    """Test 404 for invalid template."""
    response = client.get("/api/v1/templates/invalid-id-xyz")
    assert response.status_code == 404


def test_inspect_prompt_with_template():
    """Test prompt inspection (dry-run) using a template."""
    response = client.post(
        "/api/v1/prompt",
        json={"template_id": "ecommerce"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "prompt" in data
    assert "STRIDE" in data["prompt"]
    assert data["element_count"] > 0
    assert data["flow_count"] > 0


def test_inspect_prompt_with_raw_json():
    """Test prompt inspection with raw Threat Dragon JSON object."""
    # First get sample JSON
    tpl_res = client.get("/api/v1/templates/microservices")
    json_data = tpl_res.json()["json_data"]

    response = client.post(
        "/api/v1/prompt",
        json={"diagram_data": json_data},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "Auth Service" in data["prompt"]


def test_render_diagram_svg():
    """Test diagram rendering endpoint."""
    response = client.post(
        "/api/v1/render",
        json={"template_id": "microservices", "format": "svg"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "svg"
    assert "<svg" in data["image_data"]


def test_create_custom_model():
    """Test custom model creation endpoint."""
    custom_payload = {
        "title": "Custom Microservice",
        "diagram_type": "STRIDE",
        "nodes": [
            {"name": "Client App", "type": "actor", "provides_authentication": True},
            {"name": "Gateway Service", "type": "process"},
            {"name": "Database", "type": "store", "is_encrypted": True},
        ],
        "flows": [
            {"source": "Client App", "target": "Gateway Service", "name": "HTTPS Req", "protocol": "HTTPS"},
            {"source": "Gateway Service", "target": "Database", "name": "SQL Query", "protocol": "PostgreSQL"},
        ],
    }
    response = client.post("/api/v1/custom", json=custom_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Custom Microservice"
    assert "json_data" in data
    assert "svg_content" in data


def test_serve_ui_index():
    """Test that static web UI is served at root."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Dragon-GPT" in response.text
