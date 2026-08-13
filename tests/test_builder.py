import os
import json
import pytest
from utils.threat_dragon_builder import ThreatDragonModel, pytm_to_threat_dragon
from utils.diagram import DiagramHandler


def test_threat_dragon_model_builder(tmp_path):
    model = ThreatDragonModel(
        title="Test E-Commerce Platform",
        owner="SecOps",
        description="Unit test model",
        diagram_type="STRIDE",
    )

    user = model.add_actor("User", "Web user", provides_authentication=True)
    web = model.add_process("Web Service", "Nginx web server")
    db = model.add_store("Main DB", "PostgreSQL database", is_encrypted=True, stores_credentials=True)
    tb = model.add_trust_boundary("VPC Zone", "Internal subnet")

    model.add_flow(user, web, "Web Traffic", protocol="HTTPS", is_encrypted=True, is_public_network=True)
    model.add_flow(web, db, "DB Queries", protocol="Postgres/TLS", is_encrypted=True)

    # Convert to dictionary and validate schema
    schema = model.to_dict()
    assert schema["version"] == "2.6.2"
    assert schema["summary"]["title"] == "Test E-Commerce Platform"
    assert len(schema["detail"]["diagrams"]) == 1

    cells = schema["detail"]["diagrams"][0]["cells"]
    # 1 TB + 1 Actor + 1 Process + 1 Store + 2 Flows = 6 cells
    assert len(cells) == 6

    shapes = [c["shape"] for c in cells]
    assert "actor" in shapes
    assert "process" in shapes
    assert "store" in shapes
    assert "flow" in shapes
    assert "trust-boundary-box" in shapes

    # Save to temp JSON and verify DiagramHandler can parse it and make sentences
    json_file = str(tmp_path / "test_model.json")
    model.to_json(json_file)

    assert os.path.exists(json_file)

    handler = DiagramHandler(json_file)
    prompt = handler.make_sentence()

    assert "Test E-Commerce Platform" in prompt
    assert "User" in prompt
    assert "Web Service" in prompt
    assert "Main DB" in prompt
    assert "STRIDE" in prompt
    assert "provides authentication credentials" in prompt
    assert "encrypted at rest" in prompt
