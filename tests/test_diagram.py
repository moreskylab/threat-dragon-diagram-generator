import json
import pytest
from utils.diagram import DiagramHandler


def test_diagram_handler_secure_cart():
    handler = DiagramHandler("diagram/example/secure-cart.json")
    prompt = handler.make_sentence()

    assert "SecureCart Threat Model" in prompt or "New STRIDE diagram" in prompt
    assert "Customer" in prompt
    assert "Web Server" in prompt or "Database" in prompt or "Shopping Cart" in prompt
    assert "STRIDE" in prompt
    assert len(handler.components) > 0


def test_diagram_handler_missing_file():
    handler = DiagramHandler("non_existent_file.json")
    with pytest.raises(FileNotFoundError):
        handler.make_sentence()


def test_trust_boundary_box_logic():
    handler = DiagramHandler("diagram/example/secure-cart.json")
    # Box from (100, 100) to (300, 300)
    box_pos = {"x": 100, "y": 100}
    box_size = {"width": 200, "height": 200}

    # Point inside (200, 200) -> is_outside should be False
    assert handler.is_outside_of_tb_box({"x": 200, "y": 200}, box_pos, box_size) is False

    # Point outside (50, 50) -> is_outside should be True
    assert handler.is_outside_of_tb_box({"x": 50, "y": 50}, box_pos, box_size) is True

    # Point outside (400, 200) -> is_outside should be True
    assert handler.is_outside_of_tb_box({"x": 400, "y": 200}, box_pos, box_size) is True


def test_trust_boundary_curve_logic():
    handler = DiagramHandler("diagram/example/secure-cart.json")
    # Triangular boundary (0,0) -> (10, 0) -> (5, 10)
    vertices = [{"x": 0, "y": 0}, {"x": 10, "y": 0}, {"x": 5, "y": 10}]

    # A point far away
    assert handler.is_outside_of_tb_curve({"x": 100, "y": 100}, vertices) is True


def test_store_sentence_generation():
    handler = DiagramHandler("diagram/example/secure-cart.json")
    comp = {
        "name": "UserDB",
        "description": "Stores user profiles",
        "isALog": False,
        "storesCredentials": True,
        "isEncrypted": True,
        "isSigned": False,
        "flow": [],
    }
    sentence = handler.make_store_sentence(comp)
    assert "UserDB" in sentence
    assert "storing credentials" in sentence
    assert "encrypted at rest" in sentence


def test_actor_sentence_generation():
    handler = DiagramHandler("diagram/example/secure-cart.json")
    comp = {
        "name": "Customer",
        "description": "End user",
        "providesAuthentication": True,
        "flow": [],
    }
    sentence = handler.make_actor_sentence(comp)
    assert "Customer" in sentence
    assert "provides authentication credentials" in sentence
