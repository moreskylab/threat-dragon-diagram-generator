import os
import json
import time
import tempfile
import base64
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from api.config import settings
from api.schemas import (
    AnalyzeDiagramRequest,
    PromptInspectRequest,
    PromptInspectResponse,
    ThreatModelReportResponse,
    RenderDiagramRequest,
    RenderDiagramResponse,
    CustomModelRequest,
)
from api.metrics import THREAT_MODELS_GENERATED_TOTAL, DIAGRAMS_RENDERED_TOTAL
from api.routes.templates import TEMPLATE_BUILDERS
from utils.diagram import DiagramHandler
from utils.chatgpt import OpenAIHandler
from utils.threat_dragon_builder import ThreatDragonModel
from utils.diagram_png import render_svg_fallback, render_png_diagram

router = APIRouter(prefix="/api/v1", tags=["Threat Modeling & Diagrams"])


def _extract_diagram_prompt_and_stats(
    diagram_data: Optional[Dict[str, Any]],
    template_id: Optional[str],
    diagram_index: int = 0,
) -> tuple[str, str, str, int, int]:
    """Helper to obtain generated prompt and metadata from json dict or template."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        if diagram_data:
            json.dump(diagram_data, tmp)
            tmp_path = tmp.name
        elif template_id and template_id in TEMPLATE_BUILDERS:
            builder_fn, default_title, _, _, _ = TEMPLATE_BUILDERS[template_id]
            model = builder_fn()
            json.dump(model.to_dict(), tmp)
            tmp_path = tmp.name
        else:
            raise HTTPException(
                status_code=400,
                detail="Either 'diagram_data' or a valid 'template_id' must be provided.",
            )

    try:
        handler = DiagramHandler(tmp_path, diagram_index=diagram_index)
        prompt = handler.make_sentence()
        diagram_title = getattr(handler, "diagram_title", "Threat Dragon Diagram")
        diagram_type = getattr(handler, "diagram_type", "STRIDE")
        element_count = len(getattr(handler, "components", []))
        flow_count = len(getattr(handler, "flows", []))
        return prompt, diagram_title, diagram_type, element_count, flow_count
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@router.post("/prompt", response_model=PromptInspectResponse, summary="Inspect Threat Model Prompt (Dry-Run)")
def inspect_prompt(req: PromptInspectRequest) -> PromptInspectResponse:
    """Parse Threat Dragon JSON diagram and generate the comprehensive LLM prompt without calling external APIs."""
    try:
        prompt, title, dtype, element_count, flow_count = _extract_diagram_prompt_and_stats(
            diagram_data=req.diagram_data,
            template_id=req.template_id,
            diagram_index=req.diagram_index,
        )

        return PromptInspectResponse(
            success=True,
            diagram_title=title,
            diagram_type=dtype,
            prompt=prompt,
            element_count=element_count,
            flow_count=flow_count,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse diagram: {str(e)}")


@router.post("/analyze", response_model=ThreatModelReportResponse, summary="Generate AI Threat Model Report")
def analyze_diagram(req: AnalyzeDiagramRequest) -> ThreatModelReportResponse:
    """Analyze an architecture diagram using LLM (OpenAI, Gemini, Ollama, local models) to produce STRIDE/LINDDUN threat reports."""
    start_time = time.time()
    model_name = req.model_name or settings.openai_model or "gpt-4o-mini"
    api_key = req.api_key or settings.openai_api_key or os.getenv("OPENAI_API_KEY")
    base_url = req.base_url or settings.openai_base_url or os.getenv("OPENAI_BASE_URL")

    # If base_url is set (e.g. Ollama), key can be a placeholder
    if not api_key and base_url:
        api_key = "local-key"
    elif not api_key:
        raise HTTPException(
            status_code=400,
            detail="API Key required. Provide 'api_key' in request or set OPENAI_API_KEY in server environment.",
        )

    try:
        prompt, title, dtype, _, _ = _extract_diagram_prompt_and_stats(
            diagram_data=req.diagram_data,
            template_id=req.template_id,
            diagram_index=req.diagram_index,
        )
    except HTTPException:
        raise
    except Exception as e:
        THREAT_MODELS_GENERATED_TOTAL.labels(model=model_name, status="parse_error").inc()
        raise HTTPException(status_code=422, detail=f"Diagram parsing error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        THREAT_MODELS_GENERATED_TOTAL.labels(model=model_name, status="parse_error").inc()
        raise HTTPException(status_code=422, detail=f"Diagram parsing error: {str(e)}")

    try:
        llm_handler = OpenAIHandler(
            api_key=api_key,
            ai_model=model_name,
            base_url=base_url,
            temperature=req.temperature,
        )
        report = llm_handler.do_threat_modeling(prompt)
        elapsed = round(time.time() - start_time, 2)

        if not report:
            THREAT_MODELS_GENERATED_TOTAL.labels(model=model_name, status="empty_response").inc()
            raise HTTPException(status_code=502, detail="LLM returned an empty threat modeling report.")

        THREAT_MODELS_GENERATED_TOTAL.labels(model=model_name, status="success").inc()

        return ThreatModelReportResponse(
            success=True,
            diagram_title=title,
            diagram_type=dtype,
            model_used=model_name,
            report_markdown=report,
            prompt=prompt if req.include_prompt else None,
            execution_time_seconds=elapsed,
        )
    except HTTPException:
        raise
    except Exception as e:
        THREAT_MODELS_GENERATED_TOTAL.labels(model=model_name, status="api_error").inc()
        raise HTTPException(status_code=500, detail=f"LLM Threat Modeling failed: {str(e)}")


@router.post("/render", response_model=RenderDiagramResponse, summary="Render Architecture Diagram (SVG/PNG)")
def render_diagram(req: RenderDiagramRequest) -> RenderDiagramResponse:
    """Render Threat Dragon diagram into SVG vector graphic or PNG image."""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, "model.json")
            if req.diagram_data:
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(req.diagram_data, f)
            elif req.template_id and req.template_id in TEMPLATE_BUILDERS:
                builder_fn, _, _, _, _ = TEMPLATE_BUILDERS[req.template_id]
                model = builder_fn()
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(model.to_dict(), f)
            else:
                raise HTTPException(status_code=400, detail="Provide 'diagram_data' or valid 'template_id'.")

            # Parse back to a ThreatDragonModel representation
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Build ThreatDragonModel
            detail = data.get("detail", {})
            diagrams_list = detail.get("diagrams", [])
            diagram = diagrams_list[0] if diagrams_list else {}
            title = diagram.get("title", detail.get("summary", {}).get("title", "Threat Model"))
            diagram_type = diagram.get("diagramType", "STRIDE")

            model = ThreatDragonModel(title=title, diagram_type=diagram_type)
            cells = diagram.get("cells", [])

            # Map cells
            for c in cells:
                shape = c.get("shape", "")
                cdata = c.get("data", {})
                name = cdata.get("name", c.get("attrs", {}).get("text", {}).get("text", "Unknown"))
                pos = c.get("position", {})
                size = c.get("size", {})
                x = pos.get("x")
                y = pos.get("y")

                if shape == "actor":
                    model.add_actor(name=name, description=cdata.get("description", ""), provides_authentication=cdata.get("providesAuthentication", False), x=x, y=y)
                elif shape == "process":
                    model.add_process(name=name, description=cdata.get("description", ""), out_of_scope=cdata.get("outOfScope", False), x=x, y=y)
                elif shape == "store":
                    model.add_store(name=name, description=cdata.get("description", ""), is_encrypted=cdata.get("isEncrypted", False), stores_credentials=cdata.get("storesCredentials", False), is_log=cdata.get("isLog", False), x=x, y=y)
                elif shape == "trust-boundary-box" or shape == "trust-boundary-curve":
                    model.add_trust_boundary(name=name, description=cdata.get("description", ""), x=x, y=y, width=size.get("width"), height=size.get("height"))

            # Map flows
            for c in cells:
                shape = c.get("shape", "")
                if shape in ("flow", "standard.Link", "edge"):
                    cdata = c.get("data", {})
                    name = cdata.get("name", c.get("labels", [{}])[0].get("attrs", {}).get("text", {}).get("text", "Flow") if c.get("labels") else "Flow")
                    source_id = c.get("source", {}).get("cell")
                    target_id = c.get("target", {}).get("cell")
                    source_elem = model._element_by_id.get(source_id)
                    target_elem = model._element_by_id.get(target_id)
                    if source_elem and target_elem:
                        model.add_flow(
                            source=source_elem,
                            target=target_elem,
                            name=name,
                            description=cdata.get("description", ""),
                            protocol=cdata.get("protocol", "HTTPS"),
                            is_encrypted=cdata.get("isEncrypted", False),
                            is_public_network=cdata.get("isPublicNetwork", False),
                        )

            fmt = req.format.lower()
            if fmt == "png":
                png_out = os.path.join(tmpdir, "diagram.png")
                rendered_path = render_png_diagram(model, output_filename=png_out)
                if rendered_path and os.path.exists(rendered_path):
                    with open(rendered_path, "rb") as f:
                        encoded = base64.b64encode(f.read()).decode("utf-8")
                    DIAGRAMS_RENDERED_TOTAL.labels(format="png", status="success").inc()
                    return RenderDiagramResponse(format="png", image_data=encoded, content_type="image/png")

            # Fallback / default: SVG
            svg_out = os.path.join(tmpdir, "diagram.svg")
            render_svg_fallback(model, svg_out)
            with open(svg_out, "r", encoding="utf-8") as f:
                svg_data = f.read()
            DIAGRAMS_RENDERED_TOTAL.labels(format="svg", status="success").inc()
            return RenderDiagramResponse(format="svg", image_data=svg_data, content_type="image/svg+xml")

    except HTTPException:
        raise
    except Exception as e:
        DIAGRAMS_RENDERED_TOTAL.labels(format=req.format, status="error").inc()
        raise HTTPException(status_code=500, detail=f"Diagram rendering failed: {str(e)}")


@router.post("/custom", summary="Build Custom Threat Model")
def create_custom_model(req: CustomModelRequest) -> Dict[str, Any]:
    """Create a new Threat Dragon model programmatically from custom nodes and flows."""
    model = ThreatDragonModel(
        title=req.title,
        owner=req.owner,
        description=req.description,
        diagram_type=req.diagram_type,
    )

    created_nodes: Dict[str, Dict[str, Any]] = {}

    for node in req.nodes:
        ntype = node.type.lower()
        if ntype == "actor":
            elem = model.add_actor(node.name, node.description, provides_authentication=node.provides_authentication, out_of_scope=node.out_of_scope)
        elif ntype == "process":
            elem = model.add_process(node.name, node.description, out_of_scope=node.out_of_scope)
        elif ntype == "store":
            elem = model.add_store(node.name, node.description, is_encrypted=node.is_encrypted, stores_credentials=node.stores_credentials, is_log=node.is_log, out_of_scope=node.out_of_scope)
        elif ntype == "boundary":
            elem = model.add_trust_boundary(node.name, node.description)
        else:
            continue
        created_nodes[node.name] = elem
        if node.id:
            created_nodes[node.id] = elem

    for flow in req.flows:
        src = created_nodes.get(flow.source)
        dst = created_nodes.get(flow.target)
        if src and dst:
            model.add_flow(
                source=src,
                target=dst,
                name=flow.name,
                description=flow.description,
                protocol=flow.protocol,
                is_encrypted=flow.is_encrypted,
                is_public_network=flow.is_public_network,
            )

    json_dict = model.to_dict()

    with tempfile.TemporaryDirectory() as tmpdir:
        svg_file = os.path.join(tmpdir, "diagram.svg")
        render_svg_fallback(model, svg_file)
        with open(svg_file, "r", encoding="utf-8") as f:
            svg_content = f.read()

    return {
        "title": model.title,
        "json_data": json_dict,
        "svg_content": svg_content,
    }
