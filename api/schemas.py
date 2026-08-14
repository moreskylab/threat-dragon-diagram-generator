from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthStatus(BaseModel):
    status: str = "ok"
    version: str
    environment: str
    timestamp: str
    uptime_seconds: float


class TemplateInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    diagram_type: str = "STRIDE"
    element_count: int


class GenerateTemplateRequest(BaseModel):
    template_id: str = Field(..., description="ID of the template: 'ecommerce', 'microservices', 'k8s-cloudnative', 'payment-gateway'")
    title: Optional[str] = Field(None, description="Optional custom title override")
    diagram_type: str = Field("STRIDE", description="Threat modeling methodology: STRIDE, LINDDUN, CIA")


class PromptInspectRequest(BaseModel):
    diagram_data: Optional[Dict[str, Any]] = Field(None, description="OWASP Threat Dragon JSON object")
    template_id: Optional[str] = Field(None, description="Template ID to generate prompt from if diagram_data not provided")
    diagram_index: int = Field(0, description="Diagram index to analyze within the Threat Dragon file")


class PromptInspectResponse(BaseModel):
    success: bool = True
    diagram_title: str
    diagram_type: str
    prompt: str
    element_count: int
    flow_count: int


class AnalyzeDiagramRequest(BaseModel):
    diagram_data: Optional[Dict[str, Any]] = Field(None, description="OWASP Threat Dragon JSON object")
    template_id: Optional[str] = Field(None, description="Template ID to analyze if diagram_data not provided")
    diagram_index: int = Field(0, description="Diagram index to analyze")
    model_name: Optional[str] = Field(None, description="LLM model (defaults to OPENAI_MODEL env var or gpt-4o-mini)")
    api_key: Optional[str] = Field(None, description="OpenAI / API key (defaults to OPENAI_API_KEY env var)")
    base_url: Optional[str] = Field(None, description="Custom LLM API Base URL (e.g. Ollama http://localhost:11434/v1)")
    temperature: float = Field(0.2, ge=0.0, le=2.0, description="LLM sampling temperature")
    include_prompt: bool = Field(False, description="Include the prompt sent to the LLM in the response")


class ThreatModelReportResponse(BaseModel):
    success: bool
    diagram_title: str
    diagram_type: str
    model_used: str
    report_markdown: str
    prompt: Optional[str] = None
    execution_time_seconds: float


class RenderDiagramRequest(BaseModel):
    diagram_data: Optional[Dict[str, Any]] = Field(None, description="OWASP Threat Dragon JSON object")
    template_id: Optional[str] = Field(None, description="Template ID to render if diagram_data not provided")
    format: str = Field("svg", description="Format: 'svg' or 'png'")


class RenderDiagramResponse(BaseModel):
    format: str
    image_data: str
    content_type: str


class CustomModelNode(BaseModel):
    id: Optional[str] = None
    name: str
    type: str = Field(..., description="actor, process, store, boundary")
    description: str = ""
    is_encrypted: bool = False
    provides_authentication: bool = False
    stores_credentials: bool = False
    is_log: bool = False
    out_of_scope: bool = False


class CustomModelFlow(BaseModel):
    source: str = Field(..., description="Name or ID of source node")
    target: str = Field(..., description="Name or ID of target node")
    name: str
    description: str = ""
    protocol: str = "HTTPS"
    is_encrypted: bool = True
    is_public_network: bool = False


class CustomModelRequest(BaseModel):
    title: str = "Custom Threat Model"
    owner: str = "Security Team"
    description: str = "Generated via Dragon-GPT Cloud Studio"
    diagram_type: str = "STRIDE"
    nodes: List[CustomModelNode] = []
    flows: List[CustomModelFlow] = []
