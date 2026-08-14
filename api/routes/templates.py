import base64
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, Query
from utils.threat_dragon_builder import ThreatDragonModel
from utils.diagram_png import render_svg_fallback
from api.schemas import TemplateInfo, GenerateTemplateRequest

router = APIRouter(prefix="/api/v1/templates", tags=["Architecture Templates"])


def get_ecommerce_model(title: str = "SecureCart E-Commerce Platform", diagram_type: str = "STRIDE") -> ThreatDragonModel:
    model = ThreatDragonModel(
        title=title,
        owner="Cloud & Security Engineering Team",
        description="Threat model for SecureCart web store, payment gateway, and order database.",
        diagram_type=diagram_type,
    )
    customer = model.add_actor("Customer", "Mobile client & browser shopping cart", provides_authentication=True)
    admin = model.add_actor("System Admin", "Privileged DevOps engineer", provides_authentication=True)
    web_server = model.add_process("Web Application", "Frontend React/Node server")
    api_gateway = model.add_process("API Gateway", "Reverse proxy & JWT validator")
    order_service = model.add_process("Order Service", "Handles orders & inventory")
    payment_processor = model.add_process("Payment Gateway", "Stripe PCI compliant processor", out_of_scope=True)
    user_db = model.add_store("User DB", "PostgreSQL credentials store", stores_credentials=True, is_encrypted=True)
    order_db = model.add_store("Order DB", "Transactional database", is_encrypted=True)
    audit_logs = model.add_store("Audit Logs", "Append-only SIEM logs", is_log=True, is_signed=True)

    model.add_trust_boundary("Corporate Cloud DMZ & VPC", "Secured network perimeter with WAF")

    model.add_flow(customer, web_server, "Customer Web Traffic", protocol="HTTPS/TLS 1.3", is_public_network=True)
    model.add_flow(admin, api_gateway, "Admin Portal Access", protocol="HTTPS/mTLS", is_public_network=False)
    model.add_flow(web_server, api_gateway, "Internal API Calls", protocol="gRPC/mTLS", is_encrypted=True)
    model.add_flow(api_gateway, order_service, "Dispatch Orders", protocol="gRPC", is_encrypted=True)
    model.add_flow(api_gateway, user_db, "Verify Auth Tokens", protocol="PostgreSQL/TLS", is_encrypted=True)
    model.add_flow(order_service, order_db, "Persist Transactions", protocol="PostgreSQL/TLS", is_encrypted=True)
    model.add_flow(order_service, payment_processor, "Process Payment", protocol="HTTPS/REST", is_public_network=True)
    model.add_flow(api_gateway, audit_logs, "Stream Security Events", protocol="Syslog/TLS", is_encrypted=True)
    return model


def get_microservices_model(title: str = "Cloud Microservices Architecture", diagram_type: str = "STRIDE") -> ThreatDragonModel:
    model = ThreatDragonModel(
        title=title,
        owner="DevSecOps Platform Team",
        description="Cloud native microservices with Ingress, Auth, Product Catalog, and NoSQL DB",
        diagram_type=diagram_type,
    )
    user = model.add_actor("End User", "Mobile & Web Client", provides_authentication=True)
    ingress = model.add_process("Ingress Controller", "K8s Envoy Ingress Gateway")
    auth_service = model.add_process("Auth Service", "OAuth2 / OIDC Token Issuer")
    catalog_service = model.add_process("Catalog Service", "Product Catalog API")
    db = model.add_store("Document DB", "MongoDB cluster", is_encrypted=True)

    model.add_trust_boundary("Kubernetes Cluster", "Internal Istio Service Mesh")

    model.add_flow(user, ingress, "HTTPS Traffic", protocol="HTTPS/TLS 1.3", is_public_network=True)
    model.add_flow(ingress, auth_service, "Authenticate Request", protocol="gRPC/mTLS")
    model.add_flow(ingress, catalog_service, "Fetch Products", protocol="gRPC/mTLS")
    model.add_flow(catalog_service, db, "Read/Write Catalog", protocol="Mongo/TLS")
    return model


def get_cloudnative_k8s_model(title: str = "Cloud Native K8s Threat Model", diagram_type: str = "STRIDE") -> ThreatDragonModel:
    model = ThreatDragonModel(
        title=title,
        owner="Enterprise Infrastructure Security",
        description="Cloud Native Kubernetes architecture with WAF, Ingress, Pods, Redis cache, and Vault",
        diagram_type=diagram_type,
    )
    user = model.add_actor("External Client", "Browser / Mobile App", provides_authentication=True)
    waf = model.add_process("Cloudflare WAF", "DDoS mitigation and Edge SSL termination", out_of_scope=True)
    ingress = model.add_process("K8s NGINX Ingress", "Ingress controller & TLS router")
    api_pods = model.add_process("Backend API Pods", "FastAPI microservices in autoscaling Deployment")
    vault = model.add_process("HashiCorp Vault", "Secrets management & dynamic credentials")
    cache = model.add_store("Redis Cache", "In-memory session and cache store", is_encrypted=True)
    postgres = model.add_store("PostgreSQL Cluster", "Primary transactional database", stores_credentials=True, is_encrypted=True)

    model.add_trust_boundary("K8s Production Namespace", "Protected by NetworkPolicies and mTLS")

    model.add_flow(user, waf, "Internet Traffic", protocol="HTTPS", is_public_network=True)
    model.add_flow(waf, ingress, "Proxied Traffic", protocol="HTTPS/TLS 1.3")
    model.add_flow(ingress, api_pods, "Cluster Ingress Traffic", protocol="HTTP/mTLS")
    model.add_flow(api_pods, vault, "Fetch App Secrets", protocol="HTTPS/Vault-Token", is_encrypted=True)
    model.add_flow(api_pods, cache, "Cache Read/Write", protocol="Redis/TLS", is_encrypted=True)
    model.add_flow(api_pods, postgres, "Database Queries", protocol="PostgreSQL/TLS", is_encrypted=True)
    return model


def get_payment_gateway_model(title: str = "PCI-DSS Payment Gateway", diagram_type: str = "STRIDE") -> ThreatDragonModel:
    model = ThreatDragonModel(
        title=title,
        owner="Financial Security Architecture",
        description="PCI-DSS compliant payment processing subsystem with tokenization and HSM",
        diagram_type=diagram_type,
    )
    payer = model.add_actor("Payer Cardholder", "Checkout user", provides_authentication=True)
    api_gw = model.add_process("Payment API Gateway", "Ingress reverse proxy and rate limiter")
    token_svc = model.add_process("Tokenization Service", "Converts PAN to random tokens")
    hsm = model.add_process("HSM Encryption Engine", "Hardware Security Module for cryptographic keys")
    bank_gw = model.add_process("Acquiring Bank API", "External banking settlement network", out_of_scope=True)
    vault_db = model.add_store("Encrypted Card Vault", "AES-256 GCM encrypted PAN storage", stores_credentials=True, is_encrypted=True)

    model.add_trust_boundary("PCI-DSS Isolated CDE", "Cardholder Data Environment with Zero Trust")

    model.add_flow(payer, api_gw, "Submit Payment Card", protocol="HTTPS/TLS 1.3", is_public_network=True)
    model.add_flow(api_gw, token_svc, "Authorize & Tokenize", protocol="gRPC/mTLS", is_encrypted=True)
    model.add_flow(token_svc, hsm, "Generate Card Key", protocol="PKCS#11", is_encrypted=True)
    model.add_flow(token_svc, vault_db, "Store Encrypted Token", protocol="PostgreSQL/TLS", is_encrypted=True)
    model.add_flow(token_svc, bank_gw, "Settle Transaction", protocol="ISO 8583 / HTTPS", is_public_network=True)
    return model


TEMPLATE_BUILDERS = {
    "ecommerce": (get_ecommerce_model, "SecureCart E-Commerce Platform", "E-Commerce web store, checkout, order DB, and payment gateway.", "Web / E-Commerce", 9),
    "microservices": (get_microservices_model, "Cloud Microservices Architecture", "Kubernetes Envoy ingress, Auth, Product Catalog, and MongoDB.", "Cloud Microservices", 5),
    "k8s-cloudnative": (get_cloudnative_k8s_model, "Cloud Native K8s Threat Model", "Kubernetes cluster with WAF, Nginx Ingress, API pods, Redis, and Vault.", "Kubernetes & Cloud Native", 7),
    "payment-gateway": (get_payment_gateway_model, "PCI-DSS Payment Gateway", "PCI-DSS isolated cardholder data environment with tokenization and HSM.", "FinTech & Banking", 6),
}


@router.get("", response_model=List[TemplateInfo], summary="List Architecture Templates")
def list_templates() -> List[TemplateInfo]:
    """Retrieve all available pre-built architecture templates."""
    results = []
    for tid, (_, name, desc, category, count) in TEMPLATE_BUILDERS.items():
        results.append(TemplateInfo(
            id=tid,
            name=name,
            description=desc,
            category=category,
            diagram_type="STRIDE",
            element_count=count,
        ))
    return results


@router.get("/{template_id}", summary="Get Template Model and Diagram")
def get_template(
    template_id: str,
    title: str = Query(None, description="Custom title override"),
    diagram_type: str = Query("STRIDE", description="Methodology: STRIDE, LINDDUN, CIA"),
) -> Dict[str, Any]:
    """Generate and retrieve the Threat Dragon JSON and SVG diagram for a specific template."""
    if template_id not in TEMPLATE_BUILDERS:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found. Available: {list(TEMPLATE_BUILDERS.keys())}")

    builder_fn, default_title, _, _, _ = TEMPLATE_BUILDERS[template_id]
    model = builder_fn(title=title or default_title, diagram_type=diagram_type)

    json_data = model.to_dict()

    # Generate standalone SVG diagram
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        svg_file = os.path.join(tmpdir, "diagram.svg")
        render_svg_fallback(model, svg_file)
        with open(svg_file, "r", encoding="utf-8") as f:
            svg_content = f.read()

    return {
        "template_id": template_id,
        "title": model.title,
        "diagram_type": model.diagram_type,
        "json_data": json_data,
        "svg_content": svg_content,
    }
