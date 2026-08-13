import argparse
import os
import sys
from utils.threat_dragon_builder import ThreatDragonModel, pytm_to_threat_dragon
from utils.diagram_png import render_png_diagram


def build_sample_ecommerce_model() -> ThreatDragonModel:
    """Build a sample E-Commerce / SecureCart Threat Model."""
    model = ThreatDragonModel(
        title="SecureCart E-Commerce Platform",
        owner="Security & Cloud Engineering Team",
        description="Threat model for SecureCart web store, payment gateway, and order database.",
        diagram_type="STRIDE",
    )

    # 1. External Actors
    customer = model.add_actor(
        name="Customer",
        description="End-user accessing the web store via browser or mobile app",
        provides_authentication=True,
    )
    admin = model.add_actor(
        name="System Administrator",
        description="Privileged user managing backend inventory and configurations",
        provides_authentication=True,
    )

    # 2. Processes / Services
    web_server = model.add_process(
        name="Web Application",
        description="Frontend Node.js / React web store server",
    )
    api_gateway = model.add_process(
        name="API Gateway",
        description="Reverse proxy and authentication gateway",
    )
    order_service = model.add_process(
        name="Order Processing Service",
        description="Backend microservice handling orders, checkout, and inventory",
    )
    payment_processor = model.add_process(
        name="External Payment Gateway",
        description="Third-party PCI-DSS compliant payment provider (e.g. Stripe)",
        out_of_scope=True,
    )

    # 3. Data Stores
    user_db = model.add_store(
        name="User Credentials DB",
        description="PostgreSQL storing user credentials, hashed passwords, and profile data",
        stores_credentials=True,
        is_encrypted=True,
    )
    order_db = model.add_store(
        name="Orders & Transactions DB",
        description="Database storing customer orders and transaction history",
        is_encrypted=True,
    )
    audit_logs = model.add_store(
        name="Security Audit Logs",
        description="Append-only centralized log store (SIEM / CloudWatch)",
        is_log=True,
        is_signed=True,
    )

    # 4. Trust Boundary
    model.add_trust_boundary(
        name="Corporate Cloud DMZ & Private VPC",
        description="Secured internal network perimeter protected by WAF and Firewalls",
    )

    # 5. Data Flows
    model.add_flow(
        source=customer,
        target=web_server,
        name="Customer Web Traffic",
        description="HTTPS traffic for browsing catalog and shopping cart",
        protocol="HTTPS/TLS 1.3",
        is_encrypted=True,
        is_public_network=True,
    )
    model.add_flow(
        source=admin,
        target=api_gateway,
        name="Admin Management Portal",
        description="MFA authenticated administrative access",
        protocol="HTTPS/mTLS",
        is_encrypted=True,
        is_public_network=False,
    )
    model.add_flow(
        source=web_server,
        target=api_gateway,
        name="Internal API Calls",
        description="REST API requests forwarded from web application",
        protocol="gRPC / TLS",
        is_encrypted=True,
    )
    model.add_flow(
        source=api_gateway,
        target=order_service,
        name="Dispatch Order Requests",
        description="Routed verified requests to order service",
        protocol="gRPC",
        is_encrypted=True,
    )
    model.add_flow(
        source=api_gateway,
        target=user_db,
        name="Verify Auth Tokens",
        description="Query user credentials and validate session tokens",
        protocol="PostgreSQL/TLS",
        is_encrypted=True,
    )
    model.add_flow(
        source=order_service,
        target=order_db,
        name="Persist Order Records",
        description="Save customer order transactions",
        protocol="PostgreSQL/TLS",
        is_encrypted=True,
    )
    model.add_flow(
        source=order_service,
        target=payment_processor,
        name="Process Credit Card Payment",
        description="Tokenized payment authorization call",
        protocol="HTTPS/REST",
        is_encrypted=True,
        is_public_network=True,
    )
    model.add_flow(
        source=api_gateway,
        target=audit_logs,
        name="Stream Audit Events",
        description="Write access and security event logs",
        protocol="Syslog/TLS",
        is_encrypted=True,
    )

    return model


def build_sample_microservices_model() -> ThreatDragonModel:
    """Build a sample Cloud Microservices Threat Model."""
    model = ThreatDragonModel(
        title="Cloud Microservices Architecture",
        owner="DevSecOps Team",
        description="Microservices with Ingress, Auth, Payment, and NoSQL DB",
        diagram_type="STRIDE",
    )

    user = model.add_actor("End User", "Mobile/Web Client", provides_authentication=True)
    ingress = model.add_process("Ingress Controller", "K8s Envoy Ingress Gateway")
    auth_service = model.add_process("Auth Service", "OAuth2 / OIDC Token Issuer")
    catalog_service = model.add_process("Catalog Service", "Product Catalog API")
    db = model.add_store("Document DB", "MongoDB cluster", is_encrypted=True)

    model.add_trust_boundary("Kubernetes Cluster", "Internal Service Mesh")

    model.add_flow(user, ingress, "User Requests", protocol="HTTPS", is_public_network=True)
    model.add_flow(ingress, auth_service, "Authenticate Request", protocol="gRPC")
    model.add_flow(ingress, catalog_service, "Fetch Products", protocol="gRPC")
    model.add_flow(catalog_service, db, "Read/Write Catalog", protocol="Mongo/TLS")

    return model


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="generate-diagram",
        description="Generate OWASP Threat Dragon JSON models and PNG architecture diagrams using Python / pytm / diagrams.",
    )
    parser.add_argument(
        "--template",
        "-t",
        choices=["ecommerce", "secure-cart", "microservices"],
        default="ecommerce",
        help="Predefined architecture template to generate (default: ecommerce)",
    )
    parser.add_argument(
        "--title",
        help="Custom title for the threat model",
    )
    parser.add_argument(
        "--output-json",
        "-j",
        default="diagram/generated/threat-dragon-model.json",
        help="Output file path for OWASP Threat Dragon JSON (default: diagram/generated/threat-dragon-model.json)",
    )
    parser.add_argument(
        "--output-png",
        "-p",
        default="diagram/generated/architecture-diagram.png",
        help="Output file path for PNG diagram (default: diagram/generated/architecture-diagram.png)",
    )
    parser.add_argument(
        "--no-png",
        action="store_true",
        help="Skip generating PNG diagram",
    )
    parser.add_argument(
        "--threat-model",
        "-m",
        action="store_true",
        help="Immediately run AI threat modeling on the generated JSON diagram",
    )

    args = parser.parse_args()

    # 1. Select / Build Model
    if args.template in ("ecommerce", "secure-cart"):
        model = build_sample_ecommerce_model()
    else:
        model = build_sample_microservices_model()

    if args.title:
        model.title = args.title

    # 2. Export Threat Dragon JSON
    out_json_dir = os.path.dirname(args.output_json)
    if out_json_dir:
        os.makedirs(out_json_dir, exist_ok=True)

    json_path = model.to_json(args.output_json)
    print(f"[SUCCESS] OWASP Threat Dragon JSON generated at: {json_path}")

    # 3. Export PNG / SVG Diagram
    if not args.no_png:
        diag_path = render_png_diagram(model, output_filename=args.output_png)
        if diag_path:
            print(f"[SUCCESS] Architecture diagram generated at: {diag_path}")

    # 4. Optional: Run LLM Threat Modeling directly
    if args.threat_model:
        print("\n" + "=" * 60)
        print("Launching automated LLM threat modeling...")
        print("=" * 60)
        from utils.diagram import DiagramHandler
        dh = DiagramHandler(json_path)
        prompt = dh.make_sentence()
        print("\nGenerated Prompt for Threat Modeling:\n")
        print(prompt)


if __name__ == "__main__":
    main()
