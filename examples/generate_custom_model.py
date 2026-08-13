"""
Example: Define a custom software architecture in Python and export to
1. OWASP Threat Dragon v2 JSON (.json)
2. High-resolution Architecture Diagram (.png)
"""
from utils.threat_dragon_builder import ThreatDragonModel
from utils.diagram_png import render_png_diagram


def main():
    # 1. Initialize Threat Dragon Model
    model = ThreatDragonModel(
        title="Banking Fintech Payment Gateway",
        owner="Fintech Security Architecture Team",
        description="Core banking API, payment orchestration, and ledger database.",
        diagram_type="STRIDE",
    )

    # 2. Add Actors
    customer = model.add_actor(
        name="Mobile Banking App User",
        description="Retail banking customer authenticated via biometric/OAuth2",
        provides_authentication=True,
    )
    support_staff = model.add_actor(
        name="Bank Support Specialist",
        description="Internal support staff accessing CRM via VPN and MFA",
        provides_authentication=True,
    )

    # 3. Add Processes & Services
    waf = model.add_process("Cloudflare WAF / DDoS Shield", "Edge security & rate limiting")
    api_gateway = model.add_process("Kong API Gateway", "API routing, JWT validation, and throttling")
    payment_engine = model.add_process("Payment Orchestrator", "Core transaction processing microservice")
    fraud_detector = model.add_process("AI Fraud Detection Engine", "Real-time transaction scoring model")

    # 4. Add Data Stores
    ledger_db = model.add_store(
        name="Immutable Ledger DB",
        description="Encrypted PostgreSQL store with audit logging for financial transactions",
        stores_credentials=False,
        is_encrypted=True,
        is_signed=True,
    )
    redis_cache = model.add_store(
        name="Redis Session Cache",
        description="In-memory cache for user sessions and rate limits",
        is_encrypted=True,
    )

    # 5. Add Trust Boundary
    model.add_trust_boundary(
        name="PCI-DSS Compliant Secure Zone",
        description="Isolated VPC subnet with strict security groups and mutual TLS",
    )

    # 6. Add Data Flows
    model.add_flow(customer, waf, "HTTPS Mobile Traffic", protocol="TLS 1.3", is_public_network=True)
    model.add_flow(waf, api_gateway, "Inspected Traffic", protocol="HTTPS")
    model.add_flow(api_gateway, redis_cache, "Check Session / Rate Limit", protocol="RESP/TLS")
    model.add_flow(api_gateway, payment_engine, "Forward Validated Payment", protocol="gRPC / mTLS")
    model.add_flow(payment_engine, fraud_detector, "Evaluate Risk Score", protocol="gRPC")
    model.add_flow(payment_engine, ledger_db, "Commit Transaction Record", protocol="PostgreSQL/TLS")
    model.add_flow(support_staff, api_gateway, "Admin CRM Queries", protocol="HTTPS/mTLS")

    # 7. Export OWASP Threat Dragon JSON
    json_path = "diagram/generated/banking-fintech.json"
    model.to_json(json_path)
    print(f"[OK] Generated OWASP Threat Dragon JSON: {json_path}")

    # 8. Export PNG Architecture Diagram
    png_path = "diagram/generated/banking-fintech.png"
    render_png_diagram(model, output_filename=png_path)
    print(f"[OK] Generated Architecture Diagram: {png_path}")


if __name__ == "__main__":
    main()
