"""
Example: Define a Threat Model using `pytm` and convert it into
1. OWASP Threat Dragon v2 JSON (.json)
2. High-resolution Architecture Diagram (.png)
"""
from utils.threat_dragon_builder import pytm_to_threat_dragon
from utils.diagram_png import render_png_diagram

try:
    from pytm import TM, Server, Datastore, Actor, Boundary, Dataflow
except ImportError:
    # Fallback / mock class if pytm not yet installed in active environment
    print("[INFO] 'pytm' package not installed. Run 'uv pip install pytm' to use native pytm classes.")
    TM = None


def main():
    if TM is None:
        print("[WARNING] Skipping native pytm execution because 'pytm' package is not installed.")
        return

    # 1. Define Threat Model using pytm
    tm = TM("Online Health Portal")
    tm.description = "Telehealth patient portal and electronic health records (EHR) system."

    # 2. Define Entities in pytm
    patient = Actor("Patient")
    patient.description = "Healthcare patient logging into telemedicine portal"
    patient.providesAuthentication = True

    web_portal = Server("Patient Web Portal")
    web_portal.description = "React frontend and Node.js backend"

    ehr_service = Server("EHR Backend Service")
    ehr_service.description = "HIPAA-compliant Electronic Health Record processing API"

    ehr_db = Datastore("EHR Database")
    ehr_db.description = "Encrypted database storing patient health records"
    ehr_db.isEncrypted = True
    ehr_db.storesCredentials = False

    audit_logs = Datastore("HIPAA Audit Logs")
    audit_logs.isALog = True
    audit_logs.isSigned = True

    # 3. Define Boundary in pytm
    vpc = Boundary("HIPAA Compliant Private Cloud VPC")

    # 4. Define Dataflows in pytm
    Dataflow(patient, web_portal, "Patient Login & Queries", protocol="HTTPS", isEncrypted=True)
    Dataflow(web_portal, ehr_service, "Fetch Medical History", protocol="gRPC / TLS", isEncrypted=True)
    Dataflow(ehr_service, ehr_db, "Read/Write Patient Records", protocol="PostgreSQL/TLS", isEncrypted=True)
    Dataflow(ehr_service, audit_logs, "Log Record Access", protocol="Syslog/TLS", isEncrypted=True)

    # 5. Convert pytm model to Threat Dragon Model
    td_model = pytm_to_threat_dragon(tm)

    # 6. Save Threat Dragon JSON
    json_path = "diagram/generated/health-portal-threat-dragon.json"
    td_model.to_json(json_path)
    print(f"[OK] Exported pytm model to OWASP Threat Dragon JSON: {json_path}")

    # 7. Render PNG Architecture Diagram
    png_path = "diagram/generated/health-portal-diagram.png"
    render_png_diagram(td_model, output_filename=png_path)
    print(f"[OK] Exported architecture diagram PNG: {png_path}")


if __name__ == "__main__":
    main()
