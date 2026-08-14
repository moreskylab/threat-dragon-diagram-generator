# Dragon-GPT: Cloud Native OWASP Threat Dragon LLM Platform 🐉☁️

Dragon-GPT is an enterprise-ready, **Cloud-Native Automated Threat Modeling Platform** that connects **Architecture Diagrams As Code**, **pytm**, **OWASP Threat Dragon**, and **Large Language Models (OpenAI, Gemini, Ollama, vLLM)**.

---

## ✨ Features

- **🌐 Cloud Studio Web UI**: Interactive, dark-mode cybersecurity dashboard with drag-and-drop JSON upload, live architecture SVG/PNG diagrams, and one-click AI threat analysis.
- **⚡ Cloud Native REST API (FastAPI)**: Microservice endpoints for diagram generation, prompt dry-runs, STRIDE/LINDDUN threat reporting, and custom model synthesis.
- **📊 Cloud Native Telemetry**: Kubernetes health probes (`/healthz`, `/readyz`), and Prometheus metrics exporter (`/metrics`).
- **🐳 Multi-Stage Docker & Compose**: Hardened non-root production Dockerfile with Graphviz pre-installed, and Docker Compose with Prometheus and local Ollama stack.
- **☸️ Kubernetes & Helm Ready**: Complete K8s manifests (`k8s/`) and production Helm chart (`charts/dragon-gpt/`) with HPA autoscaling and Ingress TLS.
- **🤖 Multi-LLM Provider Support**: Compatible with OpenAI (`gpt-4o`, `gpt-4o-mini`), Google Gemini, Anthropic, or local offline LLMs via Ollama/vLLM.
- **📜 Diagram as Code to OWASP Threat Dragon**: Define architecture programmatically in Python and export 100% compliant OWASP Threat Dragon v2 JSON (`.json`).

---

## 🚀 Quick Start

### 1. Run the Cloud Studio Locally

Using [`uv`](https://docs.astral.sh/uv/):
```bash
# Clone the repository
git clone https://github.com/moreskylab/threat-dragon-diagram-generator.git
cd threat-dragon-diagram-generator

# Install dependencies and launch the server
uv sync
uv run uvicorn api.main:app --reload --port 8000
```

Open your browser at:
- **Cloud Studio UI**: [http://localhost:8000/app](http://localhost:8000/app)
- **Interactive OpenAPI (Swagger) Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Prometheus Metrics**: [http://localhost:8000/metrics](http://localhost:8000/metrics)
- **Liveness Probe**: [http://localhost:8000/healthz](http://localhost:8000/healthz)

---

### 2. Run with Docker Compose

Spin up the complete containerized stack (Dragon-GPT API + Prometheus Telemetry):

```bash
docker compose up -d
```

- Dragon-GPT Web UI & API: `http://localhost:8000`
- Prometheus Dashboard: `http://localhost:9090`

---

### 3. Deploy to Kubernetes

Deploy using `kustomize`:
```bash
kubectl apply -k k8s/
```

Or deploy using the official **Helm Chart**:
```bash
helm install dragon-gpt charts/dragon-gpt/ \
  --set secrets.openaiApiKey="sk-..." \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host="threat-model.internal"
```

---

## 📡 Cloud Native REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/healthz` | `GET` | Kubernetes Liveness Probe |
| `/readyz` | `GET` | Kubernetes Readiness Probe |
| `/metrics` | `GET` | Prometheus telemetry metrics |
| `/api/v1/templates` | `GET` | List pre-built architecture reference templates |
| `/api/v1/templates/{id}` | `GET` | Get template JSON and rendered SVG diagram |
| `/api/v1/prompt` | `POST` | Inspect LLM threat prompt (Dry-run without API key) |
| `/api/v1/analyze` | `POST` | Execute AI threat modeling and return STRIDE report |
| `/api/v1/render` | `POST` | Render Threat Dragon JSON into SVG or PNG |
| `/api/v1/custom` | `POST` | Build custom Threat Dragon model from nodes and flows |

---

## 🎨 CLI & Python Script Usage

### 1. Generating Threat Dragon JSON & Architecture Diagrams
```bash
# Generate E-Commerce architecture diagram and Threat Dragon JSON
uv run generate.py -t ecommerce -j diagram/generated/secure-cart.json -p diagram/generated/secure-cart.png

# Generate Cloud Microservices architecture
uv run generate.py -t microservices -j diagram/generated/microservices.json -p diagram/generated/microservices.png
```

### 2. CLI Threat Modeling
```bash
# Dry-run prompt inspection
uv run main.py -f diagram/generated/secure-cart.json -p

# Run AI threat modeling with OpenAI
uv run main.py -f diagram/generated/secure-cart.json -o report.md
```

---

## 🧪 Testing

Run the automated test suite:
```bash
uv run pytest -v tests/
```

---

## 🛡️ License

Apache 2.0 / MIT License.
