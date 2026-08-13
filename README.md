# Dragon-GPT: OWASP Threat Dragon LLM Generator 🐉

Dragon-GPT is an automated threat modeling toolkit that connects **Python Diagrams As Code**, **pytm**, **OWASP Threat Dragon**, and **LLMs (OpenAI, Gemini, Ollama, vLLM)**.

---

## ✨ Features

- **Diagram as Code to OWASP Threat Dragon**: Define your architecture in Python and export 100% compliant OWASP Threat Dragon JSON diagrams (`.json`).
- **Visual Architecture Diagrams (PNG)**: Generate visual architecture diagrams using the `diagrams` (`mingrammer/diagrams`) and `pytm` Python packages.
- **pytm Integration**: Seamlessly convert `pytm` Threat Models into Threat Dragon format.
- **Automated Threat Modeling via LLMs**: Send visual or code-defined architectures to LLMs (OpenAI `gpt-4o`, Google `gemini`, local `ollama/llama3`, etc.) to produce categorized STRIDE / LINDDUN / CIA threat modeling reports.
- **Dry-Run & Prompt Inspection**: Inspect the generated threat analysis prompt without requiring an active API key.

---

## 🚀 Quick Start

### 1. Installation

Using [`uv`](https://docs.astral.sh/uv/) (recommended):
```bash
# Clone the repository
git clone https://github.com/moreskylab/threat-dragon-diagram-generator.git
cd threat-dragon-diagram-generator

# Run directly with uv
uv run main.py --help
```

Or with `pip`:
```bash
pip install -e .
```

### 2. Configure Environment (`.env`)

Create a `.env` file:
```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini # or google/gemini-3.1-flash-lite, llama3, etc.
# Optional:
# OPENAI_BASE_URL=http://localhost:11434/v1
```

> **Note on PNG rendering**: To generate PNG images with `diagrams` / `Graphviz`, ensure Graphviz is installed on your system:
> - **Windows**: `winget install Graphviz.Graphviz` or `choco install graphviz`
> - **macOS**: `brew install graphviz`
> - **Linux**: `sudo apt install graphviz`

---

## 🎨 1. Generating Threat Dragon JSON & PNG Diagrams

You can generate both an **OWASP Threat Dragon JSON file** and an **Architecture Diagram PNG** directly from Python or using the `generate.py` CLI tool:

### Using the CLI Generator
```bash
# Generate SecureCart E-Commerce model (JSON + PNG)
uv run generate.py -t ecommerce -j diagram/generated/secure-cart.json -p diagram/generated/secure-cart.png

# Generate Cloud Microservices template
uv run generate.py -t microservices -j diagram/generated/microservices.json
```

### Defining Models Programmatically in Python
```python
from utils.threat_dragon_builder import ThreatDragonModel
from utils.diagram_png import render_png_diagram

# 1. Initialize Threat Model
model = ThreatDragonModel(title="Payment Gateway", diagram_type="STRIDE")

# 2. Add Components
user = model.add_actor("Customer", "Mobile client", provides_authentication=True)
api = model.add_process("API Gateway", "Reverse proxy & JWT validator")
db = model.add_store("Ledger DB", "PostgreSQL database", is_encrypted=True)

# 3. Add Trust Boundary
model.add_trust_boundary("PCI-DSS Secure Subnet")

# 4. Add Data Flows
model.add_flow(user, api, "HTTPS Requests", protocol="TLS 1.3", is_public_network=True)
model.add_flow(api, db, "DB Transactions", protocol="Postgres/TLS", is_encrypted=True)

# 5. Export to OWASP Threat Dragon JSON & PNG Diagram
model.to_json("diagram/generated/payment-gateway.json")
render_png_diagram(model, output_filename="diagram/generated/payment-gateway.png")
```

---

## 🤖 2. Generating Threat Models with LLMs

Once you have an OWASP Threat Dragon diagram (either exported from Threat Dragon or generated with Python), run `main.py` to analyze it:

### Inspect Prompt Only (Dry-Run, No API Key Required)
```bash
uv run main.py -l diagram/example/secure-cart.json -p
```

### Run with OpenAI / Gemini
```bash
# OpenAI GPT-4o-mini
uv run main.py diagram/example/secure-cart.json -m gpt-4o-mini -o threat-model-report.md

# Gemini (via OpenAI-compatible endpoint or OpenRouter)
uv run main.py diagram/example/secure-cart.json -m google/gemini-3.1-flash-lite -o threat-model-report.md
```

### Run with Local Models (Ollama / vLLM)
```bash
uv run main.py -f diagram/example/secure-cart.json -m llama3 -u http://localhost:11434/v1
```

---

## 🛠️ CLI Reference

### `generate.py`
| Option | Shorthand | Description | Default |
|---|---|---|---|
| `--template` | `-t` | Architecture template (`ecommerce`, `microservices`) | `ecommerce` |
| `--output-json` | `-j` | Path to save OWASP Threat Dragon JSON | `diagram/generated/threat-dragon-model.json` |
| `--output-png` | `-p` | Path to save PNG architecture diagram | `diagram/generated/architecture-diagram.png` |
| `--no-png` | - | Skip PNG diagram rendering | `False` |
| `--threat-model` | `-m` | Automatically trigger LLM threat modeling after generation | `False` |

### `main.py`
| Option | Shorthand | Description | Default |
|---|---|---|---|
| `filename` | Positional | Path to Threat Dragon JSON diagram file | - |
| `--file`, `--load`, `--input` | `-f`, `-l`, `-i` | Flag to pass diagram file path | - |
| `--prompt-only`, `--dry-run` | `-p` | Print generated prompt without API call | `False` |
| `--api-key` | `-k` | API key (or `OPENAI_API_KEY` in `.env`) | - |
| `--model` | `-m` | Model name | `gpt-4o-mini` |
| `--base-url` | `-u` | Base URL for API endpoint | - |
| `--diagram-index` | `-d` | Diagram index for multi-diagram files | `0` |
| `--output` | `-o` | Output file path for report | stdout |

---

## 🧪 Running Tests

```bash
uv run pytest
```
