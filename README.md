# Dragon-GPT: OWASP Threat Dragon LLM Generator 🐉

Dragon-GPT is an automated threat modeling CLI tool that extracts architecture components, data flows, and trust boundaries from **OWASP Threat Dragon** diagrams (`.json`) and generates comprehensive threat models using OpenAI or OpenAI-compatible LLMs (Ollama, vLLM, Azure OpenAI, OpenRouter, etc.).

---

## ✨ Features

- **OWASP Threat Dragon Support**: Parses Threat Dragon JSON diagram exports (STRIDE, LINDDUN, CIA, etc.).
- **Automatic Prompt Engineering**: Converts visual diagram elements (actors, processes, stores, trust boundaries, bidirectional/encrypted data flows) into structured, contextual threat modeling prompts.
- **Multiple LLM Providers**: Works with OpenAI (`gpt-4o`, `gpt-4o-mini`, `gpt-3.5-turbo`) and local/custom OpenAI-compatible endpoints (Ollama, LocalAI, vLLM).
- **Prompt-Only / Dry-Run Mode**: Inspect generated prompts and architecture descriptions without making network or API calls.
- **Flexible CLI**: Supports both positional and option flags (`-f`, `-l`, `-i`, `--file`, `--load`), multi-diagram selection (`-d`), temperature tuning, and file output export.
- **Optimized & Tested**: Robust geometric trust zone calculations, $O(1)$ component indexing, and automated test suite.

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

Or using standard Python `venv` + `pip`:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

### 2. Configure Environment

Create a `.env` file in the root directory:
```env
OPENAI_API_KEY=sk-...
# Optional:
# OPENAI_BASE_URL=http://localhost:11434/v1
```

---

## 📖 Usage Examples

### Inspect the Generated Prompt (No API Key Required)
```bash
uv run main.py -l diagram/example/secure-cart.json --prompt-only
```
or using `-p` / `--dry-run`:
```bash
uv run main.py diagram/example/secure-cart.json -p
```

### Generate Threat Model with OpenAI
```bash
uv run main.py diagram/example/secure-cart.json -m gpt-4o-mini -o threat-model-report.md
```

### Run with Local Models via Ollama
```bash
uv run main.py -f diagram/example/secure-cart.json -m llama3 -u http://localhost:11434/v1
```

### Select a Specific Diagram from Multi-Diagram Files
```bash
uv run main.py diagram/example/secure-cart.json --diagram-index 0
```

---

## 🛠️ CLI Options Reference

| Option | Shorthand | Description | Default |
|---|---|---|---|
| `filename` | Positional | Path to Threat Dragon JSON diagram file | - |
| `--file`, `--load`, `--input` | `-f`, `-l`, `-i` | Flag to pass the diagram file path | - |
| `--prompt-only`, `--dry-run` | `-p` | Output generated prompt only without LLM API calls | `False` |
| `--api-key` | `-k` | OpenAI API key (or `OPENAI_API_KEY` in `.env`) | - |
| `--model` | `-m` | LLM model identifier | `gpt-4o-mini` |
| `--base-url` | `-u` | Custom OpenAI-compatible endpoint URL | - |
| `--diagram-index` | `-d` | Zero-based index of diagram to analyze | `0` |
| `--temperature` | `-t` | Model sampling temperature | `0.2` |
| `--output` | `-o` | Output file path to save report or prompt | stdout |
| `--verbose` | `-v` | Enable detailed logging | `False` |

---

## 🧪 Running Tests

Run the test suite using `pytest`:
```bash
uv run pytest
```
