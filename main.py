import argparse
import os
import sys
from dotenv import load_dotenv
from utils.diagram import DiagramHandler
from utils.chatgpt import OpenAIHandler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dragon-gpt",
        description="Dragon-GPT: Automated Threat Modeling CLI for OWASP Threat Dragon diagrams using LLMs.",
    )
    # Support positional argument or optional flags (-f, -l, -i, --file, --load, --input)
    parser.add_argument(
        "filename",
        nargs="?",
        default=None,
        help="Path to the Threat Dragon JSON diagram file",
    )
    parser.add_argument(
        "--file",
        "-f",
        "-l",
        "-i",
        "--load",
        "--input",
        dest="file_opt",
        help="Alternative flag to specify the diagram file path",
    )
    parser.add_argument(
        "--api-key",
        "-k",
        dest="api_key",
        help="OpenAI API key (or set OPENAI_API_KEY in your environment/.env)",
    )
    parser.add_argument(
        "--model",
        "-m",
        default="gpt-4o-mini",
        help="LLM model name (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--base-url",
        "-u",
        dest="base_url",
        help="Custom base URL for OpenAI-compatible endpoint (e.g., Ollama: http://localhost:11434/v1)",
    )
    parser.add_argument(
        "--diagram-index",
        "-d",
        type=int,
        default=0,
        help="Index of the diagram within the file to analyze (default: 0)",
    )
    parser.add_argument(
        "--temperature",
        "-t",
        type=float,
        default=0.2,
        help="Sampling temperature for the LLM (default: 0.2)",
    )
    parser.add_argument(
        "--prompt-only",
        "--dry-run",
        "-p",
        action="store_true",
        dest="prompt_only",
        help="Generate and display the threat modeling prompt without calling the LLM API",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save output (threat model report or prompt) to specified file path",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output logging",
    )
    return parser


def resolve_filepath(args: argparse.Namespace) -> str:
    filepath = args.filename or args.file_opt
    if not filepath:
        print("[ERROR] No diagram file specified. Provide a file as an argument or via -f / -l / --file.")
        sys.exit(1)
    if not os.path.exists(filepath):
        print(f"[ERROR] Diagram file not found: {filepath}")
        sys.exit(1)
    return filepath


def main() -> None:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    diagram_path = resolve_filepath(args)

    if args.verbose:
        print(f"[INFO] Parsing Threat Dragon file: {diagram_path} (diagram index: {args.diagram_index})")

    try:
        diagram = DiagramHandler(diagram_path, diagram_index=args.diagram_index)
        prompt = diagram.make_sentence()
    except Exception as e:
        print(f"[ERROR] Failed to parse diagram: {e}")
        sys.exit(1)

    # Dry-run / prompt-only mode
    if args.prompt_only:
        print("\n" + "=" * 60)
        print("Generated Threat Modeling Prompt:")
        print("=" * 60)
        print(prompt)
        print("=" * 60)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(prompt)
            print(f"[INFO] Prompt saved to {args.output}")
        return

    # Check for API Key
    openai_key = args.api_key or os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
    base_url = args.base_url or os.getenv("OPENAI_BASE_URL")

    # If base_url is set (e.g. local Ollama), API key can default to dummy value if omitted
    if not openai_key:
        if base_url:
            openai_key = "local-key"
        else:
            print("[ERROR] OpenAI API Key is required. Set OPENAI_API_KEY in .env or pass --api-key / -k.")
            print("To inspect the generated prompt without calling OpenAI, use --prompt-only / -p.")
            sys.exit(1)

    if args.verbose:
        print(f"[INFO] Using model: {args.model}")
        if base_url:
            print(f"[INFO] Using custom base URL: {base_url}")

    print("\nSending diagram analysis to LLM for threat modeling...")
    handler = OpenAIHandler(
        api_key=openai_key,
        ai_model=args.model,
        base_url=base_url,
        temperature=args.temperature,
    )

    report = handler.do_threat_modeling(prompt)
    if report is None:
        print("[ERROR] Threat modeling failed. See logs above.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Threat Modeling Report:")
    print("=" * 60)
    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[INFO] Threat model report successfully saved to: {args.output}")


if __name__ == "__main__":
    main()