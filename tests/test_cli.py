import pytest
from main import build_parser, resolve_filepath


def test_cli_positional_arg():
    parser = build_parser()
    args = parser.parse_args(["diagram/example/secure-cart.json"])
    assert args.filename == "diagram/example/secure-cart.json"
    assert resolve_filepath(args) == "diagram/example/secure-cart.json"


def test_cli_dash_l_flag():
    parser = build_parser()
    args = parser.parse_args(["-l", "diagram/example/secure-cart.json"])
    assert args.file_opt == "diagram/example/secure-cart.json"
    assert resolve_filepath(args) == "diagram/example/secure-cart.json"


def test_cli_dash_f_flag():
    parser = build_parser()
    args = parser.parse_args(["-f", "diagram/example/secure-cart.json", "-p"])
    assert args.file_opt == "diagram/example/secure-cart.json"
    assert args.prompt_only is True
    assert resolve_filepath(args) == "diagram/example/secure-cart.json"


def test_cli_dry_run_flag():
    parser = build_parser()
    args = parser.parse_args(["diagram/example/secure-cart.json", "--dry-run"])
    assert args.prompt_only is True


def test_cli_custom_base_url_and_model():
    parser = build_parser()
    args = parser.parse_args([
        "-f", "diagram/example/secure-cart.json",
        "-m", "llama3",
        "-u", "http://localhost:11434/v1"
    ])
    assert args.model == "llama3"
    assert args.base_url == "http://localhost:11434/v1"
