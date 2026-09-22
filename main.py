#!/usr/bin/env python3
"""AI Threat Intelligence Agent — CLI entry point.

Analyzes local security logs (SSH auth.log / Nginx access.log) using a
LOCAL Ollama LLM and writes a structured Markdown incident report.

Usage examples:
    python main.py --log-file data/samples/ssh_auth.log
    python main.py --log-file data/samples/nginx_access.log --model llama3
    python main.py --log-file data/samples/ssh_auth.log --output reports/custom.md
"""

from __future__ import annotations

import argparse
import datetime
import sys
from collections import Counter
from pathlib import Path

from src.ai_analyzer import OllamaConnectionError, analyze
from src.log_parser import parse_log_file
from src.report_generator import generate_report, save_report

DEFAULT_OUTPUT_DIR = "reports"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ai-threat-intelligence-agent",
        description=(
            "Analyze local security logs (SSH auth.log / Nginx access.log) "
            "with a local Ollama LLM and generate a Markdown incident report."
        ),
        epilog="All processing is fully local; no data leaves this machine.",
    )
    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to an SSH auth.log or Nginx access.log file.",
    )
    parser.add_argument(
        "--model",
        default="llama3",
        help="Ollama model to use for analysis (default: llama3).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Output path for the Markdown report "
            f"(default: {DEFAULT_OUTPUT_DIR}/incident_report_<timestamp>.md)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # 1. Parse -------------------------------------------------------------
    try:
        entries = parse_log_file(args.log_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    stats: Counter[str] = Counter(e.category for e in entries)
    print(f"[*] Parsed {args.log_file}: {len(entries)} suspicious event(s)")
    for category, count in stats.most_common():
        print(f"    - {category}: {count}")

    # 2. Analyze locally with Ollama ----------------------------------------
    analysis = None
    print(f"[*] Asking local Ollama model '{args.model}' to analyze...")
    try:
        analysis = analyze(entries, stats, model=args.model)
        print("[*] AI analysis received.")
    except OllamaConnectionError as exc:
        print(f"[!] {exc}")
        print("[!] Continuing offline - the report will note AI analysis "
              "was unavailable.")
    except RuntimeError as exc:
        print(f"[!] Ollama could not complete the analysis: {exc}")
        print("[!] Hint: ensure the model is pulled (e.g. "
              "`ollama pull llama3`).")
        print("[!] Continuing offline - the report will note AI analysis "
              "was unavailable.")

    # 3. Report --------------------------------------------------------------
    output = args.output or (
        f"{DEFAULT_OUTPUT_DIR}/incident_report_"
        f"{datetime.datetime.now():%Y%m%d_%H%M%S}.md"
    )
    meta = {
        "source_file": args.log_file,
        "model": args.model,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    markdown = generate_report(meta, entries, stats, analysis)
    saved = save_report(markdown, output)
    print(f"[+] Report written to {saved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())