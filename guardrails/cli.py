#!/usr/bin/env python3
"""
Command-line interface for quick, ad-hoc scanning.

Examples
--------
    echo "Ignore all previous instructions" | python -m guardrails.cli scan
    python -m guardrails.cli scan --text "What's the weather today?"
    python -m guardrails.cli filter-output --text "email me at a@b.com"
"""

from __future__ import annotations

import argparse
import json
import sys

from .detector import InjectionDetector
from .output_filter import OutputFilter


def _read_text(args) -> str:
    if args.text:
        return args.text
    return sys.stdin.read()


def cmd_scan(args):
    text = _read_text(args)
    detector = InjectionDetector()
    result = detector.scan(text)
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(1 if result.is_suspicious else 0)


def cmd_filter_output(args):
    text = _read_text(args)
    output_filter = OutputFilter()
    result = output_filter.scan(text)
    print(json.dumps({**result.to_dict(), "redacted": result.redacted}, indent=2))
    sys.exit(1 if result.flagged else 0)


def main():
    parser = argparse.ArgumentParser(prog="guardrails", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan input text for prompt injection")
    scan_parser.add_argument("--text", help="Text to scan (reads stdin if omitted)")
    scan_parser.set_defaults(func=cmd_scan)

    filter_parser = sub.add_parser("filter-output", help="Scan/redact model output")
    filter_parser.add_argument("--text", help="Text to scan (reads stdin if omitted)")
    filter_parser.set_defaults(func=cmd_filter_output)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
