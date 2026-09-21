"""Command line entry point for the Fantuan Network analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import Transcript, build_report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fantuan-analysis",
        description="Analyze a fantuan-sim transcript and write an English report.",
    )
    parser.add_argument("--input", required=True, type=Path, help="transcript JSON path")
    parser.add_argument("--out", required=True, type=Path, help="output report path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.is_file():
        print(f"error: transcript not found: {args.input}", file=sys.stderr)
        return 1

    transcript = Transcript.load(args.input)
    report = build_report(transcript)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(f"report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
