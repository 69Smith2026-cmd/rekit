from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from rekit.logging_setup import setup_logging
from rekit.reporters import to_json, to_markdown, write_report
from rekit.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rekit", description="Static-analysis toolkit for malware triage")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--format", choices=["json", "markdown", "both"], default="markdown")
    p.add_argument("--max-size", type=int, default=50 * 1024 * 1024)
    p.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging("DEBUG" if args.verbose else None)

    result = scan(args.paths, max_size=args.max_size)

    if args.output:
        write_report(result, args.output)
    else:
        if args.format in ("json", "both"):
            print(to_json(result))
        if args.format in ("markdown", "both"):
            print(to_markdown(result))

    if args.fail_on:
        from rekit.models import Severity
        if result.worst.rank >= Severity(args.fail_on).rank:
            return 2
    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
