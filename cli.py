#!/usr/bin/env python3
"""
CLI interface for the AI-Powered Secure Code Analysis Tool.

Usage:
    python cli.py <file>
    python cli.py --code "import os; os.system('ls ' + user_input)"
    cat mycode.py | python cli.py -
"""

import argparse
import json
import sys

import analyzer
from config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW


# ANSI colours
_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLOURS = {
    SEVERITY_CRITICAL: "\033[91m",   # bright red
    SEVERITY_HIGH:     "\033[31m",   # red
    SEVERITY_MEDIUM:   "\033[33m",   # yellow
    SEVERITY_LOW:      "\033[34m",   # blue
    "INFO":            "\033[37m",   # white
}


def _colour(text: str, severity: str) -> str:
    c = _COLOURS.get(severity, "")
    return f"{c}{text}{_RESET}"


def print_result(result: dict, use_colour: bool = True) -> None:
    def c(text, sev):
        return _colour(text, sev) if use_colour else text

    print()
    print(f"{_BOLD}═══ AI-Powered Secure Code Analysis ═══{_RESET if use_colour else ''}")
    print(f"Language   : {result['language']}")
    print(f"Overall Risk: {c(result['overall_risk'], result['overall_risk'])}")
    print(f"AI Analysis: {'✓ enabled' if result['ai_available'] else '✗ disabled (set OPENAI_API_KEY)'}")
    print()
    print("Summary:")
    print(f"  {result['summary']}")
    print()

    if not result["vulnerabilities"]:
        print("✓ No vulnerabilities found.")
        return

    counts = result["counts"]
    print("Findings summary:")
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, "INFO"]:
        n = counts.get(sev, 0)
        if n:
            print(f"  {c(sev, sev):20s} {n}")

    print()
    print(f"{'─' * 60}")

    for idx, v in enumerate(result["vulnerabilities"], 1):
        sev = v["severity"]
        line_info = f" (line {v['line']})" if v.get("line") else ""
        src = f"[{v['source']}]"
        cwe = f" {v['cwe']}" if v.get("cwe") else ""
        print(f"\n{idx}. {c(v['title'], sev)}{line_info}  {src}{cwe}")
        print(f"   Severity   : {c(sev, sev)}")
        print(f"   Description: {v['description']}")
        print(f"   Fix        : {v['recommendation']}")

    print(f"\n{'─' * 60}")
    print(f"Total: {result['total']} issue(s) found.")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI-Powered Secure Code Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("file", nargs="?", help="Source file to analyse (use - for stdin)")
    group.add_argument("--code", metavar="CODE", help="Inline code snippet to analyse")
    parser.add_argument("--filename", default="code.py", help="Virtual filename (determines language)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--no-colour", action="store_true", help="Disable ANSI colour output")
    args = parser.parse_args()

    code = ""
    filename = args.filename

    if args.code:
        code = args.code
    elif args.file:
        if args.file == "-":
            code = sys.stdin.read()
        else:
            try:
                with open(args.file, encoding="utf-8", errors="replace") as fh:
                    code = fh.read()
                filename = args.file
            except OSError as exc:
                print(f"Error reading file: {exc}", file=sys.stderr)
                return 1
    else:
        parser.print_help()
        return 1

    if not code.strip():
        print("No code to analyse.", file=sys.stderr)
        return 1

    result = analyzer.analyse(code, filename)
    data = result.to_dict()

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_result(data, use_colour=not args.no_colour)

    # Exit code reflects severity
    sev = data["overall_risk"]
    return 0 if sev == "INFO" else (2 if sev in (SEVERITY_CRITICAL, SEVERITY_HIGH) else 1)


if __name__ == "__main__":
    sys.exit(main())
