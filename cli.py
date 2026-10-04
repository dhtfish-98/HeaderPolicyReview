"""Local command-line entry point for HeaderPolicyReview."""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import review
from local_input import read_local_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Review declared security headers in a local HTTP Archive export.")
    parser.add_argument("input", type=Path, help="local authorized input")

    parser.add_argument("--json", action="store_true", help="emit JSON findings")
    parser.add_argument("--version", action="version", version=f"%(prog)s {review.__version__}")
    args = parser.parse_args(argv)
    input_path = args.input
    try:
        data = read_local_file(input_path)
        text = data.decode("utf-8")
        findings = review.review_text(text)
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    else:
        for item in findings:
            print(f"{item['rule']}: {item['location']}: {item['note']}")
        if not findings:
            print("No review prompts for the checks implemented")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
