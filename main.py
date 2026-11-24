"""Command-line entry point for IPA64-Converter."""

import argparse
import json
import sys

from core.ipa_reader import IPAError, inspect_ipa


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect an iOS IPA and detect its main executable architectures."
    )
    parser.add_argument("ipa", help="Path to the .ipa file")
    parser.add_argument(
        "--output", "-o",
        help="Optional path for a JSON report",
    )
    args = parser.parse_args()

    try:
        report = inspect_ipa(args.ipa)
    except IPAError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as output_file:
                output_file.write(rendered + "\n")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
