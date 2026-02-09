import argparse
import sys

from analyzer.checks import (
    check_open_tcp_port,
    check_deprecated_tls,
)
from analyzer.utils import (
    exit_code_from_findings,
    findings_to_json,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Security Analyzer"
    )

    parser.add_argument(
        "--host",
        required=True,
        help="Target host to analyze",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Target port (default: 443)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    findings = []

    findings.extend(check_open_tcp_port(args.host, args.port))
    findings.extend(check_deprecated_tls(args.host, args.port))

    if args.json:
        print(findings_to_json(findings))
    else:
        for f in findings:
            print(f"{f.severity.value} - {f.observation}")

    sys.exit(exit_code_from_findings(findings))


if __name__ == "__main__":
    main()
