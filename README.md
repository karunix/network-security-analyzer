# Network Security Analyzer

A lightweight network security analyzer that identifies common
exposure and misconfiguration risks using deterministic, testable checks.
## Features

- Detects open TCP ports
- Detects deprecated TLS versions (TLS 1.0, TLS 1.1)
- Human-readable and JSON output
- Exit codes suitable for CI/CD integration
- Deterministic, fast unit tests

## Installation

```bash
git clone git@github.com:karunix/network-security-analyzer.git
cd network-security-analyzer
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Usage
python main.py --host example.com
python main.py --host example.com --json
Exit Codes
Exit Code	Meaning
0	No findings
1	Medium severity findings
2	High severity findings
Security Philosophy
This tool focuses on deterministic detection of misconfiguration rather
than noisy scanning. It is designed to be safe, testable, and automation-friendly.

Limitations
Not a port scanner

Does not exploit services

Does not enumerate ciphers (yet)

License
MIT
