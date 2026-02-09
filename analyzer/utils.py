from analyzer.models import Severity


def exit_code_from_findings(findings):
    if not findings:
        return 0

    severities = {f.severity for f in findings}

    if Severity.HIGH in severities:
        return 2
    if Severity.MEDIUM in severities:
        return 1

    return 0
