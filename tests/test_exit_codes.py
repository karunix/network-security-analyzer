from analyzer.models import Finding, Severity
from analyzer.utils import exit_code_from_findings


def test_no_findings_exit_zero():
    assert exit_code_from_findings([]) == 0


def test_medium_exit_one():
    findings = [
        Finding(
            scope="test",
            observation="medium issue",
            severity=Severity.MEDIUM,
            explanation="",
            recommendation="",
        )
    ]
    assert exit_code_from_findings(findings) == 1


def test_high_exit_two():
    findings = [
        Finding(
            scope="test",
            observation="high issue",
            severity=Severity.HIGH,
            explanation="",
            recommendation="",
        )
    ]
    assert exit_code_from_findings(findings) == 2
