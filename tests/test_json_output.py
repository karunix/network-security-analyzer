import json
from analyzer.models import Finding, Severity
from analyzer.utils import findings_to_json


def test_findings_to_json_serialization():
    findings = [
        Finding(
            scope="Network",
            observation="TLS 1.0 enabled",
            severity=Severity.HIGH,
            explanation="Deprecated TLS version",
            recommendation="Disable TLS 1.0",
        )
    ]

    output = findings_to_json(findings)
    data = json.loads(output)

    assert "findings" in data
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["findings"][0]["observation"] == "TLS 1.0 enabled"
