import ssl
from analyzer.checks import check_deprecated_tls
from analyzer.models import Severity


def test_deprecated_tls_detected(monkeypatch):
    class FakeContext:
        def __init__(self, protocol):
            self.protocol = protocol

        def wrap_socket(self, sock, server_hostname=None):
            return True

    def fake_create_context(protocol):
        # Simulate TLS 1.0 being accepted
        if protocol == ssl.PROTOCOL_TLSv1:
            return FakeContext(protocol)
        raise ssl.SSLError("Protocol not supported")

    monkeypatch.setattr(ssl, "SSLContext", fake_create_context)

    findings = check_deprecated_tls("example.com", 443)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "TLS 1.0" in findings[0].observation


def test_only_modern_tls_produces_no_findings(monkeypatch):
    def fake_create_context(protocol):
        raise ssl.SSLError("Protocol not supported")

    monkeypatch.setattr(ssl, "SSLContext", fake_create_context)

    findings = check_deprecated_tls("example.com", 443)

    assert findings == []
