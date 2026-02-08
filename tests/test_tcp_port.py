import socket
from analyzer.checks import check_open_tcp_port
from analyzer.models import Severity


def test_open_port_produces_finding(monkeypatch):
    class FakeSocket:
        def settimeout(self, _):
            pass

        def connect(self, addr):
            # Simulate successful TCP connection
            return None

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())

    findings = check_open_tcp_port("127.0.0.1", 22)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "port 22" in findings[0].observation.lower()


def test_closed_port_produces_no_finding(monkeypatch):
    class FakeSocket:
        def settimeout(self, _):
            pass

        def connect(self, addr):
            raise ConnectionRefusedError

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())

    findings = check_open_tcp_port("127.0.0.1", 9999)

    assert findings == []
