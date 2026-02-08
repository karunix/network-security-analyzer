import socket
from analyzer.models import Finding, Severity


def check_open_tcp_port(host: str, port: int, timeout: float = 3.0):
    findings = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
    except (ConnectionRefusedError, TimeoutError, OSError):
        # Port is closed or unreachable → no finding
        return findings
    else:
        findings.append(
            Finding(
                scope="Network exposure",
                observation=f"TCP port {port} is open on {host}",
                severity=Severity.MEDIUM,
                explanation=(
                    "An open TCP port indicates a listening service that may "
                    "increase the attack surface."
                ),
                recommendation=(
                    "Close the port if the service is not required, or restrict "
                    "access using firewall rules."
                ),
            )
        )
    finally:
        sock.close()

    return findings
