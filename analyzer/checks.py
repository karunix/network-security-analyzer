import socket
import ssl
from analyzer.models import Finding, Severity


def check_open_tcp_port(host: str, port: int, timeout: float = 3.0):
    findings = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
    except (ConnectionRefusedError, TimeoutError, OSError):
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


def check_deprecated_tls(host: str, port: int, timeout: float = 3.0):
    findings = []

    deprecated_protocols = {
        ssl.PROTOCOL_TLSv1: "TLS 1.0",
        ssl.PROTOCOL_TLSv1_1: "TLS 1.1",
    }

    for protocol, name in deprecated_protocols.items():
        try:
            context = ssl.SSLContext(protocol)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            sock.connect((host, port))
            context.wrap_socket(sock, server_hostname=host)
            sock.close()

            findings.append(
                Finding(
                    scope="TLS configuration",
                    observation=f"{name} is enabled on {host}:{port}",
                    severity=Severity.HIGH,
                    explanation=(
                        f"{name} is deprecated and vulnerable to known "
                        "cryptographic weaknesses."
                    ),
                    recommendation=(
                        f"Disable {name} and configure the server to allow "
                        "only modern TLS versions (TLS 1.2 or TLS 1.3)."
                    ),
                )
            )

        except (ssl.SSLError, ConnectionRefusedError, TimeoutError, OSError):
            continue

    return findings
