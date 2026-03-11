"""HTTP brute force login builder for credential stuffing traffic.

Generates realistic HTTP form-based login brute force traffic:
repeated POST /login attempts with different credentials, each in
a separate TCP session with a unique source port. Failed attempts
get 401 responses, the final successful attempt gets 200.

Uses TCPSession composition -- one session per login attempt.

No Flask imports allowed in engine modules.
"""

import random
from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder

# Realistic common usernames used in credential stuffing attacks
USERNAMES = [
    "admin",
    "root",
    "administrator",
    "jsmith",
    "user",
    "test",
    "guest",
    "operator",
    "service",
    "webmaster",
]

# Realistic common passwords from breach databases
PASSWORDS = [
    "password123",
    "letmein",
    "admin",
    "123456",
    "password",
    "qwerty",
    "welcome1",
    "changeme",
    "Pass@123",
    "trustno1",
    "dragon",
    "master",
    "monkey",
    "shadow",
    "sunshine",
    "iloveyou",
]


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


def _build_http_request(
    method: str,
    path: str,
    host: str,
    body: str = "",
    content_type: str = "",
) -> bytes:
    """Build a well-formed HTTP request with correct Content-Length."""
    body_bytes = body.encode()
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    if body:
        lines.append(f"Content-Length: {len(body_bytes)}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    return ("\r\n".join(lines)).encode() + body_bytes


def _build_http_response(status_code: int, status_text: str, body: str) -> bytes:
    """Build a well-formed HTTP response with correct Content-Length."""
    body_bytes = body.encode()
    lines = [
        f"HTTP/1.1 {status_code} {status_text}",
        "Content-Type: application/json",
        f"Content-Length: {len(body_bytes)}",
        "Connection: close",
        "",
        "",
    ]
    return ("\r\n".join(lines)).encode() + body_bytes


@register_builder("brute_force", version=1)
class BruteForceBuilder(BaseBuilder):
    """Builder that generates HTTP brute force login traffic.

    Produces multiple TCP sessions, each containing a single HTTP
    POST /login attempt. Failed attempts receive 401 Unauthorized,
    the final successful attempt receives 200 OK.

    Parameters:
        dst_ip: Target web server IP (default: random RFC 1918).
        dport: Target web server port (default: 80).
        target_host: HTTP Host header value (default: login.example.com).
        attempt_count: Number of failed attempts (default: 15, range 10-20).
        success_username: Username for successful login (default: admin).
        success_password: Password for successful login (default: Welcome2024!).
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate brute force login packets.

        Yields packets from multiple TCP sessions, each containing
        one HTTP POST /login request and its response.
        """
        dst_ip = params.get("dst_ip") or _random_rfc1918_ip()
        dport = params.get("dport", 80)
        target_host = params.get("target_host", "login.example.com")
        attempt_count = params.get("attempt_count", 15)
        success_username = params.get("success_username", "admin")
        success_password = params.get("success_password", "Welcome2024!")

        # Clamp attempt_count to valid range
        attempt_count = max(10, min(20, attempt_count))

        # Generate attacker IP
        src_ip = _random_rfc1918_ip()

        # Build list of failed credential pairs
        success_pair = (success_username, success_password)
        failed_creds = []
        while len(failed_creds) < attempt_count:
            username = random.choice(USERNAMES)
            password = random.choice(PASSWORDS)
            if (username, password) != success_pair:
                failed_creds.append((username, password))

        count = 0

        # Failed attempts
        for username, password in failed_creds:
            session = TCPSession(src_ip=src_ip, dst_ip=dst_ip, dport=dport)

            # Handshake
            for pkt in session.handshake():
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # HTTP POST request
            body = f"username={username}&password={password}"
            request = _build_http_request(
                "POST",
                "/login",
                target_host,
                body=body,
                content_type="application/x-www-form-urlencoded",
            )
            for pkt in session.send_data(request, from_client=True):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # HTTP 401 response
            response_body = '{"error": "Invalid credentials"}'
            response = _build_http_response(401, "Unauthorized", response_body)
            for pkt in session.send_data(response, from_client=False):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # Teardown
            for pkt in session.teardown():
                count += 1
                if callback:
                    callback(count)
                yield pkt

        # Successful attempt
        session = TCPSession(src_ip=src_ip, dst_ip=dst_ip, dport=dport)

        for pkt in session.handshake():
            count += 1
            if callback:
                callback(count)
            yield pkt

        body = f"username={success_username}&password={success_password}"
        request = _build_http_request(
            "POST",
            "/login",
            target_host,
            body=body,
            content_type="application/x-www-form-urlencoded",
        )
        for pkt in session.send_data(request, from_client=True):
            count += 1
            if callback:
                callback(count)
            yield pkt

        response_body = (
            '{"message": "Login successful", "token": "eyJhbGciOiJIUzI1NiJ9..."}'
        )
        response = _build_http_response(200, "OK", response_body)
        for pkt in session.send_data(response, from_client=False):
            count += 1
            if callback:
                callback(count)
            yield pkt

        for pkt in session.teardown():
            count += 1
            if callback:
                callback(count)
            yield pkt
