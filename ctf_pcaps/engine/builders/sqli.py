"""SQL injection builder for HTTP GET injection attack traffic.

Generates realistic SQL injection traffic: HTTP GET requests with
progressively sophisticated injection payloads in query parameters.
Progresses from tautology probes (trigger server errors) through
column enumeration (UNION SELECT with wrong/right column counts)
to data extraction (UNION SELECT from users table).

Uses TCPSession composition -- one session per HTTP request.

No Flask imports allowed in engine modules.
"""

import random
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder

# SQL injection payload progression:
# Phase 1: Tautology probes (trigger 500 errors)
# Phase 2: Column enumeration (wrong count = 400, right count = 200)
# Phase 3: Data extraction (200 with leaked data)
SQLI_PAYLOADS = [
    # Phase 1: Probing -- tautology tests (trigger errors)
    ("' OR '1'='1", "tautology"),
    ("' OR 1=1--", "tautology"),
    ("1' OR '1'='1'--", "tautology"),
    # Phase 2: Column enumeration (progressive UNION tests)
    ("' UNION SELECT NULL--", "union_fail"),
    ("' UNION SELECT NULL,NULL--", "union_fail"),
    ("' UNION SELECT NULL,NULL,NULL--", "union_success"),
    # Phase 3: Data extraction
    ("' UNION SELECT username,password,email FROM users--", "extraction"),
]


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


def _build_http_get_request(path: str, host: str) -> bytes:
    """Build a well-formed HTTP GET request."""
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode()


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


# Response templates keyed by payload result type
_RESPONSE_MAP: dict[str, tuple[int, str, str]] = {
    "tautology": (
        500,
        "Internal Server Error",
        '{"error": "Internal Server Error"}',
    ),
    "union_fail": (400, "Bad Request", '{"error": "Bad Request"}'),
    "union_success": (200, "OK", '{"results": [null, null, null]}'),
    "extraction": (
        200,
        "OK",
        '{"results": [{"username": "admin",'
        ' "password": "s3cr3t_db_pass",'
        ' "email": "admin@example.com"}]}',
    ),
}


def _get_response_for_payload(result_type: str) -> tuple[int, str, str]:
    """Return (status_code, status_text, body) for a payload result type."""
    return _RESPONSE_MAP.get(
        result_type,
        (500, "Internal Server Error", '{"error": "Unknown error"}'),
    )


@register_builder("sqli", version=1)
class SqliBuilder(BaseBuilder):
    """Builder that generates SQL injection attack traffic.

    Produces multiple TCP sessions, each containing a single HTTP
    GET request with a SQL injection payload in the query parameter.
    Payloads progress from tautology probes to UNION SELECT
    data extraction.

    Parameters:
        dst_ip: Target web server IP (default: random RFC 1918).
        dport: Target web server port (default: 80).
        target_host: HTTP Host header value (default: shop.example.com).
        path: URL path for injection target (default: /search).
        param_name: Query parameter name for injection (default: q).
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate SQL injection attack packets.

        Yields packets from multiple TCP sessions, each containing
        one HTTP GET request with an injection payload and its response.
        """
        dst_ip = params.get("dst_ip") or _random_rfc1918_ip()
        dport = params.get("dport", 80)
        target_host = params.get("target_host", "shop.example.com")
        path = params.get("path", "/search")
        param_name = params.get("param_name", "q")

        # Generate attacker IP
        src_ip = _random_rfc1918_ip()

        count = 0

        for payload, result_type in SQLI_PAYLOADS:
            session = TCPSession(src_ip=src_ip, dst_ip=dst_ip, dport=dport)

            # Handshake
            for pkt in session.handshake():
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # URL-encode the payload (encode everything including quotes)
            encoded_payload = urllib.parse.quote(payload, safe="")
            request_path = f"{path}?{param_name}={encoded_payload}"
            request = _build_http_get_request(request_path, target_host)
            for pkt in session.send_data(request, from_client=True):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # Response based on payload type
            status_code, status_text, body = _get_response_for_payload(result_type)
            response = _build_http_response(status_code, status_text, body)
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
