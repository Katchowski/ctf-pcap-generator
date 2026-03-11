"""Shared HTTP request/response helpers for PCAP builders.

Provides reusable functions to construct well-formed HTTP/1.1
request and response byte sequences. Used by HTTP-based scenario
builders (brute_force, sqli, XSS, directory traversal, etc.).

Content-Length is always computed from len(body.encode()) to handle
multi-byte characters correctly.

No Flask imports allowed in engine modules.
"""


def build_http_request(
    method: str,
    path: str,
    host: str,
    body: str = "",
    content_type: str = "",
    headers: dict[str, str] | None = None,
) -> bytes:
    """Build a well-formed HTTP/1.1 request as bytes.

    Args:
        method: HTTP method (GET, POST, PUT, etc.).
        path: Request path including query string.
        host: Value for the Host header.
        body: Optional request body (empty string = no body).
        content_type: Optional Content-Type header value.
        headers: Optional extra headers as {name: value} dict.

    Returns:
        Complete HTTP request as bytes, ready for TCP payload.
    """
    body_bytes = body.encode()
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]

    if content_type:
        lines.append(f"Content-Type: {content_type}")

    if body:
        lines.append(f"Content-Length: {len(body_bytes)}")

    if headers:
        for name, value in headers.items():
            lines.append(f"{name}: {value}")

    lines.append("Connection: close")
    lines.append("")
    lines.append("")

    return ("\r\n".join(lines)).encode() + body_bytes


def build_http_response(
    status_code: int,
    status_text: str,
    body: str,
    content_type: str = "text/html",
    headers: dict[str, str] | None = None,
) -> bytes:
    """Build a well-formed HTTP/1.1 response as bytes.

    Args:
        status_code: HTTP status code (200, 404, etc.).
        status_text: Status reason phrase (OK, Not Found, etc.).
        body: Response body text.
        content_type: Content-Type header value (default: text/html).
        headers: Optional extra headers as {name: value} dict.

    Returns:
        Complete HTTP response as bytes, ready for TCP payload.
    """
    body_bytes = body.encode()
    lines = [
        f"HTTP/1.1 {status_code} {status_text}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body_bytes)}",
    ]

    if headers:
        for name, value in headers.items():
            lines.append(f"{name}: {value}")

    lines.append("Connection: close")
    lines.append("")
    lines.append("")

    return ("\r\n".join(lines)).encode() + body_bytes
