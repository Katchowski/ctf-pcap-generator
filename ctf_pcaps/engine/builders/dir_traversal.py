"""Directory traversal builder for path traversal attack traffic.

Generates realistic directory traversal attack traffic: HTTP GET
requests with ../ path sequences attempting to read files outside
the web root. Multiple attempts show a realistic attack progression
with some returning 404/403 errors and one succeeding with 200 and
leaked file contents containing the flag.

Uses TCPSession composition -- one session per HTTP request/response
cycle (same pattern as sqli.py).

No Flask imports allowed in engine modules.
"""

import random
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.flag import encode_flag_chain
from ctf_pcaps.engine.protocols.http_session import (
    build_http_request,
    build_http_response,
)
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder

# OS-specific traversal paths with expected response codes.
# Format: (path, status_code, status_text, body_template)
# {flag_placeholder} in body is replaced with actual/placeholder flag.
LINUX_TRAVERSALS = [
    (
        "../etc/hosts",
        404,
        "Not Found",
        "<html><body><h1>404 Not Found</h1>"
        "<p>The requested file was not found.</p></body></html>",
    ),
    (
        "../../etc/shadow",
        403,
        "Forbidden",
        "<html><body><h1>403 Forbidden</h1>"
        "<p>Access denied.</p></body></html>",
    ),
    (
        "../../../etc/passwd",
        200,
        "OK",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    ),
    (
        "../../../../var/log/auth.log",
        403,
        "Forbidden",
        "<html><body><h1>403 Forbidden</h1>"
        "<p>Access denied.</p></body></html>",
    ),
    (
        "../../../../../tmp/flag.txt",
        200,
        "OK",
        "{flag_placeholder}",
    ),
]

WINDOWS_TRAVERSALS = [
    (
        "..\\windows\\system.ini",
        403,
        "Forbidden",
        "<html><body><h1>403 Forbidden</h1>"
        "<p>Access denied.</p></body></html>",
    ),
    (
        "..\\..\\windows\\win.ini",
        404,
        "Not Found",
        "<html><body><h1>404 Not Found</h1>"
        "<p>The requested file was not found.</p></body></html>",
    ),
    (
        "..\\..\\..\\Users\\admin\\Desktop\\flag.txt",
        200,
        "OK",
        "{flag_placeholder}",
    ),
]

TRAVERSALS = {
    "linux": LINUX_TRAVERSALS,
    "windows": WINDOWS_TRAVERSALS,
}

# Placeholder flag used when __flag_text is not provided
_PLACEHOLDER_FLAG = "FLAG{placeholder_dir_traversal_flag}"


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
        f".{random.randint(1, 254)}"
    )


@register_builder("dir_traversal", version=1)
class DirTraversalBuilder(BaseBuilder):
    """Builder that generates directory traversal attack traffic.

    Produces multiple TCP sessions, each containing a single HTTP GET
    request with a path traversal sequence and the server's response.
    Some attempts return 404/403, and the final successful attempt
    returns 200 with leaked file contents containing the flag.

    Parameters:
        src_ip: Attacker IP (default: random RFC 1918).
        dst_ip: Target web server IP (default: 10.0.0.80).
        dport: Target web server port (default: 80).
        target_host: HTTP Host header value (default: files.example.com).
        base_path: URL base path before traversal (default: /download).
        os_type: Target OS for file paths (default: linux).
        traversal_depth: Max traversal attempts (default: 5).
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate directory traversal attack packets.

        Yields packets from multiple TCP sessions, each containing
        one HTTP GET request with a traversal path and its response.
        """
        src_ip = params.get("src_ip") or _random_rfc1918_ip()
        dst_ip = params.get("dst_ip") or _random_rfc1918_ip()
        dport = params.get("dport", 80)
        target_host = params.get("target_host", "files.example.com")
        base_path = params.get("base_path", "/download")
        os_type = params.get("os_type", "linux")
        traversal_depth = params.get("traversal_depth", 5)

        # Resolve flag text for thematic embedding
        flag_text = params.get("__flag_text")
        flag_encoding = params.get("__flag_encoding")

        if flag_text:
            if flag_encoding:
                embedded_flag = encode_flag_chain(flag_text, flag_encoding)
            else:
                embedded_flag = flag_text
        else:
            embedded_flag = _PLACEHOLDER_FLAG

        # Select OS-specific traversal paths, limited by depth
        traversal_set = TRAVERSALS.get(os_type, LINUX_TRAVERSALS)[
            :traversal_depth
        ]

        count = 0

        for trav_path, status_code, status_text, body_template in traversal_set:
            # Replace flag placeholder in body
            body = body_template.replace(
                "{flag_placeholder}", embedded_flag
            )

            session = TCPSession(
                src_ip=src_ip, dst_ip=dst_ip, dport=dport
            )

            # Handshake
            for pkt in session.handshake():
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # HTTP GET with traversal path (URL-encode the path)
            encoded_path = urllib.parse.quote(trav_path, safe="/\\")
            request_path = f"{base_path}/{encoded_path}"
            request = build_http_request("GET", request_path, target_host)
            for pkt in session.send_data(request, from_client=True):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # HTTP response with appropriate status code
            content_type = "text/html" if status_code != 200 else "text/plain"
            # For 200 responses with HTML-like content, use text/html
            if status_code == 200 and body.startswith("<"):
                content_type = "text/html"
            response = build_http_response(
                status_code, status_text, body, content_type=content_type
            )
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
