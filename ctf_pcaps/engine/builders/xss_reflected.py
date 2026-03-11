"""XSS reflected builder for HTTP reflected script injection traffic.

Generates realistic reflected XSS attack traffic: HTTP GET requests
with progressively sophisticated XSS payloads in a query parameter.
The server reflects the payload unescaped in the HTML response body,
culminating in a script tag that alerts the flag.

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

# XSS payload progression: (payload, status_code)
# Progresses from benign probe through script injection to flag payload.
# The last entry is the flag payload -- {flag_placeholder} is replaced.
XSS_PAYLOADS = [
    ("<b>test</b>", 200),
    ("<script>alert(1)</script>", 200),
    ("<img src=x onerror=alert(document.cookie)>", 200),
    ("<script>alert('{flag_placeholder}')</script>", 200),
]

# HTML response template -- reflects the payload verbatim (unescaped)
_HTML_TEMPLATE = (
    "<html><body><h1>Search Results</h1>"
    "<p>You searched for: {payload}</p>"
    "<p>No results found.</p></body></html>"
)

# Placeholder flag used when __flag_text is not provided
_PLACEHOLDER_FLAG = "FLAG{placeholder_xss_flag}"


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
        f".{random.randint(1, 254)}"
    )


@register_builder("xss_reflected", version=1)
class XssReflectedBuilder(BaseBuilder):
    """Builder that generates reflected XSS attack traffic.

    Produces multiple TCP sessions, each containing a single HTTP GET
    request with an XSS payload in a query parameter and an HTTP
    response that reflects the payload unescaped in an HTML page body.

    Parameters:
        src_ip: Attacker IP (default: random RFC 1918).
        dst_ip: Target web server IP (default: 10.0.0.80).
        dport: Target web server port (default: 80).
        target_host: HTTP Host header value (default: webapp.example.com).
        param_name: Query parameter name for injection (default: search).
        payload_count: Number of XSS payloads to send (default: 4).
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate reflected XSS attack packets.

        Yields packets from multiple TCP sessions, each containing
        one HTTP GET request with an XSS payload and its response.
        """
        src_ip = params.get("src_ip") or _random_rfc1918_ip()
        dst_ip = params.get("dst_ip") or _random_rfc1918_ip()
        dport = params.get("dport", 80)
        target_host = params.get("target_host", "webapp.example.com")
        param_name = params.get("param_name", "search")
        payload_count = params.get("payload_count", 4)

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

        # Select payloads up to payload_count
        payloads = XSS_PAYLOADS[:payload_count]

        count = 0

        for payload_template, status_code in payloads:
            # Replace flag placeholder in the flag payload
            payload = payload_template.replace(
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

            # HTTP GET with payload URL-encoded in query param
            encoded_payload = urllib.parse.quote(payload, safe="")
            request_path = f"/search?{param_name}={encoded_payload}"
            request = build_http_request("GET", request_path, target_host)
            for pkt in session.send_data(request, from_client=True):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # HTTP response reflecting payload unescaped in HTML body
            html_body = _HTML_TEMPLATE.format(payload=payload)
            response = build_http_response(
                status_code, "OK", html_body, content_type="text/html"
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
