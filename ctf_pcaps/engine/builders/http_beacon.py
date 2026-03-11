"""HTTP beaconing/C2 builder for malware callback traffic generation.

Generates realistic HTTP beacon traffic: periodic HTTP GET callbacks
to a C2 server with base64-encoded check-in data in query parameters.
Server responses contain base64-encoded commands disguised as CDN
JSON responses. Each beacon cycle is a separate TCP session.

Uses TCPSession for packet crafting. One TCP session per beacon cycle.

No Flask imports allowed in engine modules.
"""

import base64
import json
import random
from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder

BEACON_PATHS = [
    "/api/status",
    "/updates/check",
    "/static/config.json",
    "/cdn/health",
    "/api/v2/sync",
]

C2_COMMANDS = [
    "cmd|whoami",
    "cmd|hostname",
    "cmd|ipconfig /all",
    "cmd|net user",
    "cmd|systeminfo",
    "cmd|tasklist",
    "exfil|C:\\Users\\victim\\Documents\\credentials.txt",
    "cmd|netstat -an",
    "sleep|300",
    "cmd|dir C:\\Users\\victim\\Desktop",
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


@register_builder("http_beacon", version=1)
class HttpBeaconBuilder(BaseBuilder):
    """Builder that generates HTTP beaconing/C2 callback traffic.

    Each beacon cycle creates a new TCP session with an HTTP GET
    check-in and a JSON response containing a base64-encoded C2
    command.

    Parameters:
    - dst_ip: C2 server IP (default: random RFC 1918)
    - dport: C2 server port (default: 443)
    - c2_host: HTTP Host header (default: "cdn-static.updates.com")
    - beacon_count: Number of beacon cycles (default: 8, range 5-10)
    - session_id: Session identifier (default: random hex)
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate HTTP beacon callback traffic.

        Yields packets for multiple TCP sessions, each containing
        an HTTP GET request and JSON response with C2 commands.
        """
        dst_ip = params.get("dst_ip") or _random_rfc1918_ip()
        dport = params.get("dport", 443)
        c2_host = params.get("c2_host", "cdn-static.updates.com")
        beacon_count = params.get("beacon_count", 8)
        session_id = params.get("session_id") or (f"{random.randint(0, 0xFFFFFF):06x}")

        src_ip = _random_rfc1918_ip()
        count = 0

        for i in range(beacon_count):
            # Each beacon cycle uses a new TCP session
            session = TCPSession(src_ip=src_ip, dst_ip=dst_ip, dport=dport)

            # TCP handshake
            for pkt in session.handshake():
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # Build beacon check-in data
            beacon_data = base64.b64encode(
                f"beacon|{session_id}|cycle_{i}".encode()
            ).decode()

            # Choose beacon path
            path = BEACON_PATHS[i % len(BEACON_PATHS)]

            # Build HTTP GET request
            request = (
                f"GET {path}?id={beacon_data} HTTP/1.1\r\n"
                f"Host: {c2_host}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            # Send request (client -> server)
            for pkt in session.send_data(request.encode(), from_client=True):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # Pick C2 command and encode
            command = C2_COMMANDS[i % len(C2_COMMANDS)]
            encoded_command = base64.b64encode(command.encode()).decode()

            # Build JSON response body
            body = json.dumps(
                {"status": "ok", "data": encoded_command},
                separators=(",", ":"),
            )

            # Build HTTP 200 response
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )

            # Send response (server -> client)
            for pkt in session.send_data(response.encode(), from_client=False):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # TCP teardown
            for pkt in session.teardown():
                count += 1
                if callback:
                    callback(count)
                yield pkt
