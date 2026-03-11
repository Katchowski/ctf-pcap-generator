"""Demo TCP builder using TCPSession protocol helper.

Generates a complete TCP session: three-way handshake, data transfer
based on scenario steps, and four-way teardown.

No Flask imports allowed in engine modules.
"""

from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder


@register_builder("simple_tcp", version=1)
class SimpleTCPBuilder(BaseBuilder):
    """Builder that generates a complete TCP session.

    Supports the following step actions:
    - send_data: Send payload data from client to server.

    Parameters:
    - dst_ip: Destination IP (default "10.0.0.2")
    - dport: Destination port (default 80)
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate TCP session packets.

        Yields handshake, per-step data packets, and teardown.
        """
        session = TCPSession(
            dst_ip=params.get("dst_ip", "10.0.0.2"),
            dport=int(params.get("dport", 80)),
        )

        count = 0

        # Handshake
        for pkt in session.handshake():
            count += 1
            if callback:
                callback(count)
            yield pkt

        # Process steps
        for step in steps:
            if step.get("action") == "send_data":
                payload = step.get("payload", "")
                if isinstance(payload, str):
                    payload = payload.encode()
                for pkt in session.send_data(payload):
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
