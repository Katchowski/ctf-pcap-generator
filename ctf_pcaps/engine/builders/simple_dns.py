"""Demo DNS/UDP builder using DNSQueryHelper protocol helper.

Generates DNS query/response pairs for domain lookups defined
in scenario steps.

No Flask imports allowed in engine modules.
"""

from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.protocols.dns_query import DNSQueryHelper
from ctf_pcaps.engine.registry import register_builder


@register_builder("simple_dns", version=1)
class SimpleDNSBuilder(BaseBuilder):
    """Builder that generates DNS query/response pairs.

    Supports the following step actions:
    - dns_lookup: Generate a DNS query and response for a domain.

    Parameters:
    - dns_server: DNS server IP (default "8.8.8.8")
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate DNS query/response packets.

        For each dns_lookup step, yields a query packet followed by
        a response packet with a generated answer IP.
        """
        helper = DNSQueryHelper(
            dst_ip=params.get("dns_server", "8.8.8.8"),
        )

        count = 0

        for step in steps:
            if step.get("action") == "dns_lookup":
                domain = step.get("domain", "example.com")
                answer_ip = step.get("answer_ip", "93.184.216.34")

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
