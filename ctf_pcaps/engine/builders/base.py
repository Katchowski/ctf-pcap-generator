"""Base builder abstract class defining the builder contract.

All concrete builders must subclass BaseBuilder and implement the
build() method. Builders yield packets one at a time for streaming
to PcapWriter.

No Flask imports allowed in engine modules.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from typing import Any


class BaseBuilder(ABC):
    """Abstract base class for all PCAP builders.

    Concrete subclasses must implement build() which yields packets
    one at a time. The callback parameter allows progress reporting.
    """

    @abstractmethod
    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate packets for a scenario.

        Args:
            params: Resolved template parameters.
            steps: List of step dicts from the scenario template.
            callback: Optional progress callback fired with packet count.

        Yields:
            Scapy Packet objects (type hint is Any to avoid import-time
            coupling with Scapy).
        """
