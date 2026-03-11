"""Streaming PcapWriter wrapper with atomic rename and size limits.

Writes packets one-by-one to a temporary file via Scapy PcapWriter,
then atomically renames to a UUID-based final filename on success.
Temp files are cleaned up on any failure.

No Flask imports allowed in engine modules.
"""

import os
import tempfile
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import structlog
from scapy.utils import PcapWriter

logger = structlog.get_logger()


class LimitsExceededError(Exception):
    """Raised when packet count or file size limits are exceeded."""


def stream_to_pcap(
    packets: Iterator,
    output_dir: str | Path,
    max_packets: int = 100_000,
    max_size_mb: int = 100,
    callback: Callable | None = None,
    callback_interval: int = 100,
) -> tuple[Path, int]:
    """Stream packets to a PCAP file with limits and atomic write.

    Writes packets one-by-one via PcapWriter (no memory accumulation),
    enforces packet count and file size limits, and uses atomic rename
    to ensure partial/corrupt PCAPs are never visible.

    Args:
        packets: Iterator yielding Scapy Packet objects.
        output_dir: Directory for the output PCAP file.
        max_packets: Maximum number of packets allowed.
        max_size_mb: Maximum file size in megabytes.
        callback: Optional function called with current packet count.
        callback_interval: How often to fire the callback (every N packets).

    Returns:
        Tuple of (final_path, packet_count).

    Raises:
        LimitsExceededError: If packet count or file size exceeds limits.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    final_name = f"{uuid.uuid4().hex[:8]}.pcap"
    final_path = output_dir / final_name
    max_size_bytes = max_size_mb * 1024 * 1024

    logger.info(
        "pcap_generation_start",
        output_dir=str(output_dir),
        max_packets=max_packets,
        max_size_mb=max_size_mb,
    )

    # Create temp file in same directory for atomic rename.
    # We only need the path; the file itself is opened by PcapWriter.
    with tempfile.NamedTemporaryFile(
        dir=output_dir, suffix=".pcap.tmp", delete=False
    ) as fd:
        tmp_path = Path(fd.name)

    packet_count = 0
    try:
        with PcapWriter(str(tmp_path), sync=False) as writer:
            for pkt in packets:
                writer.write(pkt)
                packet_count += 1

                if callback and packet_count % callback_interval == 0:
                    callback(packet_count)

                if packet_count > max_packets:
                    raise LimitsExceededError(
                        f"Packet count limit exceeded: {max_packets}"
                    )

                if tmp_path.stat().st_size > max_size_bytes:
                    raise LimitsExceededError(
                        f"File size limit exceeded: {max_size_mb}MB"
                    )

        # Atomic rename -- final file appears only on success
        os.replace(str(tmp_path), str(final_path))

        file_size = final_path.stat().st_size
        logger.info(
            "pcap_generation_complete",
            path=str(final_path),
            packet_count=packet_count,
            file_size_bytes=file_size,
        )

    except Exception:
        # Clean up temp file on ANY failure
        tmp_path.unlink(missing_ok=True)
        logger.error(
            "pcap_generation_failed",
            packet_count=packet_count,
            tmp_path=str(tmp_path),
        )
        raise

    return final_path, packet_count
