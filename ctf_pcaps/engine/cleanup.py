"""Stale PCAP file cleanup based on time-to-live.

Sweeps an output directory and deletes .pcap files older than the
configured TTL, plus orphaned .pcap.tmp files older than 1 hour.

No Flask imports allowed in engine modules.
"""

import time
from pathlib import Path

import structlog

logger = structlog.get_logger()


def sweep_stale_files(output_dir: str | Path, ttl_hours: int = 24) -> int:
    """Delete stale .pcap files and orphaned .pcap.tmp files.

    Scans the output directory and removes:
    - .pcap files with mtime older than ttl_hours
    - .pcap.tmp files with mtime older than 1 hour (orphaned temp files)

    Args:
        output_dir: Directory to sweep.
        ttl_hours: Maximum age in hours for .pcap files.

    Returns:
        Count of deleted files.
    """
    output_dir = Path(output_dir)
    if not output_dir.exists():
        return 0

    now = time.time()
    pcap_cutoff = now - (ttl_hours * 3600)
    tmp_cutoff = now - 3600  # 1 hour for orphaned temp files
    deleted = 0

    for file_path in output_dir.iterdir():
        if not file_path.is_file():
            continue

        try:
            mtime = file_path.stat().st_mtime

            if file_path.name.endswith(".pcap.tmp") and mtime < tmp_cutoff:
                file_path.unlink()
                logger.info(
                    "cleanup_deleted_orphan",
                    path=str(file_path),
                    age_hours=round((now - mtime) / 3600, 1),
                )
                deleted += 1
            elif (
                file_path.suffix == ".pcap"
                and not file_path.name.endswith(".pcap.tmp")
                and mtime < pcap_cutoff
            ):
                file_path.unlink()
                logger.info(
                    "cleanup_deleted_stale",
                    path=str(file_path),
                    age_hours=round((now - mtime) / 3600, 1),
                )
                deleted += 1

        except OSError:
            logger.warning(
                "cleanup_file_error",
                path=str(file_path),
                exc_info=True,
            )

    if deleted > 0:
        logger.info("cleanup_sweep_complete", deleted_count=deleted)

    return deleted
