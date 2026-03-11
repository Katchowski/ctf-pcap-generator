"""JSON file persistence for CTFd settings and generation history.

Belongs to the integration layer -- must NOT import from web or engine.
Persists data as JSON files in the OUTPUT_DIR directory.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import structlog

logger = structlog.get_logger()

CTFD_CONFIG_FILE = "ctfd_config.json"
GENERATION_HISTORY_FILE = "generation_history.json"


# -- Private helpers --


def _load_json(path: Path, default: dict | list | None = None):
    """Load JSON from file, returning default if missing or corrupt."""
    if default is None:
        default = {}
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("json_load_failed", path=str(path))
        return default


def _save_json(path: Path, data: dict | list) -> None:
    """Write data to JSON file with readable formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8",
    )


# -- CTFd config persistence --


def load_ctfd_config(output_dir: Path) -> dict:
    """Load CTFd configuration from ctfd_config.json.

    Args:
        output_dir: Directory containing the config file.

    Returns:
        Dict with "url" and "token" keys. Returns defaults if file
        is missing or contains invalid JSON.
    """
    path = output_dir / CTFD_CONFIG_FILE
    default = {"url": "", "token": ""}
    result = _load_json(path, default)
    # Ensure expected keys exist even if file has partial data
    if not isinstance(result, dict):
        return default
    return {
        "url": result.get("url", ""),
        "token": result.get("token", ""),
    }


def save_ctfd_config(output_dir: Path, url: str, token: str) -> None:
    """Save CTFd configuration to ctfd_config.json.

    Strips trailing slashes from the URL before saving.

    Args:
        output_dir: Directory to write the config file.
        url: CTFd instance URL.
        token: CTFd API token.
    """
    path = output_dir / CTFD_CONFIG_FILE
    data = {
        "url": url.rstrip("/"),
        "token": token,
    }
    _save_json(path, data)
    logger.info("ctfd_config_saved", url=data["url"])


# -- Generation history persistence --


def load_history(output_dir: Path) -> list[dict]:
    """Load generation history from generation_history.json.

    Args:
        output_dir: Directory containing the history file.

    Returns:
        List of history entry dicts. Returns empty list if file
        is missing or contains invalid JSON.
    """
    path = output_dir / GENERATION_HISTORY_FILE
    result = _load_json(path, [])
    if not isinstance(result, list):
        return []
    return result


def save_history_entry(output_dir: Path, entry: dict) -> None:
    """Append a new entry to the generation history.

    Args:
        output_dir: Directory containing the history file.
        entry: History entry dict with keys like filename, scenario_slug,
               scenario_name, category, flag_text, difficulty, timestamp,
               file_size_bytes, pushed, push_challenge_id, etc.
    """
    path = output_dir / GENERATION_HISTORY_FILE
    history = load_history(output_dir)
    history.append(entry)
    _save_json(path, history)
    logger.info("history_entry_saved", filename=entry.get("filename"))


def update_history_push_status(
    output_dir: Path,
    filename: str,
    challenge_id: int,
    challenge_name: str,
) -> None:
    """Update the push status of a history entry by filename.

    Finds the entry matching the given filename and updates its
    push fields. If no entry matches, this is a no-op.

    Args:
        output_dir: Directory containing the history file.
        filename: PCAP filename to locate in history.
        challenge_id: CTFd challenge ID from the push response.
        challenge_name: Challenge name used in CTFd.
    """
    path = output_dir / GENERATION_HISTORY_FILE
    history = load_history(output_dir)

    updated = False
    for entry in history:
        if entry.get("filename") == filename:
            entry["pushed"] = True
            entry["push_challenge_id"] = challenge_id
            entry["push_challenge_name"] = challenge_name
            entry["push_timestamp"] = datetime.now(UTC).isoformat()
            updated = True
            break

    if updated:
        _save_json(path, history)
        logger.info(
            "history_push_status_updated",
            filename=filename,
            challenge_id=challenge_id,
        )
    else:
        logger.debug(
            "history_push_status_not_found",
            filename=filename,
        )
