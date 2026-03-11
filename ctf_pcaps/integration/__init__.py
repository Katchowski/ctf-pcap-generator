"""CTFd integration layer.

Provides the CTFd REST API client and JSON persistence helpers.
This layer has no dependencies on the web or engine layers.
"""

from ctf_pcaps.integration.ctfd_client import (
    CTFdAuthError,
    CTFdClient,
    CTFdConnectionError,
    CTFdDuplicateError,
    CTFdError,
)
from ctf_pcaps.integration.persistence import (
    load_ctfd_config,
    load_history,
    save_ctfd_config,
    save_history_entry,
    update_history_push_status,
)

__all__ = [
    "CTFdAuthError",
    "CTFdClient",
    "CTFdConnectionError",
    "CTFdDuplicateError",
    "CTFdError",
    "load_ctfd_config",
    "load_history",
    "save_ctfd_config",
    "save_history_entry",
    "update_history_push_status",
]
