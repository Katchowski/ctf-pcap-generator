"""CTFd REST API v1 client.

Belongs to the integration layer -- must NOT import from web or engine.
Handles all HTTP communication with a CTFd instance: connection testing,
challenge creation, file upload, and flag creation.
"""

from __future__ import annotations

from pathlib import Path

import requests
import structlog

logger = structlog.get_logger()


# -- Exception hierarchy --


class CTFdError(Exception):
    """Base exception for CTFd API errors."""


class CTFdAuthError(CTFdError):
    """Authentication/authorization failure (401/403)."""


class CTFdConnectionError(CTFdError):
    """Cannot reach CTFd instance (timeout, connection refused, DNS failure)."""


class CTFdDuplicateError(CTFdError):
    """A challenge with the given name already exists on the CTFd instance."""


# -- Client --


class CTFdClient:
    """Client for CTFd REST API v1.

    Provides connection testing and the three-step challenge push flow:
    create challenge, upload PCAP file, create flag.
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {api_token}",
                "Content-Type": "application/json",
            }
        )
        self.session.allow_redirects = False

    # -- Public API --

    def test_connection(self) -> bool:
        """Verify connectivity and auth by hitting GET /api/v1/challenges.

        Uses a shorter timeout (10s) than push operations because
        connection tests should fail fast.

        Returns:
            True if the connection and authentication succeeded.

        Raises:
            CTFdAuthError: If the API token is invalid or expired (401/403).
            CTFdConnectionError: If the server is unreachable or times out.
        """
        url = f"{self.base_url}/api/v1/challenges"
        logger.info("ctfd_test_connection", url=url)

        try:
            resp = self.session.get(url, timeout=10)
        except requests.exceptions.Timeout as exc:
            logger.warning("ctfd_connection_timeout", url=url)
            raise CTFdConnectionError(
                f"Connection to {self.base_url} timed out"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            logger.warning("ctfd_connection_error", url=url)
            raise CTFdConnectionError(f"Cannot reach CTFd at {self.base_url}") from exc

        if resp.status_code in (301, 302, 303, 307, 308, 401, 403):
            logger.warning(
                "ctfd_auth_failure",
                url=url,
                status=resp.status_code,
            )
            raise CTFdAuthError("Invalid or expired API token")

        resp.raise_for_status()
        logger.info("ctfd_connection_ok", url=url)
        return True

    def push_challenge(
        self,
        *,
        name: str,
        description: str,
        category: str,
        value: int,
        state: str,
        file_path: Path,
        flag_content: str,
        hints: list[dict] | None = None,
    ) -> dict:
        """Push a complete challenge to CTFd (multi-step flow).

        1. Check for duplicate challenge name.
        2. POST /api/v1/challenges to create the challenge entry.
        3. POST /api/v1/files to upload the PCAP file.
        4. POST /api/v1/flags to create the matching flag.
        5. POST /api/v1/hints for each hint (if provided).

        Args:
            name: Challenge display name.
            description: Challenge description (Markdown supported).
            category: Challenge category string.
            value: Points awarded on solve.
            state: "hidden" or "visible".
            file_path: Path to the PCAP file to upload.
            flag_content: The flag string to create.
            hints: Optional list of {"content": str, "cost": int} dicts.

        Returns:
            Dict with "challenge_id" and "admin_url" keys.

        Raises:
            CTFdDuplicateError: If a challenge with the same name exists.
            CTFdAuthError: If the API token is invalid or expired.
            CTFdConnectionError: If the server is unreachable.
            CTFdError: If the file exceeds CTFd upload limit (413).
        """
        logger.info("ctfd_push_challenge", name=name, category=category)

        # Step 0: Check for duplicate name
        self._check_duplicate_name(name)

        # Step 1: Create challenge
        challenge_id = self._create_challenge(
            name=name,
            description=description,
            category=category,
            value=value,
            state=state,
        )

        # Step 2: Upload PCAP file
        self._upload_file(challenge_id=challenge_id, file_path=file_path)

        # Step 3: Create flag
        self._create_flag(challenge_id=challenge_id, flag_content=flag_content)

        # Step 4: Create hints (if provided)
        if hints:
            for hint in hints:
                self._create_hint(
                    challenge_id=challenge_id,
                    content=hint["content"],
                    cost=hint["cost"],
                )

        admin_url = f"{self.base_url}/admin/challenges/{challenge_id}"
        logger.info(
            "ctfd_push_complete",
            challenge_id=challenge_id,
            admin_url=admin_url,
        )
        return {"challenge_id": challenge_id, "admin_url": admin_url}

    # -- Private helpers --

    def _check_duplicate_name(self, name: str) -> None:
        """GET /api/v1/challenges and check if name already exists."""
        url = f"{self.base_url}/api/v1/challenges"
        logger.debug("ctfd_check_duplicate", name=name)

        try:
            resp = self.session.get(url, timeout=self.timeout)
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ) as exc:
            raise CTFdConnectionError(f"Cannot reach CTFd at {self.base_url}") from exc

        self._handle_response_errors(resp)

        try:
            data = resp.json().get("data", [])
        except (ValueError, requests.exceptions.JSONDecodeError):
            msg = f"Unexpected response from CTFd at {url} (not JSON)"
            raise CTFdError(msg) from None
        for challenge in data:
            if challenge.get("name") == name:
                raise CTFdDuplicateError(f"A challenge named '{name}' already exists")

    def _create_challenge(
        self,
        *,
        name: str,
        description: str,
        category: str,
        value: int,
        state: str,
    ) -> int:
        """POST /api/v1/challenges -- returns challenge_id."""
        url = f"{self.base_url}/api/v1/challenges"
        logger.info("ctfd_create_challenge", name=name)

        try:
            resp = self.session.post(
                url,
                json={
                    "name": name,
                    "description": description,
                    "category": category,
                    "value": value,
                    "state": state,
                    "type": "standard",
                },
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ) as exc:
            raise CTFdConnectionError(f"Cannot reach CTFd at {self.base_url}") from exc

        self._handle_response_errors(resp)

        data = resp.json()
        challenge_id = data["data"]["id"]
        logger.info("ctfd_challenge_created", challenge_id=challenge_id, name=name)
        return challenge_id

    def _upload_file(self, *, challenge_id: int, file_path: Path) -> None:
        """POST /api/v1/files -- multipart upload."""
        url = f"{self.base_url}/api/v1/files"
        filename = file_path.name  # Use filename only, not full path
        logger.info(
            "ctfd_upload_file",
            challenge_id=challenge_id,
            filename=filename,
        )

        try:
            with open(file_path, "rb") as f:
                # Drop Content-Type so requests sets multipart boundary
                resp = self.session.post(
                    url,
                    files={"file": (filename, f, "application/octet-stream")},
                    data={
                        "challenge_id": challenge_id,
                        "type": "challenge",
                    },
                    headers={"Content-Type": None},
                    timeout=60,  # Longer timeout for file upload
                )
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ) as exc:
            raise CTFdConnectionError(f"Cannot reach CTFd at {self.base_url}") from exc

        self._handle_response_errors(resp)
        logger.info("ctfd_file_uploaded", challenge_id=challenge_id)

    def _create_flag(self, *, challenge_id: int, flag_content: str) -> None:
        """POST /api/v1/flags -- create static flag."""
        url = f"{self.base_url}/api/v1/flags"
        logger.info("ctfd_create_flag", challenge_id=challenge_id)

        try:
            resp = self.session.post(
                url,
                json={
                    "challenge_id": challenge_id,
                    "content": flag_content,
                    "type": "static",
                    "data": "case_sensitive",
                },
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ) as exc:
            raise CTFdConnectionError(f"Cannot reach CTFd at {self.base_url}") from exc

        self._handle_response_errors(resp)
        logger.info("ctfd_flag_created", challenge_id=challenge_id)

    def _create_hint(self, *, challenge_id: int, content: str, cost: int) -> int:
        """POST /api/v1/hints -- create a hint for a challenge.

        Args:
            challenge_id: CTFd challenge ID to attach hint to.
            content: Hint text content.
            cost: Point cost to unlock the hint.

        Returns:
            The created hint's ID.
        """
        url = f"{self.base_url}/api/v1/hints"
        logger.info("ctfd_create_hint", challenge_id=challenge_id, cost=cost)

        try:
            resp = self.session.post(
                url,
                json={
                    "challenge_id": challenge_id,
                    "content": content,
                    "cost": cost,
                    "type": "standard",
                },
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ) as exc:
            raise CTFdConnectionError(f"Cannot reach CTFd at {self.base_url}") from exc

        self._handle_response_errors(resp)
        hint_id = resp.json()["data"]["id"]
        logger.info(
            "ctfd_hint_created",
            challenge_id=challenge_id,
            hint_id=hint_id,
        )
        return hint_id

    def _handle_response_errors(self, resp: requests.Response) -> None:
        """Map HTTP errors to CTFd-specific exceptions."""
        status = resp.status_code
        if status in (301, 302, 303, 307, 308):
            raise CTFdAuthError("Invalid or expired API token")
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            if status in (401, 403):
                raise CTFdAuthError("Invalid or expired API token") from exc
            if status == 413:
                raise CTFdError("PCAP file exceeds CTFd upload limit") from exc
            raise CTFdError(f"CTFd API error: {status}") from exc
