"""Tests for CTFdClient -- CTFd REST API v1 integration."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ctf_pcaps.integration.ctfd_client import (
    CTFdAuthError,
    CTFdClient,
    CTFdConnectionError,
    CTFdDuplicateError,
    CTFdError,
)


@pytest.fixture()
def client():
    """Create a CTFdClient with a test URL and token."""
    return CTFdClient(
        base_url="https://ctfd.example.com",
        api_token="test-token-123",
    )


class TestBaseUrlNormalization:
    """Verify base_url trailing slash is stripped."""

    def test_trailing_slash_stripped(self):
        c = CTFdClient(
            base_url="https://ctfd.example.com/",
            api_token="token",
        )
        assert c.base_url == "https://ctfd.example.com"

    def test_no_trailing_slash_unchanged(self):
        c = CTFdClient(
            base_url="https://ctfd.example.com",
            api_token="token",
        )
        assert c.base_url == "https://ctfd.example.com"

    def test_multiple_trailing_slashes_stripped(self):
        c = CTFdClient(
            base_url="https://ctfd.example.com///",
            api_token="token",
        )
        assert c.base_url == "https://ctfd.example.com"


class TestSessionHeaders:
    """Verify session header configuration."""

    def test_authorization_header_set(self, client):
        assert client.session.headers["Authorization"] == "Token test-token-123"

    def test_content_type_set_on_session(self, client):
        assert client.session.headers["Content-Type"] == "application/json"


class TestTestConnection:
    """Tests for test_connection method."""

    def test_connection_success(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
            result = client.test_connection()

        assert result is True
        mock_get.assert_called_once_with(
            "https://ctfd.example.com/api/v1/challenges",
            timeout=10,
        )

    def test_connection_auth_failure_401(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with (
            patch.object(client.session, "get", return_value=mock_resp),
            pytest.raises(CTFdAuthError),
        ):
            client.test_connection()

    def test_connection_auth_failure_403(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with (
            patch.object(client.session, "get", return_value=mock_resp),
            pytest.raises(CTFdAuthError),
        ):
            client.test_connection()

    def test_connection_timeout(self, client):
        with (
            patch.object(
                client.session,
                "get",
                side_effect=requests.exceptions.Timeout,
            ),
            pytest.raises(CTFdConnectionError),
        ):
            client.test_connection()

    def test_connection_refused(self, client):
        with (
            patch.object(
                client.session,
                "get",
                side_effect=requests.exceptions.ConnectionError,
            ),
            pytest.raises(CTFdConnectionError),
        ):
            client.test_connection()

    def test_connection_uses_short_timeout(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
            client.test_connection()

        _, kwargs = mock_get.call_args
        assert kwargs["timeout"] == 10


class TestPushChallenge:
    """Tests for push_challenge method."""

    def _setup_push_mocks(self, client):
        """Configure mocks for a successful push_challenge flow."""
        # GET /api/v1/challenges for duplicate check - no duplicates
        challenges_resp = MagicMock()
        challenges_resp.status_code = 200
        challenges_resp.json.return_value = {"success": True, "data": []}
        challenges_resp.raise_for_status = MagicMock()

        # POST /api/v1/challenges
        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.json.return_value = {
            "success": True,
            "data": {"id": 42, "name": "Test Challenge"},
        }
        create_resp.raise_for_status = MagicMock()

        # POST /api/v1/files
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.json.return_value = {
            "success": True,
            "data": [{"id": 1, "location": "files/test.pcap"}],
        }
        upload_resp.raise_for_status = MagicMock()

        # POST /api/v1/flags
        flag_resp = MagicMock()
        flag_resp.status_code = 200
        flag_resp.json.return_value = {
            "success": True,
            "data": {"id": 1, "challenge_id": 42},
        }
        flag_resp.raise_for_status = MagicMock()

        return challenges_resp, create_resp, upload_resp, flag_resp

    def test_push_challenge_success(self, client, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp, create_resp, upload_resp, flag_resp = self._setup_push_mocks(
            client
        )

        with (
            patch.object(
                client.session,
                "get",
                return_value=challenges_resp,
            ),
            patch.object(
                client.session,
                "post",
                side_effect=[create_resp, upload_resp, flag_resp],
            ),
        ):
            result = client.push_challenge(
                name="Test Challenge",
                description="A test challenge",
                category="Network Attack",
                value=250,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
            )

        assert result["challenge_id"] == 42
        assert result["admin_url"] == "https://ctfd.example.com/admin/challenges/42"

    def test_push_challenge_three_sequential_posts(self, client, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp, create_resp, upload_resp, flag_resp = self._setup_push_mocks(
            client
        )

        with (
            patch.object(
                client.session,
                "get",
                return_value=challenges_resp,
            ),
            patch.object(
                client.session,
                "post",
                side_effect=[create_resp, upload_resp, flag_resp],
            ) as mock_post,
        ):
            client.push_challenge(
                name="Test Challenge",
                description="A test challenge",
                category="Network Attack",
                value=250,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
            )

        assert mock_post.call_count == 3

    def test_push_challenge_duplicate_name(self, client, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp = MagicMock()
        challenges_resp.status_code = 200
        challenges_resp.json.return_value = {
            "success": True,
            "data": [
                {"id": 10, "name": "Existing Challenge"},
            ],
        }
        challenges_resp.raise_for_status = MagicMock()

        with (
            patch.object(client.session, "get", return_value=challenges_resp),
            pytest.raises(CTFdDuplicateError),
        ):
            client.push_challenge(
                name="Existing Challenge",
                description="Duplicate",
                category="Network Attack",
                value=100,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{dup}",
            )

    def test_push_challenge_auth_failure(self, client, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        # Duplicate check passes
        challenges_resp = MagicMock()
        challenges_resp.status_code = 200
        challenges_resp.json.return_value = {"success": True, "data": []}
        challenges_resp.raise_for_status = MagicMock()

        # Create challenge returns 401
        create_resp = MagicMock()
        create_resp.status_code = 401
        http_error = requests.exceptions.HTTPError(response=create_resp)
        create_resp.raise_for_status.side_effect = http_error

        with (
            patch.object(client.session, "get", return_value=challenges_resp),
            patch.object(client.session, "post", return_value=create_resp),
            pytest.raises(CTFdAuthError),
        ):
            client.push_challenge(
                name="Test",
                description="Test",
                category="Network Attack",
                value=100,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
            )

    def test_push_challenge_file_upload_413(self, client, tmp_path):
        pcap_file = tmp_path / "big.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        # Duplicate check passes
        challenges_resp = MagicMock()
        challenges_resp.status_code = 200
        challenges_resp.json.return_value = {"success": True, "data": []}
        challenges_resp.raise_for_status = MagicMock()

        # Create challenge succeeds
        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.json.return_value = {
            "success": True,
            "data": {"id": 42},
        }
        create_resp.raise_for_status = MagicMock()

        # File upload returns 413
        upload_resp = MagicMock()
        upload_resp.status_code = 413
        http_error = requests.exceptions.HTTPError(response=upload_resp)
        upload_resp.raise_for_status.side_effect = http_error

        with (
            patch.object(client.session, "get", return_value=challenges_resp),
            patch.object(
                client.session,
                "post",
                side_effect=[create_resp, upload_resp],
            ),
            pytest.raises(CTFdError, match="upload limit"),
        ):
            client.push_challenge(
                name="Big Challenge",
                description="Too large",
                category="Network Attack",
                value=100,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{big}",
            )

    def test_file_upload_uses_filename_only(self, client, tmp_path):
        pcap_file = tmp_path / "test_scan.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp, create_resp, upload_resp, flag_resp = self._setup_push_mocks(
            client
        )

        with (
            patch.object(
                client.session,
                "get",
                return_value=challenges_resp,
            ),
            patch.object(
                client.session,
                "post",
                side_effect=[create_resp, upload_resp, flag_resp],
            ) as mock_post,
        ):
            client.push_challenge(
                name="Test",
                description="Test",
                category="Network Attack",
                value=100,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
            )

        # Second post call is the file upload
        upload_call = mock_post.call_args_list[1]
        files_arg = upload_call[1]["files"]
        # files={"file": (filename, f, content_type)}
        uploaded_filename = files_arg["file"][0]
        assert uploaded_filename == "test_scan.pcap"
        assert "/" not in uploaded_filename
        assert "\\" not in uploaded_filename


class TestCreateHint:
    """Tests for _create_hint method."""

    def test_create_hint_sends_correct_payload(self, client):
        """_create_hint sends correct JSON to /api/v1/hints."""
        hint_resp = MagicMock()
        hint_resp.status_code = 200
        hint_resp.json.return_value = {
            "success": True,
            "data": {"id": 7, "challenge_id": 42},
        }
        hint_resp.raise_for_status = MagicMock()

        with patch.object(client.session, "post", return_value=hint_resp) as mock_post:
            result = client._create_hint(
                challenge_id=42,
                content="Look at DNS traffic.",
                cost=25,
            )

        assert result == 7
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"] == {
            "challenge_id": 42,
            "content": "Look at DNS traffic.",
            "cost": 25,
            "type": "standard",
        }
        assert "/api/v1/hints" in mock_post.call_args[0][0]

    def test_create_hint_connection_error(self, client):
        """_create_hint raises CTFdConnectionError on timeout."""
        with (
            patch.object(
                client.session,
                "post",
                side_effect=requests.exceptions.Timeout,
            ),
            pytest.raises(CTFdConnectionError),
        ):
            client._create_hint(challenge_id=42, content="hint", cost=10)


class TestPushChallengeWithHints:
    """Tests for push_challenge with hints parameter."""

    def _setup_push_mocks_with_hints(self, hint_count=2):
        """Create mocks for a push flow with hint creation."""
        # GET /api/v1/challenges
        challenges_resp = MagicMock()
        challenges_resp.status_code = 200
        challenges_resp.json.return_value = {"success": True, "data": []}
        challenges_resp.raise_for_status = MagicMock()

        # POST /api/v1/challenges
        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.json.return_value = {
            "success": True,
            "data": {"id": 42, "name": "Test"},
        }
        create_resp.raise_for_status = MagicMock()

        # POST /api/v1/files
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.json.return_value = {
            "success": True,
            "data": [{"id": 1}],
        }
        upload_resp.raise_for_status = MagicMock()

        # POST /api/v1/flags
        flag_resp = MagicMock()
        flag_resp.status_code = 200
        flag_resp.json.return_value = {
            "success": True,
            "data": {"id": 1, "challenge_id": 42},
        }
        flag_resp.raise_for_status = MagicMock()

        # POST /api/v1/hints responses
        hint_resps = []
        for i in range(hint_count):
            hint_resp = MagicMock()
            hint_resp.status_code = 200
            hint_resp.json.return_value = {
                "success": True,
                "data": {"id": 10 + i, "challenge_id": 42},
            }
            hint_resp.raise_for_status = MagicMock()
            hint_resps.append(hint_resp)

        post_responses = [create_resp, upload_resp, flag_resp, *hint_resps]
        return challenges_resp, post_responses

    def test_push_with_hints_creates_hints(self, client, tmp_path):
        """push_challenge with hints creates hints after flag."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp, post_responses = self._setup_push_mocks_with_hints(
            hint_count=2
        )

        hints = [
            {"content": "Look at DNS traffic.", "cost": 25},
            {"content": "Filter dns.qry.name.", "cost": 50},
        ]

        with (
            patch.object(client.session, "get", return_value=challenges_resp),
            patch.object(
                client.session, "post", side_effect=post_responses
            ) as mock_post,
        ):
            result = client.push_challenge(
                name="Test",
                description="Test",
                category="Network Attack",
                value=250,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
                hints=hints,
            )

        # 3 base posts + 2 hint posts = 5
        assert mock_post.call_count == 5
        assert result["challenge_id"] == 42

    def test_push_without_hints_backward_compatible(self, client, tmp_path):
        """push_challenge without hints still works (no hint creation)."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp, post_responses = self._setup_push_mocks_with_hints(
            hint_count=0
        )

        with (
            patch.object(client.session, "get", return_value=challenges_resp),
            patch.object(
                client.session, "post", side_effect=post_responses
            ) as mock_post,
        ):
            result = client.push_challenge(
                name="Test",
                description="Test",
                category="Network Attack",
                value=250,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
            )

        # Only 3 base posts (no hints)
        assert mock_post.call_count == 3
        assert result["challenge_id"] == 42

    def test_push_with_hints_none_backward_compatible(self, client, tmp_path):
        """push_challenge with hints=None skips hint creation."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

        challenges_resp, post_responses = self._setup_push_mocks_with_hints(
            hint_count=0
        )

        with (
            patch.object(client.session, "get", return_value=challenges_resp),
            patch.object(
                client.session, "post", side_effect=post_responses
            ) as mock_post,
        ):
            result = client.push_challenge(
                name="Test",
                description="Test",
                category="Network Attack",
                value=250,
                state="hidden",
                file_path=pcap_file,
                flag_content="flag{test}",
                hints=None,
            )

        assert mock_post.call_count == 3
        assert result["challenge_id"] == 42


class TestExceptionHierarchy:
    """Verify exception class hierarchy."""

    def test_auth_error_is_ctfd_error(self):
        assert issubclass(CTFdAuthError, CTFdError)

    def test_connection_error_is_ctfd_error(self):
        assert issubclass(CTFdConnectionError, CTFdError)

    def test_duplicate_error_is_ctfd_error(self):
        assert issubclass(CTFdDuplicateError, CTFdError)

    def test_ctfd_error_is_exception(self):
        assert issubclass(CTFdError, Exception)
