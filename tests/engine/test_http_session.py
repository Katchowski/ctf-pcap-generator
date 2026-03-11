"""Tests for shared HTTP request/response helper functions.

Verifies build_http_request and build_http_response produce
well-formed HTTP bytes with correct Content-Length, headers,
and body handling including multi-byte character support.
"""


from ctf_pcaps.engine.protocols.http_session import (
    build_http_request,
    build_http_response,
)


class TestBuildHttpRequest:
    """Tests for build_http_request helper."""

    def test_get_request_basic(self):
        """GET request starts with method, path, and Host header."""
        result = build_http_request("GET", "/search?q=test", "example.com")
        assert result.startswith(
            b"GET /search?q=test HTTP/1.1\r\nHost: example.com"
        )

    def test_get_request_no_content_length(self):
        """GET request with no body omits Content-Length header."""
        result = build_http_request("GET", "/index", "example.com")
        assert b"Content-Length" not in result

    def test_post_request_with_body(self):
        """POST with body includes Content-Type, Content-Length, and body bytes."""
        result = build_http_request(
            "POST",
            "/login",
            "example.com",
            body="user=admin",
            content_type="application/x-www-form-urlencoded",
        )
        assert b"POST /login HTTP/1.1" in result
        assert b"Content-Type: application/x-www-form-urlencoded" in result
        assert b"Content-Length: 10" in result
        # Body after double CRLF
        parts = result.split(b"\r\n\r\n", 1)
        assert len(parts) == 2
        assert parts[1] == b"user=admin"

    def test_post_request_content_length_matches_body_bytes(self):
        """Content-Length matches byte length of body, not char length."""
        result = build_http_request(
            "POST",
            "/submit",
            "example.com",
            body="user=admin&pass=pw",
            content_type="application/x-www-form-urlencoded",
        )
        body_text = "user=admin&pass=pw"
        expected_len = len(body_text.encode())
        assert f"Content-Length: {expected_len}".encode() in result

    def test_no_body_omits_content_length(self):
        """Request with empty body omits Content-Length."""
        result = build_http_request("GET", "/page", "example.com")
        assert b"Content-Length" not in result

    def test_extra_headers_included(self):
        """Extra headers dict entries are included in output."""
        result = build_http_request(
            "GET",
            "/api",
            "example.com",
            headers={"Authorization": "Bearer abc123", "Accept": "text/html"},
        )
        assert b"Authorization: Bearer abc123" in result
        assert b"Accept: text/html" in result

    def test_connection_close_header(self):
        """Request includes Connection: close header."""
        result = build_http_request("GET", "/", "example.com")
        assert b"Connection: close" in result

    def test_multibyte_body_content_length(self):
        """Content-Length is byte-accurate for multi-byte characters."""
        # Unicode snowman is 3 bytes in UTF-8
        body = "data=\u2603"
        result = build_http_request(
            "POST",
            "/submit",
            "example.com",
            body=body,
            content_type="text/plain",
        )
        expected_byte_len = len(body.encode())
        assert expected_byte_len == 8  # "data=" (5) + snowman (3)
        assert f"Content-Length: {expected_byte_len}".encode() in result

    def test_returns_bytes(self):
        """build_http_request returns bytes, not str."""
        result = build_http_request("GET", "/", "example.com")
        assert isinstance(result, bytes)


class TestBuildHttpResponse:
    """Tests for build_http_response helper."""

    def test_basic_200_response(self):
        """200 OK response starts with correct status line."""
        result = build_http_response(200, "OK", "hello")
        assert result.startswith(b"HTTP/1.1 200 OK")

    def test_content_length_matches_body(self):
        """Content-Length header matches byte length of body."""
        result = build_http_response(200, "OK", "hello")
        assert b"Content-Length: 5" in result

    def test_404_response(self):
        """404 response has correct status line."""
        result = build_http_response(404, "Not Found", "not here")
        assert b"HTTP/1.1 404 Not Found" in result

    def test_default_content_type_is_text_html(self):
        """Default content type is text/html."""
        result = build_http_response(200, "OK", "<h1>Hi</h1>")
        assert b"Content-Type: text/html" in result

    def test_custom_content_type(self):
        """Custom content_type overrides default."""
        result = build_http_response(
            200, "OK", '{"key": "val"}', content_type="application/json"
        )
        assert b"Content-Type: application/json" in result
        assert b"Content-Type: text/html" not in result

    def test_extra_headers_included(self):
        """Extra headers dict entries are included in output."""
        result = build_http_response(
            200,
            "OK",
            "body",
            headers={"X-Custom": "value", "Set-Cookie": "sid=abc"},
        )
        assert b"X-Custom: value" in result
        assert b"Set-Cookie: sid=abc" in result

    def test_body_after_double_crlf(self):
        """Body appears after double CRLF separator."""
        body_text = "response body here"
        result = build_http_response(200, "OK", body_text)
        parts = result.split(b"\r\n\r\n", 1)
        assert len(parts) == 2
        assert parts[1] == body_text.encode()

    def test_multibyte_body_content_length(self):
        """Content-Length is byte-accurate for multi-byte characters."""
        # Unicode snowman is 3 bytes in UTF-8
        body = "result=\u2603"
        result = build_http_response(200, "OK", body)
        expected_byte_len = len(body.encode())
        assert expected_byte_len == 10  # "result=" (7) + snowman (3)
        assert f"Content-Length: {expected_byte_len}".encode() in result

    def test_connection_close_header(self):
        """Response includes Connection: close header."""
        result = build_http_response(200, "OK", "ok")
        assert b"Connection: close" in result

    def test_returns_bytes(self):
        """build_http_response returns bytes, not str."""
        result = build_http_response(200, "OK", "test")
        assert isinstance(result, bytes)
