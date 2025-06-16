# __init__.py for requests_wininet
"""Implements Window's WinINet API for python requests."""

from __future__ import annotations

import ctypes
import gzip
import logging
import urllib.parse
import zlib
from ctypes import wintypes
from dataclasses import dataclass
from typing import TYPE_CHECKING

import requests
from requests.adapters import BaseAdapter
from requests.models import PreparedRequest, Response
from requests.structures import CaseInsensitiveDict

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

# Constants for WinINet
INTERNET_OPEN_TYPE_PRECONFIG = 0
INTERNET_FLAG_RELOAD = 0x80000000
INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
INTERNET_FLAG_SECURE = 0x00800000
INTERNET_SERVICE_HTTP = 3
INTERNET_OPTION_CONNECT_TIMEOUT = 2
INTERNET_OPTION_RECEIVE_TIMEOUT = 6
HTTP_QUERY_STATUS_CODE = 19
HTTP_QUERY_RAW_HEADERS_CRLF = 22
HTTP_QUERY_STATUS_TEXT = 20
CHUNKED_ENCODING = "chunked"
MAX_HEADER_SIZE = 16 * 1024
CHUNK_SIZE = 4096
TWO = 2
ONE = 1

INTERNET_ERROR_BASE = 12000
ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED = 12044
FLAGS_IE_DIALOG = 0x00000001

wininet = ctypes.windll.wininet
kernel32 = ctypes.windll.kernel32

logger = logging.getLogger("requests_wininet.WinINetAdapter")


@dataclass
class RequestHandles:
    """Container for WinINet handles."""

    h_request: int
    h_connect: int
    h_internet: int


class WinINetAdapter(BaseAdapter):
    """A transport adapter for requests using WinINet."""

    max_header_size: int
    _hwnd: int

    def __init__(self, hwnd: int = 0, max_header_size: int = MAX_HEADER_SIZE) -> None:
        """Initialize the WinINetAdapter.

        :param hwnd: Optional handle to a window for displaying dialogs.
        """
        super().__init__()
        self._hwnd = hwnd
        self.max_header_size = max_header_size

    def _get_status_code(self, h_request: int) -> int:
        """Return the HTTP status code from a WinINet request handle."""
        code = wintypes.DWORD()
        size = wintypes.DWORD(ctypes.sizeof(code))
        if wininet.HttpQueryInfoW(h_request, HTTP_QUERY_STATUS_CODE, ctypes.byref(code), ctypes.byref(size), None):
            return code.value
        size = wintypes.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if wininet.HttpQueryInfoW(h_request, HTTP_QUERY_STATUS_CODE, buf, ctypes.byref(size), None):
            try:
                return int(buf.value)
            except ValueError:
                return 0
        else:
            return 0

    def _prepare_headers(self, request: PreparedRequest) -> str:
        headers = ""
        if request.headers:
            for k, v in request.headers.items():
                headers += f"{k}: {v}\r\n"
        return headers

    def _prepare_body(self, request: PreparedRequest) -> tuple[bytes | None, int]:
        body = request.body
        if body is not None:
            if isinstance(body, str):
                body = body.encode("utf-8")
            body_len = len(body)
        else:
            body_len = 0
        return body, body_len

    def _parse_headers(self, h_request: int) -> dict:
        parsed_headers = {}
        buf_size = 4096
        max_size = getattr(self, "max_header_size", MAX_HEADER_SIZE)
        while buf_size <= max_size:
            headers_buf = ctypes.create_unicode_buffer(buf_size)
            headers_len = wintypes.DWORD(buf_size)
            success = wininet.HttpQueryInfoW(
                h_request,
                HTTP_QUERY_RAW_HEADERS_CRLF,
                headers_buf,
                ctypes.byref(headers_len),
                None,
            )
            if success:
                raw_headers = headers_buf.value
                # Parse headers into dict
                header_lines = raw_headers.split("\r\n")[1:]  # skip status line
                for line in header_lines:
                    if not line.strip():
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        parsed_headers[k.strip()] = v.strip()
                return parsed_headers
            if headers_len.value > buf_size:
                buf_size = headers_len.value
                continue
            break
        return parsed_headers

    def _parse_reason(self, h_request: int) -> str:
        buf_size = 128
        max_size = getattr(self, "max_header_size", MAX_HEADER_SIZE)
        while buf_size <= max_size:
            reason_buf = ctypes.create_unicode_buffer(buf_size)
            reason_len = wintypes.DWORD(buf_size)
            success = wininet.HttpQueryInfoW(
                h_request,
                HTTP_QUERY_STATUS_TEXT | 0x20000000,
                reason_buf,
                ctypes.byref(reason_len),
                None,
            )
            if success:
                return reason_buf.value
            if reason_len.value > buf_size:
                buf_size = reason_len.value
                continue
            break
        return ""

    def _read_content(self, h_request: int) -> bytes:
        buffer = ctypes.create_string_buffer(CHUNK_SIZE)
        bytes_read = wintypes.DWORD(0)
        content = b""
        while True:
            success = wininet.InternetReadFile(h_request, buffer, CHUNK_SIZE, ctypes.byref(bytes_read))
            if not success or bytes_read.value == 0:
                break
            content += buffer.raw[: bytes_read.value]
        return content

    def _dechunk(self, data: bytes) -> bytes:
        i = 0
        out = b""
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j == -1:
                # Not a valid chunked encoding, return original data
                return data
            try:
                chunk_size = int(data[i:j], 16)
            except ValueError:
                # Not a valid chunk size, return original data
                return data
            if chunk_size == 0:
                break
            i = j + 2
            out += data[i : i + chunk_size]
            i += chunk_size + 2  # skip chunk and trailing \r\n
        return out

    def _set_timeouts(self, handle: int, timeout: float | tuple[float, None] | tuple[float, float] | None) -> None:
        logger.debug("Setting timeouts: %r", timeout)
        if timeout is None:
            return
        if isinstance(timeout, (int, float)):
            connect_timeout = int(timeout * 1000)
            receive_timeout = int(timeout * 1000)
        elif isinstance(timeout, tuple):
            if len(timeout) == TWO:
                connect_timeout = int(timeout[0] * 1000) if timeout[0] is not None else 0
                receive_timeout = int(timeout[1] * 1000) if timeout[1] is not None else 0
            elif len(timeout) == ONE:
                connect_timeout = int(timeout[0] * 1000)
                receive_timeout = int(timeout[0] * 1000)
            else:
                return
        else:
            return
        if connect_timeout:
            wininet.InternetSetOptionW(
                handle,
                INTERNET_OPTION_CONNECT_TIMEOUT,
                ctypes.byref(ctypes.c_int(connect_timeout)),
                ctypes.sizeof(ctypes.c_int),
            )
        if receive_timeout:
            wininet.InternetSetOptionW(
                handle,
                INTERNET_OPTION_RECEIVE_TIMEOUT,
                ctypes.byref(ctypes.c_int(receive_timeout)),
                ctypes.sizeof(ctypes.c_int),
            )

    def _open_request(self, h_connect: int, method: str, path: str, flags: int) -> int:
        h_request = wininet.HttpOpenRequestW(
            h_connect,
            method,
            path,
            None,
            None,
            None,
            flags,
            0,
        )
        if not h_request:
            errno = kernel32.GetLastError()
            wininet.InternetCloseHandle(h_connect)
            msg = f"HttpOpenRequestW failed: {errno}"
            raise requests.exceptions.ConnectionError(msg)
        return h_request

    def _send_request(self, handles: RequestHandles, headers: str, body: bytes | None, body_len: int) -> None:
        if not wininet.HttpSendRequestW(handles.h_request, headers, len(headers), body, body_len):
            self._handle_send_failure(handles, headers, body)

    def _handle_send_failure(self, handles: RequestHandles, req_headers: str, send_data: bytes | None) -> None:
        error = kernel32.GetLastError()
        if error == ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED:
            logger.warning("Error 12044 (client certificate required) for request. Prompting user with InternetErrorDlg.")
            dlg_result = wininet.InternetErrorDlg(self._hwnd, handles.h_request, error, FLAGS_IE_DIALOG, None)
            if dlg_result == 0:
                try:
                    self._send_request(handles, req_headers, send_data, len(send_data) if send_data else 0)
                except requests.exceptions.SSLError:
                    logger.exception("Failed to send request after user dialog.")
                    raise
            else:
                logger.error("User did not select a certificate or dialog failed.")
                msg = "Client certificate required, but none was provided."
                raise requests.exceptions.SSLError(msg)
        else:
            msg = f"Failed to send request. WinINet error: {error}"
            raise requests.exceptions.ConnectionError(msg)

    def _open_connection(self, h_internet: int, host: str, port: int) -> int:
        h_connect = wininet.InternetConnectW(h_internet, host, port, None, None, INTERNET_SERVICE_HTTP, 0, 0)
        if not h_connect:
            errno = kernel32.GetLastError()
            wininet.InternetCloseHandle(h_internet)
            msg = f"InternetConnectW failed: {errno}"
            raise requests.exceptions.ConnectionError(msg)
        return h_connect

    def _open_internet(self, timeout: float | tuple[float, None] | tuple[float, float] | None) -> int:
        h_internet = wininet.InternetOpenW("PythonWinINetAdapter", INTERNET_OPEN_TYPE_PRECONFIG, None, None, 0)
        if not h_internet:
            errno = kernel32.GetLastError()
            msg = f"InternetOpenW failed: {errno}"
            raise requests.exceptions.ConnectionError(msg)
        self._set_timeouts(h_internet, timeout)
        return h_internet

    def _setup_handles(
        self,
        request: PreparedRequest,
        timeout: float | tuple[float, None] | tuple[float, float] | None,
    ) -> tuple[RequestHandles, str, bytes | None, int, str, str, str, int, int]:
        url = urllib.parse.urlparse(request.url)
        host = str(url.hostname or "")
        port = url.port or (443 if url.scheme == "https" else 80)
        path = str(url.path or "/")
        if url.query:
            path = path + "?" + str(url.query)
        is_https = url.scheme == "https"
        h_internet = self._open_internet(timeout)
        h_connect = self._open_connection(h_internet, host, port)
        method = request.method or "GET"
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
        if is_https:
            flags |= INTERNET_FLAG_SECURE
        h_request = self._open_request(h_connect, method, path, flags)
        handles = RequestHandles(h_request, h_connect, h_internet)
        headers = self._prepare_headers(request)
        body, body_len = self._prepare_body(request)
        return handles, headers, body, body_len, host, path, method, flags, port

    def _parse_response(self, h_request: int) -> tuple[int, str, dict, bytes]:
        status_code = self._get_status_code(h_request)
        reason = self._parse_reason(h_request)
        parsed_headers = self._parse_headers(h_request)
        content = self._read_content(h_request)
        return status_code, reason, parsed_headers, content

    def send(  # noqa: PLR0913
        self,
        request: PreparedRequest,
        stream: bool = False,  # noqa: FBT001,FBT002
        timeout: float | tuple[float, None] | tuple[float, float] | None = None,
        verify: bool | str = True,  # noqa: FBT002,ARG002
        cert: object = None,  # noqa: ARG002
        proxies: object = None,  # noqa: ARG002
    ) -> Response:
        """Send a request using the WinINet adapter.

        :param request: The request to send.
        :param stream: Whether to stream the response.
        :param timeout: The timeout for the request.
        :param verify: Whether to verify SSL certificates.
        :param cert: Client certificate for SSL authentication.
        :param proxies: Proxies to use for the request.
        :return: The response from the server.
        """
        logger.debug("Preparing %s %s", request.method, request.url)
        handles, headers, body, body_len, host, path, method, flags, port = self._setup_handles(request, timeout)
        logger.debug("Connecting to %s:%d (HTTPS=%r)", host, port, request.url and "https" in request.url)
        logger.debug("HttpOpenRequestW: method=%s, path=%s, flags=%d", method, path, flags)
        logger.debug("Sending headers: %r", headers)
        if body is not None:
            logger.debug("Sending body of length: %d", body_len)
        self._send_request(handles, headers, body, body_len)
        logger.debug("HttpSendRequestW sent")
        status_code, reason, parsed_headers, content = self._parse_response(handles.h_request)
        logger.debug("Status code: %r", status_code)
        logger.debug("Reason: %r", reason)
        logger.debug("Parsed headers: %r", parsed_headers)
        transfer_encoding = parsed_headers.get("Transfer-Encoding", "").lower()
        content_encoding = parsed_headers.get("Content-Encoding", "").lower()
        content = self._decode_content(content, transfer_encoding, content_encoding)
        wininet.InternetCloseHandle(handles.h_request)
        wininet.InternetCloseHandle(handles.h_connect)
        wininet.InternetCloseHandle(handles.h_internet)

        def generate_content() -> Generator[bytes, None, None]:
            logger.debug("Starting streaming response generator")
            h_internet = self._open_internet(timeout)
            h_connect = self._open_connection(h_internet, host, port)
            h_request = self._open_request(h_connect, method, path, flags)
            handles_stream = RequestHandles(h_request, h_connect, h_internet)
            self._send_request(handles_stream, headers, body, body_len)
            try:
                buffer = ctypes.create_string_buffer(CHUNK_SIZE)
                bytes_read = wintypes.DWORD(0)
                while True:
                    success = wininet.InternetReadFile(h_request, buffer, CHUNK_SIZE, ctypes.byref(bytes_read))
                    if not success or bytes_read.value == 0:
                        break
                    yield buffer.raw[: bytes_read.value]
            finally:
                wininet.InternetCloseHandle(h_request)
                wininet.InternetCloseHandle(h_connect)
                wininet.InternetCloseHandle(h_internet)
            logger.debug("Streaming response generator finished")

        return self._build_response(
            request=request,
            status_code=status_code,
            reason=reason,
            parsed_headers=parsed_headers,
            content=content,
            stream=stream,
            generate_content=generate_content,
        )

    def _build_response(  # noqa: PLR0913
        self,
        request: PreparedRequest,
        status_code: int,
        reason: str,
        parsed_headers: dict,
        content: bytes,
        *,  # keyword-only arguments must follow
        stream: bool = False,
        generate_content: Callable[[], Generator[bytes, None, None]] | None = None,
    ) -> Response:
        response = Response()
        response.status_code = status_code or 200
        response.url = str(request.url) if request.url is not None else ""
        response.request = request
        response.headers = CaseInsensitiveDict(parsed_headers)
        response.reason = reason or "OK"
        response.encoding = None
        if stream:
            # _content is private, but requests uses it internally. No public setter exists.
            response._content = content if content else b""  # noqa: SLF001
            response.raw = generate_content() if generate_content else None
        else:
            response._content = content  # noqa: SLF001
            response.raw = None
        logger.debug(
            "Returning response: status=%r, reason=%r, headers=%r",
            response.status_code,
            response.reason,
            dict(response.headers),
        )
        return response

    def _decode_content(self, content: bytes, transfer_encoding: str, content_encoding: str) -> bytes:
        """Decompress and/or dechunk content as needed."""
        if content_encoding == "gzip":
            try:
                content = gzip.decompress(content)
                logger.debug("Decompressed gzip response")
            except OSError as e:
                logger.warning("Failed to decompress gzip: %r", e)
        elif content_encoding == "deflate":
            try:
                content = zlib.decompress(content)
                logger.debug("Decompressed deflate response")
            except zlib.error as e:
                logger.warning("Failed to decompress deflate: %r", e)
        elif CHUNKED_ENCODING in transfer_encoding:
            content = self._dechunk(content)
            logger.debug("Dechunked response to %d bytes", len(content))
        return content

    def close(self) -> None:
        """Close the adapter and clean up resources."""
        # No persistent resources to clean up
        return
