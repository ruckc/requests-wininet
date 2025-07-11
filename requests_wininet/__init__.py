# __init__.py for requests_wininet
"""Implements Window's WinINet API for python requests."""

from __future__ import annotations

import contextlib
import ctypes
import logging
from os import error
import urllib.parse
from ctypes import wintypes
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from types import TracebackType

import pywincrypt32
import requests
from requests.adapters import BaseAdapter
from requests.models import PreparedRequest, Response
from requests.structures import CaseInsensitiveDict
from urllib3.response import HTTPResponse
from io import BytesIO

class GeneratorWrapper:
    """Wraps a generator to make it look like a file-like object for urllib3."""
    
    def __init__(self, generator):
        self.generator = generator
        self.buffer = b""
        self.closed = False
        
    def read(self, size=-1):
        if self.closed:
            return b""
            
        if size == -1:
            # Read all remaining data
            chunks = [self.buffer]
            self.buffer = b""
            try:
                for chunk in self.generator:
                    chunks.append(chunk)
                self.closed = True
                return b"".join(chunks)
            except StopIteration:
                self.closed = True
                return b"".join(chunks)
        else:
            # Read up to size bytes
            while len(self.buffer) < size:
                try:
                    chunk = next(self.generator)
                    self.buffer += chunk
                except StopIteration:
                    self.closed = True
                    break
            
            if len(self.buffer) <= size:
                result = self.buffer
                self.buffer = b""
                return result
            else:
                result = self.buffer[:size]
                self.buffer = self.buffer[size:]
                return result
    
    def readline(self, size=-1):
        # Simple implementation for compatibility
        return self.read(size)
    
    def close(self):
        self.closed = True
        
    def __iter__(self):
        return self
        
    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            return next(self.generator)
        except StopIteration:
            self.closed = True
            raise

# Constants for WinINet and CryptoAPI
INTERNET_OPEN_TYPE_PRECONFIG = 0
INTERNET_FLAG_RELOAD = 0x80000000
INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
INTERNET_FLAG_SECURE = 0x00800000
INTERNET_SERVICE_HTTP = 3
INTERNET_OPTION_CONNECT_TIMEOUT = 2
INTERNET_OPTION_RECEIVE_TIMEOUT = 6
INTERNET_OPTION_CLIENT_CERT_CONTEXT = 84
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
FLAGS_IE_DIALOG = (
    0x00000001 | 0x00000002 | 0x00000004
)  # FLAGS_ERROR_UI_FILTER_FOR_ERRORS | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA

CERT_STORE_PROV_SYSTEM = 10
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
CERT_FIND_HASH = 2
X509_ASN_ENCODING = 0x00000001

logger = logging.getLogger("requests_wininet.WinINetAdapter")


class WinINetAPI:
    """Encapsulates all WinINet and CryptoAPI ctypes logic and handle management."""

    def __init__(self) -> None:
        """Initialize WinINetAPI."""
        self.wininet = ctypes.windll.wininet
        self.kernel32 = ctypes.windll.kernel32

    class Handle:
        """Context manager for WinINet handles."""

        def __init__(self, api: WinINetAPI, handle: int) -> None:
            """Initialize Handle context manager."""
            self.api = api
            self.handle = handle

        def __enter__(self) -> int:
            """Enter context, return handle."""
            return self.handle

        def __exit__(
            self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
        ) -> None:
            """Exit context, close handle."""
            if self.handle:
                self.api.wininet.InternetCloseHandle(self.handle)

    def open_internet(self, timeout: float | tuple[float, None] | tuple[float, float] | None) -> Handle:
        """Open an internet handle with timeout."""
        h_internet = self.wininet.InternetOpenW("PythonWinINetAdapter", INTERNET_OPEN_TYPE_PRECONFIG, None, None, 0)
        if not h_internet:
            errno = self.kernel32.GetLastError()
            msg = f"InternetOpenW failed: {errno}"
            raise requests.exceptions.ConnectionError(msg)
        self.set_timeouts(h_internet, timeout)
        return self.Handle(self, h_internet)

    def open_connection(self, h_internet: int, host: str, port: int) -> Handle:
        """Open a connection handle."""
        h_connect = self.wininet.InternetConnectW(h_internet, host, port, None, None, INTERNET_SERVICE_HTTP, 0, 0)
        if not h_connect:
            errno = self.kernel32.GetLastError()
            self.wininet.InternetCloseHandle(h_internet)
            msg = f"InternetConnectW failed: {errno}"
            raise requests.exceptions.ConnectionError(msg)
        return self.Handle(self, h_connect)

    def open_request(self, h_connect: int, method: str, path: str, flags: int) -> Handle:
        """Open a request handle."""
        h_request = self.wininet.HttpOpenRequestW(h_connect, method, path, None, None, None, flags, 0)
        if not h_request:
            errno = self.kernel32.GetLastError()
            self.wininet.InternetCloseHandle(h_connect)
            msg = f"HttpOpenRequestW failed: {errno}"
            raise requests.exceptions.ConnectionError(msg)
        return self.Handle(self, h_request)

    def set_timeouts(self, handle: int, timeout: float | tuple[float, None] | tuple[float, float] | None) -> None:
        """Set connection and receive timeouts on a handle."""
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
            self.wininet.InternetSetOptionW(
                handle,
                INTERNET_OPTION_CONNECT_TIMEOUT,
                ctypes.byref(ctypes.c_int(connect_timeout)),
                ctypes.sizeof(ctypes.c_int),
            )
        if receive_timeout:
            self.wininet.InternetSetOptionW(
                handle,
                INTERNET_OPTION_RECEIVE_TIMEOUT,
                ctypes.byref(ctypes.c_int(receive_timeout)),
                ctypes.sizeof(ctypes.c_int),
            )


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
        self.api = WinINetAPI()

    def _get_status_code(self, h_request: int) -> int:
        """Return the HTTP status code from a WinINet request handle."""
        code = wintypes.DWORD()
        size = wintypes.DWORD(ctypes.sizeof(code))
        if self.api.wininet.HttpQueryInfoW(h_request, HTTP_QUERY_STATUS_CODE, ctypes.byref(code), ctypes.byref(size), None):
            return code.value
        size = wintypes.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if self.api.wininet.HttpQueryInfoW(h_request, HTTP_QUERY_STATUS_CODE, buf, ctypes.byref(size), None):
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
            success = self.api.wininet.HttpQueryInfoW(
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
            success = self.api.wininet.HttpQueryInfoW(
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
            success = self.api.wininet.InternetReadFile(h_request, buffer, CHUNK_SIZE, ctypes.byref(bytes_read))
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

    def send(  # noqa: PLR0913
        self,
        request: PreparedRequest,
        stream: bool = False,  # noqa: FBT001,FBT002
        timeout: float | tuple[float, None] | tuple[float, float] | None = None,
        verify: bool | str = True,  # noqa: ARG002,FBT002
        cert: object = None,
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
        url = urllib.parse.urlparse(request.url)
        host = str(url.hostname or "")
        port = url.port or (443 if url.scheme == "https" else 80)
        path = str(url.path or "/")
        if url.query:
            path = path + "?" + str(url.query)
        is_https = url.scheme == "https"
        method = request.method or "GET"
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
        if is_https:
            flags |= INTERNET_FLAG_SECURE
        headers = self._prepare_headers(request)
        body, body_len = self._prepare_body(request)
        cert_ctx = None
        with (
            self.api.open_internet(timeout) as h_internet,
            self.api.open_connection(h_internet, host, port) as h_connect,
            self.api.open_request(h_connect, method, path, flags) as h_request,
        ):
            cert_ctx_mgr = (
                pywincrypt32.with_certificate("MY", cert)
                if cert and isinstance(cert, str) and request.url and request.url.lower().startswith("https")
                else contextlib.nullcontext()
            )
            with cert_ctx_mgr as cert_ctx:
                if cert_ctx:
                    logger.debug(
                        "Setting client certificate context for request to %s", pywincrypt32.get_cert_subject(cert_ctx)
                    )
                    self.api.wininet.InternetSetOptionW(
                        h_request,
                        INTERNET_OPTION_CLIENT_CERT_CONTEXT,
                        cert_ctx,
                        ctypes.sizeof(cert_ctx),
                    )
                self._send_request(h_request, headers, body, body_len)
                status_code = self._get_status_code(h_request)
                reason = self._parse_reason(h_request)
                parsed_headers = self._parse_headers(h_request)
                content = self._read_content(h_request)
                # Let requests handle both transfer and content encoding

        def generate_content() -> Generator[bytes, None, None]:
            logger.debug("Starting streaming response generator")
            # Raw data will be yielded - let requests handle content/transfer encoding
            with (
                self.api.open_internet(timeout) as h_internet,
                self.api.open_connection(h_internet, host, port) as h_connect,
                self.api.open_request(h_connect, method, path, flags) as h_request,
            ):
                self._send_request(h_request, headers, body, body_len)
                buffer = ctypes.create_string_buffer(CHUNK_SIZE)
                bytes_read = wintypes.DWORD(0)
                while True:
                    success = self.api.wininet.InternetReadFile(h_request, buffer, CHUNK_SIZE, ctypes.byref(bytes_read))
                    if not success or bytes_read.value == 0:
                        break
                    yield buffer.raw[: bytes_read.value]
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

    def _send_request(self, h_request: int, headers: str, body: bytes | None, body_len: int) -> None:
        if not self.api.wininet.HttpSendRequestW(h_request, headers, len(headers), body, body_len):
            self._handle_send_failure(h_request, headers, body)

    def _log_cert_context(self, h_request: int, label: str) -> None:
        """Log whether a client certificate context is set on the request handle."""
        import ctypes
        from ctypes import wintypes

        # Prepare buffer for CERT_CONTEXT pointer
        buf = (ctypes.c_void_p)()
        buf_size = wintypes.DWORD(ctypes.sizeof(buf))
        res = self.api.wininet.InternetQueryOptionW(
            h_request,
            INTERNET_OPTION_CLIENT_CERT_CONTEXT,
            ctypes.byref(buf),
            ctypes.byref(buf_size),
        )
        err = self.api.kernel32.GetLastError()
        if res and buf.value:
            logger.debug("[%s] CERT_CONTEXT is set: 0x%x", label, buf.value)
        else:
            logger.debug("[%s] CERT_CONTEXT is NOT set or query failed (res=%r, %d)", label, res, err)

    def _handle_send_failure(self, h_request: int, req_headers: str, send_data: bytes | None) -> None:
        error = self.api.kernel32.GetLastError()
        if error == ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED:
            self._log_cert_context(h_request, "before InternetErrorDlg")
            logger.warning("Error 12044 (client certificate required) for request. Prompting user with InternetErrorDlg.")
            dlg_result = self.api.wininet.InternetErrorDlg(self._hwnd, h_request, error, FLAGS_IE_DIALOG, None)
            self._log_cert_context(h_request, "after InternetErrorDlg")
            if dlg_result == 0:
                try:
                    self._send_request(h_request, req_headers, send_data, len(send_data) if send_data else 0)
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

    def _build_response(  # noqa: PLR0913
        self,
        request: PreparedRequest,
        status_code: int,
        reason: str,
        parsed_headers: dict,
        content: bytes,
        *,
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
        
        # Create an HTTPResponse object that requests can use for content encoding handling
        if stream and generate_content:
            # For streaming, wrap the generator in a file-like object
            wrapped_generator = GeneratorWrapper(generate_content())
            response.raw = HTTPResponse(
                body=wrapped_generator,
                headers=parsed_headers,
                status=status_code,
                reason=reason,
                preload_content=False,
                decode_content=True,
                original_response=None
            )
            # Mark as not consumed so requests will handle streaming properly
            response.raw._body = None
        else:
            # For non-streaming, create an HTTPResponse with the content
            response.raw = HTTPResponse(
                body=BytesIO(content),
                headers=parsed_headers,
                status=status_code,
                reason=reason,
                preload_content=False,
                decode_content=True,
                original_response=None
            )
            # Mark as not consumed so requests will handle content encoding
            response.raw._body = None
        
        logger.debug(
            "Returning response: status=%r, reason=%r, headers=%r",
            response.status_code,
            response.reason,
            dict(response.headers),
        )
        return response
