import ctypes
import logging
import urllib.parse
from ctypes import wintypes
from typing import Tuple

from requests.adapters import BaseAdapter
from requests.models import PreparedRequest, Response
from requests.structures import CaseInsensitiveDict

# Constants for WinINet
INTERNET_OPEN_TYPE_PRECONFIG = 0
INTERNET_FLAG_RELOAD = 0x80000000
INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000

wininet = ctypes.windll.wininet

logger = logging.getLogger("requests_wininet.WinINetAdapter")


class WinINetAdapter(BaseAdapter):
    """A transport adapter for requests using WinINet."""

    max_header_size = 16 * 1024  # 16KB default, can be changed per instance

    def _get_status_code(self, hRequest) -> int:
        """Helper to get the HTTP status code from a WinINet request handle."""
        code = wintypes.DWORD()
        size = wintypes.DWORD(ctypes.sizeof(code))
        HTTP_QUERY_STATUS_CODE = 19
        if wininet.HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE, ctypes.byref(code), ctypes.byref(size), None):
            return code.value

        size = wintypes.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)

        if wininet.HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE, buf, ctypes.byref(size), None):
            try:
                return int(buf.value)
            except ValueError:
                pass

        return 0

    def _prepare_headers(self, request):
        headers = ""
        if request.headers:
            for k, v in request.headers.items():
                headers += f"{k}: {v}\r\n"
        return headers

    def _prepare_body(self, request):
        body = request.body
        if body is not None:
            if isinstance(body, str):
                body = body.encode("utf-8")
            body_len = len(body)
        else:
            body_len = 0
        return body, body_len

    def _parse_headers(self, hRequest):
        HTTP_QUERY_RAW_HEADERS_CRLF = 22
        parsed_headers = {}
        buf_size = 4096
        max_size = getattr(self, "max_header_size", 16 * 1024)
        while buf_size <= max_size:
            headers_buf = ctypes.create_unicode_buffer(buf_size)
            headers_len = wintypes.DWORD(buf_size)
            success = wininet.HttpQueryInfoW(
                hRequest,
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
            elif headers_len.value > buf_size:
                buf_size = headers_len.value
                continue
            else:
                break
        return parsed_headers

    def _parse_reason(self, hRequest):
        HTTP_QUERY_STATUS_TEXT = 20
        buf_size = 128
        max_size = getattr(self, "max_header_size", 16 * 1024)
        while buf_size <= max_size:
            reason_buf = ctypes.create_unicode_buffer(buf_size)
            reason_len = wintypes.DWORD(buf_size)
            success = wininet.HttpQueryInfoW(
                hRequest,
                HTTP_QUERY_STATUS_TEXT | 0x20000000,
                reason_buf,
                ctypes.byref(reason_len),
                None,
            )
            if success:
                return reason_buf.value
            elif reason_len.value > buf_size:
                buf_size = reason_len.value
                continue
            else:
                break
        return ""

    def _read_content(self, hRequest):
        buffer = ctypes.create_string_buffer(4096)
        bytes_read = wintypes.DWORD(0)
        content = b""
        while True:
            success = wininet.InternetReadFile(hRequest, buffer, 4096, ctypes.byref(bytes_read))
            if not success or bytes_read.value == 0:
                break
            content += buffer.raw[: bytes_read.value]
        return content

    def _dechunk(self, data):
        i = 0
        out = b""
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j == -1:
                break
            chunk_size = int(data[i:j], 16)
            if chunk_size == 0:
                break
            i = j + 2
            out += data[i : i + chunk_size]
            i += chunk_size + 2  # skip chunk and trailing \r\n
        return out

    def _set_timeouts(self, handle, timeout):
        logger.debug(f"Setting timeouts: {timeout}")
        if timeout is None:
            return
        if isinstance(timeout, (int, float)):
            connect_timeout = int(timeout * 1000)
            receive_timeout = int(timeout * 1000)
        elif isinstance(timeout, tuple):
            if len(timeout) == 2:
                connect_timeout = int(timeout[0] * 1000) if timeout[0] is not None else 0
                receive_timeout = int(timeout[1] * 1000) if timeout[1] is not None else 0
            elif len(timeout) == 1:
                connect_timeout = int(timeout[0] * 1000)
                receive_timeout = int(timeout[0] * 1000)
            else:
                return
        else:
            return
        if connect_timeout:
            wininet.InternetSetOptionW(handle, 2, ctypes.byref(ctypes.c_int(connect_timeout)), ctypes.sizeof(ctypes.c_int))
        if receive_timeout:
            wininet.InternetSetOptionW(handle, 6, ctypes.byref(ctypes.c_int(receive_timeout)), ctypes.sizeof(ctypes.c_int))

    def _open_request(self, hConnect, method, path, flags):
        hRequest = wininet.HttpOpenRequestW(
            hConnect,
            method,
            path,
            None,
            None,
            None,
            flags,
            0,
        )
        if not hRequest:
            wininet.InternetCloseHandle(hConnect)
            raise OSError("HttpOpenRequestW failed")
        return hRequest

    def _send_request(self, hRequest, headers, body, body_len, hConnect, hInternet):
        if not wininet.HttpSendRequestW(hRequest, headers, len(headers), body, body_len):
            wininet.InternetCloseHandle(hRequest)
            wininet.InternetCloseHandle(hConnect)
            wininet.InternetCloseHandle(hInternet)
            raise OSError("HttpSendRequestW failed")

    def _open_connection(self, hInternet, host, port):
        hConnect = wininet.InternetConnectW(hInternet, host, port, None, None, 3, 0, 0)
        if not hConnect:
            wininet.InternetCloseHandle(hInternet)
            raise OSError("InternetConnectW failed")
        return hConnect

    def _open_internet(self, timeout):
        hInternet = wininet.InternetOpenW("PythonWinINetAdapter", INTERNET_OPEN_TYPE_PRECONFIG, None, None, 0)
        if not hInternet:
            raise OSError("InternetOpenW failed")
        self._set_timeouts(hInternet, timeout)
        return hInternet

    def _build_response(self, request, status_code, reason, parsed_headers, content, stream, generate_content):
        response = Response()
        response.status_code = status_code or 200
        response.url = str(request.url) if request.url is not None else ""
        response.request = request
        response.headers = CaseInsensitiveDict(parsed_headers)
        response.reason = reason or "OK"
        response.encoding = None
        if stream:
            response._content = None
            response.raw = generate_content()
        else:
            response._content = content
            response.raw = None
        logger.debug(
            f"Returning response: status={response.status_code}, reason={response.reason}, headers={dict(response.headers)}"
        )
        return response

    def send(
        self,
        request: PreparedRequest,
        stream: bool = False,
        timeout: float | Tuple[float, None] | Tuple[float, float] | None = None,
        verify=True,
        cert=None,
        proxies=None,
    ):
        logger.debug(f"Preparing {request.method} {request.url}")
        url = urllib.parse.urlparse(request.url)
        host = url.hostname
        port = url.port or (443 if url.scheme == "https" else 80)
        path = url.path or "/"
        if url.query:
            if not isinstance(path, str):
                path = str(path)
            path = path + "?" + str(url.query)
        is_https = url.scheme == "https"
        logger.debug(f"Connecting to {host}:{port} (HTTPS={is_https})")
        hInternet = self._open_internet(timeout)
        hConnect = self._open_connection(hInternet, host, port)
        method = request.method or "GET"
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
        if is_https:
            flags |= 0x00800000  # INTERNET_FLAG_SECURE
        logger.debug(f"HttpOpenRequestW: method={method}, path={path}, flags={flags}")
        hRequest = self._open_request(hConnect, method, path, flags)
        headers = self._prepare_headers(request)
        body, body_len = self._prepare_body(request)
        logger.debug(f"Sending headers: {headers!r}")
        if body is not None:
            logger.debug(f"Sending body of length: {body_len}")
        self._send_request(hRequest, headers, body, body_len, hConnect, hInternet)
        logger.debug("HttpSendRequestW sent")
        status_code = self._get_status_code(hRequest)
        reason = self._parse_reason(hRequest)
        parsed_headers = self._parse_headers(hRequest)
        logger.debug(f"Status code: {status_code}")
        logger.debug(f"Reason: {reason}")
        logger.debug(f"Parsed headers: {parsed_headers}")
        content = self._read_content(hRequest)
        logger.debug(f"Read {len(content)} bytes from response")
        transfer_encoding = parsed_headers.get("Transfer-Encoding", "").lower()
        if "chunked" in transfer_encoding:
            content = self._dechunk(content)
            logger.debug(f"Dechunked response to {len(content)} bytes")
        wininet.InternetCloseHandle(hRequest)
        wininet.InternetCloseHandle(hConnect)
        wininet.InternetCloseHandle(hInternet)
        def generate_content():
            logger.debug("Starting streaming response generator")
            hInternet = self._open_internet(timeout)
            hConnect = self._open_connection(hInternet, host, port)
            hRequest = self._open_request(hConnect, method, path, flags)
            self._send_request(hRequest, headers, body, body_len, hConnect, hInternet)
            try:
                buffer = ctypes.create_string_buffer(4096)
                bytes_read = wintypes.DWORD(0)
                while True:
                    success = wininet.InternetReadFile(hRequest, buffer, 4096, ctypes.byref(bytes_read))
                    if not success or bytes_read.value == 0:
                        break
                    yield buffer.raw[: bytes_read.value]
            finally:
                wininet.InternetCloseHandle(hRequest)
                wininet.InternetCloseHandle(hConnect)
                wininet.InternetCloseHandle(hInternet)
            logger.debug("Streaming response generator finished")
        return self._build_response(request, status_code, reason, parsed_headers, content, stream, generate_content)

    def close(self):
        # No persistent resources to clean up
        pass
