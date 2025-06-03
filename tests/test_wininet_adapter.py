import http.server
import logging
import socket
import socketserver
import threading
import time

import pytest
import requests

from requests_wininet import WinINetAdapter

# Enable debug logging for requests_wininet.WinINetAdapter in all tests
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests_wininet.WinINetAdapter").setLevel(logging.DEBUG)


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello, world!")


def run_server(port):
    with socketserver.TCPServer(("", port), Handler) as httpd:
        httpd.serve_forever()


@pytest.fixture(scope="module", autouse=True)
def start_server():
    # Find a random available port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        port = s.getsockname()[1]
    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(0.25)  # Give server time to start
    yield port
    # No explicit shutdown needed due to daemon thread


def test_requests_default_adapter(start_server):
    port = start_server
    resp = requests.get(f"http://localhost:{port}")
    assert resp.status_code == 200
    assert resp.text == "Hello, world!"


def test_requests_wininet_adapter(start_server):
    port = start_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}")
    assert resp.status_code == 200
    assert resp.text == "Hello, world!"


def test_streaming_wininet_adapter(start_server):
    port = start_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}", stream=True)
    content = b"".join(resp.raw)
    assert content == b"Hello, world!"


LARGE_CONTENT = b"A" * (1024 * 1024 + 123)  # 1MB + 123 bytes


class LargeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.send_header("Content-Length", str(len(LARGE_CONTENT)))
        self.end_headers()
        self.wfile.write(LARGE_CONTENT)


def run_large_server(port):
    with socketserver.TCPServer(("", port), LargeHandler) as httpd:
        httpd.serve_forever()


@pytest.fixture(scope="module")
def start_large_server():
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        port = s.getsockname()[1]
    server_thread = threading.Thread(target=run_large_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(0.25)
    yield port
    # No explicit shutdown needed


def test_large_streaming_wininet_adapter(start_large_server):
    port = start_large_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}", stream=True)
    content = b"".join(resp.raw)
    assert content == LARGE_CONTENT
    assert len(content) == len(LARGE_CONTENT)


def test_large_default_adapter(start_large_server):
    port = start_large_server
    resp = requests.get(f"http://localhost:{port}")
    assert resp.status_code == 200
    assert resp.content == LARGE_CONTENT
    assert len(resp.content) == len(LARGE_CONTENT)


class ErrorHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/404":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
        elif self.path == "/500":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in [b"chunk1", b"chunk2", b"chunk3"]:
                self.wfile.write(b"%X\r\n" % len(chunk))
                self.wfile.write(chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"POST:" + post_data)

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        put_data = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"PUT:" + put_data)

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Test-Header", "HeaderValue")
        self.end_headers()


def run_error_server(port):
    with socketserver.TCPServer(("", port), ErrorHandler) as httpd:
        httpd.serve_forever()


@pytest.fixture(scope="module")
def start_error_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        port = s.getsockname()[1]
    server_thread = threading.Thread(target=run_error_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(0.25)
    yield port


# Timeout test (connection timeout)
def test_timeout_wininet_adapter():
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    # Use a non-routable IP to force timeout
    with pytest.raises((requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, OSError)):
        session.get("http://10.255.255.1", timeout=0.001)


def test_timeout_default_adapter():
    with pytest.raises((requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, OSError)):
        requests.get("http://10.255.255.1", timeout=0.001)


# HTTP error codes
def test_404_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}/404")
    assert resp.status_code == 404
    assert b"Not Found" in resp.content


def test_500_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}/500")
    assert resp.status_code == 500
    assert b"Internal Server Error" in resp.content


def test_404_default_adapter(start_error_server):
    port = start_error_server
    resp = requests.get(f"http://localhost:{port}/404")
    assert resp.status_code == 404
    assert b"Not Found" in resp.content


def test_500_default_adapter(start_error_server):
    port = start_error_server
    resp = requests.get(f"http://localhost:{port}/500")
    assert resp.status_code == 500
    assert b"Internal Server Error" in resp.content


# Headers handling
def test_custom_request_headers_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}/", headers={"X-Custom-Header": "TestValue"})
    assert resp.status_code == 200


# Chunked transfer encoding
def test_chunked_response_default_adapter(start_error_server):
    port = start_error_server
    resp = requests.get(f"http://localhost:{port}/chunked")
    assert resp.status_code == 200
    assert b"chunk1" in resp.content


# Binary data
def test_binary_data_wininet_adapter(start_large_server):
    port = start_large_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.get(f"http://localhost:{port}")
    assert resp.content == LARGE_CONTENT


# Multiple sequential requests
def test_multiple_sequential_requests_wininet_adapter(start_server):
    port = start_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    for _ in range(5):
        resp = session.get(f"http://localhost:{port}")
        assert resp.status_code == 200
        assert resp.text == "Hello, world!"


# POST, PUT, DELETE, HEAD
def test_post_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.post(f"http://localhost:{port}/", data="data123")
    assert resp.status_code == 200
    assert b"POST:data123" in resp.content


def test_put_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.put(f"http://localhost:{port}/", data="putdata")
    assert resp.status_code == 200
    assert b"PUT:putdata" in resp.content


def test_delete_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.delete(f"http://localhost:{port}/")
    assert resp.status_code == 204


def test_head_wininet_adapter(start_error_server):
    port = start_error_server
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    resp = session.head(f"http://localhost:{port}/")
    assert resp.status_code == 200
    assert resp.headers.get("X-Test-Header") == "HeaderValue"


# Connection error
def test_connection_error_wininet_adapter():
    session = requests.Session()
    session.mount("http://", WinINetAdapter())
    with pytest.raises((requests.exceptions.ConnectionError, OSError)):
        session.get("http://localhost:65534", timeout=0.1)
