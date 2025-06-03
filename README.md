# requests-wininet

[![PyPI version](https://badge.fury.io/py/requests-wininet.svg)](https://badge.fury.io/py/requests-wininet)

A transport adapter for Python's `requests` library that uses the Windows WinINet API. This allows Python HTTP(S) requests to leverage the same proxy, authentication, and network stack as Internet Explorer and other native Windows applications.  This is designed for GUI applications that need to use the same client certificates and proxy settings as the user's Windows environment.

## Features
- Seamless integration with the `requests` library
- Provides integrated support for existing windows client certificates, similar to how Chrome and Edge handle them
- Drop-in replacement for the default `requests` transport adapter
- Uses Windows WinINet for HTTP/HTTPS
- Supports system proxy settings and authentication dialogs
- Handles chunked transfer encoding and streaming responses
- Python 3.13+

## Requirements
- Windows OS
- Python >= 3.13
- `requests >= 2.32.3, <3.0.0`

## Installation

```sh
pip install requests-wininet
```

Or with Poetry:

```sh
poetry add requests-wininet
```

## Usage

```python
import requests
from requests_wininet import WinINetAdapter

session = requests.Session()
session.mount("http://", WinINetAdapter())
session.mount("https://", WinINetAdapter())

response = session.get("https://example.com")
print(response.status_code)
print(response.headers)
print(response.text)
```

## Development & Testing

- Clone the repository and install dependencies:
  ```sh
  poetry install
  ```
- Run tests:
  ```sh
  poetry run pytest
  ```
- Run code coverage:
  ```sh
  poetry run coverage run -m pytest
  poetry run coverage report
  ```

## License
APACHE-2.0

## Author
Curtis Ruck (<ruckc@users.github.com>)
