__version__ = "1.0.0"

from requests import utils
from requests.models import Request, Response, PreparedRequest
from requests.status_codes import codes
from requests.exceptions import (
    RequestException, Timeout, URLRequired,
    TooManyRedirects, HTTPError, ConnectionError
)

from .adapters import ValidatingHTTPAdapter
from .api import *  # noqa: F401,F403
from .api import RequestsAPIWrapper, Session
from .addrvalidator import AddrValidator
from .exceptions import UnacceptableAddressException

# Re-exported from `requests` for convenience, as this package is meant to be
# a drop-in replacement for it.
__all__ = (
    "AddrValidator",
    "HTTPError",
    "PreparedRequest",
    "Request",
    "RequestException",
    "RequestsAPIWrapper",
    "Response",
    "Session",
    "Timeout",
    "TooManyRedirects",
    "URLRequired",
    "UnacceptableAddressException",
    "ValidatingHTTPAdapter",
    "codes",
    "utils",
    "ConnectionError",
)
