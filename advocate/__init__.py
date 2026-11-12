"""
Advocate - A wrapper around the requests library for safely making HTTP requests.

This module provides a drop-in replacement for requests that prevents SSRF attacks
and other security issues when making HTTP requests on behalf of untrusted parties.
"""

__version__ = "1.0.0"

# Re-export the main API from submodules
from requests import utils
from requests.exceptions import (
    ConnectionError,
    HTTPError,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
from requests.models import PreparedRequest, Request, Response
from requests.status_codes import codes

from .adapters import ValidatingHTTPAdapter
from .addrvalidator import AddrValidator
from .api import (
    RequestsAPIWrapper,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
    session,
    Session,
)
from .exceptions import (
    AdvocateException,
    ConfigException,
    MountDisabledException,
    NameserverException,
    ProxyDisabledException,
    UnacceptableAddressException,
)

__all__ = [
    # Main API functions
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "session",
    "Session",
    "RequestsAPIWrapper",
    # Validators
    "AddrValidator",
    # Adapters
    "ValidatingHTTPAdapter",
    # Exceptions
    "AdvocateException",
    "UnacceptableAddressException",
    "NameserverException",
    "MountDisabledException",
    "ProxyDisabledException",
    "ConfigException",
    # Re-exported from requests
    "Request",
    "Response",
    "PreparedRequest",
    "utils",
    "codes",
    "RequestException",
    "Timeout",
    "URLRequired",
    "TooManyRedirects",
    "HTTPError",
    "ConnectionError",
]
