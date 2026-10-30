from __future__ import annotations

__version__ = "2.0.0"

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
    Session,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
    session,
)
from .exceptions import UnacceptableAddressException

__all__ = (
    "AddrValidator",
    "ConnectionError",
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
    "__version__",
    "codes",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "session",
    "utils",
)
