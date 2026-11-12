"""
advocate.api
~~~~~~~~~~~~

This module implements the Requests API, largely a copy/paste from `requests`
itself.

:copyright: (c) 2015 by Jordan Milne.
:license: Apache2, see LICENSE for more details.

"""
import hashlib
import pickle
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

import requests
from requests import Session as RequestsSession
from requests.models import Response

from .adapters import ValidatingHTTPAdapter
from .addrvalidator import AddrValidator
from .exceptions import MountDisabledException


class Session(RequestsSession):
    """Convenience wrapper around `requests.Session` set up for `advocate`ing.
    
    This session class automatically applies Advocate's validation to all
    HTTP requests made through it.
    
    Attributes:
        validator: The AddrValidator instance used for validation.
    """

    __attrs__ = RequestsSession.__attrs__ + ["validator"]
    DEFAULT_VALIDATOR: Optional[AddrValidator] = None
    """
    User-replaceable default validator to use for all Advocate sessions,
    includes sessions created by advocate.get()
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an Advocate session.
        
        Args:
            *args: Positional arguments passed to requests.Session.
            **kwargs: Keyword arguments. The 'validator' keyword argument is used
                     to specify the AddrValidator instance.
        """
        self.validator = kwargs.pop("validator", None) or self.DEFAULT_VALIDATOR
        adapter_kwargs = kwargs.pop("_adapter_kwargs", {})

        # `Session.__init__()` calls `mount()` internally, so we need to allow
        # it temporarily
        self.__mount_allowed = True
        RequestsSession.__init__(self, *args, **kwargs)

        # Drop any existing adapters
        self.adapters = OrderedDict()

        self.mount("http://", ValidatingHTTPAdapter(validator=self.validator, **adapter_kwargs))
        self.mount("https://", ValidatingHTTPAdapter(validator=self.validator, **adapter_kwargs))
        self.__mount_allowed = False

    def mount(self, *args: Any, **kwargs: Any) -> None:
        """Wrapper around `mount()` to prevent a protection bypass.
        
        Args:
            *args: Positional arguments for mount.
            **kwargs: Keyword arguments for mount.
            
        Raises:
            MountDisabledException: If mount is called after session initialization.
        """
        if self.__mount_allowed:
            super().mount(*args, **kwargs)
        else:
            raise MountDisabledException(
                "mount() is disabled to prevent protection bypasses"
            )


def session(*args: Any, **kwargs: Any) -> Session:
    """Create a new Advocate session.
    
    Args:
        *args: Positional arguments passed to Session.
        **kwargs: Keyword arguments passed to Session.
        
    Returns:
        A new Session instance.
    """
    return Session(*args, **kwargs)


def request(method: str, url: str, **kwargs: Any) -> Response:
    """Constructs and sends a Request object.

    :param method: method for the new Request object.
    :param url: URL for the new Request object.
    :param params: (optional) Dictionary or bytes to be sent in the query string for the Request.
    :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the Request.
    :param json: (optional) json data to send in the body of the Request.
    :param headers: (optional) Dictionary of HTTP Headers to send with the Request.
    :param cookies: (optional) Dict or CookieJar object to send with the Request.
    :param files: (optional) Dictionary of file-like-objects for multipart encoding upload.
    :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) How long to wait for the server to send data
        before giving up, as a float, or a connect/read timeout tuple.
    :type timeout: float or tuple
    :param allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE redirect following is allowed.
    :type allow_redirects: bool
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    :param verify: (optional) if True, the SSL cert will be verified. A CA_BUNDLE path can also be provided.
    :param stream: (optional) if False, the response content will be immediately downloaded.
    :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, (cert, key) pair.
    :return: Response object
    :rtype: requests.Response

    Usage::

      >>> import advocate
      >>> req = advocate.request('GET', 'http://httpbin.org/get')
      <Response [200]>
    """

    validator = kwargs.pop("validator", None)
    with Session(validator=validator) as sess:
        response = sess.request(method=method, url=url, **kwargs)
    return response


def get(url: str, **kwargs: Any) -> Response:
    """Sends a GET request.

    :param url: URL for the new Request object.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    kwargs.setdefault('allow_redirects', True)
    return request('get', url, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    """Sends a OPTIONS request.

    :param url: URL for the new Request object.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    kwargs.setdefault('allow_redirects', True)
    return request('options', url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    """Sends a HEAD request.

    :param url: URL for the new Request object.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    kwargs.setdefault('allow_redirects', False)
    return request('head', url, **kwargs)


def post(url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
    """Sends a POST request.

    :param url: URL for the new Request object.
    :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the Request.
    :param json: (optional) json data to send in the body of the Request.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    return request('post', url, data=data, json=json, **kwargs)


def put(url: str, data: Any = None, **kwargs: Any) -> Response:
    """Sends a PUT request.

    :param url: URL for the new Request object.
    :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the Request.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    return request('put', url, data=data, **kwargs)


def patch(url: str, data: Any = None, **kwargs: Any) -> Response:
    """Sends a PATCH request.

    :param url: URL for the new Request object.
    :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the Request.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    return request('patch', url, data=data, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    """Sends a DELETE request.

    :param url: URL for the new Request object.
    :param kwargs: Optional arguments that request takes.
    :return: Response object
    :rtype: requests.Response
    """

    return request('delete', url, **kwargs)


class RequestsAPIWrapper:
    """Provides a `requests.api`-like interface with a specific validator.
    
    This class allows you to create a custom requests-like API with a
    pre-configured validator, making it easier to apply consistent
    security policies across your application.
    
    Attributes:
        validator: The AddrValidator instance used for validation.
        Session: A Session class that uses the wrapper's validator.
        request: The request function with the wrapper's validator.
        get: The get function with the wrapper's validator.
        post: The post function with the wrapper's validator.
        put: The put function with the wrapper's validator.
        patch: The patch function with the wrapper's validator.
        delete: The delete function with the wrapper's validator.
        head: The head function with the wrapper's validator.
        options: The options function with the wrapper's validator.
    """

    # Due to how the classes are dynamically constructed pickling may not work
    # correctly unless loaded within the same interpreter instance.
    # Enable at your peril.
    SUPPORT_WRAPPER_PICKLING = False

    def __init__(self, validator: AddrValidator) -> None:
        """Initialize the RequestsAPIWrapper.
        
        Args:
            validator: The AddrValidator instance to use for all requests.
        """
        # Do this here to avoid circular import issues
        try:
            from . import futures
            if futures.FuturesSession is not None:
                have_requests_futures = True
            else:
                have_requests_futures = False
        except (ImportError, AttributeError):
            have_requests_futures = False

        self.validator = validator
        outer_self = self

        class _WrappedSession(Session):
            """An `advocate.Session` that uses the wrapper's blacklist.

            The wrapper is meant to be a transparent replacement for `requests`,
            so people should be able to subclass `wrapper.Session` and still
            get the desired validation behaviour.
            """
            DEFAULT_VALIDATOR = outer_self.validator

        self._make_wrapper_cls_global(_WrappedSession)
        self.Session = _WrappedSession  # type: ignore[assignment]

        if have_requests_futures:
            from . import futures
            # Get the FuturesSession class from the module
            FuturesSessionClass = futures.FuturesSession
            if FuturesSessionClass is not None:
                class _WrappedFuturesSession(FuturesSessionClass):
                    """Like _WrappedSession, but for `FuturesSession`s."""
                    DEFAULT_VALIDATOR = outer_self.validator
                self._make_wrapper_cls_global(_WrappedFuturesSession)
                self.FuturesSession = _WrappedFuturesSession  # type: ignore[assignment]

        self.request = self._default_arg_wrapper(request)
        self.get = self._default_arg_wrapper(get)
        self.options = self._default_arg_wrapper(options)
        self.head = self._default_arg_wrapper(head)
        self.post = self._default_arg_wrapper(post)
        self.put = self._default_arg_wrapper(put)
        self.patch = self._default_arg_wrapper(patch)
        self.delete = self._default_arg_wrapper(delete)
        self.session = self._default_arg_wrapper(session)

    def __getattr__(self, item: str) -> Any:
        """Get attributes from the base advocate module.
        
        This class is meant to mimic the requests base module, so if we don't
        have this attribute, it might be on the base module (like the Request
        class, etc.)
        """
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            import advocate
            return getattr(advocate, item)

    def _default_arg_wrapper(self, fun: Callable[..., Any]) -> Callable[..., Any]:
        """Create a wrapper that adds the default validator argument."""
        def wrapped_func(*args: Any, **kwargs: Any) -> Any:
            kwargs.setdefault("validator", self.validator)
            return fun(*args, **kwargs)
        return wrapped_func

    def _make_wrapper_cls_global(self, cls: Type[Any]) -> None:
        """Make a wrapper class available at module level for pickling."""
        if not self.SUPPORT_WRAPPER_PICKLING:
            return
        # Gnarly, but necessary to give pickle a consistent module-level
        # reference for each wrapper.
        import pickle as pickle_module
        wrapper_hash = hashlib.sha256(pickle_module.dumps(self)).hexdigest()
        cls.__name__ = "_".join((cls.__name__, wrapper_hash))
        cls.__qualname__ = ".".join((__name__, cls.__name__))
        if not globals().get(cls.__name__):
            globals()[cls.__name__] = cls


__all__ = (
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "session",
    "Session",
    "RequestsAPIWrapper",
)
