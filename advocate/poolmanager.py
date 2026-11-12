"""
Validating Pool Manager for Advocate.

This module provides a pool manager that integrates with urllib3 and uses
Advocate's validating connection pools.
"""

import collections
import functools
from collections.abc import Callable
from typing import Any, Dict

from urllib3 import PoolManager
from urllib3.poolmanager import PoolKey, _default_key_normalizer

from .addrvalidator import AddrValidator
from .connectionpool import (
    ValidatingHTTPConnectionPool,
    ValidatingHTTPSConnectionPool,
)

pool_classes_by_scheme = {
    "http": ValidatingHTTPConnectionPool,
    "https": ValidatingHTTPSConnectionPool,
}

AdvocatePoolKey = collections.namedtuple(
    'AdvocatePoolKey',
    PoolKey._fields + ('key_validator',)
)


def key_normalizer(key_class: Any, request_context: dict[str, Any]) -> Any:
    """Create a pool key with validator ID.

    Args:
        key_class: The pool key class.
        request_context: The request context dictionary.

    Returns:
        A normalized pool key.
    """
    request_context = request_context.copy()
    # TODO: add ability to serialize validator rules to dict,
    # allowing pool to be shared between sessions with the same
    # rules.
    validator: AddrValidator = request_context["validator"]
    request_context["validator"] = id(validator)
    return _default_key_normalizer(key_class, request_context)


key_fn_by_scheme: dict[str, Callable[..., Any]] = {
    'http': functools.partial(key_normalizer, AdvocatePoolKey),
    'https': functools.partial(key_normalizer, AdvocatePoolKey),
}


class ValidatingPoolManager(PoolManager):
    """Pool manager with address validation.

    This class extends urllib3's PoolManager to use Advocate's
    validating connection pools and to create pool keys that
    include the validator.

    Attributes:
        validator: The AddrValidator instance used for validation.
    """

    def __init__(self, *args: Any, validator: AddrValidator, **kwargs: Any) -> None:
        """Initialize a validating pool manager.

        Args:
            *args: Positional arguments passed to PoolManager.
            validator: The AddrValidator instance to use for validation.
            **kwargs: Additional keyword arguments.
        """
        self._validator = validator
        kwargs['validator'] = validator
        super().__init__(*args, **kwargs)

        # Make sure the API hasn't changed
        assert (hasattr(self, 'pool_classes_by_scheme'))

        self.pool_classes_by_scheme = pool_classes_by_scheme
        self.key_fn_by_scheme = key_fn_by_scheme.copy()
