import collections
import functools

from urllib3 import PoolManager
from urllib3.poolmanager import _default_key_normalizer, PoolKey

from .connectionpool import (
    ValidatingHTTPSConnectionPool,
    ValidatingHTTPConnectionPool,
)

pool_classes_by_scheme = {
    "http": ValidatingHTTPConnectionPool,
    "https": ValidatingHTTPSConnectionPool,
}

AdvocatePoolKey = collections.namedtuple(
    "AdvocatePoolKey", PoolKey._fields + ("key_validator",)
)


def key_normalizer(key_class, request_context):
    request_context = request_context.copy()
    validator = request_context.get("validator")
    if hasattr(validator, "as_pool_key"):
        request_context["validator"] = validator.as_pool_key()
    else:
        request_context["validator"] = id(validator)
    return _default_key_normalizer(key_class, request_context)


key_fn_by_scheme = {
    "http": functools.partial(key_normalizer, AdvocatePoolKey),
    "https": functools.partial(key_normalizer, AdvocatePoolKey),
}


class ValidatingPoolManager(PoolManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Make sure the API hasn't changed
        assert hasattr(self, "pool_classes_by_scheme")

        self.pool_classes_by_scheme = pool_classes_by_scheme
        self.key_fn_by_scheme = key_fn_by_scheme.copy()
