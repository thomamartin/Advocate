"""
Validating Connection Pools for Advocate.

This module provides connection pool classes that integrate with urllib3
and use Advocate's validating connection classes.
"""

from typing import Any

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from .connection import (
    ValidatingHTTPConnection,
    ValidatingHTTPSConnection,
)

# Don't silently break if the private API changes across urllib3 versions
assert(hasattr(HTTPConnectionPool, 'ConnectionCls'))
assert(hasattr(HTTPSConnectionPool, 'ConnectionCls'))
assert(hasattr(HTTPConnectionPool, 'scheme'))
assert(hasattr(HTTPSConnectionPool, 'scheme'))


class ValidatingHTTPConnectionPool(HTTPConnectionPool):
    """HTTP connection pool with address validation.

    This class extends urllib3's HTTPConnectionPool to use
    ValidatingHTTPConnection for all connections.
    """

    scheme = 'http'
    ConnectionCls = ValidatingHTTPConnection


class ValidatingHTTPSConnectionPool(HTTPSConnectionPool):
    """HTTPS connection pool with address validation.

    This class extends urllib3's HTTPSConnectionPool to use
    ValidatingHTTPSConnection for all connections.
    """

    scheme = 'https'
    ConnectionCls = ValidatingHTTPSConnection
