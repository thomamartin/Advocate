"""
Validating HTTP Adapters for Advocate.

This module provides HTTP adapters that integrate with the requests library
and use Advocate's validation logic to prevent SSRF attacks.
"""

from typing import Any, Dict, Optional

from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter

from .addrvalidator import AddrValidator
from .exceptions import ProxyDisabledException
from .poolmanager import ValidatingPoolManager


class ValidatingHTTPAdapter(HTTPAdapter):
    """HTTP adapter that validates addresses before making connections.
    
    This adapter wraps the standard requests HTTPAdapter and adds validation
    of addresses using Advocate's AddrValidator before allowing connections.
    
    Attributes:
        _validator: The AddrValidator instance used for validation.
    """

    __attrs__ = HTTPAdapter.__attrs__ + ['_validator']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the validating HTTP adapter.
        
        Args:
            *args: Positional arguments passed to HTTPAdapter.
            **kwargs: Keyword arguments. The 'validator' keyword argument is used
                     to specify the AddrValidator instance.
        """
        self._validator: AddrValidator = kwargs.pop('validator', None)
        if not self._validator:
            self._validator = AddrValidator()
        super().__init__(*args, **kwargs)

    def init_poolmanager(
            self, 
            connections: int, 
            maxsize: int, 
            block: bool = DEFAULT_POOLBLOCK,
            **pool_kwargs: Any
    ) -> None:
        """Initialize the pool manager with validation support.
        
        Args:
            connections: Number of connection pools to cache.
            maxsize: Maximum number of connections to save in the pool.
            block: Whether to block when no free connections are available.
            **pool_kwargs: Additional keyword arguments for the pool manager.
        """
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = ValidatingPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            validator=self._validator,
            **pool_kwargs
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> None:
        """Disable proxy support.
        
        Args:
            proxy: The proxy URL.
            **proxy_kwargs: Additional keyword arguments.
            
        Raises:
            ProxyDisabledException: Always raised, as proxies cannot be used with Advocate.
        """
        raise ProxyDisabledException("Proxies cannot be used with Advocate")
