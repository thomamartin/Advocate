from __future__ import annotations

from typing import Any, NoReturn

from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter

from .addrvalidator import AddrValidator
from .exceptions import ProxyDisabledException
from .poolmanager import ValidatingPoolManager


class ValidatingHTTPAdapter(HTTPAdapter):
    __attrs__ = [*HTTPAdapter.__attrs__, "_validator"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._validator: AddrValidator = (
            kwargs.pop("validator", None) or AddrValidator()
        )
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = DEFAULT_POOLBLOCK,
        **pool_kwargs: Any,
    ) -> None:
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = ValidatingPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            validator=self._validator,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> NoReturn:
        raise ProxyDisabledException("Proxies cannot be used with Advocate")
