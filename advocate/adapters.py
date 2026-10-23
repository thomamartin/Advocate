from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from urllib3.util import parse_url

from .addrvalidator import AddrValidator
from .exceptions import ProxyDisabledException, UnacceptableAddressException
from .poolmanager import ValidatingPoolManager


class ValidatingHTTPAdapter(HTTPAdapter):
    __attrs__ = HTTPAdapter.__attrs__ + ["_validator"]

    def __init__(self, *args, **kwargs):
        self._validator = kwargs.pop("validator", None)
        if not self._validator:
            self._validator = AddrValidator()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
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

    def send(self, request, *args, **kwargs):
        if self._validator.hostname_blacklist and request.headers:
            host_header = request.headers.get("Host")
            if host_header:
                host = (parse_url(f"//{host_header}").host or host_header).strip("[]")
                if not self._validator.is_hostname_allowed(host):
                    raise UnacceptableAddressException(host)
        return super().send(request, *args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        raise ProxyDisabledException("Proxies cannot be used with Advocate")
