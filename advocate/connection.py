"""
Validating Connection for Advocate.

This module provides socket connection functions that integrate Advocate's
validation logic to prevent SSRF attacks at the connection level.
"""

import ipaddress
import socket
from socket import timeout as SocketTimeout
from typing import Any, Dict, List, Optional, Tuple, TypeVar, Union

from urllib3.connection import HTTPSConnection, HTTPConnection
from urllib3.exceptions import ConnectTimeoutError
from urllib3.util.connection import _set_socket_options
from urllib3.util.connection import create_connection as old_create_connection

from . import addrvalidator
from .exceptions import UnacceptableAddressException

# Type variable for socket addresses
SocketAddress = TypeVar('SocketAddress', bound=Tuple[Any, ...])

# Type alias for addrinfo tuple
AddrInfoTuple = Tuple[int, int, int, bytes, Tuple[Any, ...]]


def advocate_getaddrinfo(host: str, port: int, get_canonname: bool = False) -> List[AddrInfoTuple]:
    """Get address information with canonical name support.
    
    Args:
        host: The hostname to resolve.
        port: The port number.
        get_canonname: Whether to request canonical names from DNS.
        
    Returns:
        A list of address information tuples.
    """
    addrinfo = socket.getaddrinfo(
        host,
        port,
        0,
        socket.SOCK_STREAM,
        0,
        # We need what the DNS client sees the hostname as, correctly handles
        # IDNs and tricky things like `private.foocorp.org\x00.google.com`.
        # All IDNs will be converted to punycode.
        socket.AI_CANONNAME if get_canonname else 0,
    )
    return fix_addrinfo(addrinfo)


def fix_addrinfo(records: List[AddrInfoTuple]) -> List[AddrInfoTuple]:
    """Propagate the canonname across records and parse IPs.

    I'm not sure if this is just the behaviour of `getaddrinfo` on Linux, but
    it seems like only the first record in the set has the canonname field
    populated.
    
    Args:
        records: List of address information tuples.
        
    Returns:
        Fixed list with canonical names propagated and IPs parsed.
    """
    def fix_record(record: AddrInfoTuple, canonname: bytes) -> AddrInfoTuple:
        sa = record[4]
        sa = (ipaddress.ip_address(sa[0]),) + sa[1:]
        return record[0], record[1], record[2], canonname, sa

    canonname: Optional[bytes] = None
    if records:
        # Apparently the canonical name is only included in the first record?
        # Add it to all of them.
        assert(len(records[0]) == 5)
        canonname = records[0][3]
    return tuple(fix_record(x, canonname) for x in records)


def validating_create_connection(
    address: Tuple[str, int],
    timeout: Optional[float] = socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address: Optional[Tuple[str, int]] = None,
    socket_options: Optional[Any] = None,
    validator: Optional[addrvalidator.AddrValidator] = None,
) -> socket.socket:
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.

    Args:
        address: A tuple of (host, port).
        timeout: Socket timeout in seconds.
        source_address: Source address to bind to.
        socket_options: Socket options to set.
        validator: The AddrValidator instance to use for validation.
        
    Returns:
        A connected socket object.
        
    Raises:
        UnacceptableAddressException: If the address fails validation.
        socket.error: If connection fails for other reasons.
    """

    host, port = address
    # We can skip asking for the canon name if we're not doing hostname-based
    # blacklisting.
    need_canonname = False
    if validator and validator.hostname_blacklist:
        need_canonname = True
        # We check both the non-canonical and canonical hostnames so we can
        # catch both of these:
        # CNAME from nonblacklisted.com -> blacklisted.com
        # CNAME from blacklisted.com -> nonblacklisted.com
        if not validator.is_hostname_allowed(host):
            raise UnacceptableAddressException((host, port))

    err: Optional[Exception] = None
    addrinfo_list = advocate_getaddrinfo(host, port, get_canonname=need_canonname)
    if addrinfo_list:
        if validator and validator.autodetect_local_addresses:
            local_addresses = addrvalidator.determine_local_addresses()
        else:
            local_addresses = []
        for res in addrinfo_list:
            # Are we allowed to connect with this result?
            if validator and not validator.is_addrinfo_allowed(
                res,
                _local_addresses=local_addresses,
            ):
                continue
            af, socktype, proto, canonname, sa = res
            # Unparse the validated IP
            sa = (sa[0].exploded,) + sa[1:]
            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(af, socktype, proto)

                # If provided, set socket level options before connecting.
                # This is the only addition urllib3 makes to this function.
                _set_socket_options(sock, socket_options)

                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()
                    sock = None

        if err is None:
            # If we got here, none of the results were acceptable
            if validator:
                err = UnacceptableAddressException(address)
            else:
                err = socket.error("No acceptable addresses found")
    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


# TODO: Is there a better way to add this to multiple classes with different
# base classes? I tried a mixin, but it used the base method instead.
def _validating_new_conn(self: Any) -> socket.socket:
    """Establish a socket connection and set nodelay settings on it.

    :return: New socket connection.
    """
    extra_kw: Dict[str, Any] = {}
    if self.source_address:
        extra_kw['source_address'] = self.source_address

    if self.socket_options:
        extra_kw['socket_options'] = self.socket_options

    try:
        # Hack around HTTPretty's patched sockets
        # TODO: some better method of hacking around it that checks if we
        # _would have_ connected to a private addr?
        conn_func = validating_create_connection
        if socket.getaddrinfo.__module__.startswith("httpretty"):
            conn_func = old_create_connection
        else:
            extra_kw["validator"] = self._validator

        conn = conn_func(
            (self.host, self.port),
            self.timeout,
            **extra_kw
        )

    except SocketTimeout:
        raise ConnectTimeoutError(
            self, "Connection to %s timed out. (connect timeout=%s)" %
            (self.host, self.timeout))

    return conn


# Don't silently break if the private API changes across urllib3 versions
assert(hasattr(HTTPConnection, '_new_conn'))
assert(hasattr(HTTPSConnection, '_new_conn'))


class ValidatingHTTPConnection(HTTPConnection):
    """HTTP connection class with address validation.
    
    This class extends urllib3's HTTPConnection to add Advocate's
    address validation before making connections.
    
    Attributes:
        _validator: The AddrValidator instance used for validation.
    """

    _new_conn = _validating_new_conn

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a validating HTTP connection.
        
        Args:
            *args: Positional arguments passed to HTTPConnection.
            **kwargs: Keyword arguments. The 'validator' keyword argument is used
                     to specify the AddrValidator instance.
        """
        self._validator = kwargs.pop("validator")
        HTTPConnection.__init__(self, *args, **kwargs)


class ValidatingHTTPSConnection(HTTPSConnection):
    """HTTPS connection class with address validation.
    
    This class extends urllib3's HTTPSConnection to add Advocate's
    address validation before making connections.
    
    Attributes:
        _validator: The AddrValidator instance used for validation.
    """

    _new_conn = _validating_new_conn

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a validating HTTPS connection.
        
        Args:
            *args: Positional arguments passed to HTTPSConnection.
            **kwargs: Keyword arguments. The 'validator' keyword argument is used
                     to specify the AddrValidator instance.
        """
        self._validator = kwargs.pop("validator")
        HTTPSConnection.__init__(self, *args, **kwargs)
