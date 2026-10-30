from __future__ import annotations

from collections.abc import Sequence
import ipaddress
import socket
import sys
from typing import Any

from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import (
    ConnectTimeoutError,
    LocationParseError,
    NameResolutionError,
    NewConnectionError,
)
from urllib3.util.connection import (
    _TYPE_SOCKET_OPTIONS,
    _set_socket_options,
)
from urllib3.util.connection import create_connection as old_create_connection
from urllib3.util.timeout import _DEFAULT_TIMEOUT, _TYPE_TIMEOUT

from . import addrvalidator
from .addrvalidator import AddrValidator
from .exceptions import UnacceptableAddressException


def advocate_getaddrinfo(
    host: str | bytes | None,
    port: str | bytes | int | None,
    get_canonname: bool = False,
) -> tuple[tuple[Any, ...], ...]:
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


def fix_addrinfo(records: Sequence[tuple[Any, ...]]) -> tuple[tuple[Any, ...], ...]:
    """Propagate the canonname across records and parse IPs.

    I'm not sure if this is just the behaviour of `getaddrinfo` on Linux, but
    it seems like only the first record in the set has the canonname field
    populated.
    """

    def fix_record(record: tuple[Any, ...], canonname: str | None) -> tuple[Any, ...]:
        sa = record[4]
        sa = (ipaddress.ip_address(sa[0]),) + sa[1:]
        return record[0], record[1], record[2], canonname, sa

    canonname = None
    if records:
        # Apparently the canonical name is only included in the first record?
        # Add it to all of them.
        assert len(records[0]) == 5
        canonname = records[0][3]
    return tuple(fix_record(x, canonname) for x in records)


# Lifted from requests' urllib3, which in turn lifted it from `socket.py`. Oy!
def validating_create_connection(
    address: tuple[str, int],
    timeout: _TYPE_TIMEOUT = _DEFAULT_TIMEOUT,
    source_address: tuple[str, int] | None = None,
    socket_options: _TYPE_SOCKET_OPTIONS | None = None,
    validator: AddrValidator | None = None,
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
    """
    host, port = address
    if host.startswith("["):
        host = host.strip("[]")

    if validator is None:
        validator = AddrValidator()

    # We can skip asking for the canon name if we're not doing hostname-based
    # blacklisting.
    need_canonname = False
    if validator.hostname_blacklist:
        need_canonname = True
        # We check both the non-canonical and canonical hostnames so we can
        # catch both of these:
        # CNAME from nonblacklisted.com -> blacklisted.com
        # CNAME from blacklisted.com -> nonblacklisted.com
        if not validator.is_hostname_allowed(host):
            raise UnacceptableAddressException(host)

    try:
        host.encode("idna")
    except UnicodeError:
        raise LocationParseError(f"'{host}', label empty or too long") from None

    err: Exception | None = None
    addrinfo = advocate_getaddrinfo(host, port, get_canonname=need_canonname)
    if addrinfo:
        if validator.autodetect_local_addresses:
            local_addresses = addrvalidator.determine_local_addresses()
        else:
            local_addresses = []
        for res in addrinfo:
            # Are we allowed to connect with this result?
            if not validator.is_addrinfo_allowed(
                res,
                _local_addresses=local_addresses,
            ):
                continue
            af, socktype, proto, canonname, sa = res
            # Unparse the validated IP
            sa = (sa[0].exploded,) + sa[1:]
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)

                # If provided, set socket level options before connecting.
                # This is the only addition urllib3 makes to this function.
                _set_socket_options(sock, socket_options)

                if (
                    timeout is not _DEFAULT_TIMEOUT
                    and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT
                ):
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                err = None
                return sock

            except OSError as _:
                err = _
                if sock is not None:
                    sock.close()
                    sock = None

        if err is None:
            # If we got here, none of the results were acceptable
            err = UnacceptableAddressException(address)
    if err is not None:
        try:
            raise err
        finally:
            err = None
    else:
        raise OSError("getaddrinfo returns an empty list")


# TODO: Is there a better way to add this to multiple classes with different
# base classes? I tried a mixin, but it used the base method instead.
def _validating_new_conn(self: ValidatingHTTPConnection) -> socket.socket:
    """Establish a socket connection and set nodelay settings on it.

    :return: New socket connection.
    """
    extra_kw: dict[str, Any] = {}
    if self.source_address:
        extra_kw["source_address"] = self.source_address

    if self.socket_options:
        extra_kw["socket_options"] = self.socket_options

    try:
        # Hack around HTTPretty's patched sockets
        # TODO: some better method of hacking around it that checks if we
        # _would have_ connected to a private addr?
        conn_func: Any = validating_create_connection
        if socket.getaddrinfo.__module__.startswith("httpretty"):
            conn_func = old_create_connection
        else:
            extra_kw["validator"] = self._validator

        dns_host = getattr(self, "_dns_host", self.host)
        conn: socket.socket = conn_func(
            (dns_host, self.port),
            self.timeout,
            **extra_kw,
        )

    except socket.gaierror as e:
        raise NameResolutionError(self.host, self, e) from e
    except TimeoutError as e:
        raise ConnectTimeoutError(
            self,
            f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
        ) from e
    except OSError as e:
        raise NewConnectionError(
            self, f"Failed to establish a new connection: {e}"
        ) from e

    sys.audit("http.client.connect", self, self.host, self.port)

    return conn


# Don't silently break if the private API changes across urllib3 versions
assert hasattr(HTTPConnection, "_new_conn")
assert hasattr(HTTPSConnection, "_new_conn")


class ValidatingHTTPConnection(HTTPConnection):
    _new_conn = _validating_new_conn

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._validator: AddrValidator | None = kwargs.pop("validator", None)
        super().__init__(*args, **kwargs)


class ValidatingHTTPSConnection(HTTPSConnection):
    _new_conn = _validating_new_conn

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._validator: AddrValidator | None = kwargs.pop("validator", None)
        super().__init__(*args, **kwargs)
