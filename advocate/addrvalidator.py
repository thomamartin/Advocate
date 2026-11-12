"""
Address Validator for Advocate.

This module provides the AddrValidator class which validates IP addresses,
hostnames, and address information to prevent SSRF attacks and other
security issues.
"""

import functools
import fnmatch
import ipaddress
import re
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union

try:
    import netifaces
    HAVE_NETIFACES = True
except ImportError:
    netifaces = None  # type: ignore
    HAVE_NETIFACES = False

from .exceptions import ConfigException, NameserverException


def canonicalize_hostname(hostname: str) -> str:
    """Lowercase and punycodify a hostname.
    
    Args:
        hostname: The hostname to canonicalize.
        
    Returns:
        The canonicalized hostname in lowercase with IDNA encoding.
    """
    # We do the lowercasing after IDNA encoding because we only want to
    # lowercase the *ASCII* chars.
    # TODO: The differences between IDNA2003 and IDNA2008 might be relevant
    # to us, but both specs are damn confusing.
    return str(hostname.encode("idna").lower(), 'utf-8')


def determine_local_addresses() -> List[ipaddress.IPv4Network]:
    """Get all IPs that refer to this machine according to netifaces.
    
    Returns:
        A list of IP network objects representing local addresses.
        
    Raises:
        ConfigException: If netifaces module is not available.
    """
    if not HAVE_NETIFACES:
        raise ConfigException(
            "Tried to determine local addresses, "
            "but netifaces module was not importable"
        )
    ips: List[ipaddress.IPv4Network] = []
    for interface in netifaces.interfaces():
        if_families = netifaces.ifaddresses(interface)
        for family_kind in {netifaces.AF_INET, netifaces.AF_INET6}:
            addrs = if_families.get(family_kind, [])
            for addr in (x.get("addr", "") for x in addrs):
                if family_kind == netifaces.AF_INET6:
                    # We can't do anything sensible with the scope here
                    addr = addr.split("%")[0]
                ips.append(ipaddress.ip_network(addr))
    return ips


def add_local_address_arg(func: Callable[..., Any]) -> Callable[..., Any]:
    """Add the "_local_addresses" kwarg if it's missing.

    IMO this information shouldn't be cached between calls (what if one of the
    adapters got a new IP at runtime?,) and we don't want each function to
    recalculate it. Just recalculate it if the caller didn't provide it for us.
    """
    @functools.wraps(func)
    def wrapper(self: "AddrValidator", *args: Any, **kwargs: Any) -> Any:
        if "_local_addresses" not in kwargs:
            if self.autodetect_local_addresses:
                kwargs["_local_addresses"] = determine_local_addresses()
            else:
                kwargs["_local_addresses"] = []
        return func(self, *args, **kwargs)
    return wrapper


# Type alias for addrinfo tuple
AddrInfoTuple = Tuple[int, int, int, bytes, Tuple[Any, ...]]


class AddrValidator:
    """Validator for IP addresses, hostnames, and address information.
    
    This class provides comprehensive validation of network addresses to
    prevent SSRF attacks and other security issues. It supports blacklists
    and whitelists for IPs, ports, and hostnames, and can auto-detect
    local addresses.
    
    Attributes:
        ip_blacklist: Set of IP networks to blacklist.
        ip_whitelist: Set of IP networks to whitelist (takes precedence over blacklist).
        port_blacklist: Set of ports to blacklist.
        port_whitelist: Set of ports to whitelist (takes precedence over blacklist).
        hostname_blacklist: Set of hostname patterns to blacklist.
        allow_ipv6: Whether to allow IPv6 addresses.
        allow_teredo: Whether to allow Teredo tunneling.
        allow_6to4: Whether to allow 6to4 tunneling.
        allow_dns64: Whether to allow DNS64.
        autodetect_local_addresses: Whether to automatically detect local addresses.
    """

    _6TO4_RELAY_NET = ipaddress.ip_network("192.88.99.0/24")
    # Just the well known prefix, DNS64 servers can set their own
    # prefix, but in practice most probably don't.
    _DNS64_WK_PREFIX = ipaddress.ip_network("64:ff9b::/96")
    DEFAULT_PORT_WHITELIST: Set[int] = {80, 8080, 443, 8443, 8000}

    def __init__(
            self,
            ip_blacklist: Optional[Set[ipaddress.IPv4Network]] = None,
            ip_whitelist: Optional[Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None,
            port_whitelist: Optional[Set[int]] = None,
            port_blacklist: Optional[Set[int]] = None,
            hostname_blacklist: Optional[Set[str]] = None,
            allow_ipv6: bool = False,
            allow_teredo: bool = False,
            allow_6to4: bool = False,
            allow_dns64: bool = False,
            # Must be explicitly set to "False" if you don't want to try
            # detecting local interface addresses with netifaces.
            autodetect_local_addresses: bool = True,
    ) -> None:
        if not port_blacklist and not port_whitelist:
            # An assortment of common HTTPS? ports.
            port_whitelist = self.DEFAULT_PORT_WHITELIST.copy()
        self.ip_blacklist = ip_blacklist or set()
        self.ip_whitelist = ip_whitelist or set()
        self.port_blacklist = port_blacklist or set()
        self.port_whitelist = port_whitelist or set()
        # TODO: ATM this can contain either regexes or globs that are converted
        # to regexes upon every check. Create a collection that automagically
        # converts them to regexes on insert?
        self.hostname_blacklist = hostname_blacklist or set()
        self.allow_ipv6 = allow_ipv6
        self.allow_teredo = allow_teredo
        self.allow_6to4 = allow_6to4
        self.allow_dns64 = allow_dns64
        self.autodetect_local_addresses = autodetect_local_addresses

    @add_local_address_arg
    def is_ip_allowed(
            self, 
            addr_ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
            _local_addresses: Optional[List[ipaddress.IPv4Network]] = None
    ) -> bool:
        """Check if an IP address is allowed.
        
        Args:
            addr_ip: The IP address to check.
            _local_addresses: Local addresses to check against (auto-detected if not provided).
            
        Returns:
            True if the IP address is allowed, False otherwise.
        """
        if not isinstance(
                addr_ip,
                (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ):
            addr_ip = ipaddress.ip_address(addr_ip)

        # The whitelist should take precedence over the blacklist so we can
        # punch holes in blacklisted ranges
        if any(addr_ip in net for net in self.ip_whitelist):
            return True

        if any(addr_ip in net for net in self.ip_blacklist):
            return False

        if any(addr_ip in net for net in _local_addresses):
            return False

        if addr_ip.version == 4:
            if not addr_ip.is_private:
                # IPs for carrier-grade NAT. Seems weird that it doesn't set
                # `is_private`, but we need to check `not is_global`
                if not ipaddress.ip_network(addr_ip).is_global:
                    return False
        elif addr_ip.version == 6:
            # You'd better have a good reason for enabling IPv6
            # because Advocate's techniques don't work well without NAT.
            if not self.allow_ipv6:
                return False

            # v6 addresses can also map to IPv4 addresses! Tricky!
            v4_nested: List[ipaddress.IPv4Address] = []
            if addr_ip.ipv4_mapped:
                v4_nested.append(addr_ip.ipv4_mapped)
            # WTF IPv6? Why you gotta have a billion tunneling mechanisms?
            # XXX: Do we even really care about these? If we're tunneling
            # through public servers we shouldn't be able to access
            # addresses on our private network, right?
            if addr_ip.sixtofour:
                if not self.allow_6to4:
                    return False
                v4_nested.append(addr_ip.sixtofour)
            if addr_ip.teredo:
                if not self.allow_teredo:
                    return False
                # Check both the client *and* server IPs
                v4_nested.extend(addr_ip.teredo)
            if addr_ip in self._DNS64_WK_PREFIX:
                if not self.allow_dns64:
                    return False
                # When using the well-known prefix the last 4 bytes
                # are the IPv4 addr
                v4_nested.append(ipaddress.ip_address(addr_ip.packed[-4:]))

            if not all(self.is_ip_allowed(addr_v4) for addr_v4 in v4_nested):
                return False

            # fec0::*, apparently deprecated?
            if addr_ip.is_site_local:
                return False
        else:
            raise ValueError("Unsupported IP version(?): %r" % addr_ip)

        # 169.254.XXX.XXX, AWS uses these for autoconfiguration
        if addr_ip.is_link_local:
            return False
        # 127.0.0.1, ::1, etc.
        if addr_ip.is_loopback:
            return False
        if addr_ip.is_multicast:
            return False
        # 192.168.XXX.XXX, 10.XXX.XXX.XXX
        if addr_ip.is_private:
            return False
        # 255.255.255.255, ::ffff:XXXX:XXXX (v6->v4) mapping
        if addr_ip.is_reserved:
            return False
        # There's no reason to connect directly to a 6to4 relay
        if addr_ip in self._6TO4_RELAY_NET:
            return False
        # 0.0.0.0
        if addr_ip.is_unspecified:
            return False

        # It doesn't look bad, so... it's must be ok!
        return True

    def _hostname_matches_pattern(self, hostname: str, pattern: Union[str, Pattern[str]]) -> bool:
        """Check if a hostname matches a pattern.
        
        Args:
            hostname: The hostname to check.
            pattern: The pattern to match against (can be a glob string or regex).
            
        Returns:
            True if the hostname matches the pattern, False otherwise.
        """
        # If they specified a string, just assume they only want basic globbing.
        # This stops people from not realizing they're dealing in REs and
        # not escaping their periods unless they specifically pass in an RE.
        # This has the added benefit of letting us sanely handle globbed
        # IDNs by default.
        if isinstance(pattern, str):
            # convert the glob to a punycode glob, then a regex
            pattern = fnmatch.translate(canonicalize_hostname(pattern))

        hostname = canonicalize_hostname(hostname)
        # Down the line the hostname may get treated as a null-terminated string
        # (as with `socket.getaddrinfo`.) Try to account for that.
        #
        #    >>> socket.getaddrinfo("example.com\x00aaaa", 80)
        #    [(2, 1, 6, '', ('93.184.216.34', 80)), [...]
        no_null_hostname = hostname.split("\x00")[0]

        return any(re.match(pattern, x.strip(".")) for x
                   in (no_null_hostname, hostname))

    def is_hostname_allowed(self, hostname: str) -> bool:
        """Check if a hostname is allowed.
        
        Args:
            hostname: The hostname to check.
            
        Returns:
            True if the hostname is allowed, False otherwise.
        """
        # Sometimes (like with "external" services that your IP has privileged
        # access to) you might not always know the IP range to blacklist access
        # to, or the `A` record might change without you noticing.
        # For e.x.: `foocorp.external.org`.
        #
        # Another option is doing something like:
        #
        #     for addrinfo in socket.getaddrinfo("foocorp.external.org", 80):
        #         global_validator.ip_blacklist.add(ip_address(addrinfo[4][0]))
        #
        # but that's not always a good idea if they're behind a third-party lb.
        for pattern in self.hostname_blacklist:
            if self._hostname_matches_pattern(hostname, pattern):
                return False
        return True

    @add_local_address_arg
    def is_addrinfo_allowed(
            self, 
            addrinfo: AddrInfoTuple,
            _local_addresses: Optional[List[ipaddress.IPv4Network]] = None
    ) -> bool:
        """Check if address information is allowed.
        
        Args:
            addrinfo: The address information tuple from socket.getaddrinfo.
            _local_addresses: Local addresses to check against.
            
        Returns:
            True if the address information is allowed, False otherwise.
        """
        assert(len(addrinfo) == 5)
        # XXX: Do we care about any of the other elements? Guessing not.
        family, socktype, proto, canonname, sockaddr = addrinfo

        # The 4th elem in addrinfo may either be a tuple of two or four items,
        # depending on whether we're dealing with IPv4 or v6
        if len(sockaddr) == 2:
            # v4
            ip, port = sockaddr
        elif len(sockaddr) == 4:
            # v6
            # XXX: what *are* `flow_info` and `scope_id`? Anything useful?
            # Seems like we can figure out all we need about the scope from
            # the `is_<x>` properties.
            ip, port, flow_info, scope_id = sockaddr
        else:
            raise ValueError("Unexpected addrinfo format %r" % sockaddr)

        # Probably won't help protect against SSRF, but might prevent our being
        # used to attack others' non-HTTP services. See
        # http://www.remote.org/jochen/sec/hfpa/
        if self.port_whitelist and port not in self.port_whitelist:
            return False
        if port in self.port_blacklist:
            return False

        if self.hostname_blacklist:
            if not canonname:
                raise NameserverException(
                    "addrinfo must contain the canon name to do blacklisting "
                    "based on hostname. Make sure you use the "
                    "`socket.AI_CANONNAME` flag, and that each record contains "
                    "the canon name. Your DNS server might also be garbage."
                )

            if not self.is_hostname_allowed(canonname):
                return False

        return self.is_ip_allowed(ip, _local_addresses=_local_addresses)
