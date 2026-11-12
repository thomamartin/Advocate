"""
Custom exceptions for Advocate.

These exceptions are raised when security validations fail or when
operations that could bypass security protections are attempted.
"""

from typing import Any, Tuple


class AdvocateException(Exception):
    """Base exception class for all Advocate errors."""

    pass


class UnacceptableAddressException(AdvocateException):
    """Raised when an address fails validation checks.
    
    This exception is raised when Advocate detects that a connection attempt
    is being made to an address that violates the configured security policies.
    
    Attributes:
        address: The address that was rejected, typically a (hostname, port) tuple.
    """

    def __init__(self, address: Tuple[str, int]) -> None:
        self.address = address
        super().__init__(str(address))


class NameserverException(AdvocateException):
    """Raised when there's an issue with DNS resolution.
    
    This typically occurs when the nameserver doesn't provide canonical names
    as expected by Advocate's validation logic.
    """

    pass


class MountDisabledException(AdvocateException):
    """Raised when attempting to use mount() on an Advocate Session.
    
    The mount() method is disabled in Advocate to prevent protection bypasses
    by clobbering the validating adapters.
    """

    pass


class ProxyDisabledException(NotImplementedError, AdvocateException):
    """Raised when attempting to use proxies with Advocate.
    
    Advocate does not support HTTP proxies as they could potentially
    bypass the security validations.
    """

    pass


class ConfigException(AdvocateException):
    """Raised when there's a configuration error.
    
    This typically occurs when required dependencies are missing or
    when there's an issue with the configuration of the validator.
    """

    pass
