from __future__ import annotations


class AdvocateException(Exception):
    """Base exception for all Advocate errors."""


class UnacceptableAddressException(AdvocateException):
    """Raised when attempting to connect to a disallowed IP, port, or hostname."""


class NameserverException(AdvocateException):
    """Raised when a nameserver returns unexpected or incomplete records."""


class MountDisabledException(AdvocateException):
    """Raised when attempting to call Session.mount() on an Advocate session."""


class ProxyDisabledException(NotImplementedError, AdvocateException):
    """Raised when attempting to use an HTTP proxy with Advocate."""


class ConfigException(AdvocateException):
    """Raised when Advocate is misconfigured or missing an optional dependency."""


__all__ = (
    "AdvocateException",
    "ConfigException",
    "MountDisabledException",
    "NameserverException",
    "ProxyDisabledException",
    "UnacceptableAddressException",
)
