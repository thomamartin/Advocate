# Advocate

![Python versions](https://img.shields.io/pypi/pyversions/advocate.svg)
[![PyPI version](https://img.shields.io/pypi/v/advocate.svg)](https://pypi.org/project/advocate/)

Advocate is a set of tools based around the [requests](https://github.com/psf/requests) library for safely making
HTTP requests on behalf of a third party. Specifically, it aims to prevent 
common techniques that enable [SSRF attacks](https://cwe.mitre.org/data/definitions/918.html).

Advocate was inspired by [fin1te's SafeCurl project](https://github.com/fin1te/safecurl).

## Installation

```bash
pip install advocate
```

To include `requests-futures` support:

```bash
pip install advocate[futures]
```

Advocate is officially supported on Python 3.11+.

## Examples

Advocate is a drop-in replacement for requests. In most cases you can just replace `requests` with
`advocate` where necessary:

```python
>>> import advocate
>>> print(advocate.get("http://example.com/"))
<Response [200]>
```

Advocate also provides a subclassed `requests.Session` with sane defaults for
validation already configured:

```python
>>> import advocate
>>> sess = advocate.Session()
>>> print(sess.get("http://example.com/"))
<Response [200]>
>>> print(sess.get("http://localhost/"))
advocate.exceptions.UnacceptableAddressException: ('localhost', 80)
```

All wrapped request functions accept a `validator` keyword argument where you
can set additional rules:

```python
>>> import advocate
>>> validator = advocate.AddrValidator(hostname_blacklist={"*.museum"})
>>> print(advocate.get("http://educational.MUSEUM/", validator=validator))
advocate.exceptions.UnacceptableAddressException: educational.MUSEUM
```

If you require custom rules beyond the defaults but want to avoid passing
the `validator` argument everywhere, use `RequestsAPIWrapper`:

```python
>>> from advocate import AddrValidator, RequestsAPIWrapper
>>> import ipaddress
>>> custom_advocate = RequestsAPIWrapper(AddrValidator(ip_blacklist={
...     ipaddress.ip_network("42.42.42.42/32")
... }))
>>> print(custom_advocate.get("http://42.42.42.42/"))
advocate.exceptions.UnacceptableAddressException: ('42.42.42.42', 80)
```

Advocate passes requests' test suite with the exception of tests that require `Session.mount()`.

## Conditionally Bypassing Protection

If you want to allow certain callers to bypass Advocate's restrictions, use regular `requests`:

```python
if user == "admin":
    requests_module = requests
else:
    requests_module = advocate
resp = requests_module.get("http://example.com/api")
```

## `requests-futures` Support

A thin wrapper around [requests-futures](https://github.com/ross/requests-futures) is provided for asynchronous requests:

```python
>>> from advocate.futures import FuturesSession
>>> sess = FuturesSession()
>>> fut = sess.get("http://example.com/")
>>> fut.result()
<Response [200]>
```

You can customize the validator or pool size:

```python
>>> from advocate import AddrValidator
>>> from advocate.futures import FuturesSession
>>> sess = FuturesSession(max_workers=20, validator=AddrValidator(hostname_blacklist={"*.museum"}))
>>> fut = sess.get("http://anice.museum/")
>>> fut.result()
advocate.exceptions.UnacceptableAddressException: anice.museum
```

## How Advocate Protects Against SSRF

1. **Consistent URL Parsing**: Advocate does not attempt its own URL parsing (which often diverges from the underlying HTTP client). Instead, Advocate intercepts and validates socket connection attempts at the address level.
2. **Protection Against DNS Rebinding**: Many SSRF mitigations perform a DNS resolution check and then make an HTTP request; during the interval between check and connect, the DNS record can expire and point to an internal IP. Advocate resolves and validates in a single step when connecting the socket, preventing DNS rebinding.
3. **Redirect Validation**: Redirects are followed and inspected at every step; redirecting to internal IP addresses or prohibited hostnames will raise an `UnacceptableAddressException`.

## Caveats

* `mount()` is disallowed on sessions to prevent Advocate's validating adapters from being overwritten.
* Advocate does not support HTTP proxies (the proxy makes the remote connection, defeating socket-level address validation).
