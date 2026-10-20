# Advocate

[![Python versions](https://img.shields.io/pypi/pyversions/advocate.svg)](https://pypi.org/project/advocate/)
[![PyPI version](https://img.shields.io/pypi/v/advocate.svg)](https://pypi.org/project/advocate/)

**Advocate is no longer maintained. Please fork and rename it if you would like to continue work on it.**

Advocate is a set of tools based around the [Requests library](https://github.com/psf/requests) for safely making HTTP requests on behalf of a third party. Specifically, it aims to prevent common techniques that enable [SSRF attacks](https://cwe.mitre.org/data/definitions/918.html).

Advocate was inspired by [fin1te's SafeCurl project](https://github.com/fin1te/safecurl).

## Installation

```bash
uv add advocate
```

Advocate supports CPython 3.10 and newer. PyPy may work as well, but is not tested.

To install the package with its test dependencies and run the test suite:

```bash
uv sync --extra test
uv run pytest
```

## Examples

Advocate is more-or-less a drop-in replacement for Requests. In most cases, you can replace `requests` with `advocate` where necessary:

```pycon
>>> import advocate
>>> print(advocate.get("http://google.com/"))
<Response [200]>
```

Advocate also provides a subclass of `requests.Session` with validation defaults already set up:

```pycon
>>> import advocate
>>> sess = advocate.Session()
>>> print(sess.get("http://google.com/"))
<Response [200]>
>>> print(sess.get("http://localhost/"))
advocate.exceptions.UnacceptableAddressException: ('localhost', 80)
```

All wrapped request functions accept a `validator` argument for adding rules:

```pycon
>>> import advocate
>>> validator = advocate.AddrValidator(hostname_blacklist={"*.museum"})
>>> print(advocate.get("http://educational.MUSEUM/", validator=validator))
advocate.exceptions.UnacceptableAddressException: educational.MUSEUM
```

For custom rules without passing a validator to each call, define a `RequestsAPIWrapper` in a common module and import it instead of Advocate:

```pycon
>>> from advocate import AddrValidator, RequestsAPIWrapper
>>> import ipaddress
>>> dougs_advocate = RequestsAPIWrapper(AddrValidator(ip_blacklist={
...     # Contains data incomprehensible to mere mortals
...     ipaddress.ip_network("42.42.42.42/32")
... }))
>>> print(dougs_advocate.get("http://42.42.42.42/"))
advocate.exceptions.UnacceptableAddressException: ('42.42.42.42', 80)
```

Other than that, you can do just about everything with Advocate that you can do with unwrapped Requests. Advocate passes Requests' test suite with the exception of tests that require `Session.mount()`.

## Conditionally bypassing protection

If you want to allow certain users to bypass Advocate's restrictions, use plain Requests:

```python
if user == "mr_skeltal":
    requests_module = requests
else:
    requests_module = advocate
resp = requests_module.get("http://example.com/doot_doot")
```

## requests-futures support

A thin wrapper around [requests-futures](https://github.com/ross/requests-futures) is provided to ease writing async-friendly code:

```pycon
>>> from advocate.futures import FuturesSession
>>> sess = FuturesSession()
>>> fut = sess.get("http://example.com/")
>>> fut
<Future at 0x10c717f28 state=finished returned Response>
>>> fut.result()
<Response [200]>
```

You can do basically everything you can do with regular `FuturesSession` and `advocate.Session` instances:

```pycon
>>> from advocate import AddrValidator
>>> from advocate.futures import FuturesSession
>>> sess = FuturesSession(max_workers=20, validator=AddrValidator(hostname_blacklist={"*.museum"}))
>>> fut = sess.get("http://anice.museum/")
>>> fut
<Future at 0x10c696668 state=running>
>>> fut.result()
Traceback (most recent call last):
# [...]
advocate.exceptions.UnacceptableAddressException: anice.museum
```

## When should I use Advocate?

Any time you're fetching resources over HTTP for or from someone you don't trust!

## When should I not use Advocate?

There are a few cases where Advocate might not be a good fit:

- When good, safe support for IPv6 is important.
- When internal hosts use globally routable addresses and you can't guess their prefix to blacklist it ahead of time.
- When you already have a good handle on network security within your network.

If you're comfortable enough with Squid and network security, set up a secured Squid instance on a segregated subnet and proxy through that instead. Advocate attempts to guess whether an address references an internal host and block access, but it is preferable to proxy through a host that cannot access anything internal in the first place.

If you're writing an application or library that's meant to be usable out of the box on other people's networks, Advocate plus a user-configurable blacklist is probably the safer bet.

## This seems like it's been done before

There have been a few similar projects, but in my opinion Advocate's approach is the best because:

### It sees URLs the same as the underlying HTTP library

Parsing URLs is hard, and no two URL parsers seem to behave exactly the same. The tiniest differences in parsing between your validator and the underlying HTTP library can lead to vulnerabilities. For example, differences between PHP's `parse_url` and cURL's URL parser [allowed a blacklist bypass in SafeCurl](https://github.com/fin1te/safecurl/issues/5).

Advocate doesn't do URL parsing at all and lets Requests handle it. Advocate only looks at the address Requests actually tries to open a socket to.

### It deals with DNS rebinding

Two consecutive calls to `socket.getaddrinfo` aren't guaranteed to return the same information, depending on the system configuration. If the "safe"-looking record's TTL expires between the verification lookup and the lookup for actually opening the socket, we may end up connecting to a very different server than the one we approved.

Advocate gets around this by using one `getaddrinfo` call for both verification and connecting the socket. In pseudocode:

```python
def connect_socket(host, port):
    for res in socket.getaddrinfo(host, port):
        # `res` contains the IP address for the host
        if not is_blacklisted(res):
            # Connect the socket using `res`
```

See [Wikipedia's article on DNS rebinding attacks](https://en.wikipedia.org/wiki/DNS_rebinding) for more information.

### It handles redirects sanely

Most other SSRF-prevention libraries cover this, but much sample code online does not. Advocate will catch it because it inspects every connection attempt the underlying HTTP library makes.

## TODO

### Proper IPv6 support?

Advocate's IPv6 support is still a work in progress. IPv6 records are ignored by default for now, but you can enable them by using an `AddrValidator` with `allow_ipv6=True`.

It should mostly work as expected, but Advocate's approach might not make sense with most IPv6 deployments. See [issue #3](https://github.com/JordanMilne/Advocate/issues/3) for more information.

If you can think of any improvements to the IPv6 handling, please submit an issue or pull request!

## Caveats

- Calling `mount()` to install other adapters is disallowed to prevent Advocate's validating adapters from being clobbered.
- Advocate does not, and might never, support the use of HTTP proxies.
- Proper IPv6 support is still a work in progress, as noted above.

## Acknowledgements

- [fin1te/safecurl](https://github.com/fin1te/safecurl) for inspiration.
- [psf/requests](https://github.com/psf/requests) for the lovely Requests module.
- [kwi/py2-ipaddress](https://bitbucket.org/kwi/py2-ipaddress) for the backport of `ipaddress`.
- [hakobe/paranoidhttp](https://github.com/hakobe/paranoidhttp), a similar project targeting Go.
- [uber-common/paranoid-request](https://github.com/uber-common/paranoid-request), a similar project targeting Node.
- [LWP::UserAgent::Paranoid](http://search.cpan.org/~tsibley/LWP-UserAgent-Paranoid/), a similar project targeting Perl 5.
