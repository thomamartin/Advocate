import builtins
import http.server
import ipaddress
import pathlib
import pickle
import re
import socket
import threading
import tomllib
import types

# This needs to be done before third-party imports to make sure they all use
# our wrapped socket class, especially in case of subclasses.
from .monkeypatching import CheckedSocket, DisallowedConnectException

socket.socket = CheckedSocket

import pytest
import requests
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError

import advocate
from advocate import AddrValidator, ValidatingHTTPAdapter
from advocate.addrvalidator import canonicalize_hostname
from advocate.api import RequestsAPIWrapper
from advocate.connection import (
    ValidatingHTTPSConnection,
    advocate_getaddrinfo,
    validating_create_connection,
)
from advocate.exceptions import (
    ConfigException,
    MountDisabledException,
    NameserverException,
    UnacceptableAddressException,
)
from advocate.futures import FuturesSession
from advocate.poolmanager import AdvocatePoolKey, key_normalizer


# We use port 1 for testing because nothing is likely to legitimately listen
# on it.
AddrValidator.DEFAULT_PORT_WHITELIST.add(1)

RequestsAPIWrapper.SUPPORT_WRAPPER_PICKLING = True
global_wrapper = RequestsAPIWrapper(
    validator=AddrValidator(
        ip_whitelist={
            ipaddress.ip_network("127.0.0.1"),
        }
    )
)
RequestsAPIWrapper.SUPPORT_WRAPPER_PICKLING = False


class _WrapperSubclass(global_wrapper.Session):
    def good_method(self):
        return "foo"


def canonname_supported():
    """Check if the nameserver supports the AI_CANONNAME flag

    travis-ci.org's Python 3 env doesn't seem to support it, so don't try
    any of the test that rely on it.
    """
    try:
        addrinfo = advocate_getaddrinfo("example.com", 0, get_canonname=True)
        assert addrinfo
        return addrinfo[0][3] == "example.com"
    except (socket.gaierror, OSError):
        return False


requires_canonname = pytest.mark.skipif(
    not canonname_supported(),
    reason="Nameserver doesn't support AI_CANONNAME, skipping hostname tests",
)


def permissive_validator(**kwargs):
    default_options = dict(
        ip_blacklist=None,
        port_whitelist=None,
        port_blacklist=None,
        hostname_blacklist=None,
        allow_ipv6=True,
        allow_teredo=True,
        allow_6to4=True,
        allow_dns64=True,
        autodetect_local_addresses=False,
    )
    default_options.update(**kwargs)
    return AddrValidator(**default_options)


def assert_ip_kind_blocked(ip, **kwargs):
    validator = permissive_validator(**kwargs)
    assert not validator.is_ip_allowed(ip)


def is_addrinfo_allowed(host, port, **kwargs):
    validator = permissive_validator(**kwargs)
    allowed = False
    for res in advocate_getaddrinfo(host, port):
        if validator.is_addrinfo_allowed(res):
            allowed = True
    return allowed


def is_hostname_allowed(host, fake_lookup=False, **kwargs):
    validator = permissive_validator(**kwargs)
    if fake_lookup:
        results = [(2, 1, 6, canonicalize_hostname(host), ("1.2.3.4", 80))]
    else:
        results = advocate_getaddrinfo(host, 80, get_canonname=True)
    return any(validator.is_addrinfo_allowed(res) for res in results)


@pytest.fixture
def local_address_calls(monkeypatch):
    calls = []

    def fake_determine_local_addresses():
        calls.append(())
        return [ipaddress.ip_network("200.1.1.1")]

    monkeypatch.setattr(
        "advocate.addrvalidator.determine_local_addresses",
        fake_determine_local_addresses,
    )
    return calls


def test_version_matches_pyproject():
    pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    with pyproject.open("rb") as f:
        data = tomllib.load(f)
    assert advocate.__version__ == data["project"]["version"]
    assert data["project"]["name"] == "advocate2"
    assert data["tool"]["uv"]["build-backend"]["module-name"] == "advocate"
    assert data["project"]["urls"]["Homepage"] == "https://github.com/thomamartin/Advocate"
    assert data["project"]["urls"]["Repository"] == "https://github.com/thomamartin/Advocate"
    assert (
        data["project"]["urls"]["Issues"] == "https://github.com/thomamartin/Advocate/issues"
    )


def test_unsafe_connect_raises():
    with pytest.raises(DisallowedConnectException):
        requests.get("http://example.org/")


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("132.0.5.1", False),
        ("152.254.90.1", False),
        ("178.254.90.1", True),
        ("::1", False),
        # Google, found via `dig google.com AAAA`
        ("2607:f8b0:400a:807::200e", True),
    ],
)
def test_manual_ip_blacklist(ip, expected):
    """Test manually blacklisting based on IP"""
    validator = AddrValidator(
        allow_ipv6=True,
        ip_blacklist=(
            ipaddress.ip_network("132.0.5.0/24"),
            ipaddress.ip_network("152.0.0.0/8"),
            ipaddress.ip_network("::1"),
        ),
    )
    assert validator.is_ip_allowed(ip) is expected


def test_ip_whitelist():
    """Test manually whitelisting based on IP"""
    validator = AddrValidator(
        ip_whitelist=(ipaddress.ip_network("127.0.0.1"),),
    )
    assert validator.is_ip_allowed("127.0.0.1")


def test_ip_whitelist_blacklist_conflict():
    """Manual whitelist should take precedence over manual blacklist"""
    validator = AddrValidator(
        ip_whitelist=(ipaddress.ip_network("127.0.0.1"),),
        ip_blacklist=(ipaddress.ip_network("127.0.0.1"),),
    )
    assert validator.is_ip_allowed("127.0.0.1")


@pytest.mark.skip(reason="takes half an hour or so to run")
def test_safecurl_blacklist():
    """Test that we at least disallow everything SafeCurl does"""
    bad_netblocks = (
        ipaddress.ip_network(x)
        for x in (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/29",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
    )
    validator = AddrValidator()
    for bad_netblock in bad_netblocks:
        num_ips = bad_netblock.num_addresses
        step_size = int(min(max(num_ips / 255, 1), 128))
        for ip_idx in range(0, num_ips, step_size):
            bad_ip = bad_netblock[ip_idx]
            assert not validator.is_ip_allowed(bad_ip), bad_ip


def test_ipv4_mapped():
    assert_ip_kind_blocked("::ffff:192.168.2.1")
    assert_ip_kind_blocked("::ffff:8.8.8.8")


@pytest.mark.parametrize("allow_teredo", [True, False])
def test_teredo(allow_teredo):
    # 192.168.2.1 as the client address; disallowed even if teredo is allowed
    assert_ip_kind_blocked(
        "2001:0000:4136:e378:8000:63bf:3f57:fdf2",
        allow_teredo=allow_teredo,
    )
    # 65.54.227.120 server and 8.8.8.8 client: allowed iff allow_teredo=True
    validator = permissive_validator(allow_teredo=allow_teredo)
    assert validator.is_ip_allowed("2001:0000:4136:e378:8000:63bf:f7f7:f7f7") is allow_teredo


def test_ipv6():
    assert_ip_kind_blocked("2002:C0A8:FFFF::", allow_ipv6=False)


@pytest.mark.parametrize("allow_6to4", [True, False])
def test_sixtofour(allow_6to4):
    # 192.168.XXX.XXX: disallowed even if 6to4 is allowed
    assert_ip_kind_blocked("2002:C0A8:FFFF::", allow_6to4=allow_6to4)
    # 8.8.8.8: allowed iff allow_6to4=True
    validator = permissive_validator(allow_6to4=allow_6to4)
    assert validator.is_ip_allowed("2002:0808:0808::") is allow_6to4


@pytest.mark.parametrize("allow_dns64", [True, False])
def test_dns64(allow_dns64):
    # https://tools.ietf.org/html/rfc6052
    assert_ip_kind_blocked("64:ff9b::192.168.2.1", allow_dns64=allow_dns64)
    # 8.8.8.8: allowed iff allow_dns64=True
    validator = permissive_validator(allow_dns64=allow_dns64)
    assert validator.is_ip_allowed("64:ff9b::8.8.8.8") is allow_dns64


def test_link_local():
    # 169.254.XXX.XXX, AWS uses these for autoconfiguration
    assert_ip_kind_blocked("169.254.1.1")


def test_site_local():
    assert_ip_kind_blocked("FEC0:CCCC::")


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1"])
def test_loopback(ip):
    assert_ip_kind_blocked(ip)


def test_multicast():
    assert_ip_kind_blocked("227.1.1.1")


@pytest.mark.parametrize(
    "ip",
    ["192.168.2.1", "10.5.5.5", "0.0.0.0", "0.1.1.1", "100.64.0.0"],
)
def test_private(ip):
    assert_ip_kind_blocked(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "255.255.255.255",
        "::ffff:192.168.2.1",
        # 6to4 relay
        "192.88.99.0",
    ],
)
def test_reserved(ip):
    assert_ip_kind_blocked(ip)


def test_unspecified():
    assert_ip_kind_blocked("0.0.0.0")


def test_parsed():
    validator = permissive_validator()
    assert not validator.is_ip_allowed(ipaddress.ip_address("0.0.0.0"))
    assert validator.is_ip_allowed(ipaddress.ip_address("144.1.1.1"))


def test_addrinfo_simple():
    assert not is_addrinfo_allowed("192.168.0.1", 80)


def test_malformed_addrinfo():
    vl = permissive_validator()
    addrinfo = advocate_getaddrinfo("example.com", 80)[0] + (1,)
    with pytest.raises((AssertionError, ValueError)):
        vl.is_addrinfo_allowed(addrinfo)


def test_unexpected_proto():
    vl = permissive_validator()
    addrinfo = list(advocate_getaddrinfo("example.com", 80)[0])
    addrinfo[4] = addrinfo[4] + (1,)
    with pytest.raises(ValueError):
        vl.is_addrinfo_allowed(addrinfo)


@pytest.mark.parametrize(
    ("port", "expected"),
    [(8080, True), (80, True), (99, False)],
)
def test_default_port_whitelist(port, expected):
    assert is_addrinfo_allowed("200.1.1.1", port) is expected


@pytest.mark.parametrize(
    ("port", "expected"),
    [(80, True), (10, True), (99, False)],
)
def test_port_whitelist(port, expected):
    wl = (80, 10)
    assert is_addrinfo_allowed("200.1.1.1", port, port_whitelist=wl) is expected


@pytest.mark.parametrize(
    ("port", "expected"),
    [(80, False), (10, False), (99, True)],
)
def test_port_blacklist(port, expected):
    bl = (80, 10)
    assert is_addrinfo_allowed("200.1.1.1", port, port_blacklist=bl) is expected


def test_local_address_handling(local_address_calls):
    assert not is_addrinfo_allowed(
        "200.1.1.1",
        80,
        autodetect_local_addresses=True,
    )
    # Check that `is_ip_allowed` didn't make its own call to determine local addresses
    assert len(local_address_calls) == 1
    local_address_calls.clear()

    assert is_addrinfo_allowed(
        "200.1.1.1",
        80,
        autodetect_local_addresses=False,
    )
    assert not local_address_calls


def test_ifaddr_presence_optional(monkeypatch):
    # Advocate should still work without ifaddr, but only if you've specifically
    # said you don't care about checking against local interface addresses.
    with monkeypatch.context() as m:
        m.setattr("advocate.addrvalidator.HAVE_IFADDR", False)
        with pytest.raises(ConfigException):
            is_addrinfo_allowed("200.1.1.1", 80, autodetect_local_addresses=True)
        with pytest.raises(ConfigException):
            advocate.addrvalidator.determine_local_addresses()
        # Should be fine if you specifically asked to not look at the local addrs
        assert is_addrinfo_allowed(
            "200.1.1.1",
            80,
            autodetect_local_addresses=False,
        )

    # These shouldn't `raise`
    is_addrinfo_allowed("200.1.1.1", 80, autodetect_local_addresses=True)
    advocate.addrvalidator.determine_local_addresses()


def test_determine_local_addresses():
    local_addresses = advocate.addrvalidator.determine_local_addresses()
    assert ipaddress.ip_network("127.0.0.1") in local_addresses


@requires_canonname
def test_hostname_no_blacklist():
    assert is_hostname_allowed("example.com")


@requires_canonname
@pytest.mark.parametrize(
    ("host", "blacklist", "expected"),
    [
        ("中国.example.org", {"*.org"}, False),
        ("中国.example.oRg", {"*.Org"}, False),
        ("中国.example.org", {"xn--fiqs8s.*.org"}, False),
        ("xn--fiqs8s.example.org", {"中国.*.org"}, False),
        ("example.org", {"中国.*.org"}, True),
        ("example.com", {"中国.*.org"}, True),
        ("foo.example.org", {"中国.*.org"}, True),
    ],
)
def test_idn(host, blacklist, expected):
    assert (
        is_hostname_allowed(host, fake_lookup=True, hostname_blacklist=blacklist) is expected
    )


@requires_canonname
def test_missing_canonname():
    addrinfo = socket.getaddrinfo(
        "127.0.0.1",
        1,
        0,
        socket.SOCK_STREAM,
    )
    assert addrinfo

    # Should throw an error if we're using hostname blacklisting and the
    # addrinfo record we passed in doesn't have a canonname
    validator = permissive_validator(hostname_blacklist={"foo"})
    with pytest.raises(NameserverException):
        validator.is_addrinfo_allowed(addrinfo[0])


@requires_canonname
@pytest.mark.parametrize(
    "hostname",
    [
        "foo.baz.com\x00.example.com",
        "foo.example.com\x00.baz.com",
    ],
)
def test_embedded_null(hostname):
    vl = permissive_validator(hostname_blacklist={"*.baz.com"})
    assert not vl.is_hostname_allowed(hostname)


def test_connection_reuse(monkeypatch):
    new_conn_calls = []
    monkeypatch.setattr(
        "advocate.connection.ValidatingHTTPConnection._new_conn",
        lambda self: new_conn_calls.append(self),
    )
    with CheckedSocket.bypass_checks():
        requests.get("http://httpbin.org/")
    assert not new_conn_calls
    try:
        advocate.get("http://httpbin.org/")
    except Exception:
        pass
    assert new_conn_calls


@pytest.mark.parametrize("url", ["http://example.com", "https://example.com"])
def test_advocate_get(url):
    assert advocate.get(url).status_code == 200


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1/", "http://localhost/", "https://localhost/"],
)
def test_advocate_validator(url):
    with pytest.raises(UnacceptableAddressException):
        advocate.get(url)


@requires_canonname
def test_blacklist_hostname():
    with pytest.raises(UnacceptableAddressException):
        advocate.get(
            "https://google.com/",
            validator=AddrValidator(hostname_blacklist={"google.com"}),
        )


def test_redirect():
    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/status/204":
                self.send_response(204)
                self.end_headers()
            elif self.path == "/redirect-ok":
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.1:{self.server.server_port}/status/204"
                )
                self.end_headers()
            elif self.path == "/redirect-blocked":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.2:1/")
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        validator = AddrValidator(
            ip_whitelist={ipaddress.ip_network("127.0.0.1")},
            port_whitelist={port, 1},
        )
        assert (
            advocate.get(
                f"http://127.0.0.1:{port}/redirect-ok",
                validator=validator,
            ).status_code
            == 204
        )
        with pytest.raises(UnacceptableAddressException):
            advocate.get(
                f"http://127.0.0.1:{port}/redirect-blocked",
                validator=validator,
            )
    finally:
        server.shutdown()
        server.server_close()


def test_mount_disabled():
    sess = advocate.Session()
    with pytest.raises(MountDisabledException):
        sess.mount("foo://", None)


def test_advocate_requests_api_wrapper():
    wrapper = RequestsAPIWrapper(validator=AddrValidator())
    local_validator = AddrValidator(
        ip_whitelist={
            ipaddress.ip_network("127.0.0.1"),
        }
    )
    local_wrapper = RequestsAPIWrapper(validator=local_validator)

    with pytest.raises(UnacceptableAddressException):
        wrapper.get("http://127.0.0.1:1/")
    # Check that we got a connection exception instead of a validation one
    with pytest.raises(requests.ConnectionError):
        local_wrapper.get("http://127.0.0.1:1/")
    with pytest.raises(UnacceptableAddressException):
        wrapper.get("http://localhost:1/")
    with pytest.raises(UnacceptableAddressException):
        wrapper.get("https://localhost:1/")


def test_advocate_default_validator_replaceable(monkeypatch):
    new_validator = AddrValidator(hostname_blacklist=["example.org"])
    monkeypatch.setattr("advocate.api.Session.DEFAULT_VALIDATOR", new_validator)
    with pytest.raises(UnacceptableAddressException):
        advocate.get("http://example.org")


def test_wrapper_session_pickle():
    # Make sure the validator still works after a pickle round-trip
    sess_instance = pickle.loads(pickle.dumps(global_wrapper.Session()))

    with pytest.raises(requests.ConnectionError):
        sess_instance.get("http://127.0.0.1:1/")
    with pytest.raises(UnacceptableAddressException):
        sess_instance.get("http://127.0.1.1:1/")


def test_wrapper_session_subclass():
    # Make sure pickle doesn't explode if we try to pickle a subclass
    # of `global_wrapper.Session`
    def _check_instance(instance):
        assert instance.good_method() == "foo"

        with pytest.raises(requests.ConnectionError):
            instance.get("http://127.0.0.1:1/")
        with pytest.raises(UnacceptableAddressException):
            instance.get("http://127.0.1.1:1/")

    sess = _WrapperSubclass()
    _check_instance(sess)
    sess_unpickled = pickle.loads(pickle.dumps(sess))
    _check_instance(sess_unpickled)


@requires_canonname
def test_advocate_requests_api_wrapper_hostnames():
    wrapper = RequestsAPIWrapper(
        validator=AddrValidator(
            hostname_blacklist={"google.com"},
        )
    )
    with pytest.raises(UnacceptableAddressException):
        wrapper.get("https://google.com/")


@pytest.mark.parametrize(
    "method_name", ["get", "options", "head", "post", "put", "patch", "delete"]
)
def test_advocate_requests_api_wrapper_req_methods(method_name, requests_mock):
    wrapper = RequestsAPIWrapper(AddrValidator())
    requests_mock.request(method_name, "http://example.com/foo")
    getattr(wrapper, method_name)("http://example.com/foo")


def test_wrapper_getattr_fallback():
    wrapper = RequestsAPIWrapper(AddrValidator())
    assert wrapper.PreparedRequest is not None


def test_proxy_attempt_throws():
    with pytest.raises(NotImplementedError):
        advocate.get(
            "http://example.org/",
            proxies={
                "http": "http://example.org:3128",
                "https": "http://example.org:1080",
            },
        )


def test_connect_without_local_addresses(local_address_calls):
    validator = permissive_validator(autodetect_local_addresses=True)
    advocate.get("http://example.com/", validator=validator)
    assert len(local_address_calls) == 1
    local_address_calls.clear()

    validator = permissive_validator(autodetect_local_addresses=False)
    advocate.get("http://example.com", validator=validator)
    assert not local_address_calls


def test_futures_get():
    sess = FuturesSession()
    assert sess.get("http://example.org/").result().status_code == 200


def test_futures_custom_validator():
    validator = AddrValidator(hostname_blacklist={"example.org"})
    sess = FuturesSession(validator=validator)
    with pytest.raises(UnacceptableAddressException):
        sess.get("http://example.org").result()


def test_futures_many_workers():
    sess = FuturesSession(max_workers=50)
    for prefix in ("http://", "https://"):
        adapter = sess.get_adapter(prefix)
        assert isinstance(adapter, ValidatingHTTPAdapter)
        assert adapter._pool_maxsize == 50
    with pytest.raises(UnacceptableAddressException):
        sess.get("http://127.0.0.1:1/").result()


def test_futures_extra_positional_args():
    with pytest.raises(TypeError):
        FuturesSession(None, 2, None, {"pool_maxsize": 1})


@pytest.mark.parametrize("session_cls", [requests.Session, advocate.Session])
def test_futures_passing_session(session_cls):
    with pytest.raises(NotImplementedError):
        FuturesSession(session=session_cls())

    sess = FuturesSession()
    with pytest.raises(NotImplementedError):
        sess.session = session_cls()


def test_advocate_wrapper_futures():
    wrapper = RequestsAPIWrapper(validator=AddrValidator())
    local_validator = AddrValidator(
        ip_whitelist={
            ipaddress.ip_network("127.0.0.1"),
        }
    )
    local_wrapper = RequestsAPIWrapper(validator=local_validator)

    with pytest.raises(UnacceptableAddressException):
        sess = wrapper.FuturesSession()
        sess.get("http://127.0.0.1/").result()

    with pytest.raises(requests.ConnectionError):
        sess = local_wrapper.FuturesSession()
        sess.get("http://127.0.0.1:1/").result()

    with pytest.raises(UnacceptableAddressException):
        sess = wrapper.FuturesSession()
        sess.get("http://localhost:1/").result()
    with pytest.raises(UnacceptableAddressException):
        sess = wrapper.FuturesSession()
        sess.get("https://localhost:1/").result()


def test_determine_local_addresses_ipv4_and_ipv6(monkeypatch):
    fake_adapters = [
        types.SimpleNamespace(
            ips=[
                types.SimpleNamespace(is_IPv6=False, ip="192.0.2.10"),
                types.SimpleNamespace(is_IPv6=True, ip=("2001:db8::1", 0, 1)),
            ]
        )
    ]
    monkeypatch.setattr(
        "advocate.addrvalidator.ifaddr.get_adapters",
        lambda: fake_adapters,
    )
    local_addrs = advocate.addrvalidator.determine_local_addresses()
    assert local_addrs == [
        ipaddress.ip_network("192.0.2.10"),
        ipaddress.ip_network("2001:db8::1"),
    ]


def test_hostname_blacklist_trailing_dot_and_regex():
    validator = permissive_validator(
        hostname_blacklist={"*.example.org.", re.compile(r"^internal\..*")}
    )
    assert not validator.is_hostname_allowed("sub.example.org")
    assert not validator.is_hostname_allowed("sub.example.org.")
    assert not validator.is_hostname_allowed("internal.corp.local")
    assert validator.is_hostname_allowed("example.com")


def test_host_header_blacklist_enforcement():
    validator = AddrValidator(
        ip_whitelist={ipaddress.ip_network("127.0.0.1")},
        hostname_blacklist={"*.internal.example.com"},
    )
    with pytest.raises(UnacceptableAddressException):
        advocate.get(
            "http://127.0.0.1:1/",
            headers={"Host": "admin.internal.example.com:8080"},
            validator=validator,
        )
    with pytest.raises(requests.ConnectionError):
        advocate.get(
            "http://127.0.0.1:1/",
            headers={"Host": "public.example.com"},
            validator=validator,
        )


def test_pool_key_normalizer_and_mutation():
    validator = AddrValidator()
    k1 = key_normalizer(
        AdvocatePoolKey,
        {"scheme": "http", "host": "example.com", "port": 80, "validator": validator},
    )
    validator.ip_blacklist.add(ipaddress.ip_network("93.184.216.0/24"))
    k2 = key_normalizer(
        AdvocatePoolKey,
        {"scheme": "http", "host": "example.com", "port": 80, "validator": validator},
    )
    assert k1 != k2

    custom_validator = object()
    k3 = key_normalizer(
        AdvocatePoolKey,
        {
            "scheme": "http",
            "host": "example.com",
            "port": 80,
            "validator": custom_validator,
        },
    )
    assert k3.key_validator == id(custom_validator)


@pytest.mark.parametrize(
    "method_name",
    ["get", "options", "head", "post", "put", "patch", "delete"],
)
def test_top_level_api_methods_and_session(method_name):
    sess = advocate.session()
    assert isinstance(sess, advocate.Session)
    with pytest.raises(UnacceptableAddressException):
        getattr(advocate, method_name)("http://127.0.0.1:1/")


def test_wrapper_without_futures(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "futures" and level == 1:
            raise ImportError("mocked missing futures")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    wrapper = RequestsAPIWrapper(AddrValidator())
    assert not hasattr(wrapper, "FuturesSession")
    assert isinstance(wrapper.session(), advocate.Session)


def test_validating_connection_edge_cases(monkeypatch):
    validator = AddrValidator(
        ip_whitelist={ipaddress.ip_network("::1"), ipaddress.ip_network("127.0.0.1")},
        allow_ipv6=True,
    )
    with pytest.raises(OSError):
        validating_create_connection(
            ("[::1]", 1),
            timeout=0.1,
            source_address=("127.0.0.1", 0),
            validator=validator,
        )

    monkeypatch.setattr(
        "advocate.connection.advocate_getaddrinfo",
        lambda host, port, get_canonname=False: [],
    )
    with pytest.raises(OSError, match="getaddrinfo returns an empty list"):
        validating_create_connection(("example.com", 80), validator=validator)

    conn = ValidatingHTTPSConnection("example.com", 443, validator=validator)
    with pytest.raises(NewConnectionError):
        conn._new_conn()

    def raise_timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(
        "advocate.connection.validating_create_connection",
        raise_timeout,
    )
    with pytest.raises(ConnectTimeoutError):
        conn._new_conn()

    def raise_gaierror(*args, **kwargs):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(
        "advocate.connection.validating_create_connection",
        raise_gaierror,
    )
    with pytest.raises(NameResolutionError):
        conn._new_conn()
