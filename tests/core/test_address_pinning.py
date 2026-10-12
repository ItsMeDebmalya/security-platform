"""D60: the address checked is the address connected to (ADR-036).

The attack this guards against is DNS rebinding: a check passes on the first
answer, and the connection, which resolves the name again, goes to the second.
So the tests here use a resolver that answers with a public address first and
a forbidden one afterwards, and watch the sockets: every connection must go to
the first address, and nothing below the policy may be handed a name to
resolve for itself (`socket.getaddrinfo` sees address literals only).

The tests hand their own socket to the lab servers by patching
`socket.create_connection`: the connection is *recorded* at the public address
the client asked for, then made to a loopback server. Nothing leaves the host.
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

from core.addresses import AddressPolicy, AddressRefusedError, LabOverride
from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, DnsResponse
from core.http import HttpClient, SystemHttpBackend
from core.models import Asset
from core.tls import SystemTlsBackend, TlsClient
from corpus.generators.tls_lab import lab_server, mint

PUBLIC = "93.184.215.14"
PUBLIC_2 = "93.184.215.15"
FORBIDDEN = "169.254.169.254"
NAME = "example.test"


class FlippingDns:
    """No cache: answers `first` once per name, then `then` for ever."""

    def __init__(self, first: str = PUBLIC, then: str = FORBIDDEN) -> None:
        self.first, self.then = first, then
        self.asked: dict[str, int] = {}

    def query(self, name: str, rrtype: str, *, resolver: str | None = None) -> DnsResponse:
        if rrtype != "A":
            return DnsResponse(name, rrtype, "NODATA", [])
        self.asked[name] = self.asked.get(name, 0) + 1
        answer = self.first if self.asked[name] == 1 else self.then
        return DnsResponse(name, rrtype, "NOERROR", [answer])


class FlippingResolver:
    """The same, behind the real `DnsClient` (and so behind its cache)."""

    def __init__(self) -> None:
        self.inner = FlippingDns()

    def resolve(self, name: str, rrtype: str, upstream: str | None) -> DnsResponse:
        return self.inner.query(name, rrtype)


class StaticDns:
    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers

    def query(self, name: str, rrtype: str, *, resolver: str | None = None) -> DnsResponse:
        if rrtype != "A" or name not in self.answers:
            return DnsResponse(name, rrtype, "NODATA", [])
        return DnsResponse(name, rrtype, "NOERROR", [self.answers[name]])


@pytest.fixture
def wire(monkeypatch) -> dict:
    """Record every connection and every lookup below the policy.

    A connection is recorded at the address asked for, then made to the
    loopback port registered for it, so a real handshake can complete.
    """
    seen: dict = {"connect": [], "getaddrinfo": [], "ports": {}}
    real_connect = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo

    def connect(address, *args, **kwargs):
        host, port = address[0], address[1]
        seen["connect"].append((host, port))
        target = seen["ports"].get((host, port))
        if target is None:
            raise ConnectionRefusedError(f"test: nothing listens for {host}:{port}")
        return real_connect(("127.0.0.1", target), *args, **kwargs)

    def getaddrinfo(host, *args, **kwargs):
        seen["getaddrinfo"].append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return seen


def _names_resolved(seen: dict) -> list[str]:
    def literal(value) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in str(value) else socket.AF_INET, str(value))
        except OSError:
            return False
        return True

    return [h for h in seen["getaddrinfo"] if not literal(h)]


# --- TLS ---------------------------------------------------------------------


def _tls(dns, **kwargs) -> TlsClient:
    return TlsClient(scope=Scope(frozenset({NAME})), dns=dns, **kwargs)


def test_every_connection_of_a_handshake_goes_to_the_address_checked(wire) -> None:
    """One handshake makes up to four connections; all go to the first answer."""
    with lab_server(common_name=NAME, sans=[NAME]) as srv:
        wire["ports"][(PUBLIC, 443)] = srv.port
        observation = _tls(FlippingDns()).inspect(NAME, 443)

    assert observation.reachable
    assert len(wire["connect"]) >= 2  # observe and verify at least
    assert set(wire["connect"]) == {(PUBLIC, 443)}
    assert _names_resolved(wire) == []


def test_a_second_lookup_cannot_move_the_connection(wire) -> None:
    """Behind the real DnsClient the first answer holds for the scan; the
    resolver's later, forbidden answer is never connected to."""
    resolver = FlippingResolver()
    dns = DnsClient(resolver=resolver, resolvers=["192.0.2.53"])
    with lab_server(common_name=NAME, sans=[NAME]) as srv:
        wire["ports"][(PUBLIC, 443)] = srv.port
        client = _tls(dns)
        first = client.inspect(NAME, 443)
        second = client.inspect(NAME, 443)

    assert first.reachable and second.reachable
    assert {a for a, _ in wire["connect"]} == {PUBLIC}
    assert _names_resolved(wire) == []


def test_without_a_cache_a_rebound_answer_is_refused_never_connected(wire) -> None:
    """With no cache the second handshake looks the name up again, gets the
    forbidden address, and is refused: no connection is made for it."""
    dns = FlippingDns()
    with lab_server(common_name=NAME, sans=[NAME]) as srv:
        wire["ports"][(PUBLIC, 443)] = srv.port
        client = _tls(dns)
        client.inspect(NAME, 443)
        before = list(wire["connect"])
        refused = client.inspect(NAME, 443)

    assert refused.reachable is False
    assert refused.error is not None and refused.error.startswith("address_refused:")
    assert FORBIDDEN in refused.error
    assert wire["connect"] == before


def test_the_hostname_is_still_the_sni_and_the_name_checked(wire, tmp_path) -> None:
    with http_server(tls_for=NAME, tmp=tmp_path) as srv:
        wire["ports"][(PUBLIC, 443)] = srv["port"]
        observation = _tls(StaticDns({NAME: PUBLIC})).inspect(NAME, 443, servername=NAME)

    assert observation.reachable
    assert set(srv["sni"]) == {NAME}
    assert observation.certificate is not None
    assert observation.certificate.covers_hostname(NAME)
    assert observation.address == PUBLIC


def test_the_live_tls_backend_refuses_to_be_handed_no_address() -> None:
    with pytest.raises(ValueError, match="checked address"):
        SystemTlsBackend().handshake(NAME, 443, NAME)


def test_a_tls_target_resolving_to_private_space_is_refused_before_any_socket(wire) -> None:
    observation = _tls(StaticDns({NAME: "10.0.0.5"})).inspect(NAME, 443)
    assert observation.reachable is False
    assert observation.error is not None and "10.0.0.5" in observation.error
    assert wire["connect"] == []


def test_a_lab_override_lets_the_tls_client_reach_loopback(wire) -> None:
    lab = AddressPolicy(lab_override=LabOverride(reason="unit test", allow_non_global=True))
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        wire["ports"][("127.0.0.1", srv.port)] = srv.port
        client = TlsClient(
            scope=Scope(frozenset({"localhost"})),
            dns=StaticDns({"localhost": "127.0.0.1"}),
            addresses=lab,
        )
        assert client.inspect("localhost", srv.port).reachable


# --- HTTP --------------------------------------------------------------------


@contextmanager
def http_server(*, tls_for: str | None = None, tmp: Path | None = None) -> Iterator[dict]:
    """A tiny HTTP(S) server on loopback that records SNI, Host and the path."""
    seen: dict = {"requests": [], "sni": [], "routes": {}}
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    seen["port"] = sock.getsockname()[1]
    context = None
    if tls_for is not None:
        assert tmp is not None
        minted = mint(tmp, "http", common_name=tls_for, sans=[tls_for])
        seen["cafile"] = str(minted.cert_path)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(minted.cert_path, minted.key_path)
        context.sni_callback = lambda s, name, c: seen["sni"].append(name)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = sock.accept()
            except OSError:
                return
            conn = raw
            try:
                conn = context.wrap_socket(raw, server_side=True) if context else raw
                data = conn.recv(65536).decode("latin-1")
                line, *headers = data.split("\r\n")
                path = line.split(" ")[1]
                host = next(
                    (h.split(":", 1)[1].strip() for h in headers if h.lower().startswith("host:")),
                    None,
                )
                cookie = next(
                    (
                        h.split(":", 1)[1].strip()
                        for h in headers
                        if h.lower().startswith("cookie:")
                    ),
                    None,
                )
                seen["requests"].append({"path": path, "host": host, "cookie": cookie})
                status, extra = seen["routes"].get(path, ("200 OK", ""))
                head = f"HTTP/1.1 {status}\r\n{extra}Content-Length: 2\r\nConnection: close"
                conn.sendall(f"{head}\r\n\r\nok".encode())
            except (OSError, ssl.SSLError, IndexError):
                pass
            finally:
                conn.close()
                raw.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield seen
    finally:
        stop.set()
        sock.close()


def _http(dns, *, scope=None, **kwargs) -> HttpClient:
    return HttpClient(scope=scope or Scope(frozenset({NAME})), dns=dns, **kwargs)


def test_an_http_request_goes_to_the_checked_address_with_the_name_as_host(wire) -> None:
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        response = _http(FlippingDns()).get(f"http://{NAME}/a")

    assert response.status_code == 200
    assert response.url == f"http://{NAME}/a"
    assert srv["requests"] == [{"path": "/a", "host": NAME, "cookie": None}]
    assert wire["connect"] == [(PUBLIC, 80)]
    assert _names_resolved(wire) == []
    assert response.captured["address"] == PUBLIC


def test_https_carries_the_name_as_sni_and_host_and_checks_the_certificate_against_it(
    wire, tmp_path
) -> None:
    with http_server(tls_for=NAME, tmp=tmp_path) as srv:
        wire["ports"][(PUBLIC, 443)] = srv["port"]
        client = _http(
            StaticDns({NAME: PUBLIC}),
            backend=SystemHttpBackend(trust_anchor=srv["cafile"]),
        )
        response = client.get(f"https://{NAME}/")

    assert response.status_code == 200
    assert srv["sni"] == [NAME]
    assert srv["requests"][0]["host"] == NAME
    assert wire["connect"] == [(PUBLIC, 443)]
    assert _names_resolved(wire) == []


def test_https_with_a_certificate_for_another_name_fails_verification(wire, tmp_path) -> None:
    with http_server(tls_for="other.test", tmp=tmp_path) as srv:
        wire["ports"][(PUBLIC, 443)] = srv["port"]
        client = _http(
            StaticDns({NAME: PUBLIC}),
            backend=SystemHttpBackend(trust_anchor=srv["cafile"]),
        )
        with pytest.raises(httpx.ConnectError, match=r"(?i)hostname"):
            client.get(f"https://{NAME}/")


def test_every_redirect_hop_is_resolved_and_checked_afresh(wire) -> None:
    """D54's address twin: an in-scope hop to a name resolving to private space
    is refused at that hop, with no approval inherited from the first."""
    scope = Scope.for_target(Asset(type="domain", value=NAME))
    dns = StaticDns({NAME: PUBLIC, f"internal.{NAME}": "10.0.0.5"})
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        srv["routes"]["/"] = ("302 Found", f"Location: http://internal.{NAME}/admin\r\n")
        with pytest.raises(AddressRefusedError) as caught:
            _http(dns, scope=scope).get(f"http://{NAME}/")

    assert caught.value.host == f"internal.{NAME}"
    assert "10.0.0.5" in str(caught.value)
    assert wire["connect"] == [(PUBLIC, 80)]
    assert [r["path"] for r in srv["requests"]] == ["/"]


def test_a_redirect_to_the_same_name_cannot_rebind_it(wire) -> None:
    resolver = FlippingResolver()
    dns = DnsClient(resolver=resolver, resolvers=["192.0.2.53"])
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        srv["routes"]["/"] = ("302 Found", "Location: /next\r\n")
        response = _http(dns).get(f"http://{NAME}/")

    assert response.status_code == 200
    assert wire["connect"] == [(PUBLIC, 80), (PUBLIC, 80)]


def test_the_environment_cannot_route_a_request_through_a_proxy(wire, monkeypatch) -> None:
    """D62: httpx honours proxy variables by default; the proxy would resolve the
    name and choose the destination behind our checks."""
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.80:3128")
    monkeypatch.setenv("ALL_PROXY", "http://192.0.2.80:3128")
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        _http(StaticDns({NAME: PUBLIC})).get(f"http://{NAME}/")
    assert wire["connect"] == [(PUBLIC, 80)]


def test_two_names_on_one_address_never_share_a_connection(wire) -> None:
    other = f"www.{NAME}"
    scope = Scope.for_target(Asset(type="domain", value=NAME))
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        client = _http(StaticDns({NAME: PUBLIC, other: PUBLIC}), scope=scope)
        client.get(f"http://{NAME}/")
        client.get(f"http://{other}/")
    assert len(wire["connect"]) == 2
    assert [r["host"] for r in srv["requests"]] == [NAME, other]


def test_cookies_are_not_carried_between_requests(wire) -> None:
    """A jar would file cookies under the address and hand one name's cookie to
    another name on it; it was measured as unneeded before removal (D60)."""
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        srv["routes"]["/"] = ("302 Found", "Set-Cookie: session=abc; Path=/\r\nLocation: /next\r\n")
        _http(StaticDns({NAME: PUBLIC})).get(f"http://{NAME}/")
    assert [(r["path"], r["cookie"]) for r in srv["requests"]] == [("/", None), ("/next", None)]


def test_a_connect_failure_moves_to_the_next_checked_address(wire) -> None:
    class TwoAddresses:
        def query(self, name, rrtype, *, resolver=None):
            if rrtype != "A":
                return DnsResponse(name, rrtype, "NODATA", [])
            return DnsResponse(name, rrtype, "NOERROR", [PUBLIC, PUBLIC_2])

    with http_server() as srv:
        wire["ports"][(PUBLIC_2, 80)] = srv["port"]  # the first refuses
        response = _http(TwoAddresses()).get(f"http://{NAME}/")
    assert response.status_code == 200
    assert wire["connect"] == [(PUBLIC, 80), (PUBLIC_2, 80)]
    assert response.captured["address"] == PUBLIC_2


def test_the_live_http_backend_refuses_to_be_handed_no_address() -> None:
    with pytest.raises(ValueError, match="checked address"):
        SystemHttpBackend().send("GET", f"http://{NAME}/", body_cap=1024)


def test_an_http_target_resolving_to_metadata_is_refused_before_any_socket(wire) -> None:
    with pytest.raises(AddressRefusedError, match=re.escape(FORBIDDEN)):
        _http(StaticDns({NAME: FORBIDDEN})).get(f"http://{NAME}/latest/meta-data/")
    assert wire["connect"] == []


# --- one policy, handed out by the scan -----------------------------------------


def test_the_scan_context_hands_one_policy_and_its_resolver_to_every_client() -> None:
    from core.testssl import LiveTestsslClient

    dns = DnsClient(resolver=FlippingResolver(), resolvers=["192.0.2.53"])
    http = HttpClient(scope=Scope(frozenset({NAME})))
    tls = TlsClient(scope=Scope(frozenset({NAME})))
    testssl = LiveTestsslClient()
    ctx = ScanContext(dns=dns, http=http, tls=tls, testssl=testssl)

    assert ctx.addresses.lab_reason is None
    for client in (http, tls, testssl):
        assert client.addresses is ctx.addresses
        assert client.dns is dns


def test_a_client_with_no_policy_uses_the_default_one() -> None:
    """Fail safe: an unwired client gets the policy with no override."""
    client = _http(StaticDns({NAME: "127.0.0.1"}))
    with pytest.raises(AddressRefusedError):
        client.get(f"http://{NAME}/")


# --- a backend must say whether it opens sockets ---------------------------------


def _backends():
    import inspect

    import core.http
    import core.tls

    for module in (core.http, core.tls):
        for name, cls in inspect.getmembers(module, inspect.isclass):
            protocol = name in ("HttpBackend", "TlsBackend")
            if name.endswith("Backend") and cls.__module__ == module.__name__ and not protocol:
                yield pytest.param(cls, id=name)


@pytest.mark.parametrize("cls", list(_backends()))
def test_every_core_backend_declares_whether_it_connects(cls) -> None:
    """A client pins only for a backend that says it connects, so a live backend
    that forgot to say so would skip the policy silently. Every one in core/
    must declare it, and the live ones must say yes."""
    assert "connects" in vars(cls), f"{cls.__name__} does not declare `connects`"
    if cls.__name__.startswith("System"):
        assert cls.connects is True
    if cls.__name__.startswith("Replay"):
        assert cls.connects is False


def test_a_recording_backend_connects_exactly_when_what_it_wraps_does(tmp_path) -> None:
    from core.http import RecordingHttpBackend, ReplayHttpBackend
    from core.tls import RecordingTlsBackend, ReplayTlsBackend

    assert RecordingHttpBackend(tmp_path, SystemHttpBackend()).connects is True
    assert RecordingHttpBackend(tmp_path, ReplayHttpBackend(tmp_path)).connects is False
    assert RecordingTlsBackend(tmp_path, SystemTlsBackend()).connects is True
    assert RecordingTlsBackend(tmp_path, ReplayTlsBackend(tmp_path)).connects is False


# --- review of D60, round 1 ---------------------------------------------------


def test_a_tls_failure_on_the_first_address_is_the_answer_not_a_reason_to_move_on(
    wire, tmp_path
) -> None:
    """Should-fix 1: httpx chains the SSL error two levels down, so a check on
    `__cause__` alone never fired and a bad certificate fell through to the
    next address, which answered cleanly."""

    class TwoAddresses:
        def query(self, name, rrtype, *, resolver=None):
            if rrtype != "A":
                return DnsResponse(name, rrtype, "NODATA", [])
            return DnsResponse(name, rrtype, "NOERROR", [PUBLIC, PUBLIC_2])

    with (
        http_server(tls_for="other.test", tmp=tmp_path / "bad") as bad,
        http_server(tls_for=NAME, tmp=tmp_path / "good") as good,
    ):
        wire["ports"][(PUBLIC, 443)] = bad["port"]
        wire["ports"][(PUBLIC_2, 443)] = good["port"]
        anchors = tmp_path / "both.pem"
        anchors.write_text(Path(bad["cafile"]).read_text() + Path(good["cafile"]).read_text())
        client = _http(TwoAddresses(), backend=SystemHttpBackend(trust_anchor=str(anchors)))
        with pytest.raises(httpx.ConnectError, match=r"(?i)hostname"):
            client.get(f"https://{NAME}/")
    assert wire["connect"] == [(PUBLIC, 443)]


def test_a_backend_that_does_not_say_whether_it_connects_is_treated_as_connecting() -> None:
    """Should-fix 3: fail closed. A live backend written later that forgets
    `connects` must not skip the policy."""
    from core.http import RawHttpResponse

    class Undeclared:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[str, ...] | None]] = []

        def send(self, method, url, *, body_cap, addresses=None, **kwargs):
            self.calls.append((url, addresses))
            return RawHttpResponse(200, {}, "ok", url, 1)

    backend = Undeclared()
    with pytest.raises(AddressRefusedError):
        _http(StaticDns({NAME: "10.0.0.5"}), backend=backend).get(f"http://{NAME}/")
    assert backend.calls == []
    _http(StaticDns({NAME: PUBLIC}), backend=backend).get(f"http://{NAME}/")
    assert backend.calls == [(f"http://{NAME}/", (PUBLIC,))]


def test_the_policy_and_the_override_cannot_be_subclassed() -> None:
    """Nit 8: a subclass overriding `refusal` would relax the policy without
    naming the override, out of the walk's sight."""
    with pytest.raises(TypeError):

        class Lenient(AddressPolicy):
            pass

    with pytest.raises(TypeError):

        class Lab(LabOverride):
            pass


@pytest.mark.parametrize(
    ("answers", "expect"),
    [({NAME: "10.0.0.5"}, "address_refused:"), ({}, "connect_error:")],
    ids=["refused", "unresolved"],
)
def test_a_refused_tls_handshake_is_recorded_and_replays_the_same(
    wire, tmp_path, answers, expect
) -> None:
    """Should-fix 2: a refusal happens before the backend, so recording wrote
    nothing and the replay of that scan failed with a missing fixture."""
    from core.tls import RecordingTlsBackend, ReplayTlsBackend

    recorded = _tls(StaticDns(answers), backend=RecordingTlsBackend(tmp_path, SystemTlsBackend()))
    live = recorded.inspect(NAME, 443, servername=NAME)
    replayed = _tls(None, backend=ReplayTlsBackend(tmp_path)).inspect(NAME, 443, servername=NAME)

    assert live.error is not None and live.error.startswith(expect)
    assert (replayed.reachable, replayed.error) == (False, live.error)
    assert wire["connect"] == []


def test_a_refused_http_request_is_recorded_and_replays_the_same(wire, tmp_path) -> None:
    from core.addresses import AddressUnresolvedError
    from core.http import RecordingHttpBackend, ReplayHttpBackend

    scope = Scope.for_target(Asset(type="domain", value=NAME))
    dns = StaticDns({NAME: PUBLIC, f"internal.{NAME}": "10.0.0.5"})
    recording = RecordingHttpBackend(tmp_path, SystemHttpBackend())
    with http_server() as srv:
        wire["ports"][(PUBLIC, 80)] = srv["port"]
        srv["routes"]["/"] = ("302 Found", f"Location: http://internal.{NAME}/admin\r\n")
        with pytest.raises(AddressRefusedError) as live:
            _http(dns, scope=scope, backend=recording).get(f"http://{NAME}/")
        with pytest.raises(AddressUnresolvedError) as live_unresolved:
            _http(StaticDns({}), scope=scope, backend=recording).get(f"http://gone.{NAME}/")

    replay = _http(None, scope=scope, backend=ReplayHttpBackend(tmp_path))
    with pytest.raises(AddressRefusedError) as replayed:
        replay.get(f"http://{NAME}/")
    assert (replayed.value.host, replayed.value.refused, replayed.value.literal) == (
        live.value.host,
        live.value.refused,
        live.value.literal,
    )
    with pytest.raises(AddressUnresolvedError, match="no A or AAAA") as replayed_unresolved:
        replay.get(f"http://gone.{NAME}/")
    assert str(replayed_unresolved.value) == str(live_unresolved.value)
