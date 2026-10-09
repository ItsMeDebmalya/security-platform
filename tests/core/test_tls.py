"""The one TLS client.

Tested against real handshakes with the local lab rather than mocks: the
things that go wrong in TLS are library and protocol behaviours, and a mock
would only assert that we understood them correctly, which is the very thing
in doubt.
"""

from __future__ import annotations

import ssl

import pytest

from core.authz import Scope
from core.cost import CostMeter
from core.killswitch import KillSwitch, ScanKilledError
from core.models import Asset
from core.ratelimit import RateLimiter
from core.tls import MissingHandshakeError, RecordingTlsBackend, ReplayTlsBackend, TlsClient
from corpus.generators.tls_lab import lab_server

LOOPBACK = Scope(frozenset({"127.0.0.1"}))


def client(**kwargs) -> TlsClient:
    kwargs.setdefault("scope", LOOPBACK)
    return TlsClient(**kwargs)


def inspect(server, host="localhost", **kwargs):
    return client(**kwargs).inspect("127.0.0.1", server.port, servername=host)


# --- reading the certificate ------------------------------------------------


def test_a_healthy_server_is_reachable_and_reports_its_protocol():
    with lab_server(common_name="localhost") as srv:
        obs = inspect(srv)

    assert obs.reachable
    assert obs.protocol == "TLSv1.3"
    assert obs.cipher


def test_the_certificate_subject_and_issuer_are_read():
    with lab_server(common_name="localhost") as srv:
        obs = inspect(srv)

    assert obs.certificate is not None
    assert obs.certificate.subject_cn == "localhost"
    assert obs.certificate.issuer_cn == "localhost"


def test_the_subject_alternative_names_are_read():
    with lab_server(common_name="localhost", sans=["localhost", "alt.test"]) as srv:
        obs = inspect(srv)

    assert set(obs.certificate.sans) == {"localhost", "alt.test"}


def test_the_key_size_and_signature_algorithm_are_measured():
    with lab_server(common_name="localhost", key_bits=1024) as srv:
        obs = inspect(srv)

    assert obs.certificate.key_bits == 1024
    assert obs.certificate.key_type == "rsa"
    assert obs.certificate.signature_algorithm == "sha256"


def test_a_deprecated_signature_algorithm_is_read():
    with lab_server(common_name="localhost", digest="sha1") as srv:
        obs = inspect(srv)

    assert obs.certificate.signature_algorithm == "sha1"


def test_a_self_signed_certificate_is_recognised():
    with lab_server(common_name="localhost") as srv:
        obs = inspect(srv)

    assert obs.certificate.self_signed is True


def test_the_certificate_fingerprint_is_stable():
    with lab_server(common_name="localhost") as srv:
        first = inspect(srv).certificate.fingerprint_sha256
        second = inspect(srv).certificate.fingerprint_sha256

    assert first == second and len(first) == 64


# --- expiry -----------------------------------------------------------------


def test_an_expired_certificate_reports_negative_days_remaining():
    with lab_server(common_name="localhost", not_before_days=-800, not_after_days=-400) as srv:
        obs = inspect(srv)

    assert obs.certificate.is_expired()
    assert obs.certificate.days_until_expiry() < 0


def test_a_certificate_expiring_soon_reports_the_days_left():
    with lab_server(common_name="localhost", not_after_days=5) as srv:
        obs = inspect(srv)

    assert 0 <= obs.certificate.days_until_expiry() <= 6
    assert not obs.certificate.is_expired()


def test_a_certificate_not_yet_valid_is_recognised():
    with lab_server(common_name="localhost", not_before_days=30, not_after_days=400) as srv:
        obs = inspect(srv)

    assert obs.certificate.not_yet_valid()


# --- hostname matching ------------------------------------------------------


def test_a_certificate_covering_the_name_matches():
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        obs = inspect(srv)

    assert obs.hostname_matches is True


def test_a_certificate_for_another_name_does_not_match():
    with lab_server(common_name="other.test", sans=["other.test"]) as srv:
        obs = inspect(srv, host="localhost")

    assert obs.hostname_matches is False


def test_a_wildcard_certificate_covers_one_label():
    with lab_server(common_name="*.example.test", sans=["*.example.test"]) as srv:
        obs = inspect(srv, host="api.example.test")

    assert obs.hostname_matches is True


def test_a_wildcard_certificate_does_not_cover_two_labels():
    """`*.example.test` matches api.example.test, not a.b.example.test."""
    with lab_server(common_name="*.example.test", sans=["*.example.test"]) as srv:
        obs = inspect(srv, host="a.b.example.test")

    assert obs.hostname_matches is False


def test_a_wildcard_certificate_does_not_cover_the_bare_domain():
    with lab_server(common_name="*.example.test", sans=["*.example.test"]) as srv:
        obs = inspect(srv, host="example.test")

    assert obs.hostname_matches is False


# D48: RFC 9525 §2, "The Common Name RDN MUST NOT be used to identify a service".
# RFC 6125, which allowed falling back to the CN when there were no SANs, is
# obsoleted by RFC 9525. Both readings must refuse the fallback, or two readings
# that share a blind spot agree on a wrong answer (D38).


def test_a_certificate_naming_the_host_only_in_its_common_name_does_not_match():
    with lab_server(common_name="localhost", omit_san=True) as srv:
        obs = inspect(srv)

    assert obs.certificate is not None and not obs.certificate.sans
    assert obs.hostname_matches is False


def test_openssl_is_asked_without_the_common_name_fallback_too():
    with lab_server(common_name="localhost", omit_san=True) as srv:
        obs = inspect(srv)

    assert obs.openssl_hostname_match is False


def _inspect_ip(srv):
    return client().inspect("127.0.0.1", srv.port, servername="127.0.0.1")


def test_an_ip_target_matches_an_ip_address_san_for_both_readings():
    """D48 review, BLOCKER: without the CN fallback, an IP SAN was never read."""
    with lab_server(common_name="127.0.0.1", sans=[], ip_sans=["127.0.0.1"]) as srv:
        obs = _inspect_ip(srv)

    assert obs.certificate is not None and obs.certificate.ip_sans == ["127.0.0.1"]
    assert obs.hostname_matches is True and obs.openssl_hostname_match is True


def test_an_ip_target_matches_alongside_dns_sans():
    with lab_server(common_name="x.test", sans=["x.test"], ip_sans=["127.0.0.1"]) as srv:
        obs = _inspect_ip(srv)

    assert obs.hostname_matches is True and obs.openssl_hostname_match is True


def test_an_ip_is_never_matched_against_a_dns_san_or_the_common_name():
    with lab_server(common_name="127.0.0.1", sans=["127.0.0.1"]) as srv:
        obs = _inspect_ip(srv)

    assert obs.hostname_matches is False


def test_a_unicode_servername_is_compared_in_its_a_label_form():
    """D48 review nit: certificates carry A-labels; a U-label host must match them."""
    a_label = "xn--bcher-kva.example"
    with lab_server(common_name=a_label, sans=[a_label]) as srv:
        obs = inspect(srv)

    assert obs.certificate is not None
    assert obs.certificate.covers_hostname("bücher.example") is True
    assert obs.certificate.covers_hostname("BÜCHER.example") is True


def test_a_san_still_matches_for_both_readings():
    with lab_server(common_name="ignored.test", sans=["localhost"]) as srv:
        obs = inspect(srv)

    assert obs.hostname_matches is True and obs.openssl_hostname_match is True


# --- the trust verdict ------------------------------------------------------


def test_an_untrusted_certificate_is_reported_with_the_reason_openssl_gave():
    with lab_server(common_name="localhost") as srv:
        obs = inspect(srv)

    assert obs.trusted is False
    assert obs.verify_code is not None
    assert "self" in obs.verify_message.lower() or "issuer" in obs.verify_message.lower()


def test_openssl_reports_only_its_first_objection():
    """An expired *and* self-signed certificate comes back as "self-signed".

    OpenSSL stops at the first problem it finds, so `verify_message` is not a
    list of everything wrong. Expiry is therefore read from the certificate we
    parsed, never inferred from the absence of an expiry message.
    """
    with lab_server(common_name="localhost", not_before_days=-800, not_after_days=-400) as srv:
        obs = inspect(srv)

    assert obs.trusted is False
    assert "self-signed" in obs.verify_message.lower()
    assert obs.certificate.is_expired()  # and we know this independently


def test_expiry_surfaces_in_the_verdict_once_trust_is_not_the_objection():
    """With the certificate supplied as its own anchor, the only thing left to
    object to is the dates - which proves we really do surface OpenSSL's reason
    rather than always reporting the same one."""
    import tempfile
    from pathlib import Path as _Path

    from corpus.generators.tls_lab import LabServer, mint

    with tempfile.TemporaryDirectory() as tmp:
        minted = mint(
            _Path(tmp),
            "old",
            common_name="localhost",
            sans=["localhost"],
            not_before_days=-800,
            not_after_days=-400,
        )
        server = LabServer(minted)
        try:
            obs = client(trust_anchor=str(minted.cert_path)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.trusted is False
    assert "expired" in obs.verify_message.lower()


def test_a_certificate_trusted_by_a_supplied_anchor_verifies():
    """Proves the verifying probe really does verify, rather than always failing."""
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint

    with tempfile.TemporaryDirectory() as tmp:
        minted = mint(Path(tmp), "anchor", common_name="localhost", sans=["localhost"])
        server = LabServer(minted)
        try:
            obs = client(trust_anchor=str(minted.cert_path)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.trusted is True
    assert obs.verify_message is None


# --- the finding that shaped the design -------------------------------------


def test_an_obsolete_server_is_observed_rather_than_refused():
    """A client with the normal safety floor refuses TLS 1.0 outright, which
    would make the scanner blind to exactly the servers worth reporting. The
    observing context must get in and read what is there."""
    with lab_server(common_name="localhost", max_version=ssl.TLSVersion.TLSv1) as srv:
        obs = inspect(srv)

    assert obs.reachable
    assert obs.protocol == "TLSv1"
    assert obs.certificate is not None


def test_a_default_python_client_would_have_refused_that_server():
    """The other half of the pair above, asserted so the reason the observing
    context exists cannot be optimised away by someone tidying up."""
    import socket

    with lab_server(common_name="localhost", max_version=ssl.TLSVersion.TLSv1) as srv:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with (
            pytest.raises(ssl.SSLError),
            socket.create_connection(("127.0.0.1", srv.port), timeout=5) as raw,
        ):
            ctx.wrap_socket(raw, server_hostname="localhost").close()


# --- protocol enumeration ---------------------------------------------------


def test_a_modern_server_does_not_offer_tls_one_zero():
    with lab_server(common_name="localhost", min_version=ssl.TLSVersion.TLSv1_2) as srv:
        supported = client().supported_protocols("127.0.0.1", srv.port, servername="localhost")

    assert supported["TLSv1"] is False
    assert supported["TLSv1.2"] is True


def test_an_obsolete_server_is_seen_offering_tls_one_zero():
    with lab_server(common_name="localhost", max_version=ssl.TLSVersion.TLSv1) as srv:
        supported = client().supported_protocols("127.0.0.1", srv.port, servername="localhost")

    assert supported["TLSv1"] is True
    assert supported["TLSv1.3"] is False


# --- D17: chain-incompleteness masked by an earlier verify failure ---------


def test_an_expired_chain_that_is_otherwise_complete_verifies_time_neutrally():
    """The control case: expired but the intermediate is present. The
    time-neutral probe should find a buildable path, so no chain-incomplete
    finding is warranted."""
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint_chain

    with tempfile.TemporaryDirectory() as tmp:
        ca, leaf, chain = mint_chain(
            Path(tmp),
            "exp-complete",
            common_name="localhost",
            sans=["localhost"],
            not_before_days=-800,
            not_after_days=-400,
        )
        server = LabServer(leaf, chain_file=chain, min_version=ssl.TLSVersion.TLSv1_2)
        try:
            obs = client(trust_anchor=str(ca.cert_path)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.trusted is False
    assert obs.verify_code == 10  # expired
    assert obs.verify_code_no_time is None  # time-neutral chain builds fine


def test_a_genuinely_missing_chain_is_reported_the_same_with_or_without_the_date_problem():
    """OpenSSL builds the trust path structurally before it ever checks
    validity dates (verified directly here, and cross-checked against the
    `openssl verify` CLI): a certificate with no discoverable issuer anywhere
    - not served, not in the trust store - fails with
    "unable to get local issuer certificate" regardless of whether it is also
    expired. So for a chain that is genuinely missing everywhere, the ordinary
    verify and the time-neutral probe agree, and the pre-existing
    `VERIFY_NO_ISSUER` branch already reports `tls-chain-incomplete` on its
    own - this is the control for the masked case below, proving the
    no-issuer family of codes is not itself date-sensitive."""
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint_three_level

    with tempfile.TemporaryDirectory() as tmp:
        root, _, leaf, _ = mint_three_level(
            Path(tmp),
            "exp-incomplete",
            common_name="localhost",
            sans=["localhost"],
            not_before_days=-800,
            not_after_days=-400,
        )
        # Serve the leaf only - no intermediate, and nowhere else to find one.
        server = LabServer(leaf, min_version=ssl.TLSVersion.TLSv1_2)
        try:
            obs = client(trust_anchor=str(root.cert_path)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.trusted is False
    assert obs.verify_code in (2, 20, 21)  # unable to get local issuer
    assert obs.verify_code_no_time in (2, 20, 21)  # agrees once dates are ignored too


def test_the_time_neutral_probe_reveals_a_chain_masked_by_ambient_trust():
    """The masking D17 actually fixes: a chain that verifies successfully
    only because the client's trust store *already carries* the certificate
    the server itself never sent - production's system CA bundle commonly
    does, for a widely deployed intermediate. `verify_code` alone then reads
    "expired" and nothing else, exactly like a complete chain would. The
    time-neutral probe cannot recover the "not sent by the server" fact
    (that needs the peer's own certificate list, which is the
    `get_unverified_chain()` this design deliberately avoids), but it does
    prove there is nothing further to unmask here: ignoring dates, the same
    path builds and trusts cleanly, so the masking is confined to the date
    finding already reported separately."""
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint_three_level

    with tempfile.TemporaryDirectory() as tmp:
        root, intermediate, leaf, _ = mint_three_level(
            Path(tmp),
            "ambient",
            common_name="localhost",
            sans=["localhost"],
            not_before_days=-800,
            not_after_days=-400,
        )
        anchor = Path(tmp) / "anchor.pem"
        anchor.write_bytes(root.cert_path.read_bytes() + intermediate.cert_path.read_bytes())
        # Serve the leaf alone - the server never sends its intermediate -
        # but the trust anchor stands in for a client whose store already
        # has it cached from elsewhere.
        server = LabServer(leaf, min_version=ssl.TLSVersion.TLSv1_2)
        try:
            obs = client(trust_anchor=str(anchor)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.trusted is False
    assert obs.verify_code == 10  # expired; the ambient intermediate hides the omission
    assert obs.verify_code_no_time is None  # and there is nothing left to unmask


def test_the_time_neutral_probe_is_skipped_when_the_chain_is_already_trusted():
    """No point asking twice when there is nothing to unmask - also what keeps
    an already-passing corpus fixture's recorded content unchanged."""
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint

    with tempfile.TemporaryDirectory() as tmp:
        minted = mint(Path(tmp), "trusted", common_name="localhost", sans=["localhost"])
        server = LabServer(minted, min_version=ssl.TLSVersion.TLSv1_2)
        try:
            obs = client(trust_anchor=str(minted.cert_path)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.trusted is True
    assert obs.verify_code_no_time is None


# --- when we cannot tell ----------------------------------------------------


def test_a_closed_port_is_unreachable_and_not_a_definite_answer():
    obs = client().inspect("127.0.0.1", 1, servername="localhost")

    assert obs.reachable is False
    assert obs.is_definite() is False
    assert obs.error


def test_a_reachable_server_is_a_definite_answer():
    with lab_server(common_name="localhost") as srv:
        assert inspect(srv).is_definite() is True


# --- safety -----------------------------------------------------------------


def test_a_host_outside_scope_is_refused_before_connecting():
    from core.http import OutOfScopeError

    with pytest.raises(OutOfScopeError):
        client(scope=Scope.for_target(Asset(type="domain", value="example.com"))).inspect(
            "127.0.0.1", 443, servername="localhost"
        )


def test_the_kill_switch_is_checked_before_connecting():
    switch = KillSwitch()
    tls = client(killswitch=switch, scan_id="s1", org_id="org_a")

    switch.kill(scan_id="s1", reason="operator")

    with pytest.raises(ScanKilledError):
        tls.inspect("127.0.0.1", 443, servername="localhost")


def test_a_handshake_counts_towards_the_scan_cost():
    meter = CostMeter()
    with lab_server(common_name="localhost") as srv:
        inspect(srv, cost=meter)

    assert meter.snapshot().requests >= 1


def test_the_target_rate_limiter_is_consulted():
    seen: list[str] = []

    class SpyLimiter(RateLimiter):
        def acquire(self, host: str, tokens: float = 1.0) -> None:
            seen.append(host)

    with lab_server(common_name="localhost") as srv:
        inspect(srv, ratelimit=SpyLimiter())

    assert seen and seen[0] == "127.0.0.1"


# --- record and replay ------------------------------------------------------


def test_a_recorded_handshake_replays_identically(tmp_path):
    with lab_server(common_name="localhost", not_after_days=5) as srv:
        live = client(backend=RecordingTlsBackend(directory=tmp_path)).inspect(
            "127.0.0.1", srv.port, servername="localhost"
        )

    replayed = client(backend=ReplayTlsBackend(tmp_path)).inspect(
        "127.0.0.1", srv.port, servername="localhost"
    )

    assert replayed.certificate.fingerprint_sha256 == live.certificate.fingerprint_sha256
    assert replayed.protocol == live.protocol
    assert replayed.trusted == live.trusted


def test_replay_preserves_an_unreachable_target(tmp_path):
    client(backend=RecordingTlsBackend(directory=tmp_path)).inspect(
        "127.0.0.1", 1, servername="localhost"
    )

    replayed = client(backend=ReplayTlsBackend(tmp_path)).inspect(
        "127.0.0.1", 1, servername="localhost"
    )

    assert replayed.reachable is False


def test_replaying_an_unrecorded_handshake_fails_loudly(tmp_path):
    with pytest.raises(MissingHandshakeError, match="never-seen"):
        client(backend=ReplayTlsBackend(tmp_path)).inspect(
            "127.0.0.1", 4443, servername="never-seen.test"
        )


def test_replay_does_not_expire_a_recorded_certificate(tmp_path):
    """Days-remaining must be computed against the recording, not the replay.

    Otherwise every frozen fixture silently becomes an expiry finding as it
    ages, and the corpus rots without anyone touching it.
    """
    with lab_server(common_name="localhost", not_after_days=5) as srv:
        client(backend=RecordingTlsBackend(directory=tmp_path)).inspect(
            "127.0.0.1", srv.port, servername="localhost"
        )

    replayed = client(backend=ReplayTlsBackend(tmp_path)).inspect(
        "127.0.0.1", srv.port, servername="localhost"
    )

    assert replayed.observed_at is not None
    assert 0 <= replayed.certificate.days_until_expiry(now=replayed.observed_at) <= 6


def test_an_observation_can_be_serialised_for_evidence():
    with lab_server(common_name="localhost") as srv:
        payload = inspect(srv).to_dict()

    assert payload["protocol"] == "TLSv1.3"
    assert payload["certificate"]["subject_cn"] == "localhost"
    assert payload["trusted"] is False


def test_the_hostname_probe_uses_the_configured_trust_anchor():
    """A privately issued certificate needs its CA for the hostname probe too.

    Without it, trust fails first and OpenSSL never reaches the name - so a
    mismatch on an internal certificate got no independent verdict, while the
    same mismatch on a publicly issued one did.
    """
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint_chain

    with tempfile.TemporaryDirectory() as tmp:
        ca, leaf, chain = mint_chain(
            Path(tmp), "mismatch", common_name="other.test", sans=["other.test"]
        )
        server = LabServer(leaf, chain_file=chain)
        try:
            obs = client(trust_anchor=str(ca.cert_path)).inspect(
                "127.0.0.1", server.port, servername="localhost"
            )
        finally:
            server.close()

    assert obs.hostname_matches is False
    assert obs.openssl_hostname_match is False


# ADR-030: names are encoded as browsers encode them (UTS-46, non-transitional,
# WHATWG URL Standard), for our matcher and for the name OpenSSL is handed.
IDN_CASES = [
    ("faß.de", "xn--fa-hia.de"),  # ß kept, not mapped to ss (IDNA 2003 gave fass.de)
    ("ς.example", "xn--3xa.example"),  # final sigma kept (IDNA 2003 gave xn--4xa)
    ("BÜCHER.example", "xn--bcher-kva.example"),  # UTS-46 maps case; strict 2008 refuses
    ("हिंदी.भारत", "xn--i1b6e8byah.xn--h2brj9c"),
    ("தமிழ்.இந்தியா", "xn--rlcus7b3d.xn--xkc2dl3a5ee0h"),
    ("क्\u200dष.भारत", "xn--11b2ezcw70k.xn--h2brj9c"),  # ZWJ after a virama: allowed
    ("क्\u200cष.भारत", "xn--11b2ezcs70k.xn--h2brj9c"),  # ZWNJ after a virama: allowed
]


@pytest.mark.parametrize(("host", "a_label"), IDN_CASES)
def test_a_unicode_name_is_encoded_as_a_browser_encodes_it(host, a_label):
    from core.tls import a_label as encode

    assert encode(host) == a_label


@pytest.mark.parametrize(("host", "a_label"), IDN_CASES)
def test_both_readings_match_an_idn_certificate_through_a_real_handshake(host, a_label):
    with lab_server(common_name=a_label, sans=[a_label]) as srv:
        obs = client().inspect("127.0.0.1", srv.port, servername=host)

    assert obs.hostname_matches is True
    assert obs.openssl_hostname_match is True


@pytest.mark.parametrize("host", ["a\u200db.example", "a\u200cb.example"])
def test_a_joiner_where_contextj_forbids_it_is_not_judged(host):
    """Not a valid name: no client gets as far as a certificate, so no verdict."""
    from core.tls import a_label

    assert a_label(host) is None
    with lab_server(common_name="ab.example", sans=["ab.example"]) as srv:
        obs = client().inspect("127.0.0.1", srv.port, servername=host)
    assert obs.hostname_matches is None


def test_an_ipv6_zone_id_does_not_stop_an_address_match():
    with lab_server(common_name="x.test", sans=["x.test"]) as srv:
        cert = inspect(srv).certificate
    assert cert is not None
    from dataclasses import replace

    with_ip = replace(cert, ip_sans=["fe80::1"])
    assert with_ip.covers_hostname("fe80::1%eth0") is True
    assert with_ip.covers_hostname("[fe80::1]") is True
