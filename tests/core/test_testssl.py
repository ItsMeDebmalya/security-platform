"""D20: the runtime testssl.sh wrapper for the four legacy-cipher checks.

Everything here runs offline. `LiveTestsslClient` (the real subprocess) is
exercised only by `corpus/generators/testssl.py`, deliberately run by hand
against public badssl.com endpoints - never by the test suite.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.testssl import (
    CHECK_TO_TESTSSL_ID,
    LegacyCipherReport,
    LiveTestsslClient,
    RecordingTestsslClient,
    ReplayTestsslClient,
    StubTestsslClient,
    _parse,
)
from core.testssl import TestsslUnavailableError as UnavailableError

ADDRESS = "93.184.215.14"
"""A global unicast literal. Nothing here opens a socket to it."""


class _Dns:
    def query(self, name, rrtype, *, resolver=None):
        from core.dns import DnsResponse

        return DnsResponse(name, rrtype, "NOERROR", [ADDRESS] if rrtype == "A" else [])


def live(**kwargs) -> LiveTestsslClient:
    """A live client as the lab and corpus build it: a scope, a resolver, and
    the explicit lab override (D59). Production builds it without one."""
    from core.addresses import AddressPolicy, LabOverride
    from core.authz import Scope

    return LiveTestsslClient(
        dns=_Dns(),
        scope=Scope(frozenset({"example.test", "rc4.badssl.com"})),
        addresses=AddressPolicy(
            lab_override=LabOverride(
                reason="unit test", hosts=frozenset({"example.test", "rc4.badssl.com"})
            )
        ),
        **kwargs,
    )


def _fake_process(write):
    """A stand-in for `core.testssl._run_process` that writes `write(out)`."""
    calls = []

    def _run(argv, env, *, timeout_s, alive):
        calls.append((list(argv), env))
        out = next(a for a in argv if a.endswith(".json"))
        write(out)

    return _run, calls


RC4_REPORT = {
    "scanResult": [
        {
            "vulnerabilities": [
                {
                    "id": "RC4",
                    "severity": "HIGH",
                    "cve": "CVE-2013-2566 CVE-2015-2808",
                    "finding": "VULNERABLE, Detected ciphers: ECDHE-RSA-RC4-SHA RC4-SHA",
                },
                {"id": "SWEET32", "severity": "OK", "finding": "not vulnerable"},
                {"id": "FREAK", "severity": "OK", "finding": "not vulnerable"},
                {"id": "LOGJAM", "severity": "OK", "finding": "not vulnerable"},
                {"id": "BEAST", "severity": "OK", "finding": "not vulnerable"},
            ]
        }
    ]
}

CLEAN_REPORT = {
    "scanResult": [
        {
            "vulnerabilities": [
                {"id": "RC4", "severity": "OK", "finding": "not vulnerable"},
                {"id": "SWEET32", "severity": "OK", "finding": "not vulnerable"},
                {"id": "FREAK", "severity": "OK", "finding": "not vulnerable"},
                {"id": "LOGJAM", "severity": "OK", "finding": "not vulnerable"},
            ]
        }
    ]
}

DUPLICATE_LOGJAM_REPORT = {
    "scanResult": [
        {
            "vulnerabilities": [
                {"id": "LOGJAM", "severity": "OK", "finding": "not vulnerable, no DH EXPORT"},
                {
                    "id": "LOGJAM",
                    "severity": "CRITICAL",
                    "finding": "Unknown DH group has only 512 bits",
                },
            ]
        }
    ]
}


# --- parsing -----------------------------------------------------------------


def test_parse_marks_rc4_vulnerable() -> None:
    findings = _parse(RC4_REPORT)
    assert findings["RC4"].vulnerable is True
    assert findings["RC4"].severity == "HIGH"
    assert "RC4-SHA" in findings["RC4"].detail
    assert findings["SWEET32"].vulnerable is False


def test_parse_clean_report_has_no_vulnerable_findings() -> None:
    findings = _parse(CLEAN_REPORT)
    assert all(not f.vulnerable for f in findings.values())


def test_parse_keeps_worst_severity_when_id_repeats() -> None:
    """dh512 reports two LOGJAM verdicts (one per DH-parameter source tried);
    the worse one - the actual weak-group finding - must win, not whichever
    testssl happened to print second."""
    findings = _parse(DUPLICATE_LOGJAM_REPORT)
    assert findings["LOGJAM"].severity == "CRITICAL"
    assert findings["LOGJAM"].vulnerable is True


def test_parse_ignores_ids_outside_the_four_checks() -> None:
    findings = _parse(RC4_REPORT)
    assert "BEAST" not in findings


def test_check_to_testssl_id_covers_all_four_checks() -> None:
    assert set(CHECK_TO_TESTSSL_ID) == {
        "tls-vuln-rc4",
        "tls-vuln-sweet32",
        "tls-vuln-freak",
        "tls-vuln-logjam",
    }
    assert set(CHECK_TO_TESTSSL_ID.values()) == {"RC4", "SWEET32", "FREAK", "LOGJAM"}


# --- degrade-never-crash ------------------------------------------------------


def test_stub_client_raises_unavailable() -> None:
    with pytest.raises(UnavailableError):
        StubTestsslClient().legacy_ciphers("example.test", 443)


def test_live_client_raises_unavailable_when_binary_missing(monkeypatch, tmp_path) -> None:
    missing = tmp_path / "no-such-testssl.sh"
    monkeypatch.setattr("core.testssl.TESTSSL_PATH", missing)
    with pytest.raises(UnavailableError):
        live().legacy_ciphers("example.test", 443)


def test_live_client_raises_unavailable_on_timeout(monkeypatch) -> None:
    monkeypatch.setattr("core.testssl.available", lambda: True)

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="testssl.sh", timeout=1)

    monkeypatch.setattr("core.testssl._run_process", _raise_timeout)
    with pytest.raises(UnavailableError):
        live(timeout_s=1).legacy_ciphers("example.test", 443)


def test_live_client_raises_unavailable_on_unparsable_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("core.testssl.available", lambda: True)

    fake, _ = _fake_process(lambda out: Path(out).write_text("not json"))
    monkeypatch.setattr("core.testssl._run_process", fake)
    with pytest.raises(UnavailableError):
        live().legacy_ciphers("example.test", 443)


def test_replay_client_raises_unavailable_when_nothing_recorded(tmp_path) -> None:
    client = ReplayTestsslClient(tmp_path)
    with pytest.raises(UnavailableError):
        client.legacy_ciphers("never-recorded.test", 443)


def test_replay_client_never_touches_the_network(tmp_path, monkeypatch) -> None:
    """The corpus must run fully offline - assert replay never calls out."""

    def _fail(*args, **kwargs):
        raise AssertionError("ReplayTestsslClient must never shell out")

    monkeypatch.setattr("core.testssl._run_process", _fail)
    monkeypatch.setattr("core.testssl.subprocess.Popen", _fail)
    client = ReplayTestsslClient(tmp_path)
    with pytest.raises(UnavailableError):
        client.legacy_ciphers("never-recorded.test", 443)


# --- record/replay round trip -------------------------------------------------


def test_record_then_replay_round_trips(tmp_path, monkeypatch) -> None:
    import json

    fake, _ = _fake_process(lambda out: Path(out).write_text(json.dumps(RC4_REPORT)))
    monkeypatch.setattr("core.testssl.available", lambda: True)
    monkeypatch.setattr("core.testssl._run_process", fake)

    recorder = RecordingTestsslClient(tmp_path, inner=live())
    recorded = recorder.legacy_ciphers("rc4.badssl.com", 443)
    assert recorded.findings["RC4"].vulnerable is True

    replayed = ReplayTestsslClient(tmp_path).legacy_ciphers("rc4.badssl.com", 443)
    assert replayed.findings["RC4"].vulnerable is True
    assert replayed.findings["RC4"].severity == "HIGH"
    assert replayed.host == "rc4.badssl.com"
    assert replayed.port == 443
    assert replayed.addresses_tested == (ADDRESS,)
    assert replayed.per_address[ADDRESS]["RC4"].severity == "HIGH"
    assert replayed.lab_reason == "unit test"


def test_replay_report_for_check_maps_check_id_to_testssl_id(tmp_path) -> None:
    from core.testssl import LegacyCipherFinding

    report = LegacyCipherReport(
        host="rc4.badssl.com",
        port=443,
        recorded_at=__import__("datetime").datetime.now(tz=__import__("datetime").UTC),
        findings={"RC4": LegacyCipherFinding("RC4", "HIGH", "VULNERABLE", "CVE-2013-2566")},
    )
    assert report.for_check("tls-vuln-rc4").vulnerable is True
    assert report.for_check("tls-vuln-sweet32") is None
    assert report.for_check("not-a-real-check") is None


# --- D56: the declared argument allowlist (ADR-023 amendment) ---------------
#
# These are the primary proof that the four checks send only what they read.
# `--vulnerable` (and any run with no test flag at all, which testssl.sh
# treats as "run everything") also sends the probes ADR-023 says we never
# send. The allowlist is exact: any added, missing or reordered argument, and
# any environment variable beyond the pinned set, is refused before the
# subprocess starts.

from core.testssl import (  # noqa: E402
    TESTSSL_ARGS,
    TESTSSL_ENV_KEYS,
    TESTSSL_PATH,
    guard_invocation,
)
from core.testssl import TestsslArgumentRefusedError as RefusedError  # noqa: E402

EXPECTED_ARGS = (
    "--rc4",
    "--sweet32",
    "--freak",
    "--logjam",
    "--ids-friendly",
    "--quiet",
    "--nodns=none",
    "--connect-timeout=10",
    "--openssl-timeout=10",
)


def _capture_run(monkeypatch) -> list[tuple[list[str], dict]]:
    import json

    fake, calls = _fake_process(lambda out: Path(out).write_text(json.dumps(CLEAN_REPORT)))
    monkeypatch.setattr("core.testssl.available", lambda: True)
    monkeypatch.setattr("core.testssl._run_process", fake)
    return calls


def test_the_declared_allowlist_is_exactly_the_four_cipher_tests() -> None:
    assert TESTSSL_ARGS == EXPECTED_ARGS


def test_the_live_client_sends_exactly_the_allowlisted_command_line(monkeypatch) -> None:
    calls = _capture_run(monkeypatch)
    live().legacy_ciphers("example.test", 443)

    ((cmd, _),) = calls
    assert cmd[0] == str(TESTSSL_PATH)
    assert tuple(cmd[1:10]) == EXPECTED_ARGS
    assert cmd[10] == f"--ip={ADDRESS}"
    assert cmd[11] == "--jsonfile-pretty"
    assert cmd[12].endswith(".json")
    assert cmd[13] == "example.test:443"
    assert len(cmd) == 14


def test_no_suite_wide_or_offensive_flag_reaches_the_subprocess(monkeypatch) -> None:
    calls = _capture_run(monkeypatch)
    live().legacy_ciphers("example.test", 443)

    ((cmd, _),) = calls
    for forbidden in (
        "--vulnerable",
        "-U",
        "--vulnerabilities",
        "-e",
        "--each-cipher",
        "-E",
        "--cipher-per-proto",
        "--heartbleed",
        "-H",
        "--ccs",
        "-I",
        "--ticketbleed",
        "-T",
        "--robot",
        "-BB",
        "--full",
    ):
        assert forbidden not in cmd


def test_the_subprocess_gets_only_the_pinned_environment(monkeypatch) -> None:
    """testssl.sh reads its own settings from the environment: for example
    `OFFENSIVE=${OFFENSIVE:-true}`. An inherited environment is an argument
    list nobody declared."""
    monkeypatch.setenv("OFFENSIVE", "true")
    calls = _capture_run(monkeypatch)
    live().legacy_ciphers("example.test", 443)

    ((_, env),) = calls
    assert set(env) == set(TESTSSL_ENV_KEYS)
    assert "OFFENSIVE" not in env


def _valid_argv(tmp_path) -> list[str]:
    return [
        str(TESTSSL_PATH),
        *EXPECTED_ARGS,
        f"--ip={ADDRESS}",
        "--jsonfile-pretty",
        str(tmp_path / "out.json"),
        "example.test:443",
    ]


def _valid_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C"}


def test_the_guard_accepts_the_declared_invocation(tmp_path) -> None:
    guard_invocation(_valid_argv(tmp_path), _valid_env())


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda a: a.insert(1, "--vulnerable"), id="added-suite-flag"),
        pytest.param(lambda a: a.insert(5, "--heartbleed"), id="added-offensive-flag"),
        pytest.param(lambda a: a.remove("--rc4"), id="missing-test-flag"),
        pytest.param(
            lambda a: [a.remove(f) for f in ("--rc4", "--sweet32", "--freak", "--logjam")],
            id="no-test-flag-runs-everything",
        ),
        pytest.param(lambda a: a.remove("--ids-friendly"), id="missing-ids-friendly"),
        pytest.param(lambda a: a.__setitem__(1, "--sweet32"), id="reordered-or-duplicated"),
        pytest.param(lambda a: a.__setitem__(0, "/usr/bin/testssl.sh"), id="other-binary"),
        pytest.param(lambda a: a.__setitem__(-1, "--file=x"), id="target-is-a-flag"),
        pytest.param(lambda a: a.__setitem__(-1, "-example.test:443"), id="target-leading-dash"),
        pytest.param(lambda a: a.__setitem__(-1, "example.test:0"), id="port-out-of-range"),
        pytest.param(lambda a: a.__setitem__(-1, "exa mple.test:443"), id="target-whitespace"),
        pytest.param(lambda a: a.__setitem__(-2, "--debug"), id="outfile-is-a-flag"),
        pytest.param(lambda a: a.append("extra"), id="trailing-argument"),
        pytest.param(lambda a: a.remove(f"--ip={ADDRESS}"), id="no-pinned-address"),
        pytest.param(lambda a: a.__setitem__(10, "--ip=one"), id="ip-one-lets-testssl-resolve"),
        pytest.param(lambda a: a.__setitem__(10, "--ip=::1"), id="ip-not-ipv4"),
        pytest.param(lambda a: a.__setitem__(10, "--ip=proxy"), id="ip-proxy"),
        pytest.param(lambda a: a.remove("--nodns=none"), id="testssl-does-its-own-dns"),
    ],
)
def test_the_guard_refuses_anything_outside_the_allowlist(tmp_path, mutate) -> None:
    argv = _valid_argv(tmp_path)
    mutate(argv)
    with pytest.raises(RefusedError):
        guard_invocation(argv, _valid_env())


def test_the_guard_refuses_an_undeclared_environment_variable(tmp_path) -> None:
    env = _valid_env() | {"OFFENSIVE": "true"}
    with pytest.raises(RefusedError):
        guard_invocation(_valid_argv(tmp_path), env)


def test_the_guard_pins_the_value_of_lang_not_only_the_key(tmp_path) -> None:
    with pytest.raises(RefusedError):
        guard_invocation(_valid_argv(tmp_path), {"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})


def test_the_pinned_environment_passes_its_own_guard(tmp_path) -> None:
    from core.testssl import environment

    guard_invocation(_valid_argv(tmp_path), environment())


@pytest.mark.parametrize(
    "allowed",
    [
        pytest.param((), id="empty-runs-everything"),
        pytest.param(("--vulnerable", "--quiet"), id="suite-wide"),
        pytest.param(("--rc4", "--quiet"), id="undeclared-subset"),
    ],
)
def test_the_guard_refuses_an_undeclared_argument_list(tmp_path, allowed) -> None:
    argv = [
        str(TESTSSL_PATH),
        *allowed,
        "--jsonfile-pretty",
        str(tmp_path / "o.json"),
        "example.test:443",
    ]
    with pytest.raises(RefusedError):
        guard_invocation(argv, _valid_env(), allowed_args=allowed)


def test_a_list_instead_of_a_tuple_is_a_refusal_not_a_crash(tmp_path) -> None:
    with pytest.raises(RefusedError):
        guard_invocation(_valid_argv(tmp_path), _valid_env(), allowed_args=list(EXPECTED_ARGS))


def test_the_declared_lists_are_exactly_the_two_callers() -> None:
    from core.testssl import CROSSCHECK_ARGS, DECLARED_ARG_LISTS

    assert {EXPECTED_ARGS, CROSSCHECK_ARGS} == DECLARED_ARG_LISTS
    assert CROSSCHECK_ARGS == ("--protocols", "--server-defaults", "--quiet")


def test_a_refused_target_never_starts_the_subprocess(monkeypatch) -> None:
    """A host that would parse as a flag is refused before testssl.sh runs,
    and the refusal is the scanner's ordinary `inconclusive` path."""
    calls = _capture_run(monkeypatch)
    with pytest.raises(UnavailableError):
        live().legacy_ciphers("--vulnerable", 443)
    assert calls == []
    assert issubclass(RefusedError, UnavailableError)
