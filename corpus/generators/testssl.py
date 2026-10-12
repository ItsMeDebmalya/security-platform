"""Freeze the legacy-cipher corpus for D20 (RC4, SWEET32, FREAK, LOGJAM).

Unlike every other TLS corpus case, these are **not** a local lab server.
Legacy ciphers are compiled out of OpenSSL 3.5 - verified as "No cipher can be
selected" - so nothing on this machine, lab included, can serve one. testssl.sh
drives its own bundled OpenSSL and can, which is exactly why D20 wraps it at
runtime for these four checks (ADR-016's reserved per-check reversal).

The corpus is therefore frozen recordings against public badssl.com weak
endpoints, which exist for exactly this purpose and are safe to hit in
Light/passive mode - no authorisation needed (they are explicitly a public
testing service). Recording is real network + a real ~60-100s/host testssl.sh
run; replay (the corpus gate, `make corpus`) never touches the network.

    tools/fetch-testssl.sh                       # once
    uv run python -m corpus.generators.testssl   # re-records against badssl.com
    uv run python -m corpus.generators.testssl --testssl-only
                                                 # only testssl's verdicts (D56)

Records **both** fixture sets a Standard-mode scan needs: our own engine's TLS
handshakes (`core.tls.RecordingTlsBackend`, for the certificate/protocol
checks that also run) and testssl's vulnerability verdicts
(`core.testssl.RecordingTestsslClient`, for the four checks this module
exists for).

**FREAK has no positive case here.** `export.badssl.com` is the natural
target, but as of this recording it no longer negotiates an export-grade RSA
suite - neither our engine nor testssl.sh's bundled OpenSSL can complete an
export handshake against it, so there is no live public endpoint left to
record a real positive from. Fabricating one would be exactly the defect
recorded twice in the ledger (D-register: a hand-written fixture is not
evidence). `tls-vuln-freak` is therefore in `test_every_tls_check_has_a_
corpus_case`'s documented-uncovered set until a real positive endpoint is
found - the check ships (the code path is real and unit-tested in
`tests/core/test_testssl.py`), but its corpus recall is unproven.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, SystemResolver
from core.models import Asset
from core.testssl import LabOverride, LiveTestsslClient, RecordingTestsslClient
from core.tls import RecordingTlsBackend, TlsClient
from scanners.tls import TlsScanner

ROOT = Path(__file__).resolve().parents[2]
TLS_FIXTURES = ROOT / "corpus" / "fixtures" / "tls"
TESTSSL_FIXTURES = ROOT / "corpus" / "fixtures" / "testssl"

# case id -> real badssl.com host badssl.com maintains for this exact purpose
CASES: dict[str, str] = {
    "legacy-cipher-rc4": "rc4.badssl.com",
    "legacy-cipher-sweet32": "3des.badssl.com",
    "legacy-cipher-logjam": "dh512.badssl.com",
    # Negative control: refuses every legacy suite testssl.sh can offer.
    "legacy-cipher-clean": "mozilla-modern.badssl.com",
}

PORT = 443
RESOLVERS = ["1.1.1.1", "8.8.8.8"]
"""The same public resolvers `cli/main.py` uses for a live scan."""
SCOPE = Scope(frozenset({host for host in CASES.values()}))

OVERRIDE = LabOverride(
    reason=(
        "corpus recording against badssl.com, a public TLS test service run for exactly this "
        "(ADR-027). Its test names share addresses it operates itself, so a hello with no SNI "
        "reaches badssl.com's own default site, not an unrelated party (D59)"
    )
)
"""D59: the dedicated-address condition cannot be proven for badssl.com
either. The recordings run under this explicit override, and its reason is
written into every fixture."""


def _live() -> LiveTestsslClient:
    return LiveTestsslClient(
        dns=DnsClient(resolver=SystemResolver(RESOLVERS), resolvers=RESOLVERS),
        scope=SCOPE,
        lab_override=OVERRIDE,
    )


def generate_testssl_only() -> None:
    """Re-record testssl's verdicts without touching our own engine's TLS
    fixtures. Used for D56, where only the testssl.sh invocation changed."""
    for case_id, host in CASES.items():
        testssl_dir = TESTSSL_FIXTURES / case_id
        if testssl_dir.exists():
            shutil.rmtree(testssl_dir)
        report = RecordingTestsslClient(testssl_dir, inner=_live()).legacy_ciphers(host, PORT)
        verdicts = {i: f.severity for i, f in sorted(report.findings.items())}
        print(
            f"{case_id:<24} {host:<26} {verdicts} tested={list(report.addresses_tested)} "
            f"untested={list(report.addresses_untested)}"
        )


def generate() -> None:
    for case_id, host in CASES.items():
        tls_dir = TLS_FIXTURES / case_id
        testssl_dir = TESTSSL_FIXTURES / case_id
        if tls_dir.exists():
            shutil.rmtree(tls_dir)
        if testssl_dir.exists():
            shutil.rmtree(testssl_dir)

        ctx = ScanContext(
            tls=TlsClient(scope=SCOPE, backend=RecordingTlsBackend(tls_dir)),
            testssl=RecordingTestsslClient(testssl_dir, inner=_live()),
            progress=lambda message, fraction: None,
        )
        result = TlsScanner().run(Asset(type="url", value=f"https://{host}"), "standard", ctx)

        claims = [f.check_id for f in result.findings if f.state in ("confirmed", "highly_likely")]
        hedges = [f.check_id for f in result.findings if f.state == "suspected"]
        unknown = [f.check_id for f in result.findings if f.state == "inconclusive"]
        n_tls = len(list(tls_dir.iterdir())) if tls_dir.exists() else 0
        n_testssl = len(list(testssl_dir.iterdir())) if testssl_dir.exists() else 0
        print(
            f"{case_id:<24} {host:<26} {n_tls:>2} tls fixtures  {n_testssl:>2} testssl fixtures  "
            f"claims={claims} hedged={hedges}" + (f" inconclusive={unknown}" if unknown else "")
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--testssl-only", action="store_true")
    if parser.parse_args().testssl_only:
        generate_testssl_only()
    else:
        generate()
