"""Generate the frozen TLS handshakes for the TLS analyser's corpus.

Each case stands up a lab server with one deliberate defect and records the
scanner's handshakes against it. Recording by *running the scanner* means the
frozen set is exactly the handshakes it makes, including the protocol
enumeration and the independent hostname probe - easy to forget when writing
fixtures by hand, and their absence would quietly turn those checks into
no-ops on replay.

    uv run python -m corpus.generators.tls

Most defects are issued by a lab certificate authority that we trust while
recording. That is deliberate: a leaf signed by a trusted CA and then left to
expire produces *only* the expiry finding, which is what a real site with a
real certificate looks like. Minting each defect self-signed instead would
bury every case under a self-signed finding and make the ground truth useless.

Ports are pinned rather than ephemeral. A recorded handshake is keyed on host,
port and servername, so an ephemeral port would make every fixture
unreplayable the moment it was regenerated.
"""

from __future__ import annotations

import shutil
import ssl
import tempfile
from pathlib import Path
from typing import Any

from core.authz import Scope
from core.context import ScanContext
from core.models import Asset
from core.tls import RecordingTlsBackend, TlsClient
from corpus.generators.tls_lab import LabServer, mint, mint_chain, mint_three_level
from scanners.tls import TlsScanner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus" / "fixtures" / "tls"
SCOPE = Scope(frozenset({"localhost"}))
BASE_PORT = 14400

# case id -> (port, mode, how to build the server)
CASES: dict[str, dict[str, Any]] = {
    "healthy": {"mode": "standard", "chain": {}},
    "expired": {"mode": "light", "chain": {"not_before_days": -800, "not_after_days": -400}},
    "expiring-soon": {"mode": "light", "chain": {"not_after_days": 20}},
    "expiring-urgent": {"mode": "light", "chain": {"not_after_days": 3}},
    "not-yet-valid": {
        "mode": "light",
        "chain": {"not_before_days": 30, "not_after_days": 400},
    },
    "wrong-hostname": {"mode": "light", "chain": {"common_name": "other.test"}},
    "self-signed": {"mode": "light", "self_signed": {}},
    "untrusted-root": {"mode": "light", "untrusted_root": {}},
    "weak-key": {"mode": "standard", "chain": {"key_bits": 1024}},
    "sha1-signature": {"mode": "standard", "self_signed": {"digest": "sha1"}},
    # The CA is trusted but the server sends only its leaf, so no path can be
    # built. This is what a server that forgot its intermediates looks like.
    "incomplete-chain": {"mode": "light", "incomplete_chain": True},
    # AES128-SHA is a static-RSA suite: no ECDHE, so no forward secrecy. RC4 and
    # 3DES are compiled out of OpenSSL 3, which is why there is no weak-cipher
    # case here - see the ledger.
    "no-forward-secrecy": {
        "mode": "standard",
        "chain": {},
        "server": {
            "ciphers": "AES128-SHA:@SECLEVEL=0",
            "min_version": ssl.TLSVersion.TLSv1_2,
            "max_version": ssl.TLSVersion.TLSv1_2,
        },
    },
    "obsolete-protocol": {
        "mode": "standard",
        "chain": {},
        "server": {"max_version": ssl.TLSVersion.TLSv1},
    },
    "unreachable": {"mode": "light", "closed": True},
    # D17: OpenSSL reports only its first objection, so an expired leaf
    # served without its intermediate previously verified as "expired" and
    # the missing-chain problem never surfaced. Both must fire now.
    "expired-and-incomplete-chain": {
        "mode": "light",
        "incomplete_chain": True,
        "leaf": {"not_before_days": -800, "not_after_days": -400},
    },
    # BEAST (first derived finding, ADR-018): a completed TLS 1.0 handshake
    # negotiating a CBC-mode cipher. AES128-SHA has no AEAD suite at TLS 1.0,
    # so pinning the ceiling there is enough to force a CBC negotiation.
    "beast-vulnerable": {
        "mode": "standard",
        "chain": {},
        "server": {
            "ciphers": "AES128-SHA:@SECLEVEL=0",
            "max_version": ssl.TLSVersion.TLSv1,
        },
    },
    # D48: the leaf names `localhost` only in its Common Name, with no SAN at
    # all. RFC 9525 §2 forbids matching the CN, so this is a mismatch, for our
    # matcher and for OpenSSL's reading alike. Appended last, so no other
    # case's port moves.
    "cn-only": {"mode": "light", "chain": {"omit_san": True}},
}


def _build(tmp: Path, case_id: str, spec: dict[str, Any], port: int):
    """Stand up the server for one case. Returns (server, trust_anchor).

    Servers default to a TLS 1.2 floor. The lab runs at @SECLEVEL=0 so that
    weak configurations can be served at all, and without a floor every case
    would also accept TLS 1.0 - making every case an obsolete-protocol case and
    burying the defect each one exists to test.
    """
    server_kwargs = dict(spec.get("server", {}))
    if "max_version" not in server_kwargs:
        # A floor everywhere except the case whose whole point is an old ceiling,
        # where a floor of 1.2 and a ceiling of 1.0 leaves nothing to negotiate.
        server_kwargs.setdefault("min_version", ssl.TLSVersion.TLSv1_2)

    if "self_signed" in spec:
        options = {"common_name": "localhost", "sans": ["localhost"], **spec["self_signed"]}
        minted = mint(tmp, case_id, **options)
        return LabServer(minted, port=port, **server_kwargs), None

    if spec.get("incomplete_chain"):
        root, _, leaf, _ = mint_three_level(
            tmp, case_id, common_name="localhost", sans=["localhost"], **spec.get("leaf", {})
        )
        # Serve the leaf only: the root is trusted, the intermediate is missing.
        return LabServer(leaf, port=port, **server_kwargs), str(root.cert_path)

    if "untrusted_root" in spec:
        _, leaf, chain = mint_chain(tmp, case_id, common_name="localhost", sans=["localhost"])
        return LabServer(leaf, chain_file=chain, port=port, **server_kwargs), None

    options = dict(spec["chain"])
    common_name = options.pop("common_name", "localhost")
    sans = [common_name] if common_name != "localhost" else ["localhost"]
    ca, leaf, chain = mint_chain(tmp, case_id, common_name=common_name, sans=sans, **options)
    return LabServer(leaf, chain_file=chain, port=port, **server_kwargs), str(ca.cert_path)


def generate(only: set[str] | None = None) -> None:
    for index, (case_id, spec) in enumerate(CASES.items()):
        if only is not None and case_id not in only:
            continue
        port = BASE_PORT + index
        directory = FIXTURES / case_id
        if directory.exists():
            shutil.rmtree(directory)

        with tempfile.TemporaryDirectory() as tmp:
            server = None
            anchor = None
            if not spec.get("closed"):
                server, anchor = _build(Path(tmp), case_id, spec, port)
            try:
                ctx = ScanContext(
                    tls=TlsClient(
                        scope=SCOPE,
                        backend=RecordingTlsBackend(directory),
                        trust_anchor=anchor,
                    ),
                    progress=lambda message, fraction: None,
                )
                result = TlsScanner().run(
                    Asset(type="url", value=f"https://localhost:{port}"), spec["mode"], ctx
                )
            finally:
                if server is not None:
                    server.close()

        claims = [f.check_id for f in result.findings if f.state in ("confirmed", "highly_likely")]
        hedges = [f.check_id for f in result.findings if f.state == "suspected"]
        unknown = [f.check_id for f in result.findings if f.state == "inconclusive"]
        print(
            f"{case_id:<20} :{port}  {len(list(directory.iterdir())):>2} fixtures  "
            f"claims={claims} hedged={hedges}"
            + (f" inconclusive={len(unknown)}" if unknown else "")
        )


if __name__ == "__main__":
    import sys

    generate(set(sys.argv[1:]) or None)
