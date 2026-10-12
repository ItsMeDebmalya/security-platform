"""Cross-check our TLS observations against testssl.sh.

[ADR-016](../../docs/02-decisions.md) chose to build our own TLS engine rather
than wrap testssl.sh, and to keep testssl.sh as an independent second opinion
instead. This is that second opinion — the role a second resolver plays for the
email scanner.

**It compares observations, not verdicts.** Whether a 1024-bit key is "high" or
"critical" is an opinion and we are entitled to our own. Whether the key *is*
1024 bits is a fact, and if two independent implementations disagree about a
fact then one of them has a bug. Comparing conclusions would generate argument;
comparing facts generates information.

Not part of the gate, and deliberately so: it needs a GPLv2 shell script, it
is slow, and a corpus gate that
depends on a third-party tool being installed is a corpus gate that breaks on
someone else's machine. Run it when changing the TLS engine, and read the
disagreements.

    tools/fetch-testssl.sh                        # once
    uv run python -m corpus.crosscheck.testssl

testssl.sh is GPLv2 and runs as a separate process. Never import it, never
copy from it — the CI licence check enforces the isolation mode.

Its invocation has a declared, exact allowlist, `CROSSCHECK_ARGS`, checked by
`core.testssl.guard_invocation` with the same pinned environment as the
runtime wrapper (ADR-023 amendment, clause 2). `--protocols` and
`--server-defaults` are ordinary handshakes; nothing here runs the
vulnerability tests.
"""

from __future__ import annotations

import json
import re
import shutil
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.authz import Scope
from core.testssl import CROSSCHECK_ARGS, TESTSSL_PATH, environment, guard_invocation
from core.tls import TlsClient, TlsObservation
from corpus.generators.tls_lab import LAB_ADDRESSES, LabDns, LabServer, mint, mint_chain

ROOT = Path(__file__).resolve().parents[2]
TESTSSL = TESTSSL_PATH

# CROSSCHECK_ARGS is declared in core.testssl, beside the runtime list. No
# `--severity` filter: it drops findings rated OK, which are precisely the
# facts we agree on. Filtering them would leave a cross-check that only ever
# sees problems.
BASE_PORT = 15400

_KEY_BITS = re.compile(r"(\d+)\s*bits")
_DAYS_LEFT = re.compile(r"\((\-?\d+)\)")


@dataclass(frozen=True)
class Comparison:
    fact: str
    ours: object
    theirs: object
    agreed: bool
    note: str = ""


def available() -> bool:
    return TESTSSL.exists() and shutil.which("bash") is not None


def run_testssl(host: str, port: int, timeout_s: int = 180) -> dict[str, str]:
    """Run testssl.sh and return its findings as {id: finding}."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        argv = [str(TESTSSL), *CROSSCHECK_ARGS, "--jsonfile-pretty", str(out), f"{host}:{port}"]
        env = environment()
        guard_invocation(argv, env, allowed_args=CROSSCHECK_ARGS)
        subprocess.run(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        if not out.exists():
            return {}
        report = json.loads(out.read_text())

    findings: dict[str, str] = {}
    scan = report.get("scanResult") or []
    for block in scan:
        for section in block.values():
            if not isinstance(section, list):
                continue
            for item in section:
                if isinstance(item, dict) and "id" in item:
                    findings[item["id"]] = str(item.get("finding", ""))
    return findings


# --- the facts we can both see ----------------------------------------------


def _their_key_bits(findings: dict[str, str]) -> int | None:
    match = _KEY_BITS.search(findings.get("cert_keySize", ""))
    return int(match.group(1)) if match else None


def _their_signature(findings: dict[str, str]) -> str | None:
    """ "SHA256 with RSA" -> "sha256"."""
    text = findings.get("cert_signatureAlgorithm", "")
    match = re.match(r"\s*(SHA\d+|MD5|SHA1)\b", text, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _their_not_after(findings: dict[str, str]) -> str | None:
    """ "2027-08-25 05:26" -> "2027-08-25"."""
    text = findings.get("cert_notAfter", "")
    match = re.match(r"\s*(\d{4}-\d{2}-\d{2})", text)
    return match.group(1) if match else None


def _their_fingerprint(findings: dict[str, str]) -> str | None:
    text = findings.get("cert_fingerprintSHA256", "").strip().replace(":", "")
    return text.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", text) else None


def _their_sct(findings: dict[str, str]) -> bool | None:
    text = findings.get("certificate_transparency", "").strip().lower()
    if not text:
        return None
    return text not in ("n/a", "--", "no", "none")


def _their_chain_trusted(findings: dict[str, str]) -> bool | None:
    """testssl's verdict on the *chain*, not on the leaf.

    `cert_chain_of_trust` reports "failed (self signed)" whenever path building
    ends at a self-signed certificate the verifier does not trust - which is
    every root. Reading it as "the leaf is self-signed" is exactly the
    conflation that made us report untrusted-root.badssl.com as a self-signed
    certificate. Made twice now: once in the scanner, once in the first draft
    of this file.
    """
    chain = findings.get("cert_chain_of_trust", "").lower()
    if not chain:
        return None
    return chain.startswith("ok") or "passed" in chain


def _their_protocols(findings: dict[str, str]) -> dict[str, bool | None]:
    labels = {"TLSv1": "TLS1", "TLSv1.1": "TLS1_1", "TLSv1.2": "TLS1_2", "TLSv1.3": "TLS1_3"}
    result: dict[str, bool | None] = {}
    for ours, theirs in labels.items():
        text = findings.get(theirs)
        if text is None:
            result[ours] = None
            continue
        lowered = text.lower()
        if "not offered" in lowered or "downgraded" in lowered:
            result[ours] = False
        elif "offered" in lowered:
            result[ours] = True
        else:
            result[ours] = None
    return result


def compare(
    observation: TlsObservation,
    findings: dict[str, str],
    protocols: dict[str, bool] | None = None,
    *,
    shares_trust_store: bool = True,
) -> list[Comparison]:
    """Line up every fact both tools reported. Silence on either side is skipped.

    `shares_trust_store` is False when we were given a private trust anchor
    that testssl.sh knows nothing about. Trust verdicts are then not comparable
    - we would be measuring whose trust store was configured, not whose path
    building is right - so they are skipped rather than counted as
    disagreements.
    """
    results: list[Comparison] = []
    certificate = observation.certificate

    def add(fact: str, ours: object, theirs: object, agreed: bool | None = None) -> None:
        if theirs is None:
            return
        results.append(Comparison(fact, ours, theirs, ours == theirs if agreed is None else agreed))

    if certificate is not None:
        # The anchor: if the fingerprints match we are demonstrably looking at
        # the same certificate, and every other comparison below means something.
        add("fingerprint", certificate.fingerprint_sha256, _their_fingerprint(findings))
        add("subject_cn", certificate.subject_cn, findings.get("cert_commonName") or None)
        add("key_bits", certificate.key_bits, _their_key_bits(findings))
        add("signature", certificate.signature_algorithm, _their_signature(findings))
        add("not_after", certificate.not_after.date().isoformat(), _their_not_after(findings))
        add("has_sct", certificate.has_sct, _their_sct(findings))

        sans = findings.get("cert_subjectAltName")
        if sans:
            add("sans", sorted(certificate.sans), sorted(sans.split()))

        if shares_trust_store:
            add("chain_trusted", observation.trusted, _their_chain_trusted(findings))

    if protocols:
        for label, offered in _their_protocols(findings).items():
            if offered is None or label not in protocols:
                continue
            add(f"protocol:{label}", protocols[label], offered)

    return results


# --- the run ----------------------------------------------------------------

CASES: dict[str, dict[str, Any]] = {
    "healthy": {},
    "expired": {"not_before_days": -800, "not_after_days": -400},
    "expiring-soon": {"not_after_days": 12},
    "weak-key": {"key_bits": 1024},
    "self-signed": {"self_signed": True},
    "obsolete-protocol": {"max_version": ssl.TLSVersion.TLSv1},
}


def _serve(tmp: Path, case_id: str, spec: dict[str, Any], port: int):
    server_kwargs: dict[str, Any] = {}
    if "max_version" in spec:
        server_kwargs["max_version"] = spec["max_version"]
    else:
        server_kwargs["min_version"] = ssl.TLSVersion.TLSv1_2

    if spec.get("self_signed"):
        minted = mint(tmp, case_id, common_name="localhost", sans=["localhost"])
        return LabServer(minted, port=port, **server_kwargs), None

    options = {k: v for k, v in spec.items() if k not in ("max_version", "self_signed")}
    ca, leaf, chain = mint_chain(
        tmp, case_id, common_name="localhost", sans=["localhost"], **options
    )
    return LabServer(leaf, chain_file=chain, port=port, **server_kwargs), str(ca.cert_path)


def main() -> int:
    if not available():
        print("testssl.sh is not installed. Run tools/fetch-testssl.sh first.")
        print("This cross-check is optional and is not part of any gate.")
        return 0

    scope = Scope(frozenset({"localhost"}))
    disagreements: list[tuple[str, Comparison]] = []
    compared = 0

    for index, (case_id, spec) in enumerate(CASES.items()):
        port = BASE_PORT + index
        with tempfile.TemporaryDirectory() as tmp:
            server, anchor = _serve(Path(tmp), case_id, spec, port)
            try:
                # D60: the lab listens on loopback, so it needs the lab policy.
                client = TlsClient(
                    scope=scope, trust_anchor=anchor, dns=LabDns(), addresses=LAB_ADDRESSES
                )
                observation = client.inspect(port=port, host="localhost", servername="localhost")
                protocols = client.supported_protocols("localhost", port, servername="localhost")
                findings = run_testssl("localhost", port)
            finally:
                server.close()

        results = compare(observation, findings, protocols, shares_trust_store=anchor is None)
        if not findings:
            print(f"  {case_id:<20} testssl returned nothing - skipped")
            continue
        compared += len(results)
        agreed = sum(1 for r in results if r.agreed)
        print(
            f"  {case_id:<20} {agreed}/{len(results)} facts agreed"
            f"  ({len(findings)} testssl findings)"
        )
        for result in results:
            if not result.agreed:
                disagreements.append((case_id, result))

    print(f"\n{compared} facts compared across {len(CASES)} cases")
    if not disagreements:
        print("no disagreements")
        return 0

    print(f"\n{len(disagreements)} DISAGREEMENT(S) - one of us is wrong:")
    for case_id, result in disagreements:
        print(f"  {case_id}: {result.fact}  ours={result.ours!r}  testssl={result.theirs!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
