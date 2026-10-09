"""The Email Security Scanner.

Pure DNS, entirely passive, legally safe against any domain, and most
organisations genuinely fail it. Light mode is the free hook; the Standard
checks here are still passive, so they run without touching the target at all.

Three things this scanner is careful about, all of them from
docs/05-phase-1-first-tools.md:

- **A wildcard is checked before anything is concluded from a record
  existing.** A zone with a TXT wildcard answers every `_dmarc.*` and
  `*._domainkey.*` lookup, so presence proves nothing there. Absence still
  does - a real record wins over a wildcard - so absence findings stand.
- **SERVFAIL is not "no record".** Every check reads `is_definite()` and emits
  `inconclusive` rather than a confident absence.
- **DKIM selectors cannot be enumerated.** Not finding one of our guesses is
  `inconclusive` by construction, never "this domain has no DKIM".

What is deliberately not here: `open-relay` and `mail-tls-weak` need an SMTP
connection to a mail server, which is active rather than passive and belongs
with the authorisation gate; `lookalike-domain` needs RDAP over HTTP and a
permutation engine. All three are real checks and none of them are Light-mode
work. BIMI is omitted because its absence is a branding gap, not a security
finding, and reporting it would be padding.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.dns import DnsClient, DnsResponse
from core.evidence import dns_evidence
from core.models import Asset, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.registry import register
from core.scanner import BaseScanner
from scanners.email.checks import CHECKS, COMMON_SELECTORS, DNS_CLASS, Check
from scanners.email.checks import requires_authorisation as _requires_authorisation
from scanners.email.discovery import (
    Discovery,
    discover,
    exact_records,
    is_dmarc_candidate,
    organizational,
    walk_ancestors,
)
from scanners.email.dkim import DkimKeyRecord, parse_dkim_key
from scanners.email.dmarc import DmarcRecord, has_valid_rua, parse_dmarc
from scanners.email.spf import (
    MAX_DNS_LOOKUPS,
    SpfChain,
    SpfRecord,
    fetch_spf,
    parse_spf,
    resolve_spf_chain,
)

ENFORCED = frozenset({"quarantine", "reject"})
MIN_DKIM_BITS = 2048  # RFC 8301 3.1: signers SHOULD use at least this
RFC8301_MIN_BITS = 1024  # RFC 8301 3.1: signers MUST use at least this
NO_VERDICT_FOR_RCODE = {
    "SERVFAIL": "servfail",
    "TIMEOUT": "timeout",
    "REFUSED": "blocked_prerequisite",
}


@register
class EmailScanner(BaseScanner):
    name = "email"
    version = "1.4.1"
    supported_modes = frozenset({"light", "standard"})
    target_types = frozenset({"domain"})

    def requires_authorisation(self, mode: Mode) -> bool:
        return _requires_authorisation(mode)

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        dns = ctx.dns
        assert isinstance(dns, DnsClient), "the email scanner needs a DNS client from the context"
        return _Scan(self, target, mode, ctx, dns).execute()


class _Scan:
    """One run against one domain. Gathers the records once, then judges them."""

    def __init__(
        self, scanner: EmailScanner, target: Asset, mode: Mode, ctx: ScanContext, dns: DnsClient
    ) -> None:
        self.scanner = scanner
        self.target = target
        self.domain = target.value.lower().rstrip(".")
        self.mode = mode
        self.ctx = ctx
        self.dns = dns
        self.findings: list[Finding] = []
        self.checks: list[CheckRun] = []
        self.engine = ConfidenceEngine()
        self._also_reread: list[DnsResponse] = []

    # --- orchestration ------------------------------------------------------

    def execute(self) -> ScanResult:
        self.ctx.progress("checking the zone for wildcards", 0.05)
        self.ctx.check_alive()
        self.txt_wildcard = self.dns.has_wildcard(self.domain, "TXT")
        self.txt_wildcard_probe = self.dns.wildcard_probe(self.domain, "TXT")

        self.ctx.progress("reading SPF, DMARC and MX", 0.25)
        self.ctx.check_alive()
        self.spf = fetch_spf(self.domain, self.dns)
        self.mx_answer = self.dns.query(self.domain, "MX")
        # RFC 9989 4.10: which DMARC record applies, by DNS Tree Walk. Findings
        # *about* the record at this name read `self.dmarc`; anything that asks
        # "what does a receiver do with mail from here" reads `self.posture`.
        self.discovery = discover(
            self.domain, self.dns, author_exists=self.mx_answer.rcode != "NXDOMAIN"
        )
        self.dmarc_answer = self.discovery.target_answer
        self.dmarc = (
            _parse_dmarc_answer(self.dmarc_answer) if self.discovery.target_records <= 1 else None
        )
        self.posture = _posture_record(self.discovery, self.dmarc)

        self.ctx.progress("looking for DKIM selectors", 0.5)
        self.ctx.check_alive()
        self.dkim_keys = self._find_dkim()

        self._check_spf()
        self._check_dmarc()
        self._check_mx()
        self._check_dkim()

        if self.mode != "light":
            self.ctx.progress("resolving the SPF include chain", 0.75)
            self.ctx.check_alive()
            self.chain = resolve_spf_chain(self.domain, self.dns) if self.spf.record else None
            self._check_spf_standard()
            self._check_dmarc_standard()
            self._check_dkim_standard()
            self._check_transport_security()

        self.ctx.progress("simulating the receiver decision", 0.9)
        self._check_spoofing()

        self.ctx.progress("done", 1.0)
        cost = self.ctx.cost.snapshot()
        return ScanResult(
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            target=self.target,
            mode=self.mode,
            findings=self.findings,
            errors=[],
            telemetry=Telemetry(
                checks_run=self.checks, requests=cost.requests, wall_ms=cost.wall_ms
            ),
            finished_at=datetime.now(UTC),
        )

    # --- SPF ----------------------------------------------------------------

    def _check_spf(self) -> None:
        if not self.spf.definite:
            self._inconclusive(
                "spf-missing",
                self.spf.answer,
                f"The TXT lookup for {self.domain} returned {self.spf.answer.rcode}, so we "
                "cannot say whether an SPF record is published. That is not the same as "
                "there being none.",
            )
            return

        if self.spf.record is None:
            self._report(
                "spf-missing",
                self.spf.answer,
                description=(
                    f"{self.domain} publishes {len(self.spf.answer.records)} TXT record(s), "
                    "none of which is an SPF policy."
                ),
                impact=(
                    "Receiving mail servers have no list of hosts allowed to send mail for this "
                    "domain. SPF returns None for every sending server (RFC 7208 section 2.6.1): "
                    "it neither passes nor fails forged mail, so whether forged mail is stopped "
                    "rests on DMARC, with DKIM."
                ),
                remediation=(
                    "Publish a TXT record at "
                    f"{self.domain} of the form 'v=spf1 include:<your mail provider> -all'. "
                    "Start with ~all while you confirm every legitimate sender is covered, "
                    "then move to -all."
                ),
                validates=lambda answer: not _has_spf(answer),
            )
            return

        self._clear("spf-missing")

        if self.spf.duplicate:
            self._report(
                "spf-multiple-records",
                self.spf.answer,
                description=(
                    f"{self.domain} publishes more than one v=spf1 record. RFC 7208 section 4.5 "
                    "makes this a permerror: receivers stop evaluating SPF entirely rather than "
                    "picking one."
                ),
                impact=(
                    "SPF does not work at all for this domain, however carefully the individual "
                    "records are written."
                ),
                remediation=(
                    "Merge the records into a single TXT record. Two providers each asking you "
                    "to 'add this SPF record' is the usual cause - combine their include: terms "
                    "into one policy instead."
                ),
                validates=lambda answer: len(_spf_records(answer)) > 1,
            )
        else:
            self._clear("spf-multiple-records")

        if not self.spf.record.valid:
            self._report(
                "spf-invalid",
                self.spf.answer,
                description=(
                    f"The SPF record at {self.domain} does not parse: "
                    f"{'; '.join(self.spf.record.errors)}."
                ),
                impact=(
                    "A record receivers cannot parse is treated as permerror, which means SPF "
                    "gives no protection and may cause legitimate mail to be rejected."
                ),
                remediation=(
                    "Fix the terms listed above. Every mechanism must be one of all, include, "
                    "a, mx, ptr, ip4, ip6 or exists, optionally prefixed with +, -, ~ or ?."
                ),
                analysis={"spf": self.spf.record.to_dict()},
                validates=lambda answer: not _parse_first_spf(answer).valid,
            )
        else:
            self._clear("spf-invalid")

    def _dmarc_finding_for_posture(self) -> str | None:
        """The DMARC finding that already reports an unenforced policy, if any."""
        if not self.dmarc_answer.is_definite() or not self.discovery.definite:
            return None
        if self.discovery.target_records > 1:
            return "dmarc-invalid"
        if self.posture is None:
            return "dmarc-missing"
        posture = _dmarc_posture(self.posture)
        if self.dmarc is not None and not self.dmarc.valid:
            return None if posture in ENFORCED else "dmarc-invalid"
        return {"none": "dmarc-policy-none", "partial": "dmarc-pct-partial"}.get(posture)

    def _inherited_note(self) -> str:
        """Both readings, for a policy this domain inherits from an ancestor."""
        found = self.discovery
        return (
            f" No DMARC record is published at _dmarc.{self.domain}. Under RFC 9989's DNS "
            f"tree walk (section 4.10) the record at _dmarc.{found.source} applies, using its "
            f"{found.policy_tag}= policy. RFC 7489 receivers find the organizational domain "
            "with a Public Suffix List, which we do not consult, so we cannot confirm they "
            "apply the same record."
        )

    def _neutral_all_posture(self) -> tuple[str, str]:
        """Severity for '?all', and the sentence that says why, from DMARC.

        Operator ruling (2026-10-08): low in every posture. Each finding
        carries its own marginal risk. Enforcing DMARC drops '?all' to low, so
        low is its share; when DMARC does not enforce, the policy risk belongs
        to the DMARC finding, which this one names. The sentence still says
        what the posture means.
        """
        if not self.dmarc_answer.is_definite() or not self.discovery.definite:
            return "low", (
                " The DMARC lookup did not return a definite answer, so whether DMARC stops "
                "forged mail here is unknown."
            )
        posture = _dmarc_posture(self.posture)
        if posture == "reject":
            return "low", (
                " DMARC is p=reject, which asks receivers to reject mail that fails DMARC, so "
                "a message forged from an unlisted server is asked to be rejected unless it "
                "carries a valid DKIM signature for this domain."
            )
        if posture == "quarantine":
            return "low", (
                " DMARC is p=quarantine. RFC 9989 section 4.7 says only that the owner "
                "considers failing mail suspicious; RFC 7489 section 6.3 gives placing it in a "
                "spam folder as an example. Forged mail from an unlisted server may therefore "
                "still be delivered, to a spam folder or flagged, where a person may read and "
                "act on it."
            )
        other = self._dmarc_finding_for_posture()
        if other is None:
            return "low", (
                " DMARC does not enforce a policy here, so nothing stops forged mail. This "
                "finding is the SPF side of that weakness."
            )
        return "low", (
            " DMARC does not enforce a policy here, so nothing stops forged mail. That "
            f"exposure is reported as {other}. This finding is the same weakness seen from "
            "the SPF side: count the two as one."
        )

    def _neutral_all_note(self) -> str:
        """For the DMARC findings: point at spf-too-permissive when it reports the same gap."""
        record = self.spf.record
        if self.mode == "light" or record is None or record.all_qualifier != "?":
            return ""
        if self._dmarc_finding_for_posture() is None:
            return ""
        return (
            " The SPF record also ends in '?all', reported separately as spf-too-permissive. "
            "It describes the same exposure from the SPF side: count the two as one."
        )

    def _check_spf_standard(self) -> None:
        record = self.spf.record
        if record is None or self.chain is None:
            self._not_applicable("spf-too-permissive")
            self._not_applicable("spf-lookup-limit")
            return

        qualifier = record.all_qualifier
        remediation = (
            f"Change '{qualifier}all' to '-all' once every legitimate sender is listed, "
            "or to '~all' while you are still confirming that."
        )
        if qualifier == "+":
            self._report(
                "spf-too-permissive",
                self.spf.answer,
                description=(
                    "The SPF record ends in '+all', which tells receivers that mail from any "
                    "server is acceptable (explicit pass)."
                ),
                impact=(
                    "SPF passes for every sender on the internet, so the record provides no "
                    "protection while appearing to."
                ),
                remediation=remediation,
                validates=lambda answer: _parse_first_spf(answer).all_qualifier == "+",
            )
        elif qualifier == "?":
            # RFC 7208 2.6.2 and 8.2. Neutral is an explicit non-assertion, and
            # receivers MUST treat it exactly like "none". Saying it "accepts
            # any server" asserted a receiver behaviour the spec rules out.
            # How much it matters depends on DMARC, so severity does too.
            severity, posture_note = self._neutral_all_posture()
            self._report(
                "spf-too-permissive",
                self.spf.answer,
                severity=severity,
                title="SPF policy is neutral for senders it does not list",
                description=(
                    "The SPF record ends in '?all' (Neutral). RFC 7208 section 2.6.2 defines "
                    "Neutral as the domain explicitly not asserting whether a sending server is "
                    "authorised, and section 8.2 requires receivers to treat it exactly like "
                    "the result for a domain with no SPF policy. Servers the record lists still "
                    "pass; for every other server, SPF gives the same answer as having no SPF "
                    "policy." + posture_note
                ),
                impact=(
                    "For senders the record does not list, SPF gives receivers nothing to act "
                    "on. Whether forged mail is stopped then rests on DMARC, with DKIM, and on "
                    "each receiver's own policy."
                ),
                remediation=remediation,
                validates=lambda answer: _parse_first_spf(answer).all_qualifier == "?",
            )
        else:
            # '-all' and '~all' are a declared non-finding, not a gap. SoftFail
            # (RFC 7208 2.6.5) says the sender is probably not authorised, and
            # DMARC treats it as an SPF failure. Without DMARC the exposure is
            # dmarc-missing's, and reporting it here again would count it twice.
            self._clear("spf-too-permissive")

        if not self.chain.definite:
            self._inconclusive(
                "spf-lookup-limit",
                self.spf.answer,
                "The SPF include chain could not be walked to the end: "
                + "; ".join(self.chain.problems)
                + ". A count that stopped early is not a count.",
                analysis={"spf_chain": self.chain.to_dict()},
            )
        elif self.chain.exceeded:
            self._report(
                "spf-lookup-limit",
                self.spf.answer,
                description=(
                    f"Evaluating this SPF policy needs {self.chain.total_lookups} DNS lookups, "
                    f"above the limit of {MAX_DNS_LOOKUPS} in RFC 7208 section 4.6.4. "
                    + _chain_summary(self.chain)
                ),
                impact=(
                    "Receivers stop evaluating and return permerror, so SPF fails for this "
                    "domain entirely. Legitimate mail can be rejected and forged mail is not "
                    "caught."
                ),
                remediation=(
                    "Reduce the chain below ten lookups. The usual fix is to replace include: "
                    "terms for providers you no longer use, and to flatten a provider's ranges "
                    "into ip4:/ip6: terms - those cost no lookups at all."
                ),
                analysis={"spf_chain": self.chain.to_dict()},
                validates=self._rewalk_chain_exceeds,
            )
        else:
            self._clear("spf-lookup-limit")

    # --- DMARC --------------------------------------------------------------

    def _check_dmarc(self) -> None:
        found = self.discovery
        if not self.dmarc_answer.is_definite() or (self.dmarc is None and not found.definite):
            failed = next(q for q in found.queried if not q.is_definite())
            self._inconclusive(
                "dmarc-missing",
                failed,
                f"The TXT lookup for {failed.name} returned {failed.rcode}, so we cannot say "
                "which DMARC record, if any, applies to this domain.",
            )
            self._not_applicable("dmarc-invalid")
            self._not_applicable("dmarc-policy-none")
            return

        if found.target_records > 1:
            self._report_multiple_dmarc()
            self._not_applicable("dmarc-policy-none")
            return

        if self.dmarc is None and found.record is not None:
            self._check_inherited_dmarc()
            return

        if self.dmarc is None:
            walked = ", ".join(q.name for q in found.queried)
            self._report(
                "dmarc-missing",
                self.dmarc_answer,
                description=(
                    f"No DMARC record applies to {self.domain}. Following RFC 9989's DNS tree "
                    f"walk (section 4.10) we looked at {walked}, and none publishes one. RFC "
                    "7489 receivers, which look at the organizational domain, find none "
                    "either, because it is one of those names." + self._neutral_all_note()
                ),
                analysis={"dmarc_discovery": found.to_dict()},
                impact=(
                    "Receiving mail servers are given no instruction about what to do with mail "
                    "that fails authentication, so forged mail claiming to be from this domain "
                    "is generally delivered."
                ),
                remediation=(
                    f"Publish a TXT record at _dmarc.{self.domain} of the form "
                    "'v=DMARC1; p=none; rua=mailto:dmarc-reports@"
                    f"{self.domain}'. Start at p=none to collect reports, confirm every "
                    "legitimate sender passes, then move to p=quarantine and p=reject."
                ),
                validates=self._still_no_dmarc,
            )
            self._not_applicable("dmarc-invalid")
            self._not_applicable("dmarc-policy-none")
            return

        self._clear("dmarc-missing")

        dmarc = self.dmarc
        if not dmarc.usable:
            self._report_invalid_dmarc(dmarc)
            self._not_applicable("dmarc-policy-none")
            self._not_applicable("dmarc-test-mode")
            return
        if dmarc.receiver_handling == "discard_tag" or dmarc.legacy_issues:
            self._report_invalid_dmarc(dmarc)
        else:
            self._clear("dmarc-invalid")

        if dmarc.policy == "none":
            absent = dmarc.p_absent
            self._report(
                "dmarc-policy-none",
                self.dmarc_answer,
                title="DMARC record has no policy tag, so it means p=none" if absent else None,
                description=(
                    (
                        f"The DMARC record for {self.domain} has no p= tag. RFC 9989 section "
                        "4.7 treats that as p=none; RFC 7489 applied no DMARC processing to it "
                        "(or p=none, with a valid rua). Either way, nothing stops forged mail. "
                        "An operator with this record believes the domain is protected, and it "
                        "is not."
                    )
                    if absent
                    else (
                        f"The DMARC policy for {self.domain} is p=none, which asks receivers "
                        "to take no action on mail that fails authentication."
                    )
                )
                + self._neutral_all_note(),
                impact=(
                    "Mail forged as this domain is still delivered. p=none is a monitoring "
                    "posture, useful while you find your legitimate senders, but it stops "
                    "nothing."
                ),
                remediation=(
                    "Add p=quarantine (then p=reject) to the record once your reports show every "
                    "legitimate sender passing."
                    if absent
                    else (
                        "Once your rua reports show every legitimate sender passing, change "
                        "p=none to p=quarantine, then to p=reject. Move in that order and watch "
                        "the reports at each step."
                    )
                ),
                validates=_dmarc_policy_is_none,
            )
        else:
            self._clear("dmarc-policy-none")
        self._check_test_mode(dmarc, self.dmarc_answer)

    def _check_test_mode(self, dmarc: DmarcRecord, answer: DnsResponse) -> None:
        """t=y (RFC 9989 4.7): apply one level below the stated policy.

        RFC 7489 receivers do not know `t` and apply the policy as written, so
        the finding is receiver-dependent: worst-case severity, `suspected`.
        """
        if not dmarc.testing or dmarc.policy not in ENFORCED:
            self._clear("dmarc-test-mode")
            return
        applied = "quarantine" if dmarc.policy == "reject" else "none"
        self._report(
            "dmarc-test-mode",
            answer,
            description=(
                f"The DMARC record sets p={dmarc.policy} with t=y. RFC 9989 section 4.7 asks "
                f"receivers to apply one level below the stated policy, so failing mail gets "
                f"{applied}. RFC 7489 receivers do not know the t tag and apply "
                f"p={dmarc.policy} as written. Which happens depends on the receiver."
            ),
            impact=(
                f"At receivers following RFC 9989, forged mail gets {applied}"
                + (", so it is delivered." if applied == "none" else ", not rejected.")
            ),
            remediation=(
                "t=y is for testing a policy before you enforce it. Once your reports show "
                "every legitimate sender passing, remove t=y (or set t=n)."
            ),
            analysis={"dmarc": dmarc.to_dict()},
            validates=lambda again: (rec := _parse_dmarc_answer(again)) is not None and rec.testing,
        )

    def _report_multiple_dmarc(self) -> None:
        """More than one DMARC record at one name: every one is discarded.

        RFC 7489 6.6.3 step 5 ends policy discovery there, so no DMARC applies.
        RFC 9989 4.10 discards them and continues the walk to the
        organizational domain. Severity is dmarc-missing's: at this name, the
        worst case is no record at all.
        """
        found = self.discovery
        if found.record is None:
            outcome = (
                "No ancestor publishes a record either, so under both RFCs no DMARC policy "
                "applies to this domain."
            )
        else:
            outcome = (
                f"Under RFC 9989 the walk then reaches _dmarc.{found.source}, whose "
                f"{found.policy_tag}= policy applies. Under RFC 7489 discovery stops here "
                "and no DMARC applies."
            )
        self._report(
            "dmarc-invalid",
            self.dmarc_answer,
            title="More than one DMARC record published, so receivers discard them all",
            description=(
                f"_dmarc.{self.domain} publishes {found.target_records} DMARC records. RFC "
                "7489 section 6.6.3 and RFC 9989 section 4.10 both discard every record at "
                f"a name that has more than one. {outcome}" + self._neutral_all_note()
            ),
            impact=(
                "Whatever policy the records state, receivers do not apply it. The domain "
                "has the appearance of DMARC protection and none of the effect."
                if found.record is None
                else (
                    "Whatever policy the records state, receivers do not apply it. RFC 9989 "
                    f"receivers apply _dmarc.{found.source}'s policy instead; RFC 7489 "
                    "receivers apply no DMARC."
                )
            ),
            remediation=(
                f"Publish exactly one TXT record at _dmarc.{self.domain} beginning "
                "'v=DMARC1'. Merge whatever the records were meant to say into it."
            ),
            analysis={"dmarc_discovery": found.to_dict()},
            validates=lambda answer: len(exact_records(answer)) > 1,
        )

    def _check_inherited_dmarc(self) -> None:
        """No record here, but one applies from an ancestor (RFC 9989 4.10)."""
        found = self.discovery
        self._clear("dmarc-missing")
        effective = found.effective
        assert effective is not None and found.answer is not None
        if not effective.usable:
            self._report_inherited_unusable(effective)
            self._not_applicable("dmarc-policy-none")
            return
        self._not_applicable("dmarc-invalid")
        if effective.usable and effective.policy == "none":
            tag = found.policy_tag
            via_np = ""
            if tag == "np":
                legacy = found.effective_7489
                legacy_policy = legacy.policy if legacy is not None else None
                legacy_tag = "sp" if "sp" in found.record.tags else "p"  # type: ignore[union-attr]
                via_np = (
                    f" RFC 7489 does not define np, so its receivers apply "
                    f"{legacy_tag}={legacy_policy} from the same record instead."
                )
            self._report(
                "dmarc-policy-none",
                found.answer,
                description=(
                    f"The DMARC policy that applies to {self.domain} is none, which asks "
                    "receivers to take no action on mail that fails authentication."
                    + self._inherited_note()
                    + via_np
                    + self._neutral_all_note()
                ),
                impact=(
                    "Mail forged as this domain is still delivered wherever this record is the "
                    "one applied."
                ),
                remediation=(
                    f"At _dmarc.{found.source}, raise {tag}= from none to quarantine, then "
                    f"reject, or publish a record of its own at _dmarc.{self.domain}."
                ),
                analysis={"dmarc_discovery": found.to_dict()},
                validates=lambda answer: _effective_policy(answer, tag) == "none",
                likelihood_ratio=INHERITED_RATIO,
                justification=INHERITED_REASON,
            )
        else:
            self._clear("dmarc-policy-none")
        if effective.usable:
            self._check_test_mode(effective, found.answer)

    def _report_inherited_unusable(self, record: DmarcRecord) -> None:
        """The ancestor record that applies has no usable policy (re-review S1)."""
        found = self.discovery
        assert found.answer is not None
        handling = record.receiver_handling
        if record.np_invalid_only:
            no_rua = handling == "no_processing"
            severity = CHECKS["dmarc-missing"].severity if no_rua else "medium"
            rule = (
                "under RFC 9989 section 4.10.1 an invalid np= means receivers "
                + ("apply no DMARC processing" if no_rua else "act as if the record said p=none")
                + ", but RFC 7489 does not define np, ignores the tag and applies "
                + f"p={record.policy}. Which happens depends on the receiver"
            )
        elif handling == "treat_as_none":
            severity, rule = (
                "medium",
                (
                    "it carries a valid rua, so receivers act as if it said p=none (RFC 9989 "
                    "section 4.10.1, RFC 7489 section 6.6.3)"
                ),
            )
        elif handling == "no_processing":
            severity, rule = (
                CHECKS["dmarc-missing"].severity,
                (
                    "it carries no valid rua either, so receivers apply no DMARC processing (RFC "
                    "9989 section 4.10.1, RFC 7489 section 6.6.3)"
                ),
            )
        else:
            severity, rule = (
                CHECKS["dmarc-missing"].severity,
                (
                    "it repeats a tag, which neither DMARC RFC gives receiver handling for, so "
                    "some "
                    "receivers may apply no DMARC"
                ),
            )
        self._report(
            "dmarc-invalid",
            found.answer,
            severity=severity,
            title="The DMARC record this domain inherits has no usable policy",
            description=(
                f"_dmarc.{found.source}'s record, which applies to {self.domain}, has a "
                f"problem: {'; '.join(record.errors)}. "
                + rule[0].upper()
                + rule[1:]
                + "."
                + self._inherited_note()
            ),
            impact="Mail forged as this domain is not stopped wherever this record is applied.",
            remediation=(
                f"Fix the record at _dmarc.{found.source}, or publish one of its own at "
                f"_dmarc.{self.domain}."
            ),
            analysis={"dmarc": record.to_dict(), "dmarc_discovery": found.to_dict()},
            validates=_dmarc_is_invalid,
            likelihood_ratio=INHERITED_RATIO,
            justification=INHERITED_REASON,
        )

    def _report_invalid_dmarc(self, dmarc: DmarcRecord) -> None:
        """Say what the two DMARC RFCs say a receiver does with this record.

        RFC 9989 is primary. Where RFC 7489 gives a different verdict, the
        finding states both and is `suspected`. Severity is the worst case's
        (ADR-017): if a receiver could discard the record, that is
        dmarc-missing's severity, because the domain then has no DMARC at all.
        """
        problems = "; ".join(dmarc.errors + dmarc.legacy_issues)
        errors = "; ".join(dmarc.errors)
        lead = f"The DMARC record at _dmarc.{self.domain} has a problem: {problems}."
        note = self._neutral_all_note()
        remediation = (
            "Rewrite the record so it begins 'v=DMARC1; p=<policy>;'. Give each tag once, "
            "with a valid value."
        )
        missing_severity = CHECKS["dmarc-missing"].severity
        handling = dmarc.receiver_handling
        if handling in ("treat_as_none", "no_processing") and dmarc.np_invalid_only:
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                # Worst case under RFC 9989: p=none (medium) with a valid rua,
                # no DMARC processing at all (dmarc-missing's) without one.
                severity="medium" if handling == "treat_as_none" else missing_severity,
                title="DMARC np= value is invalid, and receivers may handle it differently",
                description=(
                    f"{lead} RFC 9989 section 4.10.1 says a receiver given an invalid np= "
                    + (
                        "acts as if the record said p=none, because it carries a valid rua."
                        if handling == "treat_as_none"
                        else "applies no DMARC processing, because it carries no valid rua."
                    )
                    + " RFC 7489 does not define np=, so its receivers ignore the tag and apply "
                    f"p={dmarc.policy}. Which happens depends on the receiver." + note
                ),
                impact=("At receivers following RFC 9989, the domain loses its DMARC enforcement."),
                remediation=remediation,
                analysis={"dmarc": dmarc.to_dict()},
                validates=_dmarc_is_invalid,
                likelihood_ratio=DUAL_RATIO,
                justification=DUAL_REASON,
            )
        elif handling == "treat_as_none":
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                severity="medium",
                title="DMARC record would be treated as p=none by receivers",
                description=(
                    f"{lead} The record has no usable policy but does carry a valid rua "
                    "address, so receivers act as if it said p=none: RFC 9989 section 4.10.1 "
                    "(MUST) and RFC 7489 section 6.6.3 (SHOULD) agree. Reports are sent, and "
                    "failing mail is not blocked. An operator with this record believes the "
                    "domain is protected, and it is not." + note
                ),
                impact=(
                    "Whatever policy was intended, receivers treat the domain as monitoring "
                    "only, so mail forged as this domain is still delivered."
                ),
                remediation=remediation,
                analysis={"dmarc": dmarc.to_dict()},
                validates=_dmarc_is_invalid,
            )
        elif handling == "ignored" and self.discovery.record is not None:
            found = self.discovery
            applied = found.effective.policy if found.effective is not None else None
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                severity="low",
                title="DMARC record is ignored, so an ancestor's policy applies instead",
                description=(
                    f"{lead} RFC 7489 section 6.3 and RFC 9989 section 4.7 both say receivers "
                    "MUST ignore this record. With no record of its own, the domain gets the "
                    f"one at _dmarc.{found.source} by RFC 9989's tree walk, and its "
                    f"{found.policy_tag}= policy ({applied}) applies, not the policy written "
                    "here. An RFC 7489 receiver falls back to the organizational domain, which "
                    "it finds with a Public Suffix List we do not consult, so it may apply the "
                    "same record, a different one, or none." + note
                ),
                impact=("The policy you wrote is not the one receivers apply; the ancestor's is."),
                remediation=(
                    f"Correct the record at _dmarc.{self.domain} so it begins exactly "
                    "'v=DMARC1', if you meant its policy to apply."
                ),
                analysis={"dmarc": dmarc.to_dict(), "dmarc_discovery": found.to_dict()},
                validates=_dmarc_is_invalid,
                likelihood_ratio=INHERITED_RATIO,
                justification=INHERITED_REASON,
            )
        elif handling in ("no_processing", "ignored"):
            rule = (
                "RFC 9989 section 4.10.1 and RFC 7489 section 6.6.3 both say a receiver given a "
                "record with no valid policy and no valid reporting address applies no DMARC "
                "processing"
                if handling == "no_processing"
                else (
                    "RFC 7489 section 6.3 and RFC 9989 section 4.7 both say the entire "
                    "record MUST then be ignored"
                )
            )
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                description=(
                    f"{lead} {rule}, so the domain is unprotected despite appearing configured."
                    + note
                ),
                impact=(
                    "The domain has the appearance of DMARC protection and none of the effect."
                ),
                remediation=remediation,
                analysis={"dmarc": dmarc.to_dict()},
                validates=_dmarc_is_invalid,
            )
        elif handling == "undefined":
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                severity=missing_severity,
                title="DMARC record repeats a tag, and receivers may handle it differently",
                description=(
                    f"{lead} A repeated tag makes the tag list invalid (RFC 6376 section 3.2, "
                    "adopted by RFC 9989 section 4.7 and RFC 7489 section 6.3), but neither "
                    "DMARC RFC says what a receiver then does. Some may ignore the record, "
                    "which leaves the domain with no DMARC at all; others may apply the policy "
                    "they can read." + note
                ),
                impact=(
                    "At receivers that discard the record, the domain has no DMARC protection."
                ),
                remediation=remediation,
                analysis={"dmarc": dmarc.to_dict()},
                validates=_dmarc_is_invalid,
                likelihood_ratio=DUAL_RATIO,
                justification=DUAL_REASON,
            )
        elif dmarc.legacy_issues:
            fixes = []
            if any(issue.startswith("p=") for issue in dmarc.legacy_issues):
                fixes.append("move p= to straight after v=")
            if any(issue.startswith("rf=") for issue in dmarc.legacy_issues):
                fixes.append("remove rf= (RFC 9989 removed it)")
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                severity=missing_severity,
                title="DMARC record is valid under RFC 9989 but not under RFC 7489",
                description=(
                    f"The DMARC record at _dmarc.{self.domain} is valid under RFC 9989, but "
                    f"not under RFC 7489: {'; '.join(dmarc.legacy_issues)}. A receiver still "
                    "implementing RFC 7489 may therefore discard the record, leaving the "
                    "domain with no DMARC at all."
                    + (
                        f" Separately, receivers discard a malformed tag: {errors}."
                        if dmarc.errors
                        else ""
                    )
                    + note
                ),
                impact="At receivers that discard the record, the domain has no DMARC protection.",
                remediation=(
                    "To be read the same by every receiver, " + " and ".join(fixes) + ". It costs "
                    "nothing under RFC 9989."
                ),
                analysis={"dmarc": dmarc.to_dict()},
                validates=lambda again: (
                    (rec := _parse_dmarc_answer(again)) is not None and bool(rec.legacy_issues)
                ),
                likelihood_ratio=DUAL_RATIO,
                justification=DUAL_REASON,
            )
        else:
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                severity="low",
                title="DMARC record has a malformed tag, which receivers discard",
                description=(
                    f"{lead} Receivers discard the malformed value and use the default (RFC "
                    "9989 section 4.8, MUST, for the tags it defines, and it ignores tags it no "
                    "longer defines, such as pct; RFC 7489 section 6.3, SHOULD), so the record "
                    "works, but it may not do what was intended." + note
                ),
                impact="The default applies in place of what the tag was meant to say.",
                remediation=remediation,
                analysis={"dmarc": dmarc.to_dict()},
                validates=_dmarc_is_invalid,
            )

    def _record_governs_made_up_subdomains(self, inherited: bool) -> bool | None:
        """Whether a made-up subdomain of this domain gets this record (review B6).

        RFC 9989 4.10.2: a made-up name walks up and takes the Organizational
        Domain's record: psd=n first, then one below a psd=y, else the record
        with the fewest labels. np on a record below that is never applied
        (section 4.7, sp/np "ignored for DMARC Policy Records published on
        subdomains of Organizational Domains"). None when a lookup failed.
        """
        if inherited:
            return True  # the walk already chose this record as the Organizational Domain's
        if self.dmarc is not None and self.dmarc.psd == "n":
            return True
        ancestors = walk_ancestors(self.domain, self.dns)
        if ancestors is None:
            return None
        own = (self.domain, self.dmarc, self.dmarc_answer)
        chosen = _org_choice(f"x.{self.domain}", [own, *ancestors])
        return chosen is not None and chosen[0] == self.domain

    def _check_dmarc_standard(self) -> None:
        found = self.discovery
        inherited = self.dmarc is None and found.target_records <= 1 and found.inherited
        record = found.effective if inherited else self.dmarc
        standard_ids = (
            "dmarc-pct-partial",
            "dmarc-obsolete-tags",
            "dmarc-np-weaker",
            "dmarc-no-rua",
            "dmarc-alignment",
        )
        if record is None or not record.usable:
            for check_id in standard_ids:
                self._not_applicable(check_id)
            return
        answer = found.answer if inherited and found.answer is not None else self.dmarc_answer
        note = self._inherited_note() if inherited else ""
        ratio = INHERITED_RATIO if inherited else None
        reason = INHERITED_REASON if inherited else None

        if record.pct < 100 and record.policy in ENFORCED:
            # pct is removed in RFC 9989 (App. C.5.2): its receivers ignore it.
            # RFC 7489 6.6.4 says what happens to mail outside the sample:
            # under reject it is quarantined, under quarantine it gets normal
            # local classification (review B3). Worst-case severity, suspected.
            applied9 = _dmarc_posture(record, "9989")
            rest = (
                "quarantines the rest (RFC 7489 section 6.6.4), so all failing mail is still "
                "at least quarantined"
                if record.policy == "reject"
                else (
                    "gives the rest normal local message classification (RFC 7489 section "
                    "6.6.4), as if there were no DMARC policy"
                )
            )
            self._report(
                "dmarc-pct-partial",
                answer,
                severity="low" if record.policy == "reject" else "medium",
                description=(
                    f"The DMARC record sets p={record.policy} with pct={record.pct}. Under RFC "
                    "9989, the current standard, pct is removed, so its receivers apply "
                    f"{applied9} to all failing mail"
                    + (" (one level below the policy, because of t=y)" if record.testing else "")
                    + f". A receiver still implementing RFC 7489 applies p={record.policy} to "
                    f"only {record.pct}% and {rest}. Which happens depends on the receiver."
                    + note
                    + self._neutral_all_note()
                ),
                impact=(
                    f"At RFC 7489 receivers, {100 - record.pct}% of failing mail is quarantined "
                    "rather than rejected."
                    if record.policy == "reject"
                    else (
                        f"At RFC 7489 receivers, an attacker sending repeatedly gets through on "
                        f"the {100 - record.pct}% that is not enforced."
                    )
                ),
                remediation=(
                    "Remove pct. To test a policy before enforcing it, use t=y (RFC 9989), then "
                    "remove it."
                ),
                validates=lambda answer: _dmarc_pct(answer) < 100,
                likelihood_ratio=DUAL_RATIO,
                justification=DUAL_REASON,
            )
        else:
            self._clear("dmarc-pct-partial")

        obsolete = record.obsolete_tags
        if obsolete:
            diverges = record.pct < 100 or bool(record.legacy_issues)
            self._report(
                "dmarc-obsolete-tags",
                answer,
                severity="low" if diverges else "info",
                description=(
                    f"The DMARC record uses tags that RFC 9989 removed: {', '.join(obsolete)}. "
                    "Receivers implementing the current standard ignore them."
                    + (
                        " Receivers still implementing RFC 7489 read them, so the record "
                        "behaves differently from receiver to receiver"
                        + (
                            " (see dmarc-invalid for what that can cost)."
                            if record.legacy_issues
                            else "."
                        )
                        if diverges
                        else (
                            " The values used here are what RFC 7489 receivers already assume "
                            "by default, so the two standards read the record the same way."
                            if _obsolete_at_defaults(record)
                            else (
                                " At RFC 7489 receivers they change only how reports are sent, "
                                "not what happens to failing mail."
                            )
                        )
                    )
                    + note
                ),
                impact=(
                    "Receivers disagree about what the record asks for."
                    if diverges
                    else "None today; the tags are noise that can mislead whoever edits the record."
                ),
                remediation=(
                    "Remove the obsolete tags. Use t=y instead of pct=0 to test a policy."
                ),
                analysis={"dmarc": record.to_dict()},
                validates=lambda again: (
                    (rec := _parse_dmarc_answer(again)) is not None and bool(rec.obsolete_tags)
                ),
            )
        else:
            self._clear("dmarc-obsolete-tags")

        np, sub = record.np, record.effective_subdomain_policy
        weaker = np in POLICY_RANK and sub in POLICY_RANK and POLICY_RANK[np] < POLICY_RANK[sub]
        governs = self._record_governs_made_up_subdomains(inherited) if weaker else None
        if weaker and governs is None:
            self._inconclusive(
                "dmarc-np-weaker",
                answer,
                "The record sets a weaker np=, but a lookup above this domain failed, so we "
                "cannot tell whether this record is the one made-up subdomains get.",
            )
        elif weaker and governs:
            self._report(
                "dmarc-np-weaker",
                answer,
                description=(
                    f"The DMARC record sets np={np} for non-existent subdomains, weaker than "
                    f"the {sub} that existing subdomains get. Under RFC 9989 (section 4.10.1), "
                    f"mail forged from a made-up subdomain of {self.domain} gets {np}. RFC 7489 "
                    f"does not define np, so its receivers apply {sub}. Which happens depends "
                    "on the receiver." + note
                ),
                impact=(
                    "At RFC 9989 receivers, an attacker can invent a subdomain to get the weaker "
                    "policy."
                ),
                remediation=f"Raise np= to at least {sub}, or remove it so subdomains get {sub}.",
                analysis={"dmarc": record.to_dict()},
                validates=lambda again: (
                    (rec := _parse_dmarc_answer(again)) is not None and rec.np == np
                ),
                likelihood_ratio=DUAL_RATIO,
                justification=DUAL_REASON,
            )
        else:
            self._clear("dmarc-np-weaker")

        if not record.rua:
            self._report(
                "dmarc-no-rua",
                answer,
                description=(
                    "The DMARC record has no rua= tag, so no aggregate reports are sent anywhere."
                    + note
                ),
                impact=(
                    "Without reports there is no way to see which senders are failing "
                    "authentication, which makes moving to an enforcing policy guesswork."
                ),
                remediation=(
                    f"Add 'rua=mailto:dmarc-reports@{self.domain}' to the record. Reports arrive "
                    "daily as XML; a report analyser makes them readable."
                ),
                validates=lambda answer: not _dmarc_rua(answer),
                likelihood_ratio=ratio,
                justification=reason,
            )
        else:
            self._clear("dmarc-no-rua")

        if record.adkim == "r" or record.aspf == "r":
            self._report(
                "dmarc-alignment",
                answer,
                description=(
                    f"DMARC alignment is relaxed (adkim={record.adkim}, "
                    f"aspf={record.aspf}). Relaxed alignment accepts any subdomain of "
                    f"{self.domain} in the authenticated identifier."
                ),
                impact=(
                    "Relaxed alignment is the default and is appropriate for most senders. It "
                    "does mean that anyone able to publish records under a subdomain can pass "
                    "DMARC for the parent."
                ),
                remediation=(
                    "If every legitimate sender signs and sends as the exact domain, set "
                    "adkim=s and aspf=s. If subdomains send mail, relaxed is the correct "
                    "setting and no change is needed."
                ),
                validates=lambda answer: _dmarc_relaxed(answer),
            )
        else:
            self._clear("dmarc-alignment")

    # --- MX -----------------------------------------------------------------

    def _check_mx(self) -> None:
        if not self.mx_answer.is_definite():
            self._inconclusive(
                "mx-missing",
                self.mx_answer,
                f"The MX lookup for {self.domain} returned {self.mx_answer.rcode}.",
            )
            return

        if _is_null_mx(self.mx_answer):
            # RFC 7505: "MX 0 ." is a deliberate statement that the domain
            # handles no mail. Reporting it as missing would be a false
            # positive against a correct configuration.
            self._clear("mx-missing")
            return

        if not self.mx_answer.records:
            self._report_missing_mx()
        else:
            self._clear("mx-missing")

    def _authorises_no_senders(self) -> bool:
        """Whether the SPF record permits nobody at all to send as this domain.

        Only a bare `v=spf1 -all` means that. A trailing `-all` on its own does
        NOT: `v=spf1 ip4:192.0.2.0/24 -all` reads "nobody except the range I
        just listed", which is a domain that very much does send mail.

        Getting this wrong produced a live false statement about a bank whose
        SPF authorises nine ranges, so the test is now every sender-authorising
        mechanism rather than a guess at the common ones.
        """
        record = self.spf.record
        if record is None or record.all_qualifier != "-" or record.redirect:
            return False
        return all(term.mechanism == "all" for term in record.terms)

    def _email_is_deliberately_configured(self) -> bool:
        """Whether someone has evidently thought about email for this domain.

        An enforcing DMARC policy is the signal. If it is there, a missing MX
        is an omission in an otherwise considered setup; if it is not, the
        domain is more likely to be unconfigured than deliberately silent.
        """
        return (
            self.posture is not None
            and self.posture.valid
            and self.posture.policy in ("quarantine", "reject")
        )

    def _report_missing_mx(self) -> None:
        if self._email_is_deliberately_configured():
            spf_text = self.spf.record.raw if self.spf.record else "no SPF record"
            policy = self.posture.policy if self.posture else ""
            posture = (
                "Its SPF record authorises no senders at all, and its DMARC policy is "
                f"p={policy}, which together say this domain neither sends nor receives "
                "mail - so the absence of MX records looks deliberate rather than broken."
                if self._authorises_no_senders()
                else (
                    f"Its DMARC policy is p={policy}, so email is clearly configured here "
                    "deliberately; the domain appears to send mail without accepting any."
                )
            )
            self._report(
                "mx-missing",
                self.mx_answer,
                severity="low",
                title="No MX records, and no explicit statement that the domain takes no mail",
                description=(
                    f"{self.domain} publishes no MX records. Its published SPF record is "
                    f"'{spf_text}'. {posture}"
                ),
                impact=(
                    "A sending server has to wait for the lookup to fail and then fall back to "
                    "the A record before giving up, which delays the bounce and can leave mail "
                    "queued for days."
                ),
                remediation=(
                    "Publish the null MX record 'MX 0 .' (RFC 7505). It tells senders "
                    "immediately and unambiguously that this domain accepts no mail, instead of "
                    "leaving them to infer it."
                ),
                validates=lambda answer: not answer.records,
            )
            return

        self._report(
            "mx-missing",
            self.mx_answer,
            description=f"{self.domain} publishes no MX records.",
            impact=(
                "Mail addressed to this domain cannot be delivered. If the domain is not meant "
                "to receive mail, saying so explicitly is better than silence."
            ),
            remediation=(
                "Publish MX records pointing at your mail provider. If the domain should never "
                "receive mail, publish the null MX record 'MX 0 .' (RFC 7505), which tells "
                "senders so immediately."
            ),
            validates=lambda answer: not answer.records,
        )

    # --- DKIM ---------------------------------------------------------------

    def _find_dkim(self) -> list[_DkimKey]:
        """Every key published under the common selectors, not just the first.

        Stopping at the first answer let a legacy key under a later selector go
        unseen. All 17 names were already queried whenever no key was found, so
        this costs at most 16 more lookups on a domain that has one.
        """
        keys: list[_DkimKey] = []
        for selector in COMMON_SELECTORS:
            self.ctx.check_alive()
            answer = self.dns.query(f"{selector}._domainkey.{self.domain}", "TXT")
            if not answer.is_definite():
                continue
            for record in answer.records:
                if ("p=" in record and "k=" in record) or record.lower().startswith("v=dkim1"):
                    keys.append(_DkimKey(selector, answer, parse_dkim_key(record)))
                    break
        return keys

    def _check_dkim(self) -> None:
        if self.dkim_keys:
            self._clear("dkim-missing")
            return

        wildcard_note = (
            " The zone also answers TXT lookups for names that do not exist (a wildcard), "
            "so a record appearing at a selector name would prove nothing either."
            if self.txt_wildcard
            else ""
        )
        self._inconclusive(
            "dkim-missing",
            self.txt_wildcard_probe or self.spf.answer,
            (
                f"None of the {len(COMMON_SELECTORS)} common DKIM selectors resolved for "
                f"{self.domain}. DKIM selector names are chosen freely by the sender and "
                "cannot be enumerated, so this does not show that the domain has no DKIM - "
                "only that we could not find a key." + wildcard_note
            ),
            impact="Unknown: we could not determine whether DKIM is configured.",
            remediation=(
                "If you know your selector, check it directly: the record lives at "
                f"<selector>._domainkey.{self.domain}. Your mail provider's documentation "
                "names the selector it uses."
            ),
        )

    def _check_dkim_standard(self) -> None:
        live = [k for k in self.dkim_keys if not k.record.revoked]
        if not live:
            self._not_applicable("dkim-weak-key")
            return

        # Key size is an RSA measure. An Ed25519 key is 256 bits by
        # construction and is not weak for it.
        rsa = [k for k in live if k.record.key_type == "rsa"]
        weak = sorted(
            (k for k in rsa if k.record.key_bits is not None and k.record.key_bits < MIN_DKIM_BITS),
            key=lambda k: k.record.key_bits or 0,
        )
        unmeasured = [k for k in rsa if k.record.key_bits is None]
        others = [k for k in live if k not in weak and k not in unmeasured]

        if not weak:
            if unmeasured:
                self._inconclusive(
                    "dkim-weak-key",
                    unmeasured[0].answer,
                    f"The DKIM key at {_names(unmeasured, self.domain)} could not be decoded, so "
                    "its strength could not be measured. We do not report an unmeasurable key "
                    "as a weak one.",
                    analysis={"dkim_keys": [k.to_dict() for k in self.dkim_keys]},
                )
            else:
                self._clear("dkim-weak-key")
            return

        weakest = weak[0]
        bits = weakest.record.key_bits or 0
        sizes = " and ".join(
            f"{k.selector}._domainkey.{self.domain} ({k.record.key_bits} bits)" for k in weak
        )
        if len(weak) == 1:
            name = f"{weakest.selector}._domainkey.{self.domain}"
            lead = f"The DKIM key published at {name} is {bits} bits."
        else:
            lead = f"DKIM keys below {MIN_DKIM_BITS} bits are published at {sizes}."

        if bits >= RFC8301_MIN_BITS:
            severity = "low"
            rule = (
                f" {'It' if len(weak) == 1 else 'Each'} meets the RFC 8301 minimum of "
                f"{RFC8301_MIN_BITS} bits, below the recommended {MIN_DKIM_BITS}."
            )
            impact = (
                "This is a margin, not a break: RFC 8301 permits the key, and recommends "
                f"{MIN_DKIM_BITS} bits for signers. Moving to {MIN_DKIM_BITS} bits brings the "
                "domain in line with that recommendation."
            )
        else:
            severity = "medium"
            rule = (
                f" {'It is' if len(weak) == 1 else f'The smallest, {bits} bits, is'} below the "
                f"RFC 8301 minimum of {RFC8301_MIN_BITS} bits, and RFC 8301 section 3.2 says "
                "verifiers MUST NOT treat signatures from such a key as valid."
            )
            impact = (
                "Verifiers that follow RFC 8301 treat signatures from this key as failing, so "
                "mail signed with it gets no DKIM credit and may fail DMARC. A verifier that "
                "still accepts it relies on a key far below the standard's minimum."
            )

        context = ""
        if others:
            context = (
                f" The domain also publishes {_names(others, self.domain)}. We cannot tell from "
                "DNS which selector it signs its mail with. RFC 6376 section 6.1.2 has a "
                "verifier fetch the key named by the signature's s= tag, so a signature may "
                "name any selector the domain publishes, the weaker one included."
            )
        if unmeasured:
            context += (
                f" The key at {_names(unmeasured, self.domain)} could not be decoded and is not "
                "counted either way."
            )

        self._report(
            "dkim-weak-key",
            weakest.answer,
            severity=severity,
            description=lead + rule + context,
            impact=impact,
            remediation=(
                "If a weaker selector is no longer used for signing, remove its record. "
                f"Otherwise generate a new {MIN_DKIM_BITS}-bit key with your mail provider, "
                "publish it under a new selector, switch signing to it, and remove the old "
                "selector once no mail is signed with it."
            ),
            analysis={"dkim_keys": [k.to_dict() for k in self.dkim_keys]},
            validates=lambda answer: _dkim_bits_below(answer, MIN_DKIM_BITS),
        )

    # --- transport security -------------------------------------------------

    def _check_transport_security(self) -> None:
        # D47. MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) protect inbound
        # delivery. A null MX (RFC 7505) says the domain accepts no mail, so
        # there is nothing to protect and the checks do not apply. With no MX
        # at all, senders fall back to the A record (RFC 5321 5.1), and RFC 8461
        # is written in terms of MX hosts without saying whether it covers that
        # fallback, so the finding is informational, never advice.
        if self.mx_answer.is_definite() and _is_null_mx(self.mx_answer):
            self._not_applicable("mta-sts-missing")
            self._not_applicable("tls-rpt-missing")
            return
        no_mx = self.mx_answer.is_definite() and not self.mx_answer.records
        self._presence_check(
            "mta-sts-missing",
            f"_mta-sts.{self.domain}",
            "v=STSv1",
            no_mx=no_mx,
            description=(f"No MTA-STS policy record is published at _mta-sts.{self.domain}."),
            impact=(
                "Without MTA-STS a sending server that cannot negotiate TLS will deliver mail "
                "in plaintext rather than refusing, so an attacker positioned on the network "
                "can strip encryption and read the message."
            ),
            remediation=(
                f"Publish a TXT record at _mta-sts.{self.domain} of the form "
                "'v=STSv1; id=<timestamp>', and serve the matching policy file at "
                f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt. Start the policy in "
                "mode: testing, then move to mode: enforce."
            ),
        )
        self._presence_check(
            "tls-rpt-missing",
            f"_smtp._tls.{self.domain}",
            "v=TLSRPTv1",
            no_mx=no_mx,
            description=f"No SMTP TLS reporting record is published at _smtp._tls.{self.domain}.",
            impact=(
                "Nobody is told when a sending server fails to establish TLS to your mail "
                "servers, so a downgrade attack or a broken certificate goes unnoticed."
            ),
            remediation=(
                f"Publish a TXT record at _smtp._tls.{self.domain} of the form "
                f"'v=TLSRPTv1; rua=mailto:tls-reports@{self.domain}'."
            ),
        )

    def _presence_check(
        self,
        check_id: str,
        name: str,
        token: str,
        *,
        description: str,
        impact: str,
        remediation: str,
        no_mx: bool = False,
    ) -> None:
        answer = self.dns.query(name, "TXT")
        if not answer.is_definite():
            self._inconclusive(
                check_id, answer, f"The TXT lookup for {name} returned {answer.rcode}."
            )
            return
        present = any(r.strip().lower().startswith(token.lower()) for r in answer.records)
        if present:
            self._clear(check_id)
            return
        if no_mx:
            description += (
                f" {self.domain} also publishes no MX records (reported as mx-missing). Mail "
                "can still arrive through the A record, but this protection is defined in "
                "terms of MX hosts, and the RFC does not say whether it applies to that "
                "fallback. So this is recorded for information, not as advice."
            )
            impact = "None that we can state while the domain publishes no MX records."
            remediation = (
                "Nothing to do here first. If the domain should receive mail, publish MX "
                "records (see mx-missing); this protection then applies to them. If it "
                "should not, publish a null MX ('MX 0 .', RFC 7505)."
            )
        self._report(
            check_id,
            answer,
            severity="info" if no_mx else None,
            description=description,
            impact=impact,
            remediation=remediation,
            validates=lambda a: (
                not any(r.strip().lower().startswith(token.lower()) for r in a.records)
            ),
        )

    # --- the summary verdict ------------------------------------------------

    def _check_spoofing(self) -> None:
        """Simulate the decision a receiving mail server would make.

        The simulation *is* the verdict, and it is stated as a simulation: we
        are reading published policy, not watching a receiver act on it.
        """
        if (
            not self.dmarc_answer.is_definite()
            or not self.discovery.definite
            or not self.spf.definite
        ):
            self._inconclusive(
                "spoofing-possible",
                self.dmarc_answer,
                "The published policy could not be read in full, so the receiver's decision "
                "cannot be simulated.",
            )
            return

        reasons, only_hedge = _spoofing_reasons(
            self.posture, self.spf.record, discovery=self.discovery
        )
        self._spoof_reasons = reasons

        if not reasons:
            self._clear("spoofing-possible")
            return

        verdict = "it may be delivered at some receivers" if only_hedge else "it would be delivered"
        self._report(
            "spoofing-possible",
            self.dmarc_answer,
            description=(
                "Simulating the decision a receiving mail server would make for a message "
                f"forged from {self.domain}: {verdict}, because " + "; and ".join(reasons) + "."
            ),
            impact=(
                "Anyone can send mail that appears to come from this domain and expect it to "
                "reach the inbox. That is the mechanism behind invoice fraud and most "
                "credential phishing that targets a company's own staff."
            ),
            remediation=(
                f"Publish an SPF record listing your senders and ending in -all, sign your mail "
                f"with DKIM, then publish 'v=DMARC1; p=reject; rua=mailto:dmarc@{self.domain}' "
                f"at _dmarc.{self.domain}. Move to p=reject only after the rua reports show "
                "every legitimate sender passing."
            ),
            validates=self._still_spoofable,
            likelihood_ratio=4.0 if only_hedge else None,
            justification=(
                "every reason depends on which DMARC record a receiver applies, and the two "
                "DMARC standards, or no standard at all, leave that uncertain"
                if only_hedge
                else None
            ),
        )

    def _rewalk_chain_exceeds(self, _answer: DnsResponse) -> bool:
        """Walk the whole include chain again through the second resolver.

        Expensive - it doubles the lookups for this one check - and worth it:
        a lookup-limit finding rests on every record in the chain, so a
        re-test that only re-read the root would validate almost nothing.
        """
        second = self.dns.second_resolver()
        if second is None:
            return False
        again = resolve_spf_chain(self.domain, self.dns, resolver=second)
        return again.definite and again.exceeded

    def _still_spoofable(self, answer: DnsResponse) -> bool | None:
        """Re-run the receiver simulation on the second resolver's DMARC **and SPF**.

        The verdict rests on both records, so both are re-read. Until D39 was
        fixed this reused the first resolver's SPF record, which went unnoticed
        because no "second" resolver was really asked. Once one was, a stale
        SPF answer at the primary passed validation. Validation passes only
        when the second resolver gives the same reasons. An SPF re-read that
        does not come back definite leaves validation `unavailable`: a timeout
        is not a disagreement.
        """
        spf_again = fetch_spf(self.domain, self.dns, resolver=self.dns.second_resolver())
        self._also_reread.append(spf_again.answer)
        if not spf_again.definite:
            return None
        found = discover(
            self.domain,
            self.dns,
            author_exists=self.mx_answer.rcode != "NXDOMAIN",
            resolver=self.dns.second_resolver(),
        )
        if not found.definite:
            return None
        own = _parse_dmarc_answer(answer) if found.target_records == 1 else None
        reasons, _ = _spoofing_reasons(
            _posture_record(found, own), spf_again.record, discovery=found
        )
        return reasons == self._spoof_reasons

    def _still_no_dmarc(self, _answer: DnsResponse) -> bool | None:
        """Re-walk the whole tree through the second resolver: still nothing applies."""
        found = discover(
            self.domain,
            self.dns,
            author_exists=self.mx_answer.rcode != "NXDOMAIN",
            resolver=self.dns.second_resolver(),
        )
        for answer in found.queried[1:]:
            self._also_reread.append(answer)
        if not found.definite:
            return None
        return found.record is None and found.target_records == 0

    # --- emitting -----------------------------------------------------------

    def _report(
        self,
        check_id: str,
        answer: DnsResponse,
        *,
        description: str,
        impact: str,
        remediation: str,
        analysis: dict[str, Any] | None = None,
        validates: Any = None,
        severity: str | None = None,
        title: str | None = None,
        likelihood_ratio: float | None = None,
        justification: str | None = None,
    ) -> None:
        check = CHECKS[check_id]
        if severity is not None or title is not None:
            # Severity is "how bad if true", and that genuinely differs with
            # context for some checks. Overriding it here keeps the reasoning
            # next to the evidence for it rather than in a lookup table.
            check = replace(check, severity=severity or check.severity, title=title or check.title)
        if likelihood_ratio is not None:
            # A weaker claim from the same check, e.g. a DMARC error whose
            # effect on receivers no spec defines. Its justification travels
            # with it, so the prior is never stated without its reason.
            check = replace(
                check,
                likelihood_ratio=likelihood_ratio,
                justification=justification or check.justification,
            )
        result = self.engine.combine(
            [
                Signal(
                    method="dns_record_parse",
                    prior=0.5,
                    likelihood_ratio=check.likelihood_ratio,
                    independence_class=DNS_CLASS,
                    prior_justification=check.justification,
                )
            ]
        )
        validation, second = self._validate(answer, validates)
        self._emit(
            check,
            answer,
            state_confidence=result,
            validation=validation,
            second=second,
            also_reread=self._also_reread,
            description=description,
            impact=impact,
            remediation=remediation,
            analysis=analysis,
        )
        self.checks.append(CheckRun(check_id=check_id, location="$", outcome="reported"))

    def _inconclusive(
        self,
        check_id: str,
        answer: DnsResponse,
        description: str,
        *,
        impact: str = "Unknown until the lookup succeeds.",
        remediation: str = (
            "Re-run the scan. A persistent failure usually means a broken delegation or a "
            "DNSSEC validation problem on the authoritative nameservers."
        ),
        analysis: dict[str, Any] | None = None,
    ) -> None:
        check = CHECKS[check_id]
        result = self.engine.combine(
            [
                Signal(
                    method="dns_record_parse",
                    prior=0.5,
                    likelihood_ratio=1.0,
                    independence_class=DNS_CLASS,
                    prior_justification=(
                        "the lookup produced no usable answer, so nothing moves the prior"
                    ),
                )
            ]
        )
        self._emit(
            check,
            answer,
            state_confidence=result,
            validation={"attempted": False, "outcome": "unavailable", "method": None},
            second=None,
            description=description,
            impact=impact,
            remediation=remediation,
            analysis=analysis,
            no_verdict_reason=NO_VERDICT_FOR_RCODE.get(answer.rcode, "blocked_prerequisite"),
        )
        self.checks.append(CheckRun(check_id=check_id, location="$", outcome="inconclusive"))

    def _emit(
        self,
        check: Check,
        answer: DnsResponse,
        *,
        state_confidence: Any,
        validation: dict[str, Any],
        second: DnsResponse | None,
        description: str,
        impact: str,
        remediation: str,
        analysis: dict[str, Any] | None,
        no_verdict_reason: str | None = None,
        also_reread: list[DnsResponse] | None = None,
    ) -> None:
        also_reread = also_reread or []
        evidence = [
            dns_evidence(
                label=f"{answer.rrtype} at {answer.name}",
                test=answer,
                control=self.txt_wildcard_probe,
                control_rationale=(
                    "a random-label probe in the same zone; without it a wildcard would make "
                    "every lookup under this domain appear to succeed"
                    if self.txt_wildcard_probe is not None
                    else "the wildcard probe did not return a definite answer"
                ),
                analysis=analysis,
            )
        ]
        if second is not None:
            evidence.append(
                dns_evidence(
                    label=f"independent re-query via {second.resolver}",
                    test=second,
                    control=None,
                    control_rationale=(
                        "the control for this re-query is the first resolver's answer, "
                        "captured above"
                    ),
                )
            )
        for extra in also_reread:
            # Every other record the validation re-read. Its outcome rests on
            # these too, so the evidence shows them (D39 review).
            evidence.append(
                dns_evidence(
                    label=(
                        f"independent re-query via {extra.resolver} "
                        f"({extra.rrtype} at {extra.name})"
                    ),
                    test=extra,
                    control=None,
                    control_rationale=(
                        "re-read for the same validation; compare with the first resolver's "
                        "answer for this name"
                    ),
                )
            )

        now = datetime.now(UTC)
        self.findings.append(
            Finding.create(
                org_id=self.ctx.org_id,
                scanner=self.scanner.name,
                scanner_version=self.scanner.version,
                check_id=check.check_id,
                title=check.title,
                target=self.target,
                location="$",
                severity=check.severity,
                confidence=state_confidence.confidence,
                confidence_provisional=state_confidence.provisional,
                no_verdict_reason=no_verdict_reason,
                detection_methods=state_confidence.detection_methods,
                validation=validation,
                evidence=evidence,
                related_assets=[
                    {"type": "domain", "value": self.domain, "relation": "observed_on"}
                ],
                description=description,
                impact=impact,
                remediation=remediation,
                references=_REFERENCES[check.check_id],
                taxonomy={"cwe": ["CWE-290"]},
                first_seen=now,
                first_seen_scan_id=self.ctx.scan_id,
                last_seen=now,
                last_seen_scan_id=self.ctx.scan_id,
                cost=self.ctx.cost.snapshot(),
            )
        )

    def _validate(
        self, answer: DnsResponse, predicate: Any
    ) -> tuple[dict[str, Any], DnsResponse | None]:
        """Re-read the record through an independent resolver.

        A second resolver is a genuinely separate observation of the same
        fact. It defends against the way this check actually goes wrong: a
        stale cache, or one broken upstream. Where no second resolver is
        configured the outcome is `unavailable` - validation that could not
        run never pretends to have passed.
        """
        self._also_reread = []
        second_resolver = self.dns.second_resolver()
        if second_resolver is None or predicate is None:
            return (
                {"attempted": False, "outcome": "unavailable", "method": "independent_resolver"},
                None,
            )

        confirmation = self.dns.query(answer.name, answer.rrtype, resolver=second_resolver)
        if not confirmation.is_definite():
            return (
                {"attempted": True, "outcome": "unavailable", "method": "independent_resolver"},
                confirmation,
            )
        # A predicate returns None when a further record it needed could not be
        # read: that is "could not validate", never "the resolver disagreed".
        verdict = predicate(confirmation)
        if verdict is None:
            return (
                {"attempted": True, "outcome": "unavailable", "method": "independent_resolver"},
                confirmation,
            )
        agreed = bool(verdict)
        return (
            {
                "attempted": True,
                "outcome": "passed" if agreed else "failed",
                "method": "independent_resolver",
            },
            confirmation,
        )

    def _clear(self, check_id: str) -> None:
        self.checks.append(CheckRun(check_id=check_id, location="$", outcome="clear"))

    def _not_applicable(self, check_id: str) -> None:
        """A check that did not run because its subject does not exist.

        `dmarc-pct-partial` on a domain with no DMARC record has nothing to
        evaluate. It is not recorded in `checks_run` at all, because it did not
        run - recording it as `clear` would claim we checked and found nothing
        wrong, and recording it as `inconclusive` would bury the one finding
        that matters (the missing record) under five restatements of it.
        """


# --- helpers ----------------------------------------------------------------

_REFERENCES = {
    "spf-missing": ["https://www.rfc-editor.org/rfc/rfc7208"],
    "spf-invalid": ["https://www.rfc-editor.org/rfc/rfc7208"],
    "spf-multiple-records": ["https://www.rfc-editor.org/rfc/rfc7208#section-4.5"],
    "spf-too-permissive": ["https://www.rfc-editor.org/rfc/rfc7208#section-5.1"],
    "spf-lookup-limit": ["https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4"],
    "dmarc-missing": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.10"],
    "dmarc-invalid": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.7"],
    "dmarc-policy-none": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.7"],
    "dmarc-pct-partial": ["https://www.rfc-editor.org/rfc/rfc9989#appendix-A.6"],
    "dmarc-obsolete-tags": ["https://www.rfc-editor.org/rfc/rfc9989#appendix-C.5.2"],
    "dmarc-test-mode": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.7"],
    "dmarc-np-weaker": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.10.1"],
    "dmarc-no-rua": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.7"],
    "dmarc-alignment": ["https://www.rfc-editor.org/rfc/rfc9989#section-4.4"],
    "mx-missing": ["https://www.rfc-editor.org/rfc/rfc7505"],
    "dkim-missing": ["https://www.rfc-editor.org/rfc/rfc6376"],
    "dkim-weak-key": ["https://www.rfc-editor.org/rfc/rfc8301"],
    "mta-sts-missing": ["https://www.rfc-editor.org/rfc/rfc8461"],
    "tls-rpt-missing": ["https://www.rfc-editor.org/rfc/rfc8460"],
    "spoofing-possible": ["https://www.rfc-editor.org/rfc/rfc9989"],
}


POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}
DUAL_RATIO = 4.0
DUAL_REASON = (
    "the record is read directly, but what a receiver does with it depends on which DMARC "
    "RFC the receiver implements, so the consequence this finding is about is uncertain"
)
INHERITED_RATIO = 4.0
INHERITED_REASON = (
    "the record applies by RFC 9989's tree walk from an ancestor; RFC 7489 receivers choose "
    "the organizational domain with a Public Suffix List we do not consult"
)


def _obsolete_at_defaults(record: DmarcRecord) -> bool:
    """RFC 7489 6.3 defaults: pct=100, rf=afrf, ri=86400, and no report size limit."""
    tags = record.tags
    if "pct" in tags and record.pct != 100:
        return False
    if "rf" in tags and tags["rf"].strip().lower() != "afrf":
        return False
    if "ri" in tags and tags["ri"].strip() != "86400":
        return False
    return not any("!" in uri for uri in record.rua + record.ruf)


def _org_choice(
    domain: str, found: list[tuple[str, DmarcRecord | None, DnsResponse]]
) -> tuple[str, DmarcRecord, DnsResponse] | None:
    usable = [(n, r, a) for n, r, a in found if r is not None]
    return organizational(domain, usable)


def _posture_record(found: Discovery, own: DmarcRecord | None) -> DmarcRecord | None:
    """The record a receiver applies: the walk's, or this name's own ignored one.

    A record here whose version is not exactly DMARC1 is discarded by the walk,
    but if nothing else applies it is still what explains the posture.
    """
    if found.record is not None:
        return found.effective
    if found.target_records > 1:
        return None
    return own


def _effective_policy(answer: DnsResponse, tag: str) -> str | None:
    record = _parse_dmarc_answer(answer)
    if record is None:
        return None
    value = record.tags.get(tag) or record.tags.get("p")
    return value.lower() if value else None


def _dmarc_posture(dmarc: DmarcRecord | None, standard: str = "9989") -> str:
    """What a receiver does with this domain's DMARC record, under one RFC.

    The single place this question is answered. Two checks once each carried
    their own copy of a wrong premise ("?all accepts any sender", "receivers
    ignore a malformed record"), so everything that needs the answer reads it
    from here. `standard` is "9989" (primary) or "7489" (still deployed).

    - `missing`: no record.
    - `unusable`: no DMARC processing, or the record is ignored outright.
    - `undefined`: forbidden, but no RFC says what a receiver does.
    - `none`: p=none, an absent p (RFC 9989), or treated as p=none.
    - `partial`: RFC 7489 only. An enforcing policy applied to under 100%.
    - `quarantine` / `reject`: enforced. Under RFC 9989, t=y lowers it one level.
    """
    if dmarc is None:
        return "missing"
    handling = dmarc.receiver_handling
    if standard == "7489":
        if dmarc.np_invalid_only:
            handling = None  # RFC 7489 does not define np, so it ignores the tag
        usable = handling in (None, "discard_tag")
        if usable and dmarc.legacy_issues:
            return "undefined"  # review B4: a discarded tag does not hide the legacy issue
        if usable and dmarc.p_absent:
            return "none" if has_valid_rua(dmarc.tags) else "unusable"
    if handling in ("no_processing", "ignored"):
        return "unusable"
    if handling == "undefined":
        return "undefined"
    if handling == "treat_as_none" or dmarc.policy == "none":
        return "none"
    policy = dmarc.policy or "none"
    if standard == "9989":
        if dmarc.testing:
            policy = {"reject": "quarantine", "quarantine": "none"}.get(policy, policy)
        return policy
    if dmarc.pct < 100:
        # RFC 7489 6.6.4: outside the sample, reject becomes quarantine
        # (still enforced) and quarantine becomes normal classification.
        return "quarantine" if policy == "reject" else "partial"
    return policy


def _dmarc_reason(dmarc: DmarcRecord | None, posture: str, inherited: bool) -> str:
    """The RFC 9989 reason a forged message is delivered, for an unenforced posture."""
    if posture == "missing":
        return (
            "there is no DMARC record, so a receiver has no instruction to reject mail "
            "that fails authentication"
        )
    if posture == "unusable":
        if dmarc is not None and dmarc.receiver_handling == "ignored":
            return (
                "the DMARC record does not begin with exactly 'v=DMARC1', and RFC 7489 "
                "section 6.3 and RFC 9989 section 4.7 both say receivers ignore such a record "
                "entirely"
            )
        return (
            "the DMARC record has no usable policy and no valid rua, and RFC 9989 section "
            "4.10.1 and RFC 7489 section 6.6.3 both say a receiver then applies no DMARC "
            "processing"
        )
    if posture == "undefined":
        return (
            "the DMARC record repeats a tag, which neither DMARC RFC gives receiver handling "
            "for, so some receivers may not apply it"
        )
    if dmarc is not None and dmarc.receiver_handling == "treat_as_none":
        return (
            "the DMARC record has no usable policy but a valid rua, so receivers act as if it "
            "said p=none (RFC 9989 section 4.10.1), which asks them to take no action"
        )
    if dmarc is not None and dmarc.p_absent:
        return (
            "the DMARC record has no p= tag, which RFC 9989 treats as p=none (RFC 7489 applied "
            "no DMARC processing), so nothing asks receivers to act"
        )
    if dmarc is not None and dmarc.testing and dmarc.policy == "quarantine":
        return "the record sets p=quarantine with t=y, which RFC 9989 receivers apply as none"
    if inherited:
        return "the DMARC policy that applies is none, which asks receivers to take no action"
    return "the DMARC policy is p=none, which asks receivers to take no action"


def _rfc7489_only_reason(dmarc: DmarcRecord | None, p7: str) -> str:
    """Why an RFC 7489 receiver delivers forged mail, citing RFC 7489 alone."""
    if p7 == "partial" and dmarc is not None:
        return _rfc7489_partial(dmarc)
    if p7 == "unusable":
        return "RFC 7489 receivers apply no DMARC processing to it (RFC 7489 section 6.6.3)"
    if p7 == "undefined":
        return "RFC 7489 does not say how its receivers handle the record, so some may ignore it"
    if p7 == "missing":
        return "RFC 7489 receivers find no DMARC record to apply"
    return "RFC 7489 receivers act as if it said p=none"


def _rfc7489_partial(dmarc: DmarcRecord) -> str:
    """RFC 7489 6.6.4 for p=quarantine with pct below 100. RFC 7489 only."""
    return (
        f"RFC 7489 receivers quarantine only {dmarc.pct}% and give the rest normal local "
        "classification (RFC 7489 section 6.6.4), so some forged messages are delivered there"
    )


def _dual_reason(
    dmarc: DmarcRecord | None, p9: str, p7: str, dmarc7489: DmarcRecord | None = None
) -> str:
    """Both readings, when only one RFC leaves the domain unenforced.

    Each RFC's half is derived from that RFC's own posture, never restated
    from the other (re-review N1).
    """
    dmarc7489 = dmarc7489 if dmarc7489 is not None else dmarc
    if dmarc is not None and dmarc7489 is not None and dmarc.policy != dmarc7489.policy:
        # An inherited np (re-review S2): RFC 9989 applies it, RFC 7489 does not know it.
        legacy_tag = "sp" if "sp" in dmarc.tags else "p"
        return (
            f"this non-existent subdomain gets np={dmarc.tags.get('np', dmarc.policy)} under RFC "
            f"9989, but RFC 7489 does not define np and applies {legacy_tag}="
            f"{dmarc7489.policy} from the same record"
        )
    if dmarc is not None and p7 == "partial":
        return (
            f"RFC 9989 receivers apply {p9} to all failing mail (it removed pct), but "
            + _rfc7489_partial(dmarc)
        )
    if dmarc is not None and dmarc.testing and p9 == "none":
        return (
            "the record sets p=quarantine with t=y, which RFC 9989 receivers apply as none; RFC "
            "7489 receivers ignore t and quarantine"
        )
    if dmarc is not None and p7 == "undefined" and dmarc.legacy_issues:
        # Built from the record's actual issues (re-review N2).
        return (
            "the record is valid under RFC 9989, but "
            f"{'; '.join(dmarc.legacy_issues)}, so an RFC 7489 receiver may discard it"
        )
    if dmarc is not None and dmarc.np_invalid_only:
        return (
            "np= is invalid, so RFC 9989 receivers do not enforce the policy; RFC 7489 "
            f"receivers ignore np and apply p={dmarc.policy}"
        )
    return "the DMARC RFCs disagree about whether this record is enforced"


def _spoofing_reasons(
    dmarc: DmarcRecord | None, spf: SpfRecord | None, *, discovery: Discovery | None = None
) -> tuple[list[str], bool]:
    """Why a receiving mail server would deliver a forged message.

    Returns the reasons and whether they are only a hedge. A reason that holds
    under one DMARC RFC and not the other is receiver-dependent: it is stated
    with both readings and can only make the finding `suspected`.

    Extracted so that validation can re-run exactly the same reasoning against
    an independently fetched record, rather than re-checking a weaker proxy.
    """
    reasons: list[str] = []
    hedged = False
    discarded = discovery is not None and discovery.target_records > 1
    inherited = discovery is not None and discovery.inherited
    # RFC 7489 does not know np, so an inherited record is read with sp or p (review S2).
    dmarc7489 = discovery.effective_7489 if inherited and discovery is not None else dmarc
    p9, p7 = _dmarc_posture(dmarc, "9989"), _dmarc_posture(dmarc7489, "7489")
    open9, open7 = p9 not in ENFORCED, p7 not in ENFORCED
    if discarded and dmarc is None:
        reasons.append(
            "the domain publishes more than one DMARC record, and RFC 7489 and RFC 9989 "
            "both discard them all, so no DMARC policy applies"
        )
    elif discarded and not open9 and discovery is not None:
        # RFC 7489 stops at the discarded records; RFC 9989 walks on to an
        # enforcing ancestor. Receiver-dependent: the worst case is stated.
        hedged = True
        reasons.append(
            "the domain publishes more than one DMARC record, which every receiver "
            "discards; RFC 7489 receivers then apply no DMARC, while RFC 9989 receivers apply "
            f"_dmarc.{discovery.source}'s policy"
        )
    elif open9 and open7:
        hedged = "undefined" in (p9, p7)
        reason = _dmarc_reason(dmarc, p9, inherited)
        if p7 != p9 and not (dmarc is not None and dmarc.p_absent):
            # Both readings deliver forged mail, for different reasons: say both
            # (review S4), in a clause that speaks for RFC 7489 only (third pass).
            # An absent p already states both readings in the first clause.
            reason += "; and " + _rfc7489_only_reason(dmarc7489, p7)
        reasons.append(reason)
    elif open9 or open7:
        hedged = True
        reasons.append(_dual_reason(dmarc, p9, p7, dmarc7489))
    if inherited and not reasons and discovery is not None and discovery.rfc7489_may_differ:
        # Enforced under RFC 9989, but an RFC 7489 receiver can be shown to
        # choose differently (a psd tag, several ancestors, or a TLD record):
        # it may find no record at all (review B5).
        hedged = True
        reasons.append(
            f"the policy that applies is inherited from _dmarc.{discovery.source} by RFC 9989's "
            "tree walk, but an RFC 7489 receiver, which finds the organizational domain with a "
            "Public Suffix List and does not know psd=, may apply a different record or none"
        )
    elif inherited and reasons and discovery is not None:
        # A policy from an ancestor: RFC 9989's walk applies it, and an RFC
        # 7489 receiver's Public Suffix List may choose another record.
        hedged = True
        reasons[-1] += (
            f" (the record that applies is inherited from _dmarc.{discovery.source} by RFC "
            "9989's tree walk; an RFC 7489 receiver may choose differently)"
        )
    posture = p9 if open9 else p7

    plus_all = spf is not None and spf.all_qualifier == "+"
    if spf is None and posture not in ENFORCED:
        # No SPF gives None, never an aligned pass, so under an enforced
        # policy forged mail fails DMARC (RFC 7489 3.1.2, 6.6.2). It adds to
        # a DMARC reason; it is never one on its own.
        reasons.append("no SPF record identifies which servers may send for the domain")
    elif plus_all:
        # '+all' is the one SPF setting that defeats an enforced DMARC policy:
        # a forger who uses this domain in the envelope gets an aligned pass.
        # '?all' (Neutral) and '~all' (SoftFail) are not passes, so they add
        # nothing a missing or unenforced DMARC policy has not already said.
        reasons.append(
            "the SPF policy ends in '+all', an explicit pass for any sending server, which "
            "DMARC counts as authentication"
        )
    # Only '+all' defeats DMARC by itself. Every other reason depends on the
    # DMARC record not being applied, so it cannot firm up a hedged one.
    only_hedge = hedged and not plus_all
    return reasons, only_hedge


def _dmarc_is_invalid(answer: DnsResponse) -> bool:
    record = _parse_dmarc_answer(answer)
    return record is not None and not record.valid


def _dmarc_pct(answer: DnsResponse) -> int:
    record = _parse_dmarc_answer(answer)
    return record.pct if record else 100


def _dmarc_rua(answer: DnsResponse) -> list[str]:
    record = _parse_dmarc_answer(answer)
    return record.rua if record else []


def _dmarc_relaxed(answer: DnsResponse) -> bool:
    record = _parse_dmarc_answer(answer)
    return record is not None and (record.adkim == "r" or record.aspf == "r")


def _dkim_bits_below(answer: DnsResponse, minimum: int) -> bool:
    for record in answer.records:
        parsed = parse_dkim_key(record)
        if parsed.key_type == "rsa" and parsed.key_bits is not None:
            return parsed.key_bits < minimum
    return False


@dataclass(frozen=True)
class _DkimKey:
    selector: str
    answer: DnsResponse
    record: DkimKeyRecord

    def to_dict(self) -> dict[str, Any]:
        return {"selector": self.selector, **self.record.to_dict()}


def _names(keys: list[_DkimKey], domain: str) -> str:
    return ", ".join(f"{k.selector}._domainkey.{domain}" for k in keys)


def _spf_records(answer: DnsResponse) -> list[str]:
    return [r for r in answer.records if r.strip().lower().startswith("v=spf1")]


def _has_spf(answer: DnsResponse) -> bool:
    return bool(_spf_records(answer))


def _parse_first_spf(answer: DnsResponse) -> SpfRecord:
    records = _spf_records(answer)
    return parse_spf(records[0]) if records else parse_spf("")


def _has_dmarc(answer: DnsResponse) -> bool:
    return any(r.strip().lower().startswith("v=dmarc1") for r in answer.records)


def _dmarc_policy_is_none(answer: DnsResponse) -> bool:
    record = _parse_dmarc_answer(answer)
    return record is not None and record.policy == "none"


def _parse_dmarc_answer(answer: DnsResponse) -> DmarcRecord | None:
    """The record at this name that a finding is about.

    Records with an exact v=DMARC1 are the only ones that count (review B1):
    exactly one is that record, and more than one are all discarded (None).
    With none, a single record whose version is wrong is returned so that it
    can be reported as ignored.
    """
    exact = exact_records(answer)
    if exact:
        return parse_dmarc(exact[0]) if len(exact) == 1 else None
    candidates = [r for r in answer.records if is_dmarc_candidate(r)]
    return parse_dmarc(candidates[0]) if len(candidates) == 1 else None


def _is_null_mx(answer: DnsResponse) -> bool:
    """RFC 7505: a single 'MX 0 .' says the domain handles no mail, deliberately."""
    records = [r.strip() for r in answer.records]
    return len(records) == 1 and records[0].split()[-1] in (".", "0 .")


def _chain_summary(chain: SpfChain) -> str:
    parts = [
        f"{step.domain} ({step.record.direct_lookup_count()})"
        for step in chain.steps
        if step.record is not None
    ]
    return "The chain is: " + " -> ".join(parts) + "."
