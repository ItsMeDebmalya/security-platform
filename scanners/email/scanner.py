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

from dataclasses import replace
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
from scanners.email.dkim import DkimKeyRecord, parse_dkim_key
from scanners.email.dmarc import DmarcRecord, parse_dmarc
from scanners.email.spf import (
    MAX_DNS_LOOKUPS,
    SpfChain,
    SpfRecord,
    fetch_spf,
    parse_spf,
    resolve_spf_chain,
)

MIN_DKIM_BITS = 2048
NO_VERDICT_FOR_RCODE = {
    "SERVFAIL": "servfail",
    "TIMEOUT": "timeout",
    "REFUSED": "blocked_prerequisite",
}


@register
class EmailScanner(BaseScanner):
    name = "email"
    version = "1.0.0"
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

    # --- orchestration ------------------------------------------------------

    def execute(self) -> ScanResult:
        self.ctx.progress("checking the zone for wildcards", 0.05)
        self.ctx.check_alive()
        self.txt_wildcard = self.dns.has_wildcard(self.domain, "TXT")
        self.txt_wildcard_probe = self.dns.wildcard_probe(self.domain, "TXT")

        self.ctx.progress("reading SPF, DMARC and MX", 0.25)
        self.ctx.check_alive()
        self.spf = fetch_spf(self.domain, self.dns)
        self.dmarc_answer = self.dns.query(f"_dmarc.{self.domain}", "TXT")
        self.dmarc = _parse_dmarc_answer(self.dmarc_answer)
        self.mx_answer = self.dns.query(self.domain, "MX")

        self.ctx.progress("looking for DKIM selectors", 0.5)
        self.ctx.check_alive()
        self.dkim_selector, self.dkim_answer, self.dkim = self._find_dkim()

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
                    "domain, so a message forged from any server passes SPF by default."
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

    def _check_spf_standard(self) -> None:
        record = self.spf.record
        if record is None or self.chain is None:
            self._not_applicable("spf-too-permissive")
            self._not_applicable("spf-lookup-limit")
            return

        qualifier = record.all_qualifier
        if qualifier in ("+", "?"):
            self._report(
                "spf-too-permissive",
                self.spf.answer,
                description=(
                    f"The SPF record ends in '{qualifier}all', which tells receivers that mail "
                    "from any server is acceptable"
                    + (" (neutral)." if qualifier == "?" else " (explicit pass).")
                ),
                impact=(
                    "SPF passes for every sender on the internet, so the record provides no "
                    "protection while appearing to."
                ),
                remediation=(
                    f"Change '{qualifier}all' to '-all' once every legitimate sender is listed, "
                    "or to '~all' while you are still confirming that."
                ),
                validates=lambda answer: _parse_first_spf(answer).all_qualifier in ("+", "?"),
            )
        else:
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
        if not self.dmarc_answer.is_definite():
            self._inconclusive(
                "dmarc-missing",
                self.dmarc_answer,
                f"The TXT lookup for _dmarc.{self.domain} returned "
                f"{self.dmarc_answer.rcode}, so we cannot say whether a DMARC record exists.",
            )
            self._not_applicable("dmarc-invalid")
            self._not_applicable("dmarc-policy-none")
            return

        if self.dmarc is None:
            self._report(
                "dmarc-missing",
                self.dmarc_answer,
                description=f"No DMARC record is published at _dmarc.{self.domain}.",
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
                validates=lambda answer: not _has_dmarc(answer),
            )
            self._not_applicable("dmarc-invalid")
            self._not_applicable("dmarc-policy-none")
            return

        self._clear("dmarc-missing")

        if not self.dmarc.valid:
            self._report(
                "dmarc-invalid",
                self.dmarc_answer,
                description=(
                    f"The DMARC record at _dmarc.{self.domain} is not valid: "
                    f"{'; '.join(self.dmarc.errors)}. Receivers ignore a record like this "
                    "entirely, so the domain is unprotected despite appearing configured."
                ),
                impact=(
                    "The domain has the appearance of DMARC protection and none of the effect."
                ),
                remediation=(
                    "Rewrite the record so it begins 'v=DMARC1; p=<policy>;' - the version tag "
                    "must come first and the policy tag must immediately follow it. Other tags "
                    "may follow in any order."
                ),
                analysis={"dmarc": self.dmarc.to_dict()},
                validates=lambda answer: _dmarc_is_invalid(answer),
            )
            self._not_applicable("dmarc-policy-none")
            return

        self._clear("dmarc-invalid")

        if self.dmarc.policy == "none":
            self._report(
                "dmarc-policy-none",
                self.dmarc_answer,
                description=(
                    f"The DMARC policy for {self.domain} is p=none, which asks receivers to "
                    "take no action on mail that fails authentication."
                ),
                impact=(
                    "Mail forged as this domain is still delivered. p=none is a monitoring "
                    "posture, useful while you find your legitimate senders, but it stops "
                    "nothing."
                ),
                remediation=(
                    "Once your rua reports show every legitimate sender passing, change p=none "
                    "to p=quarantine, then to p=reject. Move in that order and watch the "
                    "reports at each step."
                ),
                validates=_dmarc_policy_is_none,
            )
        else:
            self._clear("dmarc-policy-none")

    def _check_dmarc_standard(self) -> None:
        if self.dmarc is None or not self.dmarc.valid:
            for check_id in ("dmarc-pct-partial", "dmarc-no-rua", "dmarc-alignment"):
                self._not_applicable(check_id)
            return

        if self.dmarc.pct < 100:
            self._report(
                "dmarc-pct-partial",
                self.dmarc_answer,
                description=(
                    f"The DMARC policy applies to {self.dmarc.pct}% of failing mail (pct="
                    f"{self.dmarc.pct}). The other {100 - self.dmarc.pct}% is delivered as if "
                    "the policy were p=none."
                ),
                impact=(
                    "An attacker sending repeatedly gets through on the unprotected fraction. "
                    "A partial rollout is a step, not a destination."
                ),
                remediation=(
                    "Raise pct in stages - 25, 50, then 100 - watching your rua reports at each "
                    "step, and remove the tag entirely once you reach 100."
                ),
                validates=lambda answer: _dmarc_pct(answer) < 100,
            )
        else:
            self._clear("dmarc-pct-partial")

        if not self.dmarc.rua:
            self._report(
                "dmarc-no-rua",
                self.dmarc_answer,
                description=(
                    "The DMARC record has no rua= tag, so no aggregate reports are sent anywhere."
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
            )
        else:
            self._clear("dmarc-no-rua")

        if self.dmarc.adkim == "r" or self.dmarc.aspf == "r":
            self._report(
                "dmarc-alignment",
                self.dmarc_answer,
                description=(
                    f"DMARC alignment is relaxed (adkim={self.dmarc.adkim}, "
                    f"aspf={self.dmarc.aspf}). Relaxed alignment accepts any subdomain of "
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
            self.dmarc is not None
            and self.dmarc.valid
            and self.dmarc.policy in ("quarantine", "reject")
        )

    def _report_missing_mx(self) -> None:
        if self._email_is_deliberately_configured():
            spf_text = self.spf.record.raw if self.spf.record else "no SPF record"
            policy = self.dmarc.policy if self.dmarc else ""
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

    def _find_dkim(self) -> tuple[str | None, DnsResponse | None, DkimKeyRecord | None]:
        for selector in COMMON_SELECTORS:
            self.ctx.check_alive()
            answer = self.dns.query(f"{selector}._domainkey.{self.domain}", "TXT")
            if not answer.is_definite():
                continue
            for record in answer.records:
                if ("p=" in record and "k=" in record) or record.lower().startswith("v=dkim1"):
                    return selector, answer, parse_dkim_key(record)
        return None, None, None

    def _check_dkim(self) -> None:
        if self.dkim is not None:
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
        if self.dkim is None or self.dkim_answer is None:
            self._not_applicable("dkim-weak-key")
            return

        bits = self.dkim.key_bits
        if bits is None:
            self._inconclusive(
                "dkim-weak-key",
                self.dkim_answer,
                f"The DKIM key at {self.dkim_selector}._domainkey.{self.domain} could not be "
                "decoded, so its strength could not be measured. We do not report an "
                "unmeasurable key as a weak one.",
            )
            return

        if bits < MIN_DKIM_BITS:
            self._report(
                "dkim-weak-key",
                self.dkim_answer,
                description=(
                    f"The DKIM key published at {self.dkim_selector}._domainkey.{self.domain} "
                    f"is {bits} bits. RFC 8301 requires signers to use at least 1024 bits and "
                    f"recommends {MIN_DKIM_BITS}."
                ),
                impact=(
                    "A key this size is within reach of a well-resourced attacker, who could "
                    "then forge signed mail that passes DKIM and DMARC."
                ),
                remediation=(
                    f"Generate a new {MIN_DKIM_BITS}-bit key with your mail provider, publish "
                    "it under a new selector, switch signing to it, and remove the old selector "
                    "once no mail is signed with it."
                ),
                analysis={"dkim": self.dkim.to_dict()},
                validates=lambda answer: _dkim_bits_below(answer, MIN_DKIM_BITS),
            )
        else:
            self._clear("dkim-weak-key")

    # --- transport security -------------------------------------------------

    def _check_transport_security(self) -> None:
        self._presence_check(
            "mta-sts-missing",
            f"_mta-sts.{self.domain}",
            "v=STSv1",
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
        self._report(
            check_id,
            answer,
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
        if not self.dmarc_answer.is_definite() or not self.spf.definite:
            self._inconclusive(
                "spoofing-possible",
                self.dmarc_answer,
                "The published policy could not be read in full, so the receiver's decision "
                "cannot be simulated.",
            )
            return

        reasons = _spoofing_reasons(self.dmarc, self.spf.record)

        if not reasons:
            self._clear("spoofing-possible")
            return

        self._report(
            "spoofing-possible",
            self.dmarc_answer,
            description=(
                "Simulating the decision a receiving mail server would make for a message "
                f"forged from {self.domain}: it would be delivered, because "
                + "; and ".join(reasons)
                + "."
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

    def _still_spoofable(self, answer: DnsResponse) -> bool:
        """Re-run the receiver simulation on the second resolver's DMARC answer."""
        return bool(_spoofing_reasons(_parse_dmarc_answer(answer), self.spf.record))

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
    ) -> None:
        check = CHECKS[check_id]
        if severity is not None or title is not None:
            # Severity is "how bad if true", and that genuinely differs with
            # context for some checks. Overriding it here keeps the reasoning
            # next to the evidence for it rather than in a lookup table.
            check = replace(check, severity=severity or check.severity, title=title or check.title)
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
    ) -> None:
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
        agreed = bool(predicate(confirmation))
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
    "dmarc-missing": ["https://www.rfc-editor.org/rfc/rfc7489"],
    "dmarc-invalid": ["https://www.rfc-editor.org/rfc/rfc7489#section-6.3"],
    "dmarc-policy-none": ["https://www.rfc-editor.org/rfc/rfc7489#section-6.3"],
    "dmarc-pct-partial": ["https://www.rfc-editor.org/rfc/rfc7489#section-6.3"],
    "dmarc-no-rua": ["https://www.rfc-editor.org/rfc/rfc7489#section-7"],
    "dmarc-alignment": ["https://www.rfc-editor.org/rfc/rfc7489#section-3.1"],
    "mx-missing": ["https://www.rfc-editor.org/rfc/rfc7505"],
    "dkim-missing": ["https://www.rfc-editor.org/rfc/rfc6376"],
    "dkim-weak-key": ["https://www.rfc-editor.org/rfc/rfc8301"],
    "mta-sts-missing": ["https://www.rfc-editor.org/rfc/rfc8461"],
    "tls-rpt-missing": ["https://www.rfc-editor.org/rfc/rfc8460"],
    "spoofing-possible": ["https://www.rfc-editor.org/rfc/rfc7489"],
}


def _spoofing_reasons(dmarc: DmarcRecord | None, spf: SpfRecord | None) -> list[str]:
    """Why a receiving mail server would deliver a forged message.

    Extracted so that validation can re-run exactly the same reasoning against
    an independently fetched record, rather than re-checking a weaker proxy.
    """
    reasons: list[str] = []
    if dmarc is None:
        reasons.append(
            "there is no DMARC record, so a receiver has no instruction to reject mail "
            "that fails authentication"
        )
    elif not dmarc.valid:
        reasons.append(
            "the DMARC record is malformed and receivers ignore it, which leaves the "
            "domain in the same position as having none"
        )
    elif dmarc.policy == "none":
        reasons.append("the DMARC policy is p=none, which asks receivers to take no action")
    elif dmarc.pct < 100:
        reasons.append(
            f"the DMARC policy is applied to only {dmarc.pct}% of failing mail, so "
            f"roughly {100 - dmarc.pct}% of forged messages are delivered anyway"
        )

    if spf is None:
        reasons.append("no SPF record identifies which servers may send for the domain")
    elif spf.all_qualifier in ("+", "?"):
        reasons.append(
            f"the SPF policy ends in '{spf.all_qualifier}all', which accepts any sending server"
        )
    return reasons


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
        if parsed.key_bits is not None:
            return parsed.key_bits < minimum
    return False


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
    for record in answer.records:
        if record.strip().lower().startswith("v=dmarc1"):
            return parse_dmarc(record)
    return None


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
