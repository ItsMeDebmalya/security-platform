"""The Email Security Scanner. Every check gets a positive and a negative case."""

from __future__ import annotations

import pytest

from tests.scanners.email.conftest import (
    ED25519_P,
    RSA_512_P,
    RSA_1024_P,
    RSA_2048_P,
    answer,
    zone,
)

GOOD = dict(
    spf="v=spf1 include:_spf.example.net -all",
    dmarc="v=DMARC1; p=reject; rua=mailto:dmarc@good.example; adkim=s; aspf=s",
    dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_2048_P}"},
    mta_sts="v=STSv1; id=20260822T000000;",
    tls_rpt="v=TLSRPTv1; rua=mailto:tls@good.example",
)


def good_zone(domain="good.example", **overrides):
    settings = {**GOOD, **overrides}
    answers = zone(domain, **settings)
    answers[("_spf.example.net", "TXT")] = answer(
        "_spf.example.net", "TXT", "v=spf1 ip4:192.0.2.0/24 -all"
    )
    return answers


# --- the known-good baseline ------------------------------------------------


def test_a_correctly_configured_domain_produces_no_findings(run_scan):
    result = run_scan("good.example", good_zone(), mode="standard")

    reported = [f for f in result.findings if f.state in ("confirmed", "highly_likely")]
    assert reported == [], [(f.check_id, f.title) for f in reported]


def test_a_correctly_configured_domain_still_records_every_check_that_ran(run_scan):
    result = run_scan("good.example", good_zone(), mode="standard")

    assert len(result.telemetry.checks_run) >= 10


def test_light_mode_runs_fewer_checks_than_standard(run_scan):
    light = run_scan("good.example", good_zone(), mode="light")
    standard = run_scan("good.example", good_zone(), mode="standard")

    assert len(light.telemetry.checks_run) < len(standard.telemetry.checks_run)


def test_standard_mode_returns_everything_light_returns(run_scan):
    """Modes are additive: never a different answer for the same check."""
    light = run_scan("bad.example", zone("bad.example", spf=None, dmarc=None), mode="light")
    standard = run_scan("bad.example", zone("bad.example", spf=None, dmarc=None), mode="standard")

    light_checks = {c.check_id for c in light.telemetry.checks_run}
    standard_checks = {c.check_id for c in standard.telemetry.checks_run}
    assert light_checks <= standard_checks


# --- spf-missing / spf-invalid ---------------------------------------------


def test_a_domain_with_no_spf_record_is_reported(findings_for):
    found = findings_for("bad.example", zone("bad.example", spf=None), "spf-missing")

    assert found and found[0].state == "confirmed"


def test_a_domain_with_an_spf_record_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "spf-missing") == []


def test_a_syntactically_broken_spf_record_is_reported(findings_for):
    found = findings_for(
        "bad.example", zone("bad.example", spf="v=spf1 frobnicate:x -all"), "spf-invalid"
    )

    assert found
    assert "frobnicate" in found[0].description


def test_a_valid_spf_record_is_not_reported_as_invalid(findings_for):
    assert findings_for("good.example", good_zone(), "spf-invalid") == []


def test_two_spf_records_at_one_name_is_reported_as_a_misconfiguration(findings_for):
    answers = zone("bad.example", spf="v=spf1 -all", extra_txt=["v=spf1 include:a.example ~all"])

    found = findings_for("bad.example", answers, "spf-multiple-records")

    assert found


# --- spf-too-permissive -----------------------------------------------------


@pytest.mark.parametrize("policy", ["+all", "?all"])
def test_a_permissive_spf_policy_is_reported(findings_for, policy):
    answers = zone("bad.example", spf=f"v=spf1 ip4:192.0.2.0/24 {policy}")

    found = findings_for("bad.example", answers, "spf-too-permissive", mode="standard")

    assert found


@pytest.mark.parametrize("policy", ["-all", "~all"])
def test_a_restrictive_spf_policy_is_not_reported(findings_for, policy):
    answers = zone("ok.example", spf=f"v=spf1 ip4:192.0.2.0/24 {policy}")

    assert findings_for("ok.example", answers, "spf-too-permissive", mode="standard") == []


# --- spf-lookup-limit -------------------------------------------------------


def test_an_spf_chain_over_ten_lookups_is_reported(findings_for):
    answers = zone(
        "bad.example",
        spf="v=spf1 " + " ".join(f"include:i{i}.example" for i in range(6)) + " -all",
    )
    for i in range(6):
        answers[(f"i{i}.example", "TXT")] = answer(f"i{i}.example", "TXT", "v=spf1 a -all")

    found = findings_for("bad.example", answers, "spf-lookup-limit", mode="standard")

    assert found
    assert "12" in found[0].description


def test_an_spf_chain_full_of_ip4_terms_is_not_reported(findings_for):
    """Counting ip4 terms is the classic bug; this is the case that catches it."""
    answers = zone(
        "ok.example",
        spf="v=spf1 " + " ".join(f"ip4:192.0.2.{i}" for i in range(20)) + " -all",
    )

    assert findings_for("ok.example", answers, "spf-lookup-limit", mode="standard") == []


def test_a_chain_that_could_not_be_counted_is_inconclusive(findings_for):
    answers = zone("broken.example", spf="v=spf1 include:a.example -all")
    answers[("a.example", "TXT")] = answer("a.example", "TXT", rcode="SERVFAIL")

    found = findings_for("broken.example", answers, "spf-lookup-limit", mode="standard")

    assert found and found[0].state == "inconclusive"


# --- dmarc ------------------------------------------------------------------


def test_a_domain_with_no_dmarc_record_is_reported(findings_for):
    found = findings_for("bad.example", zone("bad.example", dmarc=None), "dmarc-missing")

    assert found and found[0].severity in ("high", "medium")


def test_a_domain_with_a_dmarc_record_is_not_reported_as_missing(findings_for):
    assert findings_for("good.example", good_zone(), "dmarc-missing") == []


def test_a_monitoring_only_dmarc_policy_is_reported(findings_for):
    answers = zone("bad.example", dmarc="v=DMARC1; p=none; rua=mailto:d@bad.example")

    found = findings_for("bad.example", answers, "dmarc-policy-none")

    assert found


def test_an_enforcing_dmarc_policy_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "dmarc-policy-none") == []


def test_a_partial_dmarc_rollout_is_reported(findings_for):
    answers = zone("bad.example", dmarc="v=DMARC1; p=reject; pct=20; rua=mailto:d@bad.example")

    found = findings_for("bad.example", answers, "dmarc-pct-partial", mode="standard")

    assert found and "20" in found[0].description


def test_a_full_rollout_is_not_reported_as_partial(findings_for):
    assert findings_for("good.example", good_zone(), "dmarc-pct-partial", mode="standard") == []


def test_a_dmarc_record_with_no_reporting_address_is_reported(findings_for):
    answers = zone("bad.example", dmarc="v=DMARC1; p=reject")

    assert findings_for("bad.example", answers, "dmarc-no-rua", mode="standard")


def test_a_dmarc_record_with_a_reporting_address_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "dmarc-no-rua", mode="standard") == []


def test_relaxed_alignment_is_reported_as_informational(findings_for):
    answers = zone("relaxed.example", dmarc="v=DMARC1; p=reject; rua=mailto:d@relaxed.example")

    found = findings_for("relaxed.example", answers, "dmarc-alignment", mode="standard")

    assert found and found[0].state == "informational"


def test_strict_alignment_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "dmarc-alignment", mode="standard") == []


def test_a_dmarc_record_receivers_would_ignore_is_reported_as_invalid(findings_for):
    """p must immediately follow v, or the record does not count at all."""
    answers = zone("bad.example", dmarc="v=DMARC1; rua=mailto:d@bad.example; p=reject")

    assert findings_for("bad.example", answers, "dmarc-invalid")


# --- mx ---------------------------------------------------------------------


def test_a_domain_with_no_mx_records_is_reported(findings_for):
    found = findings_for("bad.example", zone("bad.example", mx=()), "mx-missing")

    assert found


def test_a_domain_with_mx_records_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "mx-missing") == []


def test_a_null_mx_is_recognised_as_deliberate(findings_for):
    """RFC 7505: 'MX 0 .' says this domain sends and receives no mail."""
    answers = zone(
        "nomail.example",
        mx=("0 .",),
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:d@nomail.example",
    )

    assert findings_for("nomail.example", answers, "mx-missing") == []


# --- dkim -------------------------------------------------------------------


def test_a_weak_dkim_key_is_reported(findings_for):
    answers = good_zone("weak.example", dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_1024_P}"})

    found = findings_for("weak.example", answers, "dkim-weak-key", mode="standard")

    assert found and "1024" in found[0].description


def test_a_strong_dkim_key_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "dkim-weak-key", mode="standard") == []


def test_no_discoverable_dkim_selector_is_inconclusive_not_missing(findings_for):
    """DKIM selectors are arbitrary and cannot be enumerated. Reporting 'no
    DKIM' from a failed guess would be a false positive by construction."""
    answers = good_zone("nodkim.example", dkim={})

    found = findings_for("nodkim.example", answers, "dkim-missing")

    assert found and found[0].state == "inconclusive"


def test_a_discoverable_selector_clears_the_check(findings_for):
    assert findings_for("good.example", good_zone(), "dkim-missing") == []


# --- mta-sts and tls-rpt ----------------------------------------------------


def test_a_domain_with_no_mta_sts_record_is_reported(findings_for):
    answers = good_zone("nomtasts.example", mta_sts=None)

    assert findings_for("nomtasts.example", answers, "mta-sts-missing", mode="standard")


def test_a_domain_with_mta_sts_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "mta-sts-missing", mode="standard") == []


def test_a_domain_with_no_tls_reporting_is_reported(findings_for):
    answers = good_zone("notlsrpt.example", tls_rpt=None)

    assert findings_for("notlsrpt.example", answers, "tls-rpt-missing", mode="standard")


def test_a_domain_with_tls_reporting_is_not_reported(findings_for):
    assert findings_for("good.example", good_zone(), "tls-rpt-missing", mode="standard") == []


# --- the summary verdict ----------------------------------------------------


def test_a_domain_with_nothing_configured_can_be_spoofed(findings_for):
    answers = zone("bad.example", spf=None, dmarc=None)

    found = findings_for("bad.example", answers, "spoofing-possible")

    assert found and found[0].severity == "high"


def test_a_domain_with_dmarc_none_can_still_be_spoofed(findings_for):
    answers = zone("bad.example", spf="v=spf1 -all", dmarc="v=DMARC1; p=none")

    assert findings_for("bad.example", answers, "spoofing-possible")


def test_a_domain_with_an_enforcing_policy_cannot_be_spoofed(findings_for):
    assert findings_for("good.example", good_zone(), "spoofing-possible") == []


def test_a_partial_rollout_is_still_spoofable(findings_for):
    answers = good_zone(
        "partial.example", dmarc="v=DMARC1; p=reject; pct=10; rua=mailto:d@x.example"
    )

    assert findings_for("partial.example", answers, "spoofing-possible")


def test_the_spoofing_verdict_explains_the_receiver_decision_it_simulated(findings_for):
    answers = zone("bad.example", spf=None, dmarc=None)

    found = findings_for("bad.example", answers, "spoofing-possible")

    assert found[0].evidence[-1].kind == "dns_answer"
    assert "receiv" in found[0].description.lower()


# --- honesty under failure --------------------------------------------------


def test_a_servfail_on_the_dmarc_lookup_is_inconclusive_not_missing(findings_for):
    answers = good_zone("broken.example")
    answers[("_dmarc.broken.example", "TXT")] = answer(
        "_dmarc.broken.example", "TXT", rcode="SERVFAIL"
    )

    found = findings_for("broken.example", answers, "dmarc-missing")

    assert found and found[0].state == "inconclusive"


def test_a_wildcarded_zone_makes_presence_based_checks_inconclusive(run_scan):
    """A TXT wildcard makes every _dmarc and _domainkey lookup appear to
    succeed. Absence is still knowable - a real record would win over the
    wildcard - but nothing may be concluded from a record appearing to exist."""

    class Wildcard:
        def resolve(self, name, rrtype, resolver=None):
            if rrtype == "TXT":
                return answer(name, "TXT", "some-unrelated-token")
            return answer(name, "MX", "10 mx1.example.net.")

    from core.context import ScanContext
    from core.dns import DnsClient
    from core.models import Asset
    from scanners.email import EmailScanner

    ctx = ScanContext(dns=DnsClient(resolver=Wildcard(), resolvers=["1.1.1.1", "8.8.8.8"]))
    result = EmailScanner().run(Asset(type="domain", value="wild.example"), "light", ctx)

    by_check = {f.check_id: f for f in result.findings}
    assert by_check["dkim-missing"].state == "inconclusive"
    assert "wildcard" in by_check["dkim-missing"].description.lower()


def test_a_wildcarded_zone_can_still_report_an_absent_record(run_scan):
    """A wildcard cannot mask a record that exists: a real answer wins over it.
    Downgrading absence findings too would cost recall for no honesty gained."""

    class Wildcard:
        def resolve(self, name, rrtype, resolver=None):
            if rrtype == "TXT":
                return answer(name, "TXT", "some-unrelated-token")
            return answer(name, "MX", "10 mx1.example.net.")

    from core.context import ScanContext
    from core.dns import DnsClient
    from core.models import Asset
    from scanners.email import EmailScanner

    ctx = ScanContext(dns=DnsClient(resolver=Wildcard(), resolvers=["1.1.1.1", "8.8.8.8"]))
    result = EmailScanner().run(Asset(type="domain", value="wild.example"), "light", ctx)

    spf = next(f for f in result.findings if f.check_id == "spf-missing")
    assert spf.state == "confirmed"


def test_every_finding_carries_a_control_alongside_its_test(run_scan):
    result = run_scan("bad.example", zone("bad.example", spf=None, dmarc=None), mode="standard")

    for finding in result.findings:
        assert any(e.has_control() for e in finding.evidence), finding.check_id


def test_every_finding_declares_a_justified_prior(run_scan):
    result = run_scan("bad.example", zone("bad.example", spf=None, dmarc=None), mode="standard")

    for finding in result.findings:
        for method in finding.detection_methods:
            assert method.prior_justification, finding.check_id


def test_every_finding_has_actionable_remediation(run_scan):
    result = run_scan("bad.example", zone("bad.example", spf=None, dmarc=None), mode="standard")

    for finding in result.findings:
        assert len(finding.remediation) > 40, finding.check_id


def test_the_result_validates_against_the_frozen_schema(run_scan):
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    contracts = Path(__file__).resolve().parents[3] / "contracts"
    registry = Registry()
    schemas = {}
    for path in contracts.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        schemas[path.name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    result = run_scan("bad.example", zone("bad.example", spf=None, dmarc=None), mode="standard")

    Draft202012Validator(schemas["scanresult.schema.json"], registry=registry).validate(
        json.loads(result.model_dump_json())
    )


# --- the parse tree is part of the evidence ---------------------------------


def test_an_invalid_spf_finding_shows_the_parse_tree(findings_for):
    found = findings_for(
        "bad.example", zone("bad.example", spf="v=spf1 frobnicate:x -all"), "spf-invalid"
    )

    assert found[0].evidence[0].analysis["spf"]["errors"]


def test_a_lookup_limit_finding_shows_the_resolved_chain_and_its_count(findings_for):
    answers = zone(
        "bad.example",
        spf="v=spf1 " + " ".join(f"include:i{i}.example" for i in range(6)) + " -all",
    )
    for i in range(6):
        answers[(f"i{i}.example", "TXT")] = answer(f"i{i}.example", "TXT", "v=spf1 a -all")

    found = findings_for("bad.example", answers, "spf-lookup-limit", mode="standard")
    chain = found[0].evidence[0].analysis["spf_chain"]

    assert chain["total_lookups"] == 12
    assert chain["steps"][0]["domain"] == "bad.example"


def test_a_check_that_could_not_run_is_not_claimed_to_have_run(run_scan):
    """dmarc-pct-partial on a domain with no DMARC record has nothing to
    evaluate. Claiming it was 'clear' would say we checked and found nothing."""
    result = run_scan("bad.example", zone("bad.example", dmarc=None), mode="standard")

    ran = {c.check_id for c in result.telemetry.checks_run}
    assert "dmarc-missing" in ran
    assert "dmarc-pct-partial" not in ran


# --- severity reflects how bad it would be, in context ----------------------


def test_a_domain_with_no_mx_and_no_no_mail_posture_is_a_medium_finding(findings_for):
    """Mail addressed here is simply undeliverable."""
    answers = zone(
        "bad.example", mx=(), spf="v=spf1 include:_spf.x.example ~all", dmarc="v=DMARC1; p=none"
    )

    found = findings_for("bad.example", answers, "mx-missing")

    assert found[0].severity == "medium"


def test_a_domain_that_clearly_sends_no_mail_gets_a_low_severity_nudge(findings_for):
    """SPF -all plus an enforcing DMARC policy is a domain saying it sends no
    mail. The only thing missing is saying so to receivers, with a null MX."""
    answers = zone(
        "nomail.example",
        mx=(),
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:d@nomail.example",
    )

    found = findings_for("nomail.example", answers, "mx-missing")

    assert found[0].severity == "low"
    assert "null MX" in found[0].remediation


def test_the_low_severity_variant_says_what_it_inferred(findings_for):
    answers = zone(
        "nomail.example",
        mx=(),
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:d@nomail.example",
    )

    found = findings_for("nomail.example", answers, "mx-missing")

    assert "-all" in found[0].description


# --- a finding must never quote a record the domain did not publish ---------


def test_the_no_mail_description_quotes_the_real_spf_record(findings_for):
    """Found live against jpmorganchase.com: the description asserted
    "Its SPF record is 'v=spf1 -all'" for a domain whose SPF actually lists
    nine sending ranges. Putting words in a target's mouth is worse than
    reporting nothing."""
    spf = "v=spf1 a:spf.example.net ip4:192.0.2.0/24 -all"
    answers = zone(
        "sender.example",
        mx=(),
        spf=spf,
        dmarc="v=DMARC1; p=reject; rua=mailto:d@sender.example",
    )

    found = findings_for("sender.example", answers, "mx-missing")

    assert "v=spf1 -all" not in found[0].description
    assert spf in found[0].description


def test_a_domain_that_authorises_senders_is_not_called_a_no_mail_domain(findings_for):
    """`-all` at the end does not mean 'sends nothing'. It means 'nothing
    except what I just listed'."""
    answers = zone(
        "sender.example",
        mx=(),
        spf="v=spf1 ip4:192.0.2.0/24 -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:d@sender.example",
    )

    found = findings_for("sender.example", answers, "mx-missing")

    assert "sends no mail" not in found[0].description


def test_a_genuinely_silent_domain_is_still_recognised(findings_for):
    """A bare `v=spf1 -all` authorises nobody. That one really does send nothing."""
    answers = zone(
        "silent.example",
        mx=(),
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:d@silent.example",
    )

    found = findings_for("silent.example", answers, "mx-missing")

    assert found[0].severity == "low"
    assert "null MX" in found[0].remediation


def test_a_configured_domain_missing_only_its_mx_is_a_low_finding(findings_for):
    """An enforcing DMARC policy is evidence someone thought about email here.
    The missing MX is then an omission, not a broken setup."""
    answers = zone(
        "sender.example",
        mx=(),
        spf="v=spf1 ip4:192.0.2.0/24 -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:d@sender.example",
    )

    assert findings_for("sender.example", answers, "mx-missing")[0].severity == "low"


def test_an_unconfigured_domain_missing_its_mx_is_a_medium_finding(findings_for):
    answers = zone("broken.example", mx=(), spf=None, dmarc=None)

    assert findings_for("broken.example", answers, "mx-missing")[0].severity == "medium"


# --- claim defects found before the live re-verification (2026-10-08) -------
#
# Each of these is a finding that said more than the evidence or the spec
# supports. The rule: never assert what other people's software does unless a
# spec says it.


def test_a_neutral_all_is_described_as_neutral_not_as_accepting_any_sender(findings_for):
    """RFC 7208 2.6.2 and 8.2: '?' asserts nothing, and receivers MUST treat a
    neutral result exactly like having no SPF policy. It does not say mail
    from any server is acceptable."""
    answers = zone("neutral.example", spf="v=spf1 ip4:192.0.2.0/24 ?all")

    [found] = findings_for("neutral.example", answers, "spf-too-permissive", mode="standard")

    assert "neutral" in found.description.lower()
    assert "RFC 7208" in found.description
    assert "no SPF policy" in found.description
    assert "acceptable" not in found.description
    assert "any sender" not in found.title.lower()
    assert "accepts any" not in found.impact and "passes for every" not in found.impact


def test_an_explicit_pass_all_still_says_it_passes_any_sender(findings_for):
    answers = zone("plus.example", spf="v=spf1 ip4:192.0.2.0/24 +all")

    [found] = findings_for("plus.example", answers, "spf-too-permissive", mode="standard")

    assert "explicit pass" in found.description
    assert found.title == "SPF policy permits any sender"


def test_a_1024_bit_dkim_key_is_low_and_says_it_meets_the_minimum(findings_for):
    """RFC 8301 3.1: signers MUST use at least 1024 bits and SHOULD use 2048.
    Rating it medium while calling it compliant contradicted itself."""
    answers = good_zone("weak.example", dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_1024_P}"})

    [found] = findings_for("weak.example", answers, "dkim-weak-key", mode="standard")

    assert found.severity == "low"
    assert "meets the RFC 8301 minimum of 1024 bits" in found.description
    assert "below the recommended 2048" in found.description


def test_a_dkim_key_below_the_rfc_minimum_stays_medium(findings_for):
    answers = good_zone("tiny.example", dkim={"selector1": f"v=DKIM1; k=rsa; p={RSA_512_P}"})

    [found] = findings_for("tiny.example", answers, "dkim-weak-key", mode="standard")

    assert found.severity == "medium"
    assert "below the RFC 8301 minimum of 1024 bits" in found.description


def test_a_weak_key_behind_a_strong_first_selector_is_still_found(findings_for):
    """The old scan stopped at the first selector that answered, so a legacy
    key under a later selector was never looked at."""
    answers = good_zone(
        "mixed.example",
        dkim={
            "selector1": f"v=DKIM1; k=rsa; p={RSA_2048_P}",
            "k1": f"v=DKIM1; k=rsa; p={RSA_1024_P}",
        },
    )

    [found] = findings_for("mixed.example", answers, "dkim-weak-key", mode="standard")

    assert "k1._domainkey.mixed.example" in found.description
    assert found.state == "confirmed"


def test_when_strong_and_weak_keys_coexist_the_finding_says_it_cannot_tell_which_is_used(
    findings_for,
):
    answers = good_zone(
        "mixed.example",
        dkim={
            "selector1": f"v=DKIM1; k=rsa; p={RSA_1024_P}",
            "selector2": f"v=DKIM1; k=rsa; p={RSA_2048_P}",
        },
    )

    [found] = findings_for("mixed.example", answers, "dkim-weak-key", mode="standard")

    assert "selector2._domainkey.mixed.example" in found.description
    assert "cannot tell" in found.description
    assert "RFC 6376" in found.description
    selectors = {k["selector"] for k in found.evidence[0].analysis["dkim_keys"]}
    assert selectors == {"selector1", "selector2"}


def test_an_ed25519_key_is_not_reported_as_weak(findings_for):
    """An Ed25519 key is 256 bits by construction. Judging it by an RSA size
    threshold would call every Ed25519 key weak."""
    answers = good_zone("ed.example", dkim={"selector1": f"v=DKIM1; k=ed25519; p={ED25519_P}"})

    assert findings_for("ed.example", answers, "dkim-weak-key", mode="standard") == []


def test_a_revoked_selector_beside_a_strong_key_is_neither_weak_nor_unmeasurable(findings_for):
    answers = good_zone(
        "revoked.example",
        dkim={"selector1": "v=DKIM1; k=rsa; p=", "selector2": f"v=DKIM1; k=rsa; p={RSA_2048_P}"},
    )

    assert findings_for("revoked.example", answers, "dkim-weak-key", mode="standard") == []


def test_dmarc_with_no_policy_and_no_rua_cites_what_the_rfc_says_receivers_do(findings_for):
    """RFC 7489 6.6.3 step 6: no valid p and no valid rua means the receiver
    applies no DMARC processing. That is a spec statement, so it may be said."""
    answers = zone("nop.example", dmarc="v=DMARC1")

    [found] = findings_for("nop.example", answers, "dmarc-invalid")

    assert found.state == "confirmed"
    assert "no DMARC processing" in found.description
    assert "6.6.3" in found.description


def test_dmarc_with_no_policy_but_a_rua_says_receivers_treat_it_as_p_none(findings_for):
    answers = zone("nop.example", dmarc="v=DMARC1; rua=mailto:d@nop.example")

    [found] = findings_for("nop.example", answers, "dmarc-invalid")

    assert "as if" in found.description and "p=none" in found.description
    assert "ignore" not in found.description


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=reject; p=none; rua=mailto:d@dup.example",
        "v=DMARC1; p=reject; rua=mailto:d@dup.example; rua=mailto:e@dup.example",
        "v=DMARC1; rua=mailto:d@dup.example; p=reject",
    ],
    ids=["duplicate-p", "duplicate-rua", "p-not-second"],
)
def test_a_dmarc_error_whose_receiver_handling_no_spec_defines_is_suspected(findings_for, record):
    """RFC 7489 says v and p MUST come first and in that order, and borrows
    DKIM's rule that a duplicated tag makes the tag-list invalid - but it does
    not say what a receiver does with such a record. So we do not say either."""
    answers = zone("dup.example", dmarc=record)

    [found] = findings_for("dup.example", answers, "dmarc-invalid")

    assert found.state == "suspected"
    assert "does not define" in found.description
    assert "vary" in found.description
    assert "ignore a record like this entirely" not in found.description
    assert "would be ignored" not in found.title


def test_a_malformed_optional_tag_cites_the_rfc_rule_to_discard_it(findings_for):
    """RFC 7489 6.3: syntax errors after v and p SHOULD be discarded in favour
    of defaults - the opposite of 'receivers ignore the record'."""
    answers = zone("pct.example", dmarc="v=DMARC1; p=reject; pct=abc")

    [found] = findings_for("pct.example", answers, "dmarc-invalid")

    assert found.state == "suspected"
    assert "discard" in found.description
    assert "ignore a record like this entirely" not in found.description


# --- ?all severity by DMARC posture, and the spoofing simulation (2026-10-08)

NEUTRAL_SPF = "v=spf1 ip4:192.0.2.0/24 ?all"


def _neutral(domain, dmarc):
    return zone(domain, spf=NEUTRAL_SPF, dmarc=dmarc)


@pytest.mark.parametrize(
    ("dmarc", "severity"),
    [
        ("v=DMARC1; p=reject; rua=mailto:d@x.example", "low"),
        ("v=DMARC1; p=quarantine; rua=mailto:d@x.example", "low"),
        ("v=DMARC1; p=none; rua=mailto:d@x.example", "low"),
        ("v=DMARC1; p=reject; pct=50; rua=mailto:d@x.example", "low"),
        ("v=DMARC1; rua=mailto:d@x.example", "low"),
        ("v=DMARC1", "low"),
        (None, "low"),
    ],
    ids=["reject", "quarantine", "none", "partial", "treated-as-none", "unusable", "missing"],
)
def test_neutral_all_is_low_in_every_dmarc_posture(findings_for, dmarc, severity):
    """Operator ruling 2026-10-08: each finding carries its own marginal risk.
    Enforcing DMARC drops '?all' to low, so low is its own share; the policy
    risk belongs to the DMARC finding, which names it."""
    [found] = findings_for(
        "x.example", _neutral("x.example", dmarc), "spf-too-permissive", "standard"
    )

    assert found.severity == severity


def test_neutral_all_is_low_when_the_dmarc_lookup_failed(findings_for):
    answers = _neutral("x.example", None)
    answers[("_dmarc.x.example", "TXT")] = answer("_dmarc.x.example", "TXT", rcode="SERVFAIL")

    [found] = findings_for("x.example", answers, "spf-too-permissive", "standard")

    assert found.severity == "low"


def test_an_explicit_pass_all_is_high_even_under_p_reject(findings_for):
    answers = zone("x.example", spf="v=spf1 +all", dmarc="v=DMARC1; p=reject")

    [found] = findings_for("x.example", answers, "spf-too-permissive", "standard")

    assert found.severity == "high"


def test_quarantine_is_not_described_as_blocking_the_forgery(findings_for):
    """RFC 7489 6.3: quarantine means 'treated as suspicious', e.g. a spam
    folder. The message is still delivered somewhere a person may read it."""
    answers = _neutral("x.example", "v=DMARC1; p=quarantine")

    [found] = findings_for("x.example", answers, "spf-too-permissive", "standard")

    text = found.description + " " + found.impact
    assert "spam folder" in text
    assert "still" in text
    assert "blocked" not in text and "rejected" not in text


def test_reject_says_failing_mail_is_asked_to_be_rejected(findings_for):
    answers = _neutral("x.example", "v=DMARC1; p=reject")

    [found] = findings_for("x.example", answers, "spf-too-permissive", "standard")

    assert "p=reject" in found.description and "reject" in found.description


@pytest.mark.parametrize(
    ("dmarc", "other"),
    [
        ("v=DMARC1; p=none; rua=mailto:d@x.example", "dmarc-policy-none"),
        ("v=DMARC1; p=reject; pct=50; rua=mailto:d@x.example", "dmarc-pct-partial"),
        (None, "dmarc-missing"),
        ("v=DMARC1", "dmarc-invalid"),
    ],
)
def test_neutral_all_and_the_dmarc_weakness_name_each_other(run_scan, dmarc, other):
    """One exposure, two settings: each finding says the other exists, so a
    reader does not count it twice."""
    result = run_scan("x.example", _neutral("x.example", dmarc), mode="standard")
    by_id = {f.check_id: f for f in result.findings}

    assert other in by_id["spf-too-permissive"].description
    assert "spf-too-permissive" in by_id[other].description


def test_light_mode_does_not_point_at_a_finding_it_never_runs(run_scan):
    result = run_scan("x.example", _neutral("x.example", "v=DMARC1; p=none"), mode="light")
    [policy_none] = [f for f in result.findings if f.check_id == "dmarc-policy-none"]

    assert "spf-too-permissive" not in policy_none.description


def test_softfail_all_is_a_declared_non_finding_even_without_dmarc(findings_for):
    """~all is SoftFail (RFC 7208 2.6.5), not a pass. Without DMARC the
    exposure is dmarc-missing's to report, not this check's."""
    answers = zone("x.example", spf="v=spf1 ip4:192.0.2.0/24 ~all", dmarc=None)

    assert findings_for("x.example", answers, "spf-too-permissive", "standard") == []


def test_dmarc_treated_as_none_is_medium_and_says_the_operator_is_misled(findings_for):
    answers = zone("x.example", dmarc="v=DMARC1; rua=mailto:d@x.example")

    [found] = findings_for("x.example", answers, "dmarc-invalid")

    assert found.severity == "medium"
    assert "believes" in found.description


def test_neutral_all_under_p_reject_is_not_spoofable(findings_for):
    answers = _neutral("x.example", "v=DMARC1; p=reject; rua=mailto:d@x.example")

    assert findings_for("x.example", answers, "spoofing-possible") == []


def test_neutral_all_is_not_given_as_a_spoofing_reason(findings_for):
    [found] = findings_for("x.example", _neutral("x.example", None), "spoofing-possible")

    assert "?all" not in found.description
    assert "accepts any" not in found.description


def test_explicit_pass_all_is_spoofable_even_under_p_reject(findings_for):
    answers = zone("x.example", spf="v=spf1 +all", dmarc="v=DMARC1; p=reject")

    [found] = findings_for("x.example", answers, "spoofing-possible")

    assert found.state == "confirmed"
    assert "+all" in found.description


def test_a_dmarc_record_with_no_usable_policy_is_a_spoofing_reason_citing_the_rfc(findings_for):
    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1")

    [found] = findings_for("x.example", answers, "spoofing-possible")

    assert found.state == "confirmed"
    assert "6.6.3" in found.description
    assert "receivers ignore it" not in found.description


def test_a_record_treated_as_none_gives_the_p_none_reason(findings_for):
    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1; rua=mailto:d@x.example")

    [found] = findings_for("x.example", answers, "spoofing-possible")

    assert "p=none" in found.description


def test_a_malformed_optional_tag_is_simulated_with_its_default(findings_for):
    """RFC 7489 6.3: discard the bad tag, keep the record. pct defaults to
    100, so p=reject still applies to all failing mail."""
    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; pct=abc")

    assert findings_for("x.example", answers, "spoofing-possible") == []


@pytest.mark.parametrize(
    "dmarc",
    ["v=DMARC1; p=reject; p=none", "v=DMARC1; rua=mailto:d@x.example; p=reject"],
    ids=["duplicate-p", "p-not-second"],
)
def test_a_dmarc_error_with_undefined_handling_holds_spoofing_at_suspected(findings_for, dmarc):
    answers = zone("x.example", spf="v=spf1 -all", dmarc=dmarc)

    [found] = findings_for("x.example", answers, "spoofing-possible")

    assert found.state == "suspected"
    assert "vary" in found.description


# --- D39: the second resolver is real now, so it can disagree ---------------


def test_a_stale_primary_answer_fails_validation_at_the_second_resolver():
    """icicibank.com, 2026-10-08: one resolver served the TXT set without SPF."""
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver
    from core.models import Asset
    from scanners.email import EmailScanner

    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1; p=reject")
    stale = {("x.example", "TXT"): answer("x.example", "TXT", "google-site-verification=abc")}
    ctx = ScanContext(
        dns=DnsClient(
            resolver=FakeResolver(answers, by_resolver={"8.8.8.8": stale}),
            resolvers=["8.8.8.8", "1.1.1.1"],
        )
    )
    result = EmailScanner().run(Asset(type="domain", value="x.example"), "standard", ctx)
    by_id = {f.check_id: f for f in result.findings}

    assert by_id["spf-missing"].state == "suspected"
    assert by_id["spf-missing"].validation.outcome == "failed"
    assert "spoofing-possible" not in by_id or by_id["spoofing-possible"].state != "confirmed"


def test_the_spoofing_validation_re_reads_spf_not_only_dmarc():
    """Validation must re-observe every record the verdict rests on. It used to
    re-read DMARC from the second resolver and reuse the first one's SPF."""
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver
    from core.models import Asset
    from scanners.email import EmailScanner

    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1; p=none")
    stale = {("x.example", "TXT"): answer("x.example", "TXT", "v=spf1 +all")}
    ctx = ScanContext(
        dns=DnsClient(
            resolver=FakeResolver(answers, by_resolver={"8.8.8.8": stale}),
            resolvers=["8.8.8.8", "1.1.1.1"],
        )
    )
    result = EmailScanner().run(Asset(type="domain", value="x.example"), "standard", ctx)
    [spoof] = [f for f in result.findings if f.check_id == "spoofing-possible"]

    # p=none is a reason at both resolvers, '+all' only at the stale one. The
    # verdict still holds, but its stated reasons must survive re-reading.
    assert spoof.validation.outcome == "failed"


def test_the_spoofing_validation_shows_the_spf_record_it_re_read():
    """D39 review: a validation outcome must be traceable to what was re-read."""
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver
    from core.models import Asset
    from scanners.email import EmailScanner

    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1; p=none")
    stale = {("x.example", "TXT"): answer("x.example", "TXT", "v=spf1 +all")}
    ctx = ScanContext(
        dns=DnsClient(
            resolver=FakeResolver(answers, by_resolver={"8.8.8.8": stale}),
            resolvers=["8.8.8.8", "1.1.1.1"],
        )
    )
    result = EmailScanner().run(Asset(type="domain", value="x.example"), "standard", ctx)
    [spoof] = [f for f in result.findings if f.check_id == "spoofing-possible"]

    labels = [e.label for e in spoof.evidence]
    assert any("TXT at x.example" in label and "1.1.1.1" in label for label in labels)


def test_a_second_resolver_that_cannot_answer_the_spf_re_read_leaves_validation_unavailable():
    """A timeout is not a disagreement (D39 review)."""
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver
    from core.models import Asset
    from scanners.email import EmailScanner

    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=DMARC1; p=none")
    timeout = {("x.example", "TXT"): answer("x.example", "TXT", rcode="TIMEOUT")}
    ctx = ScanContext(
        dns=DnsClient(
            resolver=FakeResolver(answers, by_resolver={"1.1.1.1": timeout}),
            resolvers=["8.8.8.8", "1.1.1.1"],
        )
    )
    result = EmailScanner().run(Asset(type="domain", value="x.example"), "standard", ctx)
    [spoof] = [f for f in result.findings if f.check_id == "spoofing-possible"]

    assert spoof.validation.outcome == "unavailable"


# --- false claims fixed before verification (2026-10-08) --------------------


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_a_domain_with_no_spf_under_an_enforced_dmarc_policy_is_not_spoofable(findings_for, policy):
    """zomato.in, live run 1: no SPF means SPF returns None, which is not an
    aligned pass, so DMARC fails and the enforced policy applies (RFC 7208
    2.6.1; RFC 7489 3.1.2, 6.6.2). 'No SPF' is a reason only when DMARC is
    not enforced."""
    answers = zone("x.example", spf=None, dmarc=f"v=DMARC1; p={policy}")

    assert findings_for("x.example", answers, "spoofing-possible") == []


def test_no_spf_is_still_given_as_a_reason_when_dmarc_does_not_enforce(findings_for):
    answers = zone("x.example", spf=None, dmarc="v=DMARC1; p=none")

    [found] = findings_for("x.example", answers, "spoofing-possible")

    assert "no SPF record" in found.description


def test_no_spf_beside_an_undefined_dmarc_error_stays_a_hedge(findings_for):
    """'No SPF' only matters if DMARC is not applied, so it cannot turn a
    hedged DMARC reason into a claim."""
    answers = zone("x.example", spf=None, dmarc="v=DMARC1; p=reject; p=none")

    [found] = findings_for("x.example", answers, "spoofing-possible")

    assert found.state == "suspected"


def test_spf_missing_does_not_say_forged_mail_passes_spf(findings_for):
    """RFC 7208 2.6.1: with no SPF record the result is None, not Pass."""
    [found] = findings_for("x.example", zone("x.example", spf=None), "spf-missing")

    assert "passes SPF" not in found.impact
    assert "None" in found.impact


# --- D45: the version tag is case-sensitive ---------------------------------


def test_a_lower_case_dmarc_version_is_not_reported_as_a_policy(run_scan):
    """about.com, live run 2: 'v=dmarc1; p=none' was reported as p=none. Under
    both RFCs receivers MUST ignore the record, so the true finding is that."""
    answers = zone("x.example", spf="v=spf1 -all", dmarc="v=dmarc1; p=none; rua=mailto:d@x.example")
    result = run_scan("x.example", answers, mode="standard")
    by_id = {f.check_id: f for f in result.findings}

    assert "dmarc-policy-none" not in by_id
    invalid = by_id["dmarc-invalid"]
    assert invalid.state == "confirmed"
    assert "ignored" in invalid.description and "RFC 9989" in invalid.description
    spoof = by_id["spoofing-possible"]
    assert "p=none" not in spoof.description
    assert "ignore" in spoof.description


# --- D47: transport-security advice on domains that accept no mail ---------


@pytest.mark.parametrize("check_id", ["mta-sts-missing", "tls-rpt-missing"])
def test_a_null_mx_domain_gets_no_inbound_transport_advice(run_scan, check_id):
    """RFC 7505: 'MX 0 .' says the domain accepts no mail. MTA-STS (RFC 8461)
    and TLS-RPT (RFC 8460) protect inbound delivery, so there is nothing to
    protect, and telling the owner to publish them is bad advice."""
    answers = zone("nomail.example", mx=("0 .",), spf="v=spf1 -all", dmarc="v=DMARC1; p=reject")
    result = run_scan("nomail.example", answers, mode="standard")

    assert [f for f in result.findings if f.check_id == check_id] == []
    assert check_id not in {c.check_id for c in result.telemetry.checks_run}


@pytest.mark.parametrize("check_id", ["mta-sts-missing", "tls-rpt-missing"])
def test_a_domain_with_no_mx_gets_informational_transport_findings_not_advice(run_scan, check_id):
    """No MX is not 'no mail': senders fall back to the A record (RFC 5321
    5.1). RFC 8461 is written in terms of MX hosts and does not say whether it
    applies to that fallback, so we neither claim nor advise; mx-missing is
    the finding to act on."""
    answers = zone("nomx.example", mx=(), spf="v=spf1 -all", dmarc="v=DMARC1; p=reject")
    result = run_scan("nomx.example", answers, mode="standard")
    [found] = [f for f in result.findings if f.check_id == check_id]

    assert found.state == "informational"
    assert found.severity == "info"
    assert "mx-missing" in found.description


@pytest.mark.parametrize("check_id", ["mta-sts-missing", "tls-rpt-missing"])
def test_a_domain_that_receives_mail_still_gets_the_transport_findings(run_scan, check_id):
    result = run_scan("x.example", zone("x.example", spf="v=spf1 -all"), mode="standard")
    [found] = [f for f in result.findings if f.check_id == check_id]

    assert found.state == "confirmed" and found.severity == "low"
