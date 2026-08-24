"""The Email Security Scanner. Every check gets a positive and a negative case."""

from __future__ import annotations

import pytest

from tests.scanners.email.conftest import RSA_1024_P, RSA_2048_P, answer, zone

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
