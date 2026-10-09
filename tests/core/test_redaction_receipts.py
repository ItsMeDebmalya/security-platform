"""ADR-029: redaction receipts, and a receipt on public content is a finding.

Written before the implementation; every test here failed on main (44aa1ef).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from core.authz import Scope
from core.dns import DnsResponse
from core.evidence import capture_http_pair, dns_evidence
from core.http import HttpClient, RecordingHttpBackend, ReplayHttpBackend
from core.models import Asset, Finding, HttpPairEvidence, RedactionReceipt
from tests.core.test_redaction import AWS, GHP
from tests.core.test_redaction_storage import _finding_kwargs

HOST = "x.test"
TARGET = Asset(type="domain", value=HOST)
SLACK = "xoxb-1234567890-abcdefghij"


def _client(handler, backend=None) -> HttpClient:
    scope = Scope(frozenset({HOST, f"www.{HOST}", "crt.sh"}))
    if backend is None:
        return HttpClient(scope=scope, transport=httpx.MockTransport(handler))
    return HttpClient(scope=scope, backend=backend)


def _site(body: str, headers: dict[str, str] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body, headers=headers or {})

    return handler


def _receipts(items) -> set[tuple[str, int, str]]:
    return {(r["kind"], r["count"], r["where"]) for r in items}


# --- 1. the field -------------------------------------------------------------------


def test_a_receipt_holds_kind_count_and_where_and_nothing_else():
    RedactionReceipt(kind="aws_access_key_id", count=1, where="test.response.body")
    with pytest.raises(ValidationError):
        RedactionReceipt(kind="aws_access_key_id", count=1, where="x", value="AKIA")
    with pytest.raises(ValidationError):
        RedactionReceipt(kind="aws_access_key_id", count=0, where="test.response.body")
    with pytest.raises(ValidationError):  # where is a field path, never data
        RedactionReceipt(kind="aws_access_key_id", count=1, where="https://x.test/?k=1")


def test_old_evidence_without_receipts_is_still_valid():
    evidence = HttpPairEvidence.model_validate(
        {
            "kind": "http_pair",
            "label": "l",
            "captured_at": "2026-10-09T00:00:00Z",
            "redactions": ["set-cookie"],
            "control": {
                "request": {"method": "GET", "url": "https://x.test/", "headers": {}},
                "response": {"status": 200, "headers": {}},
            },
            "test": {
                "request": {"method": "GET", "url": "https://x.test/", "headers": {}},
                "response": {"status": 200, "headers": {}},
            },
        }
    )
    assert evidence.redaction_receipts == [] and evidence.redactions == ["set-cookie"]


# --- 2. made at capture, surviving replay --------------------------------------------


def test_a_live_capture_records_receipts_per_part():
    client = _client(_site(f"a {AWS} b {AWS}", {"Server": f"nginx {GHP}"}))

    captured = client.get(f"https://{HOST}/").captured

    assert _receipts(captured["redaction_receipts"]) == {
        ("aws_access_key_id", 2, "response.body"),
        ("github_token", 1, "response.headers"),
    }


def test_receipts_survive_recording_and_replay(tmp_path):
    live = _client(_site(f"a {AWS}"))
    recording = _client(None, RecordingHttpBackend(tmp_path, live._backend))
    first = recording.get(f"https://{HOST}/").captured

    replayed = _client(None, ReplayHttpBackend(tmp_path)).get(f"https://{HOST}/").captured

    assert first["redaction_receipts"] == replayed["redaction_receipts"]
    assert _receipts(replayed["redaction_receipts"]) == {("aws_access_key_id", 1, "response.body")}


def test_a_fixture_recorded_before_adr_029_gets_no_invented_receipts(tmp_path):
    recording = _client(None, RecordingHttpBackend(tmp_path, _client(_site(f"a {AWS}"))._backend))
    recording.get(f"https://{HOST}/")
    for path in tmp_path.rglob("*.json"):
        data = json.loads(path.read_text())
        data.pop("redaction_receipts")
        path.write_text(json.dumps(data))

    replayed = _client(None, ReplayHttpBackend(tmp_path)).get(f"https://{HOST}/").captured

    assert replayed["redaction_receipts"] == []
    assert "aws_access_key_id" in replayed["redactions"]  # the old list is untouched


# --- 3. evidence and findings ---------------------------------------------------------


def _pair_from(client: HttpClient, path: str = "/") -> HttpPairEvidence:
    url = f"https://{HOST}{path}"
    captured = client.get(url).captured
    request = {"method": "GET", "url": url, "headers": {}}
    return capture_http_pair(
        label="l",
        control_request=request,
        control_response=captured,
        test_request=request,
        test_response=captured,
    )


def test_http_evidence_carries_the_capture_receipts_by_side():
    evidence = _pair_from(_client(_site(f"a {AWS}")))

    assert _receipts(r.model_dump() for r in evidence.redaction_receipts) == {
        ("aws_access_key_id", 1, "control.response.body"),
        ("aws_access_key_id", 1, "test.response.body"),
    }


def test_http_evidence_built_from_raw_text_counts_what_it_redacts():
    raw = {"status": 200, "headers": {}, "body": f"{AWS} and {AWS}"}
    request = {"method": "GET", "url": f"https://{HOST}/?t={GHP}", "headers": {}}

    evidence = capture_http_pair(
        label="l",
        control_request=request,
        control_response=raw,
        test_request=request,
        test_response=raw,
    )

    got = _receipts(r.model_dump() for r in evidence.redaction_receipts)
    assert ("aws_access_key_id", 2, "test.response.body") in got
    assert ("github_token", 1, "test.request.url") in got


def _dns(name: str, records: list[str]) -> DnsResponse:
    return DnsResponse(name=name, rrtype="TXT", rcode="NOERROR", records=records, resolver="r")


def test_dns_evidence_records_receipts_on_the_answer():
    evidence = dns_evidence(
        label="l",
        test=_dns(HOST, [f"k={AWS}", "google-site-verification=abc"]),
        control=None,
        control_rationale="r",
    )

    assert _receipts(r.model_dump() for r in evidence.redaction_receipts) == {
        ("aws_access_key_id", 1, "test.answer")
    }


def test_revalidation_never_double_counts():
    evidence = _pair_from(_client(_site(f"a {AWS}")))

    again = HttpPairEvidence.model_validate(evidence.model_dump())
    again = HttpPairEvidence.model_validate_json(again.model_dump_json())

    assert again.redaction_receipts == evidence.redaction_receipts


def test_a_finding_rolls_up_its_evidence_receipts_and_ignores_forged_ones():
    first = _pair_from(_client(_site(f"a {AWS}")))
    second = _pair_from(_client(_site(f"b {SLACK}")))

    finding = Finding.create(
        **_finding_kwargs(
            evidence=[first.model_dump(mode="json"), second.model_dump(mode="json")],
        ),
        redaction_receipts=[{"kind": "forged", "count": 9, "where": "evidence.0.x"}],
    )

    got = _receipts(r.model_dump() for r in finding.redaction_receipts)
    assert ("aws_access_key_id", 1, "evidence.0.test.response.body") in got
    assert ("slack_token", 1, "evidence.1.test.response.body") in got
    assert not any(kind == "forged" for kind, _, _ in got)


def test_no_receipt_records_the_value_a_prefix_the_length_or_a_hash():
    secrets = [AWS, GHP, SLACK]
    body = " ".join(secrets)
    finding = Finding.create(
        **_finding_kwargs(
            evidence=[_pair_from(_client(_site(body))).model_dump(mode="json")],
        )
    )
    dumped = finding.model_dump_json()

    for secret in secrets:
        assert secret not in dumped
        for n in range(4, len(secret)):
            assert secret[:n] not in dumped, f"prefix of {secret[:4]}… stored"
            assert secret[-n:] not in dumped, f"suffix of …{secret[-4:]} stored"
        digests = [
            hashlib.md5(secret.encode()).hexdigest(),
            hashlib.sha1(secret.encode()).hexdigest(),
            hashlib.sha256(secret.encode()).hexdigest(),
            base64.b64encode(secret.encode()).decode(),
        ]
        for digest in digests:
            assert digest[:8] not in dumped
    receipts = json.loads(dumped)["redaction_receipts"]
    assert receipts and all(set(r) == {"kind", "count", "where"} for r in receipts)
    for receipt in receipts:  # count is how many, never how long
        assert receipt["count"] == 1
        assert not any(c.isdigit() for c in receipt["where"].replace("evidence.0", ""))


# --- 4. a receipt on public content is a finding ----------------------------------------


def _finding_with(evidence) -> Finding:
    return Finding.create(
        **_finding_kwargs(
            scanner="email",
            target={"type": "domain", "value": HOST},
            evidence=[e.model_dump(mode="json") for e in evidence],
        )
    )


def _exposures(findings):
    from core.exposure import secret_exposure_findings

    return secret_exposure_findings(
        findings,
        scanner="email",
        scanner_version="9.9.9",
        target=TARGET,
        org_id="org_internal",
        scan_id="01J8AAAAAAAAAAAAAAAAAAAAAA",
    )


def test_a_credential_in_a_target_response_is_reported_once_per_resource():
    pair = _pair_from(_client(_site(f"a {AWS} {GHP}")))
    findings = [_finding_with([pair]), _finding_with([pair])]

    exposed = _exposures(findings)

    assert len(exposed) == 1
    (finding,) = exposed
    assert finding.check_id == "secret-exposed" and finding.scanner == "email"
    assert finding.severity == "high"
    assert finding.location == f"https://{HOST}/"
    assert "aws_access_key_id" in finding.description and "github_token" in finding.description
    assert AWS not in finding.model_dump_json()


def test_a_credential_in_a_target_dns_record_is_reported():
    evidence = dns_evidence(
        label="l", test=_dns(f"_x.{HOST}", [f"k={AWS}"]), control=None, control_rationale="r"
    )

    (finding,) = _exposures([_finding_with([evidence])])

    assert finding.location == f"dns:_x.{HOST}/TXT"


@pytest.mark.parametrize(
    "case",
    [
        "third_party_host",
        "other_zone_dns",
        "request_only",
        "google_api_key",
        "set_cookie",
        "heuristic_cut",
    ],
)
def test_what_is_not_an_exposure(case):
    if case == "third_party_host":
        evidence = [_pair_from_url(f"https://crt.sh/?q={HOST}", f"a {AWS}")]
    elif case == "other_zone_dns":
        evidence = [
            dns_evidence(
                label="l",
                test=_dns("_spf.example.net", [f"k={AWS}"]),
                control=None,
                control_rationale="r",
            )
        ]
    elif case == "request_only":
        request = {"method": "GET", "url": f"https://{HOST}/?k={AWS}", "headers": {}}
        raw = {"status": 200, "headers": {}, "body": "ok"}
        evidence = [
            capture_http_pair(
                label="l",
                control_request=request,
                control_response=raw,
                test_request=request,
                test_response=raw,
            )
        ]
    elif case == "google_api_key":
        evidence = [_pair_from(_client(_site("k=AIza" + "B" * 35)))]
    elif case == "set_cookie":
        evidence = [_pair_from(_client(_site("ok", {"Set-Cookie": "sid=abc"})))]
    else:
        from tests.core.test_redaction import key_lines

        evidence = [_pair_from(_client(_site("\n".join(["x", *key_lines(6), "y"]))))]

    assert _exposures([_finding_with(evidence)]) == []


def _pair_from_url(url: str, body: str) -> HttpPairEvidence:
    raw = {"status": 200, "headers": {}, "body": body}
    request = {"method": "GET", "url": url, "headers": {}}
    return capture_http_pair(
        label="l",
        control_request=request,
        control_response=raw,
        test_request=request,
        test_response=raw,
    )


def test_the_exposure_finding_is_itself_covered_and_stable():
    pair = _pair_from(_client(_site(f"a {AWS}")))
    exposed = _exposures([_finding_with([pair])])

    assert _exposures([_finding_with([pair]), *exposed]) == []  # no exposure of an exposure
    assert [f.id for f in _exposures([_finding_with([pair])])] == [exposed[0].id]


def test_the_credential_kinds_are_the_same_as_web():
    from core.exposure import EXPOSURE_KINDS
    from scanners.web.disclosure import SECRET_KINDS

    assert EXPOSURE_KINDS == SECRET_KINDS


NOW = datetime(2026, 10, 9, tzinfo=UTC)


def test_a_response_with_its_capture_receipts_is_not_counted_twice():
    """A scanner may pass the raw body with the capture's receipts (live), or the
    fixture's redacted body with them (replay). Both must give the same receipts."""
    client = _client(_site(f"a {AWS}"))
    response = client.get(f"https://{HOST}/")
    request = {"method": "GET", "url": f"https://{HOST}/", "headers": {}}

    def pair(body):
        raw = {
            "status": 200,
            "headers": {},
            "body": body,
            "redaction_receipts": response.captured["redaction_receipts"],
        }
        return capture_http_pair(
            label="l",
            control_request=request,
            control_response=raw,
            test_request=request,
            test_response=raw,
        )

    live, replayed = pair(response.text), pair(response.captured["body"])

    assert live.redaction_receipts == replayed.redaction_receipts
    assert _receipts(r.model_dump() for r in live.redaction_receipts) == {
        ("aws_access_key_id", 1, "control.response.body"),
        ("aws_access_key_id", 1, "test.response.body"),
    }


# --- review of e6eaa45 ------------------------------------------------------------


def test_secrets_in_the_keys_of_a_free_form_side_are_still_redacted():
    """BLOCKER: ADR-028 redacts evidence however it is built, dict keys included."""
    from core.models import Evidence

    evidence = Evidence.model_validate(
        {
            "kind": "tls_handshake",
            "label": "l",
            "captured_at": "2026-10-09T00:00:00Z",
            "control_rationale": "r",
            "observed_at": "2026-10-09T00:00:00Z",
            "test": {f"banner {AWS}": "x", GHP: "y"},
            "control": {AWS: 1},
        }
    )
    dumped = evidence.model_dump_json()

    assert AWS not in dumped and GHP not in dumped
    got = _receipts(r.model_dump() for r in evidence.redaction_receipts)
    assert ("aws_access_key_id", 1, "test.data") in got
    assert ("aws_access_key_id", 1, "control.data") in got


def _ctx(handler=None, answers=None):
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver

    kwargs = {}
    if handler is not None:
        kwargs["http"] = _client(handler)
    if answers is not None:
        kwargs["dns"] = DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1"])
    return ScanContext(**kwargs)


def test_the_scan_context_logs_every_public_capture_whether_or_not_a_finding_cites_it():
    ctx = _ctx(
        handler=_site(f"a {AWS}"),
        answers={
            (HOST, "TXT"): _dns(HOST, [f"k={GHP}"]),
            ("_x.other", "TXT"): _dns("_x.other", [AWS]),
        },
    )
    ctx.http.get(f"https://{HOST}/page")
    ctx.dns.query(HOST, "TXT")
    ctx.dns.query("_x.other", "TXT")

    exposed = ctx.exposures.exposed(TARGET)

    assert {r: k for r, (k, _) in exposed.items()} == {
        f"https://{HOST}/page": {"aws_access_key_id"},
        f"dns:{HOST}/TXT": {"github_token"},
    }


def test_logged_exposures_become_findings_without_a_citing_finding():
    from core.exposure import secret_exposure_findings

    ctx = _ctx(answers={(HOST, "TXT"): _dns(HOST, [f"k={AWS}"])})
    ctx.dns.query(HOST, "TXT")

    (finding,) = secret_exposure_findings(
        [],
        scanner="email",
        scanner_version="9.9.9",
        target=TARGET,
        org_id="org_internal",
        scan_id="01J8AAAAAAAAAAAAAAAAAAAAAA",
        log=ctx.exposures,
    )

    assert finding.location == f"dns:{HOST}/TXT"
    assert AWS not in finding.model_dump_json()
    assert finding.redaction_receipts  # its own evidence carries the receipt


def test_a_capture_recorded_before_adr_029_is_logged_from_its_redaction_kinds(tmp_path):
    recording = _client(None, RecordingHttpBackend(tmp_path, _client(_site(f"a {AWS}"))._backend))
    recording.get(f"https://{HOST}/")
    for path in tmp_path.rglob("*.json"):
        data = json.loads(path.read_text())
        data.pop("redaction_receipts")
        path.write_text(json.dumps(data))
    from core.context import ScanContext

    ctx = ScanContext(http=_client(None, ReplayHttpBackend(tmp_path)))
    ctx.http.get(f"https://{HOST}/")

    assert set(ctx.exposures.exposed(TARGET)) == {f"https://{HOST}/"}


def test_one_exposure_is_reported_once_whatever_the_url_spelling():
    """Re-review of ab97721: a redirect hop, its final page, and evidence cited under
    the request URL gave three findings for two exposures."""
    from core.context import ScanContext
    from core.exposure import secret_exposure_findings, unreported_exposures
    from core.models import CheckRun, ScanResult, Telemetry

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("", "/"):
            return httpx.Response(301, headers={"Location": f"/login?next={GHP}"})
        return httpx.Response(200, text=f"key {AWS}")

    ctx = ScanContext(http=_client(handler))
    response = ctx.http.get(f"https://{HOST}")  # no trailing slash, as a caller may write it
    request = {"method": "GET", "url": f"https://{HOST}/", "headers": {}}
    cited = capture_http_pair(
        label="l",
        control_request=request,
        control_response=response.captured,
        test_request=request,
        test_response=response.captured,
    )
    findings = [_finding_with([cited])]

    exposures = secret_exposure_findings(
        findings,
        scanner="email",
        scanner_version="9.9.9",
        target=TARGET,
        org_id="org_internal",
        scan_id="01J8AAAAAAAAAAAAAAAAAAAAAA",
        log=ctx.exposures,
    )

    assert sorted(f.location for f in exposures) == [
        f"https://{HOST}/",
        f"https://{HOST}/login?next=[redacted]:github_token",
    ]
    result = ScanResult(
        scanner="email",
        scanner_version="9.9.9",
        target=TARGET,
        mode="light",
        findings=[*findings, *exposures],
        errors=[],
        telemetry=Telemetry(
            checks_run=[
                CheckRun(check_id="c", location="$", outcome="reported"),
                *[
                    CheckRun(check_id=f.check_id, location=f.location, outcome="reported")
                    for f in exposures
                ],
            ],
            suppressed=[],
        ),
        finished_at=datetime.now(UTC),
    )
    assert unreported_exposures(result, ctx.exposures) == []
