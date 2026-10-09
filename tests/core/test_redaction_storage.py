"""ADR-028 clauses 3, 5 and 6: every storage point, and only one way into a Finding.

Written before the implementation (D21). Each test must fail on the core that
predates ADR-028.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest

from core.dns import DnsResponse
from core.evidence import capture_http_pair, dns_evidence, redact_headers
from core.http import RecordingHttpBackend, ReplayHttpBackend
from core.models import Finding, ScanError
from tests.core.test_redaction import AWS, GHP, LINES, leaked, pem

NOW = datetime(2026, 10, 9, tzinfo=UTC)


def _req(url="https://x.test/", headers=None, body=None):
    return {"method": "GET", "url": url, "headers": headers or {}, "body": body}


def _resp(headers=None, body=None, status=200):
    return {"status": status, "headers": headers or {}, "body": body, "elapsed_ms": 1}


def _pair(**test):
    return capture_http_pair(
        label="t",
        control_request=_req(),
        control_response=_resp(),
        test_request=test.get("request", _req()),
        test_response=test.get("response", _resp()),
    )


def _finding_kwargs(**over):
    kwargs = dict(
        org_id="org_internal",
        scanner="example",
        scanner_version="1.0.0",
        check_id="c",
        title="t",
        target={"type": "domain", "value": "x.test"},
        location="$",
        severity="low",
        confidence=0.5,
        detection_methods=[
            {
                "method": "m",
                "independence_class": "dns",
                "prior": 0.5,
                "likelihood_ratio": 1.0,
                "prior_justification": "j",
            }
        ],
        validation={"attempted": False, "outcome": "not_applicable"},
        evidence=[_pair().model_dump(mode="json")],
        description="d",
        impact="i",
        remediation="r",
        first_seen=NOW,
        first_seen_scan_id="s",
        last_seen=NOW,
        last_seen_scan_id="s",
    )
    kwargs.update(over)
    return kwargs


# --- HTTP captures (D21's two findings) --------------------------------------


def test_a_secret_in_a_non_sensitive_header_value_is_not_stored():
    headers, kinds = redact_headers({"Server": f"nginx {AWS}"})

    assert AWS not in json.dumps(headers)
    assert "aws_access_key_id" in kinds


def test_a_secret_in_a_header_name_is_not_stored():
    headers, _ = redact_headers({f"X-{GHP}": "1"})

    assert GHP not in json.dumps(headers)


def test_a_private_key_body_in_a_response_is_not_stored():
    evidence = _pair(response=_resp(body="<pre>" + pem(LINES) + "</pre>"))

    assert leaked(evidence.model_dump_json()) == []


def test_a_secret_in_the_request_url_is_not_stored():
    evidence = _pair(request=_req(url=f"https://x.test/?key={AWS}"))

    assert AWS not in evidence.model_dump_json()


def test_a_recorded_fixture_holds_no_key_body(tmp_path):
    class Inner:
        def send(self, method, url, *, body_cap, **kwargs):
            from core.http import RawHttpResponse

            return RawHttpResponse(
                status_code=200,
                headers={"Server": f"x {AWS}"},
                text=pem(LINES),
                url=url,
                elapsed_ms=1,
            )

    RecordingHttpBackend(tmp_path, inner=Inner()).send("GET", "https://x.test/", body_cap=600)
    on_disk = "".join(p.read_text() for p in tmp_path.rglob("*.json"))

    assert leaked(on_disk) == [] and AWS not in on_disk


def test_a_legacy_fixture_with_a_key_body_is_redacted_on_replay(tmp_path):
    """A fixture written by core before ADR-028: BEGIN replaced, body kept."""
    from core.http import _fixture_name

    legacy_body = "[redacted]:private_key\n" + "\n".join(LINES) + "\n-----END RSA PRIVATE KEY-----"
    payload = {
        "status": 200,
        "headers": {"Server": f"x {AWS}"},
        "body": legacy_body,
        "body_truncated": False,
        "elapsed_ms": 1,
        "redactions": ["private_key"],
        "url": "https://x.test/",
    }
    (tmp_path / _fixture_name("GET", "https://x.test/")).write_text(json.dumps(payload))

    raw = ReplayHttpBackend(tmp_path).send("GET", "https://x.test/", body_cap=262_144)

    assert leaked(raw.text) == [] and AWS not in json.dumps(raw.headers)


# --- public material in DNS and TLS evidence is kept (clause 2) ---------------


def test_dns_evidence_keeps_a_dkim_public_key_and_redacts_a_token():
    p = "".join(LINES)
    answer = DnsResponse(
        name="s._domainkey.x.test",
        rrtype="TXT",
        rcode="NOERROR",
        records=[f"v=DKIM1; k=rsa; p={p}", f"leaked={AWS}"],
    )

    dumped = dns_evidence(
        label="l", test=answer, control=None, control_rationale="none possible"
    ).model_dump_json()

    assert p in dumped
    assert AWS not in dumped


def test_dkim_weak_key_still_reads_key_size_from_stored_evidence(run_email_scan_with_1024_key):
    """ADR-028 clause 3, and the operator's test: stored evidence keeps the key."""
    from scanners.email.dkim import parse_dkim_key

    finding = run_email_scan_with_1024_key
    records = finding.evidence[0].test.answer.records

    assert [parse_dkim_key(r).key_bits for r in records] == [1024]


def test_certificate_evidence_is_intact_after_redaction(tls_finding_from_corpus):
    before = tls_finding_from_corpus.model_dump(mode="json")["evidence"]
    again = Finding.model_validate(tls_finding_from_corpus.model_dump(mode="json"))

    assert again.model_dump(mode="json")["evidence"] == before


# --- one way into a Finding (clause 6) ----------------------------------------

SECRET_TEXT = {
    "title": f"t {AWS}",
    "description": "d " + pem(LINES),
    "impact": f"i {GHP}",
    "remediation": f"r {AWS}",
}


def _assert_clean(finding: Finding) -> None:
    dumped = finding.model_dump_json()
    assert AWS not in dumped and GHP not in dumped and leaked(dumped) == []


def test_finding_create_redacts_every_text_field():
    _assert_clean(Finding.create(**_finding_kwargs(**SECRET_TEXT)))


def test_a_secret_location_is_redacted_and_the_id_follows_it():
    finding = Finding.create(**_finding_kwargs(location=f"/?k={AWS}"))

    assert AWS not in finding.location
    assert finding.id == Finding.create(**_finding_kwargs(location=finding.location)).id


def test_deserialising_a_finding_redacts_it():
    clean = Finding.create(**_finding_kwargs())
    raw = clean.model_dump(mode="json")
    raw.update(SECRET_TEXT)

    _assert_clean(Finding.model_validate(raw))
    _assert_clean(Finding.model_validate_json(json.dumps(raw)))


def test_direct_construction_redacts_it():
    clean = Finding.create(**_finding_kwargs())
    raw = clean.model_dump()
    raw.update(SECRET_TEXT)

    _assert_clean(Finding(**raw))


def test_model_construct_is_blocked():
    with pytest.raises(TypeError):
        Finding.model_construct(**_finding_kwargs())


def test_model_copy_redacts_what_it_updates():
    clean = Finding.create(**_finding_kwargs())

    _assert_clean(clean.model_copy(update={"description": f"now {AWS}"}))


def test_a_store_written_before_adr_028_is_redacted_on_load(tmp_path):
    from core.store import FindingStore

    path = tmp_path / "s.db"
    finding = Finding.create(**_finding_kwargs())
    with FindingStore(path) as store:
        store.ingest([finding])
    raw = finding.model_dump(mode="json")
    raw["description"] = f"stored before ADR-028 {AWS}"
    db = sqlite3.connect(path)
    try:
        db.execute("UPDATE findings SET data = ?", (json.dumps(raw),))
        db.commit()
    finally:
        db.close()

    with FindingStore(path) as store:
        loaded = store.get(finding.id, finding.org_id)
        assert loaded is not None
        _assert_clean(loaded)
        _assert_clean(store.list_findings(finding.org_id)[0])


def test_evidence_built_directly_is_redacted():
    from core.models import Evidence

    raw = _pair().model_dump(mode="json")
    raw["test"]["response"]["body"] = pem(LINES)

    assert leaked(Evidence.model_validate(raw).model_dump_json()) == []


# --- errors and logs (operator's addition) ------------------------------------


def test_a_scan_error_message_is_redacted():
    error = ScanError(stage="fetch", message=f"response said {AWS}: " + pem(LINES))

    assert AWS not in error.message and leaked(error.message) == []


def test_an_exception_carrying_a_secret_is_redacted_on_stderr(capsys):
    from cli.main import report_exception

    try:
        raise RuntimeError(f"upstream returned {AWS}\n" + pem(LINES))
    except RuntimeError as exc:
        report_exception(exc)

    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert AWS not in err and leaked(err) == []


def test_progress_messages_are_redacted(capsys):
    from cli.main import _progress

    _progress(f"fetching https://x.test/?k={AWS}", 0.5)

    assert AWS not in capsys.readouterr().err
