"""`make rfc-check` and its legacy-but-deployed exemptions (operator, 2026-10-09).

An obsoleted RFC can still be the right citation: TLS 1.2 is still negotiated,
and today's CT logs run RFC 6962, not RFC 9162. Such a citation is exempt only
with a written reason, and these tests run offline in `make test`, so a missing
reason fails CI even though the network check itself does not run there.
"""

from __future__ import annotations

import pytest

from cli import rfcs


def test_every_exemption_in_the_repo_has_a_written_reason_and_is_still_cited():
    exemptions = rfcs.load_exemptions()
    cited = rfcs.cited_rfcs()

    assert exemptions, "the tls citations of RFC 5246 and 6962 are exempt"
    for number in exemptions:
        assert number in cited, f"RFC {number} is exempt but no longer cited: drop it"


@pytest.mark.parametrize(
    "entry",
    [
        {"rfc": 6962},
        {"rfc": 6962, "reason": ""},
        {"rfc": 6962, "reason": "   "},
        {"rfc": 6962, "reason": "still deployed", "successor_checked": "", "evidence": "x"},
        {"rfc": 6962, "reason": "still deployed", "successor_checked": "RFC 9162"},
    ],
    ids=["no-reason", "empty-reason", "blank-reason", "no-successor", "no-evidence"],
)
def test_an_exemption_without_its_reason_successor_or_evidence_is_refused(entry):
    with pytest.raises(ValueError):
        rfcs.parse_exemptions([entry])


def test_an_exempt_obsoleted_rfc_does_not_fail_the_check(monkeypatch, capsys):
    monkeypatch.setattr(rfcs, "cited_rfcs", lambda: {6962: {"scanners/x.py"}, 7525: {"y.py"}})
    monkeypatch.setattr(rfcs, "obsoleted_by", lambda n: ["RFC9162"] if n == 6962 else [])
    monkeypatch.setattr(
        rfcs,
        "load_exemptions",
        lambda: rfcs.parse_exemptions(
            [
                {
                    "rfc": 6962,
                    "reason": "today's CT logs run RFC 6962",
                    "successor_checked": "RFC 9162",
                    "evidence": "https://googlechrome.github.io/CertificateTransparency/log_policy.html",
                }
            ]
        ),
    )

    assert rfcs.main() == 0
    out = capsys.readouterr().out
    assert "exempt" in out and "today's CT logs" in out


def test_an_obsoleted_rfc_without_an_exemption_still_fails(monkeypatch):
    monkeypatch.setattr(rfcs, "cited_rfcs", lambda: {7525: {"scanners/x.py"}})
    monkeypatch.setattr(rfcs, "obsoleted_by", lambda n: ["RFC9325"])
    monkeypatch.setattr(rfcs, "load_exemptions", lambda: {})

    assert rfcs.main() == 1
