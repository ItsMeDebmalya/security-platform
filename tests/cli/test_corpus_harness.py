"""The corpus harness: the thing that decides whether a scanner is done."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from cli.corpus import _regressions, app, run_scanner_corpus

runner = CliRunner()


def test_the_reference_scanner_passes_its_gate():
    report = run_scanner_corpus("example")

    assert report["passed"], report["reason"]


def test_the_report_states_whether_recall_is_absolute_or_corpus_relative():
    report = run_scanner_corpus("example")

    assert report["gate"]["recall_label"]


def test_every_corpus_case_is_scored():
    report = run_scanner_corpus("example")

    assert {c["id"] for c in report["cases"]} == {
        "resolves",
        "no-a-record",
        "nxdomain",
        "servfail",
    }


def test_the_known_good_case_reports_nothing():
    report = run_scanner_corpus("example")
    known_good = [c for c in report["cases"] if c["tier"] == "known_good"]

    assert all(c["tp"] == c["fp"] == 0 for c in known_good)
    assert report["false_positives_on_known_good"] == 0


def test_the_unresolvable_case_returns_inconclusive_rather_than_an_error():
    report = run_scanner_corpus("example")
    case = next(c for c in report["cases"] if c["id"] == "servfail")

    assert case["inconclusive_delivered"] is True
    assert case["errors"] == []


def test_an_expected_inconclusive_case_does_not_inflate_the_inconclusive_rate():
    """docs/10 measures that rate where a definite answer is expected. Here one
    is not, so the case is asserted rather than averaged."""
    report = run_scanner_corpus("example")

    assert report["overall"]["inconclusive_rate"] == 0.0


def test_the_harness_writes_its_results_for_ci_to_compare():
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    from cli.corpus import LATEST

    assert "example" in {r["scanner"] for r in json.loads(LATEST.read_text())}


# --- regression detection ---------------------------------------------------


def _report(precision=1.0, recall=1.0, inconclusive=0.0, known_good_fps=0):
    return {
        "scanner": "example",
        "overall": {
            "precision": precision,
            "recall": recall,
            "inconclusive_rate": inconclusive,
        },
        "false_positives_on_known_good": known_good_fps,
    }


def test_a_precision_drop_fails_the_build():
    problems = _regressions([_report(precision=0.9)], [_report(precision=1.0)])

    assert any("precision fell" in p for p in problems)


def test_a_rising_inconclusive_rate_fails_the_build():
    problems = _regressions([_report(inconclusive=0.2)], [_report(inconclusive=0.05)])

    assert any("inconclusive rate rose" in p for p in problems)


def test_one_new_false_positive_on_a_known_good_target_fails_the_build():
    problems = _regressions([_report(known_good_fps=1)], [_report(known_good_fps=0)])

    assert any("known-good" in p for p in problems)


def test_a_recall_drop_warns_rather_than_failing():
    """A recall regression is usually a deliberate precision trade; failing it
    would push authors to over-report."""
    problems = _regressions([_report(recall=0.8)], [_report(recall=0.95)])

    assert problems == []


def test_an_unchanged_run_is_not_a_regression():
    problems = _regressions([_report()], [_report()])

    assert problems == []


# --- the email scanner ------------------------------------------------------


def test_the_email_scanner_passes_its_gate():
    report = run_scanner_corpus("email")

    assert report["passed"], report["reason"]


def test_the_email_gate_is_the_one_the_roadmap_sets():
    report = run_scanner_corpus("email")

    assert report["gate"]["precision"] == 0.99
    assert report["gate"]["recall"] == 0.95


def test_every_email_check_has_a_positive_corpus_case():
    """docs/10-measurement.md: a detection without a positive case is unproven."""
    from scanners.email.checks import CHECKS

    report = run_scanner_corpus("email")
    covered = {
        expected["check_id"] for case in report["cases"] for expected in case.get("expected", [])
    }
    # Two checks can never appear in an expected set, and it is worth being
    # explicit about why rather than letting the list quietly grow:
    #   dkim-missing   - inconclusive by construction; selectors are not enumerable
    #   dmarc-alignment - informational; relaxed alignment is the RFC default and
    #                     not a vulnerability claim, so the gate excludes it
    # Both are covered by unit tests in tests/scanners/email instead.
    never_a_claim = {"dkim-missing", "dmarc-alignment"}

    assert set(CHECKS) - never_a_claim - covered == set()


def test_no_finding_at_all_on_a_known_good_email_target():
    report = run_scanner_corpus("email")

    assert report["false_positives_on_known_good"] == 0


# --- fixtures that no longer cover the scanner ------------------------------


def test_a_case_whose_fixtures_are_incomplete_fails_that_case_not_the_whole_run(tmp_path):
    """A scanner change that adds a DNS query outruns its frozen fixtures.

    That is an ordinary thing to happen mid-change, and it must read as 'this
    case needs re-recording', not as a stack trace from inside the resolver.
    """
    import yaml

    from cli.corpus import TARGETS_DIR, run_scanner_corpus

    targets = yaml.safe_load((TARGETS_DIR / "email.yaml").read_text())
    targets["cases"] = [
        {
            "id": "empty-fixtures",
            "tier": "vulnerable",
            "source": "frozen",
            "mode": "light",
            "target": {"type": "domain", "value": "corpus-good.example"},
            "fixtures": str(tmp_path.relative_to(tmp_path.anchor)),
        }
    ]
    scratch = tmp_path / "targets"
    scratch.mkdir()
    (scratch / "email.yaml").write_text(yaml.safe_dump(targets))

    report = run_scanner_corpus("email", targets_dir=scratch)

    assert not report["passed"]
    assert "re-record" in report["reason"]


# --- the tls scanner --------------------------------------------------------


def test_the_tls_scanner_passes_its_gate():
    report = run_scanner_corpus("tls")

    assert report["passed"], report["reason"]


def test_the_tls_gate_is_the_one_the_roadmap_sets():
    report = run_scanner_corpus("tls")

    assert report["gate"]["precision"] == 0.98
    assert report["gate"]["recall"] == 0.95


def test_no_finding_at_all_on_a_healthy_tls_server():
    report = run_scanner_corpus("tls")

    assert report["false_positives_on_known_good"] == 0


def test_an_unreachable_tls_target_returns_inconclusive_rather_than_erroring():
    report = run_scanner_corpus("tls")
    case = next(c for c in report["cases"] if c["id"] == "unreachable")

    assert case["inconclusive_delivered"] is True
    assert case["errors"] == []


def test_every_tls_check_has_a_corpus_case():
    from scanners.tls.checks import CHECKS

    report = run_scanner_corpus("tls")
    covered = {
        expected["check_id"] for case in report["cases"] for expected in case.get("expected", [])
    }
    # Two checks have no positive case, and the reasons differ:
    #   tls-weak-cipher - RC4 and 3DES are compiled out of OpenSSL 3, so the lab
    #     cannot serve one at any security level. Verified, not assumed. D11.
    #   tls-no-certificate-transparency - informational, and docs/10-measurement
    #     excludes informational findings from the gate entirely.
    #   tls-no-handshake - inconclusive by construction. It exists to say "there
    #     was no TLS here" and can never be a claim, so it has no expected entry;
    #     the `unreachable` case asserts it via expect_inconclusive instead.
    uncovered = {"tls-weak-cipher", "tls-no-certificate-transparency", "tls-no-handshake"}

    assert set(CHECKS) - uncovered - covered == set()
