"""The `scan` CLI: what a human and what CI each get out of it."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


@pytest.fixture
def fixtures(tmp_path):
    """A recorded zone: example.com resolves, no-a.example does not."""
    from core.dns import DnsClient, DnsResponse, FakeResolver, RecordingResolver

    answers = {
        ("example.com", "A"): DnsResponse(
            name="example.com",
            rrtype="A",
            rcode="NOERROR",
            records=["93.184.216.34"],
            ttl=300,
        ),
        ("no-a.example", "A"): DnsResponse(
            name="no-a.example",
            rrtype="A",
            rcode="NODATA",
            records=[],
            ttl=300,
        ),
    }
    directory = tmp_path / "fixtures"
    client = DnsClient(
        resolver=RecordingResolver(FakeResolver(answers), directory),
        resolvers=["1.1.1.1", "8.8.8.8"],
    )
    for domain in ("example.com", "no-a.example"):
        client.has_wildcard(domain, "A")
        client.query(domain, "A")
        client.query(domain, "A", resolver="8.8.8.8")
    return directory


def _run(*args):
    return runner.invoke(app, list(args))


# --- listing ----------------------------------------------------------------


def test_list_names_every_registered_scanner():
    result = _run("list")

    assert result.exit_code == 0
    assert "example" in result.stdout


def test_list_reports_versions_and_modes():
    result = _run("list")

    assert "1.0.0" in result.stdout
    assert "light" in result.stdout


def test_list_as_json_is_machine_readable():
    result = _run("list", "--format", "json")

    assert any(s["name"] == "example" for s in json.loads(result.stdout))


# --- running ----------------------------------------------------------------


def test_a_scan_writes_schema_valid_json_to_a_file(fixtures, tmp_path):
    out = tmp_path / "r.json"

    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--mode",
        "light",
        "--replay",
        str(fixtures),
        "--out",
        str(out),
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(out.read_text())
    assert payload["findings"][0]["check_id"] == "example-a-record-missing"


def test_results_go_to_stdout_so_the_command_pipes(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--replay",
        str(fixtures),
        "--format",
        "json",
    )

    assert json.loads(result.stdout)["scanner"] == "example"


def test_the_table_format_is_readable_by_a_human(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--replay",
        str(fixtures),
        "--format",
        "table",
    )

    assert "example-a-record-missing" in result.stdout
    assert "confirmed" in result.stdout


def test_a_clean_target_reports_no_findings(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "example.com",
        "--replay",
        str(fixtures),
        "--format",
        "json",
    )

    assert json.loads(result.stdout)["findings"] == []


def test_an_unknown_scanner_exits_with_an_error(fixtures):
    result = _run("run", "nope", "--target", "example.com", "--replay", str(fixtures))

    assert result.exit_code == 1
    assert "nope" in result.stdout


def test_a_missing_fixture_fails_loudly_rather_than_going_to_the_wire(tmp_path):
    result = _run("run", "example", "--target", "unrecorded.example", "--replay", str(tmp_path))

    assert result.exit_code == 1
    assert "record" in result.stdout.lower()


# --- authorisation ----------------------------------------------------------


def test_standard_mode_is_refused_for_a_target_that_is_not_authorised(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--mode",
        "standard",
        "--replay",
        str(fixtures),
    )

    assert result.exit_code == 1
    assert "authoris" in result.stdout.lower()


def test_light_mode_needs_no_authorisation(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--mode",
        "light",
        "--replay",
        str(fixtures),
    )

    assert result.exit_code == 0


# --- exit codes -------------------------------------------------------------


def test_a_successful_run_with_findings_still_exits_zero_by_default(fixtures):
    result = _run("run", "example", "--target", "no-a.example", "--replay", str(fixtures))

    assert result.exit_code == 0


def test_fail_on_turns_a_finding_at_or_above_that_severity_into_exit_two(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--replay",
        str(fixtures),
        "--fail-on",
        "low",
    )

    assert result.exit_code == 2


def test_fail_on_ignores_findings_below_the_threshold(fixtures):
    result = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--replay",
        str(fixtures),
        "--fail-on",
        "high",
    )

    assert result.exit_code == 0


def test_fail_on_ignores_a_finding_that_is_not_a_claim(fixtures, tmp_path):
    """suspected and inconclusive are hedges, not claims. CI should not break on them."""
    from core.dns import DnsClient, DnsResponse, FakeResolver, RecordingResolver

    answers = {
        ("broken.example", "A"): DnsResponse(
            name="broken.example",
            rrtype="A",
            rcode="SERVFAIL",
            records=[],
            ttl=None,
        )
    }
    directory = tmp_path / "servfail"
    client = DnsClient(
        resolver=RecordingResolver(FakeResolver(answers), directory), resolvers=["1.1.1.1"]
    )
    client.has_wildcard("broken.example", "A")
    client.query("broken.example", "A")

    result = _run(
        "run",
        "example",
        "--target",
        "broken.example",
        "--replay",
        str(directory),
        "--fail-on",
        "low",
    )

    assert result.exit_code == 0


# --- recording --------------------------------------------------------------


def test_a_recorded_run_can_be_replayed_offline(fixtures, tmp_path):
    replayed = _run(
        "run",
        "example",
        "--target",
        "no-a.example",
        "--replay",
        str(fixtures),
        "--format",
        "json",
    )

    assert json.loads(replayed.stdout)["findings"][0]["state"] == "confirmed"
