"""The dependency-vulnerability gate, and in particular the way it can lie.

D77 recorded that this repository ran 67 days with no dependency CVE scanning
at all. The first real run found two vulnerabilities, both of which reach our
threat model. But the run *before* that one reported "No known vulnerabilities
found" - because it audited the wrong environment. That near-miss is what most
of these tests are about: a gate that reports clean because it looked at the
wrong thing is worse than no gate, since it also produces confidence.
"""

from __future__ import annotations

import pytest
import yaml

from cli.cves import (
    EXCEPTIONS_PATH,
    REQUIRED_EXCEPTION_FIELDS,
    AuditFinding,
    apply_exceptions,
    check_exception_shape,
    load_exceptions,
    parse_audit_report,
)


def finding(package="dnspython", version="2.8.0", vuln_id="GHSA-45c3-73f7-pv4m"):
    return AuditFinding(package=package, version=version, vuln_id=vuln_id, fix=["2.9.0"])


def exception(**over):
    base = {
        "id": "GHSA-45c3-73f7-pv4m",
        "package": "dnspython",
        "reason": "We never call dns.name.from_wire_parser on untrusted input.",
        "accepted_by": "Debmalya Dey",
        "review_by": "2099-01-01",
    }
    base.update(over)
    return base


# --- the shipped file ---------------------------------------------------------


def test_the_shipped_exception_file_parses_and_every_entry_is_complete():
    entries = load_exceptions(EXCEPTIONS_PATH)
    for entry in entries:
        assert check_exception_shape(entry) == [], entry


def test_the_shipped_exception_list_is_empty_and_that_is_the_goal_state():
    """If this fails, someone added an exception. Read it, do not delete it."""
    assert load_exceptions(EXCEPTIONS_PATH) == []


# --- the gate's own arithmetic ------------------------------------------------


def test_a_finding_with_no_exception_fails_the_build():
    problems, accepted = apply_exceptions([finding()], [], today="2026-10-28")

    assert accepted == []
    assert len(problems) == 1
    assert "GHSA-45c3-73f7-pv4m" in problems[0]


def test_an_exception_suppresses_exactly_its_own_finding():
    problems, accepted = apply_exceptions([finding()], [exception()], today="2026-10-28")

    assert problems == []
    assert len(accepted) == 1


def test_an_exception_for_one_package_does_not_cover_another():
    """The id is matched together with the package, so a reused id cannot leak.

    Two problems are expected and both are right: the certifi finding is
    unaccepted, and the dnspython exception is now stale. The test asserts the
    first one specifically rather than counting, so it cannot pass for the
    wrong reason.
    """
    problems, accepted = apply_exceptions(
        [finding(package="certifi", version="2026.7.22")],
        [exception()],
        today="2026-10-28",
    )

    assert accepted == []
    assert any("certifi" in p and "no exception" in p for p in problems), problems


def test_an_expired_exception_fails_even_though_it_matches():
    problems, accepted = apply_exceptions(
        [finding()], [exception(review_by="2026-10-27")], today="2026-10-28"
    )

    assert accepted == []
    assert len(problems) == 1
    assert "expired" in problems[0].lower()


def test_an_exception_expiring_today_is_still_valid():
    problems, _ = apply_exceptions(
        [finding()], [exception(review_by="2026-10-28")], today="2026-10-28"
    )

    assert problems == []


def test_a_stale_exception_fails_the_build_rather_than_sitting_there():
    """The vulnerability is gone. The exception now misstates the tree."""
    problems, _ = apply_exceptions([], [exception()], today="2026-10-28")

    assert len(problems) == 1
    assert "no longer" in problems[0].lower() or "remove" in problems[0].lower()


@pytest.mark.parametrize("missing", sorted(REQUIRED_EXCEPTION_FIELDS))
def test_an_incomplete_exception_is_rejected_not_quietly_accepted(missing):
    entry = exception()
    del entry[missing]

    problems = check_exception_shape(entry)

    assert problems, f"a missing {missing} was accepted"


def test_an_unparseable_review_date_is_rejected():
    assert check_exception_shape(exception(review_by="soon"))
    assert check_exception_shape(exception(review_by="28-10-2026"))


def test_an_empty_reason_is_rejected():
    assert check_exception_shape(exception(reason="   "))


# --- parsing pip-audit's report ----------------------------------------------


def test_parses_a_real_shaped_report():
    report = {
        "dependencies": [
            {"name": "pydantic", "version": "2.13.4", "vulns": []},
            {
                "name": "dnspython",
                "version": "2.8.0",
                "vulns": [
                    {"id": "GHSA-45c3-73f7-pv4m", "fix_versions": ["2.9.0"]},
                ],
            },
        ]
    }

    findings = parse_audit_report(report)

    assert len(findings) == 1
    assert findings[0].package == "dnspython"
    assert findings[0].vuln_id == "GHSA-45c3-73f7-pv4m"


def test_a_package_with_two_vulnerabilities_yields_two_findings():
    report = {
        "dependencies": [
            {
                "name": "x",
                "version": "1",
                "vulns": [{"id": "A", "fix_versions": []}, {"id": "B"}],
            }
        ]
    }

    assert len(parse_audit_report(report)) == 2


def test_an_empty_dependency_list_is_an_error_not_a_clean_report():
    """THE near-miss, as a test.

    pip-audit run without `-r` audits whatever environment it happens to be in.
    Under `uvx` that is pip-audit's own environment, which reported "No known
    vulnerabilities found" while two sat in ours. A report naming no
    dependencies at all means the audit looked at the wrong thing, and the one
    thing it must not do is read as clean.
    """
    with pytest.raises(ValueError, match="no dependencies"):
        parse_audit_report({"dependencies": []})


def test_a_report_missing_the_dependencies_key_is_an_error():
    with pytest.raises(ValueError):
        parse_audit_report({})


def test_the_audit_must_cover_every_runtime_dependency():
    """R1, applied to this gate: everything claimed is present.

    If the audited set does not contain our declared runtime dependencies, the
    gate is reporting on something other than what we ship.
    """
    import tomllib
    from pathlib import Path

    from cli.cves import missing_runtime_dependencies

    pyproject = tomllib.loads(Path("pyproject.toml").read_text())
    declared = pyproject["project"]["dependencies"]
    assert len(declared) == 9, "the count in D77 and the gate's docstring moved"

    audited = {"pydantic", "jsonschema", "pyyaml", "python-ulid", "dnspython"}
    missing = missing_runtime_dependencies(audited)

    assert "httpx" in missing and "typer" in missing
    assert "pydantic" not in missing


def test_nothing_is_missing_when_all_nine_are_audited():
    from cli.cves import RUNTIME_DEPENDENCIES, missing_runtime_dependencies

    assert missing_runtime_dependencies(set(RUNTIME_DEPENDENCIES)) == []


def test_runtime_dependency_list_matches_pyproject():
    """The list in the gate cannot drift from the one we actually declare."""
    import tomllib
    from pathlib import Path

    from cli.cves import RUNTIME_DEPENDENCIES

    pyproject = tomllib.loads(Path("pyproject.toml").read_text())
    declared = set()
    for spec in pyproject["project"]["dependencies"]:
        name = spec.split(";")[0]
        for sep in (">=", "==", "<=", "~=", ">", "<", "["):
            name = name.split(sep)[0]
        declared.add(name.strip().lower())

    assert declared == set(RUNTIME_DEPENDENCIES)


def test_the_exception_file_documents_every_required_field():
    text = EXCEPTIONS_PATH.read_text()
    for field in REQUIRED_EXCEPTION_FIELDS:
        assert field in text, f"{field} is enforced but not documented"
    parsed = yaml.safe_load(text)
    assert "exceptions" in parsed
