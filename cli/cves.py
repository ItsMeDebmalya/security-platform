"""Dependency vulnerability check. Run by CI; fails the build rather than a review.

The companion to `cli/licences.py`: that one asks whether we are *allowed* to
ship a dependency, this one asks whether the version we ship is known to be
broken. D77 recorded that the repository ran **67 days with neither**.

Two things this module exists to get right, both of them failure modes we have
already paid for elsewhere:

1. **It audits the locked set, explicitly.** `pip-audit` with no `-r` audits
   whatever environment it is in. Run under `uvx`, that is pip-audit's own
   environment - which reported "No known vulnerabilities found" while two
   vulnerabilities sat in ours. A gate that reports clean because it looked at
   the wrong thing is worse than no gate: it produces confidence as well. So
   the requirements are exported from `uv.lock` and passed explicitly, and a
   report naming no dependencies is an **error**, never a pass (D39/D63/D67,
   the same shape).

2. **An accepted vulnerability expires.** Every entry in
   `tools/cve-exceptions.yaml` carries a `review_by` date, and the build fails
   after it whether or not the vulnerability is fixed. An exception with no
   expiry is a permanent silent acceptance. An exception for a vulnerability
   that is no longer present also fails, with "remove it", because a stale
   exception misstates the current state of the tree.

Scope, stated rather than implied: the audit covers the **whole locked
dependency graph**, transitive packages included - which is wider than
`cli/licences.py`, and deliberately so, since a vulnerability reaches us
through a transitive package just as well as a direct one. `certifi`, one of
the two found on the first real run, is transitive. What is *enforced* is that
the nine declared runtime dependencies are all present in the audited set; if
they are not, the gate is reporting on something other than what we ship.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, NamedTuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS_PATH = ROOT / "tools" / "cve-exceptions.yaml"
PYPROJECT_PATH = ROOT / "pyproject.toml"

PIP_AUDIT_VERSION = "2.9.0"
"""Pinned. An audit tool that changes under us changes the gate under us."""

REQUIRED_EXCEPTION_FIELDS = frozenset({"id", "package", "reason", "accepted_by", "review_by"})

RUNTIME_DEPENDENCIES = (
    "pydantic",
    "jsonschema",
    "pyyaml",
    "python-ulid",
    "dnspython",
    "httpx",
    "typer",
    "cryptography",
    "idna",
)
"""The nine declared in pyproject.toml. A test asserts this list matches it, so
the two cannot drift apart silently."""


class AuditFinding(NamedTuple):
    package: str
    version: str
    vuln_id: str
    fix: list[str]

    def describe(self) -> str:
        fix = ", ".join(self.fix) if self.fix else "no fixed version published"
        return f"{self.package} {self.version}: {self.vuln_id} (fix: {fix})"


def load_exceptions(path: Path = EXCEPTIONS_PATH) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text()) or {}
    entries = data.get("exceptions") or []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'exceptions' must be a list")
    return entries


def check_exception_shape(entry: dict[str, Any]) -> list[str]:
    """Every field present and meaningful, or the exception is not accepted."""
    problems: list[str] = []
    name = str(entry.get("id", "<no id>"))

    for field in sorted(REQUIRED_EXCEPTION_FIELDS):
        value = entry.get(field)
        if value is None or not str(value).strip():
            problems.append(f"{name}: exception is missing {field}")

    review_by = entry.get("review_by")
    if review_by is not None and str(review_by).strip():
        try:
            _dt.date.fromisoformat(str(review_by))
        except ValueError:
            problems.append(
                f"{name}: review_by {review_by!r} is not an ISO date (YYYY-MM-DD). "
                "An exception without a readable expiry never expires."
            )

    return problems


def parse_audit_report(report: dict[str, Any]) -> list[AuditFinding]:
    """pip-audit's JSON into findings. An empty audit is an error, not a pass."""
    if "dependencies" not in report:
        raise ValueError(
            "pip-audit report has no 'dependencies' key - the audit did not run "
            "as expected, and its silence is not a clean result"
        )
    deps = report["dependencies"]
    if not deps:
        raise ValueError(
            "pip-audit audited no dependencies. This is the near-miss recorded in "
            "D91: run without an explicit requirements file it audits the ambient "
            "environment, which may not be ours. Refusing to report this as clean."
        )

    findings: list[AuditFinding] = []
    for dep in deps:
        for vuln in dep.get("vulns") or []:
            findings.append(
                AuditFinding(
                    package=str(dep["name"]).lower(),
                    version=str(dep.get("version", "?")),
                    vuln_id=str(vuln["id"]),
                    fix=[str(v) for v in (vuln.get("fix_versions") or [])],
                )
            )
    return findings


def missing_runtime_dependencies(audited: set[str]) -> list[str]:
    """R1 for this gate: everything we claim to have checked is present."""
    lowered = {name.lower().replace("_", "-") for name in audited}
    return [dep for dep in RUNTIME_DEPENDENCIES if dep not in lowered]


def apply_exceptions(
    findings: list[AuditFinding],
    exceptions: list[dict[str, Any]],
    *,
    today: str,
) -> tuple[list[str], list[str]]:
    """Return (problems, accepted). An empty problems list means CI may pass."""
    problems: list[str] = []
    accepted: list[str] = []
    now = _dt.date.fromisoformat(today)

    for entry in exceptions:
        problems.extend(check_exception_shape(entry))

    used: set[tuple[str, str]] = set()
    for found in findings:
        match = None
        for entry in exceptions:
            if (
                str(entry.get("id", "")).strip() == found.vuln_id
                and str(entry.get("package", "")).strip().lower() == found.package
            ):
                match = entry
                break

        if match is None:
            problems.append(
                f"{found.describe()} - no exception in {EXCEPTIONS_PATH.name}. "
                "Upgrade it, or accept it there with a reason and an expiry."
            )
            continue

        used.add((found.vuln_id, found.package))
        try:
            review_by = _dt.date.fromisoformat(str(match["review_by"]))
        except (ValueError, KeyError):
            continue  # already reported by check_exception_shape

        if review_by < now:
            problems.append(
                f"{found.describe()} - its exception expired on {review_by}. "
                "An exception that outlives its review date is a silent acceptance."
            )
        else:
            accepted.append(f"{found.describe()} - accepted until {review_by}")

    for entry in exceptions:
        key = (
            str(entry.get("id", "")).strip(),
            str(entry.get("package", "")).strip().lower(),
        )
        if key not in used and all(key):
            problems.append(
                f"{key[0]} ({key[1]}): an exception for a vulnerability that is no "
                "longer reported. Remove it - a stale exception misstates the tree."
            )

    return problems, accepted


def export_locked_requirements(destination: Path) -> None:
    """The locked graph, as a requirements file, so the audit cannot drift."""
    result = subprocess.run(
        [
            "uv",
            "export",
            "--no-hashes",
            "--no-emit-project",
            "--format",
            "requirements-txt",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    destination.write_text(result.stdout)


def run_pip_audit(requirements: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "uvx",
            f"pip-audit=={PIP_AUDIT_VERSION}",
            "--progress-spinner=off",
            "--format",
            "json",
            "-r",
            str(requirements),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if not result.stdout.strip():
        raise ValueError(
            "pip-audit produced no output. Treating that as a failure rather "
            f"than a pass. stderr: {result.stderr.strip()[:2000]}"
        )
    parsed: dict[str, Any] = json.loads(result.stdout)
    return parsed


def declared_runtime_dependencies() -> list[str]:
    data = tomllib.loads(PYPROJECT_PATH.read_text())
    return list(data["project"]["dependencies"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--today",
        default=_dt.date.today().isoformat(),
        help="override today's date (for testing an expiry)",
    )
    args = parser.parse_args()

    requirements = ROOT / ".cve-requirements.txt"
    try:
        export_locked_requirements(requirements)
        report = run_pip_audit(requirements)
        findings = parse_audit_report(report)
    except Exception as exc:  # a gate that cannot run has not passed
        print(f"dependency CVE check: COULD NOT RUN - {exc}", file=sys.stderr)
        return 2
    finally:
        requirements.unlink(missing_ok=True)

    audited = {str(dep["name"]) for dep in report["dependencies"]}
    missing = missing_runtime_dependencies(audited)
    if missing:
        print(
            "dependency CVE check: the audit did not cover "
            f"{', '.join(missing)} - it is not reporting on what we ship",
            file=sys.stderr,
        )
        return 2

    problems, accepted = apply_exceptions(findings, load_exceptions(), today=args.today)

    for line in accepted:
        print(f"  accepted: {line}")
    if problems:
        print(f"dependency CVE check: {len(problems)} problem(s)", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"dependency CVE check: {len(audited)} locked packages audited "
        f"({len(RUNTIME_DEPENDENCIES)} declared runtime), "
        f"{len(accepted)} accepted exception(s), no unaccepted vulnerabilities"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
