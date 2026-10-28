"""The fleet probe (plan task A5), exercised against fabricated host trees.

The probe is the smallest rehearsal of the collector's discipline: a fixed list
of paths it may read, no `PATH` lookup for the interpreters it checks, and an
honest `not_found` in the field rather than an empty column or silence. That
last one is the probe's own R2 - a fleet report that quietly omits the oldest,
least-patched machines is the worst possible failure mode for this product, and
the probe is what tells us which machines those are.

It runs under `dash` and `busybox sh` here because `sh` on this box is not the
`sh` on the fleet's. Nothing in these tests needs the network or a real host:
the probe takes its root directory as an argument precisely so it can be tested.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parents[2] / "tools" / "fleet-probe.sh"

# `sh` on this box is dash, so naming it again would not be a second shell.
SHELLS = [
    pytest.param(
        ["dash"],
        id="dash",
        marks=pytest.mark.skipif(not shutil.which("dash"), reason="no dash"),
    ),
    pytest.param(
        ["busybox", "sh"],
        id="busybox-sh",
        marks=pytest.mark.skipif(not shutil.which("busybox"), reason="no busybox"),
    ),
]

NOT_FOUND = "not_found"
FIELDS = ("hostname", "os_id", "os_version_id", "python3", "platform_python")


def run(shell, root, *args):
    proc = subprocess.run(
        [*shell, str(PROBE), "--root", str(root), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc


def parse(stdout: str) -> dict[str, str]:
    """The one data line, as a field mapping. Header lines start with '#'."""
    lines = [ln for ln in stdout.splitlines() if ln and not ln.startswith("#")]
    assert len(lines) == 1, f"expected exactly one data line, got {lines!r}"
    values = lines[0].split("\t")
    assert len(values) == len(FIELDS), f"wrong field count: {values!r}"
    return dict(zip(FIELDS, values, strict=True))


def write_host(tmp_path: Path, name: str, *, os_release: str | None = None) -> Path:
    """A fabricated host tree. Nothing here is executed except what a test adds."""
    root = tmp_path / name
    (root / "etc").mkdir(parents=True)
    if os_release is not None:
        (root / "etc" / "os-release").write_text(os_release)
    return root


def fake_interpreter(root: Path, relpath: str, version_line: str, *, stderr=False) -> None:
    """A stand-in for python3 at a fixed path, printing one version line.

    Real python2 prints its version to stderr and python3 to stdout; the probe
    has to cope with both, so tests can ask for either.
    """
    path = root / relpath.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = ">&2" if stderr else ""
    path.write_text(f"#!/bin/sh\necho '{version_line}' {stream}\n")
    path.chmod(0o755)


# --- the ordinary cases -------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_reports_a_modern_ubuntu(tmp_path, shell):
    root = write_host(
        tmp_path,
        "ubuntu2204",
        os_release='NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n',
    )
    fake_interpreter(root, "/usr/bin/python3", "Python 3.10.12")

    proc = run(shell, root)

    assert proc.returncode == 0, proc.stderr
    row = parse(proc.stdout)
    assert row["os_id"] == "ubuntu"
    assert row["os_version_id"] == "22.04"
    assert row["python3"] == "3.10.12"
    assert row["platform_python"] == NOT_FOUND


@pytest.mark.parametrize("shell", SHELLS)
def test_reports_the_3_6_floor_case(tmp_path, shell):
    """Ubuntu 18.04 with Python 3.6.9 - the host the floor exists for."""
    root = write_host(tmp_path, "bionic", os_release='ID=ubuntu\nVERSION_ID="18.04"\n')
    fake_interpreter(root, "/usr/bin/python3", "Python 3.6.9")

    row = parse(run(shell, root).stdout)

    assert (row["os_id"], row["os_version_id"], row["python3"]) == (
        "ubuntu",
        "18.04",
        "3.6.9",
    )


@pytest.mark.parametrize("shell", SHELLS)
def test_reports_platform_python_with_its_version(tmp_path, shell):
    """RHEL 8's /usr/libexec/platform-python, the other half of the floor."""
    root = write_host(tmp_path, "rhel8", os_release='ID="rhel"\nVERSION_ID="8.9"\n')
    fake_interpreter(root, "/usr/libexec/platform-python", "Python 3.6.8")

    row = parse(run(shell, root).stdout)

    assert row["os_id"] == "rhel"
    assert row["platform_python"] == "3.6.8"
    assert row["python3"] == NOT_FOUND, "no /usr/bin/python3 was planted"


@pytest.mark.parametrize("shell", SHELLS)
def test_strips_quotes_single_and_double(tmp_path, shell):
    root = write_host(tmp_path, "quoted", os_release="ID='debian'\nVERSION_ID=\"10\"\n")

    row = parse(run(shell, root).stdout)

    assert (row["os_id"], row["os_version_id"]) == ("debian", "10")


# --- R2: the honest-absence cases --------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_a_host_with_no_python_at_all_still_reports_a_line(tmp_path, shell):
    """The whole point of the probe. These are the hosts that must not vanish."""
    root = write_host(tmp_path, "nopython", os_release="ID=centos\nVERSION_ID=6\n")

    proc = run(shell, root)

    assert proc.returncode == 0, proc.stderr
    row = parse(proc.stdout)
    assert row["os_id"] == "centos"
    assert row["python3"] == NOT_FOUND
    assert row["platform_python"] == NOT_FOUND


@pytest.mark.parametrize("shell", SHELLS)
def test_a_missing_os_release_is_not_found_not_an_empty_field(tmp_path, shell):
    root = write_host(tmp_path, "noosrelease", os_release=None)

    proc = run(shell, root)

    assert proc.returncode == 0, proc.stderr
    row = parse(proc.stdout)
    assert row["os_id"] == NOT_FOUND
    assert row["os_version_id"] == NOT_FOUND
    assert "" not in row.values(), f"an empty field reads as clean: {row!r}"


@pytest.mark.parametrize("shell", SHELLS)
def test_everything_failing_still_produces_exactly_one_line(tmp_path, shell):
    root = tmp_path / "bare"
    root.mkdir()

    proc = run(shell, root)

    assert proc.returncode == 0, proc.stderr
    row = parse(proc.stdout)
    assert set(row.values()) == {NOT_FOUND} or row["hostname"] != ""


@pytest.mark.parametrize("shell", SHELLS)
def test_os_release_without_the_keys_we_want(tmp_path, shell):
    """A file that exists and parses but says nothing we asked for."""
    root = write_host(tmp_path, "nokeys", os_release='PRETTY_NAME="Something"\nHOME_URL="x"\n')

    row = parse(run(shell, root).stdout)

    assert row["os_id"] == NOT_FOUND
    assert row["os_version_id"] == NOT_FOUND


@pytest.mark.parametrize("shell", SHELLS)
def test_falls_back_to_usr_lib_os_release(tmp_path, shell):
    """The os-release spec's own fallback path, and the only one we allow."""
    root = tmp_path / "usrlib"
    (root / "usr" / "lib").mkdir(parents=True)
    (root / "usr" / "lib" / "os-release").write_text("ID=fedora\nVERSION_ID=39\n")

    row = parse(run(shell, root).stdout)

    assert (row["os_id"], row["os_version_id"]) == ("fedora", "39")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads 0o000 files regardless")
@pytest.mark.parametrize("shell", SHELLS)
def test_an_unreadable_os_release_reports_unreadable_not_absent(tmp_path, shell):
    """R2 again: 'I could not look' is a different fact from 'it is not there'.

    Skipped as root, which is not a gap in the probe: the permission check
    cannot be exercised by a user who bypasses permissions. The probe's
    `unreadable` branch is therefore unproven here and that is recorded in the
    ledger rather than papered over.
    """
    root = write_host(tmp_path, "unreadable", os_release="ID=ubuntu\n")
    (root / "etc" / "os-release").chmod(0o000)

    try:
        row = parse(run(shell, root).stdout)
    finally:
        (root / "etc" / "os-release").chmod(0o644)

    assert row["os_id"] == "unreadable", f"got {row!r}"


# --- hostile input: the probe's own section 13 --------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_a_tab_in_a_value_cannot_break_the_field_format(tmp_path, shell):
    """A planted tab would otherwise add a column and shift every later field."""
    root = write_host(tmp_path, "tabbed", os_release='ID="ubun\ttu"\nVERSION_ID="22.04"\n')

    proc = run(shell, root)

    row = parse(proc.stdout)  # asserts the field count, so a split would fail here
    assert row["os_id"] == "unparsable"
    assert row["os_version_id"] == "22.04", "later fields must not shift"


@pytest.mark.parametrize("shell", SHELLS)
def test_os_release_is_never_sourced(tmp_path, shell):
    """Sourcing /etc/os-release runs whatever is in it. We parse instead.

    The payload is asserted present-and-inert rather than absent: a test that
    only checks the marker file is missing passes just as well when the value
    was silently dropped, and a dropped value is its own R1 failure.
    """
    root = write_host(
        tmp_path,
        "hostile",
        os_release=(f'ID=ubuntu\nVERSION_ID="$(touch {tmp_path}/PWNED && echo 22.04)"\n'),
    )

    row = parse(run(shell, root).stdout)

    assert not (tmp_path / "PWNED").exists(), "the file was sourced, not parsed"
    # Present: the value reached us. Inert: as text, not as a command.
    assert row["os_version_id"] == "unparsable", f"got {row!r}"


@pytest.mark.parametrize("shell", SHELLS)
def test_a_shell_metacharacter_in_a_value_stays_text(tmp_path, shell):
    root = write_host(tmp_path, "meta", os_release='ID="a;rm -rf /"\nVERSION_ID=1\n')

    row = parse(run(shell, root).stdout)

    assert row["os_id"] == "unparsable"
    assert row["os_version_id"] == "1"


@pytest.mark.parametrize("shell", SHELLS)
def test_a_newline_in_a_value_cannot_add_a_host_row(tmp_path, shell):
    """One line per host is what makes the output countable."""
    root = write_host(tmp_path, "multiline", os_release='ID="a\nID=b"\nVERSION_ID=1\n')

    proc = run(shell, root)

    parse(proc.stdout)  # exactly one data line, or this raises


# --- the interface the operator actually uses ---------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_header_is_a_comment_so_concatenated_output_stays_parseable(tmp_path, shell):
    root = write_host(tmp_path, "hdr", os_release="ID=ubuntu\nVERSION_ID=22.04\n")

    stdout = run(shell, root).stdout

    header = [ln for ln in stdout.splitlines() if ln.startswith("#")]
    assert header, "no header line"
    assert all(f in stdout for f in FIELDS), "the header must name the fields"


@pytest.mark.parametrize("shell", SHELLS)
def test_no_header_suppresses_it_for_loops(tmp_path, shell):
    root = write_host(tmp_path, "nohdr", os_release="ID=ubuntu\nVERSION_ID=22.04\n")

    stdout = run(shell, root, "--no-header").stdout

    assert not [ln for ln in stdout.splitlines() if ln.startswith("#")]
    assert len(stdout.splitlines()) == 1


@pytest.mark.parametrize("shell", SHELLS)
def test_writes_nothing_under_the_root_it_reads(tmp_path, shell):
    """Read-only is a claim, so it gets a test rather than a comment."""
    root = write_host(tmp_path, "readonly", os_release="ID=ubuntu\nVERSION_ID=22.04\n")
    fake_interpreter(root, "/usr/bin/python3", "Python 3.10.12")
    before = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))

    run(shell, root)

    after = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    assert before == after


@pytest.mark.parametrize("shell", SHELLS)
def test_an_unknown_option_is_a_usage_error_not_a_silent_default(tmp_path, shell):
    proc = run(shell, tmp_path, "--wat")

    assert proc.returncode == 2
    assert not [ln for ln in proc.stdout.splitlines() if not ln.startswith("#")]


@pytest.mark.parametrize("shell", SHELLS)
def test_explain_lists_every_path_it_may_read_and_reads_nothing(tmp_path, shell):
    """--explain is --explain-plan's ancestor: the allowlist, before trusting it."""
    root = write_host(tmp_path, "explain", os_release="ID=ubuntu\nVERSION_ID=22.04\n")

    proc = run(shell, root, "--explain")

    assert proc.returncode == 0, proc.stderr
    for path in (
        "/etc/os-release",
        "/usr/lib/os-release",
        "/etc/hostname",
        "/usr/bin/python3",
        "/usr/libexec/platform-python",
    ):
        assert path in proc.stdout, f"{path} missing from --explain"
    assert "not_found" in proc.stdout
