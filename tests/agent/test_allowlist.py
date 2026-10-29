"""C1: the allowlists are data, reasoned, read-only, and interpolate nothing."""

import re

import pytest

from agent import allowlist as al

# Independent review set: (binary, leading args) signatures that are query-only.
REVIEWED_READ_ONLY = {
    ("uname", "-srvm"),
    ("dpkg-query", "-W"),
    ("rpm", "-qa"),
    ("ss", "-ltnp"),
    ("systemctl", "list-unit-files"),
    ("sshd", "-T"),
}
FORBIDDEN_TOKENS = {
    "install",
    "remove",
    "purge",
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "mask",
    "unmask",
    "kill",
    "daemon-reload",
    "-i",
    "-e",
    "-U",
    "-F",
    "-D",
    "--install",
    "--erase",
    "--upgrade",
    "curl",
    "wget",
    "nc",
    "sh",
    "bash",
    "-c",
}


def test_entries_exist():
    assert al.COMMANDS and al.FILES and al.EXCLUDED


@pytest.mark.parametrize("e", al.COMMANDS, ids=lambda e: e.reason_id)
def test_command_has_reason_and_limits(e):
    assert e.reason.strip() and e.reason_id.strip() and e.read_for
    assert e.timeout_s > 0 and e.max_bytes > 0
    assert isinstance(e.needs_root, bool)


@pytest.mark.parametrize("e", al.FILES, ids=lambda e: e.reason_id)
def test_file_has_reason_and_keys(e):
    assert e.reason.strip() and e.judged_from.strip() and e.reason_id.strip()
    assert e.keys and e.max_bytes > 0 and e.fmt in ("space", "equals", "bare")


def test_reason_ids_unique():
    ids = [e.reason_id for e in al.COMMANDS] + [e.reason_id for e in al.FILES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("e", al.COMMANDS, ids=lambda e: e.reason_id)
def test_no_verb_outside_the_read_only_set(e):
    assert any(e.argv[: len(sig)] == sig for sig in REVIEWED_READ_ONLY), e.argv
    assert not (set(e.argv[1:]) & FORBIDDEN_TOKENS)


@pytest.mark.parametrize("e", al.COMMANDS, ids=lambda e: e.reason_id)
def test_binary_is_a_bare_name_and_args_are_constants(e):
    assert isinstance(e.argv, tuple) and all(isinstance(a, str) for a in e.argv)
    assert "/" not in e.argv[0]


@pytest.mark.parametrize("e", al.COMMANDS, ids=lambda e: e.reason_id)
def test_nothing_interpolates(e):
    for arg in e.argv:
        if arg in al.NATIVE_FORMATS:
            continue
        assert not re.search(r"[${}%`;|&<>]", arg), arg


def test_native_formats_are_exactly_the_two_query_formats():
    assert set(al.NATIVE_FORMATS) == {al.DPKG_FORMAT, al.RPM_FORMAT}
    assert al.DPKG_FORMAT.startswith("-f=") and al.RPM_FORMAT.startswith("%{NAME}")


def test_bin_dirs_are_fixed_and_absolute():
    assert al.BIN_DIRS == ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec")


def test_exclusions_cover_the_spec_list():
    pats = [p for p, _, _ in al.EXCLUDED]
    for needed in (
        "/etc/ssh/ssh_host_*_key",
        "*.pem",
        "*.key",
        "/etc/shadow*",
        "*/.ssh/*",
        "*/.env",
    ):
        assert needed in pats


def test_no_file_entry_is_itself_excluded():
    from agent.readfile import excluded

    for e in al.FILES:
        assert excluded(e.path.replace("*", "x")) is None
