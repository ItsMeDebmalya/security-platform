"""F2 / F3: the two checks, over `collected` sections only, with evidence that cites its
section and the receipt line behind it."""

from __future__ import annotations

import ast
import pathlib

import pytest
from host_snapshots import (
    HOST_REF,
    PKG_META,
    PKG_NEW,
    PKG_OLD,
    PKG_OTHER,
    edited,
    make_snapshot,
    outcome,
    run_host_check,
)

SSH = "host-ssh-root-login"
REBOOT = "host-kernel-reboot-pending"


def running_kernel(snap):
    return snap["sections"]["kernel"]["running_release"]


def newest_installed_kernel(snap):
    names = [i["name"] for i in snap["sections"]["packages"]["items"]]
    return max(n for n in names if n.startswith("linux-image-6"))


# --- host-ssh-root-login ----------------------------------------------------------


def test_ssh_root_login_fires_on_permit_yes(positive_snapshot):
    f = run_host_check(SSH, positive_snapshot)
    assert f.severity == "high"
    ev = f.evidence[0]
    assert ev.kind == "command_output"
    assert "prohibit-password" in ev.control_rationale  # the declared expectation
    assert ev.data.output.strip() == "permitrootlogin yes"  # what the snapshot holds
    assert ev.data.receipt_ref.reason_id == "ssh.effective"
    assert ev.data.argv == ["/usr/sbin/sshd", "-T"]
    assert ev.data.host_ref == HOST_REF
    assert f.state != "confirmed"  # one method (spec 9)
    assert f.state == "suspected"
    assert len(f.detection_methods) == 1
    assert f.validation.attempted is False


def test_ssh_evidence_says_how_the_output_was_reduced(positive_snapshot):
    sel = run_host_check(SSH, positive_snapshot).evidence[0].data.output_selection
    assert sel.method == "lines_matching" and "permitrootlogin" in sel.detail
    assert sel.truncated is False and sel.captured_bytes == 4406


def test_ssh_finding_cites_its_section(positive_snapshot):
    f = run_host_check(SSH, positive_snapshot)
    assert "sections.ssh" in f.evidence[0].label
    assert f.location == "$" and f.target.type == "host" and f.target.value == "lab-vm-1"


def test_ssh_root_login_silent_on_clean(clean_snapshot):
    assert run_host_check(SSH, clean_snapshot) is None
    assert outcome(SSH, clean_snapshot) == "clear"


@pytest.mark.parametrize(
    "value", ["no", "prohibit-password", "without-password", "forced-commands-only"]
)
def test_ssh_restricted_values_are_clear(value):
    assert outcome(SSH, make_snapshot(root_login=value)) == "clear"


def test_ssh_unrecognised_value_is_inconclusive_not_clear():
    f = run_host_check(SSH, make_snapshot(root_login="maybe"))
    assert f.state == "inconclusive" and "maybe" in f.description


def test_errored_section_is_inconclusive_not_pass(ssh_errored_snapshot):
    f = run_host_check(SSH, ssh_errored_snapshot)
    assert f.state == "inconclusive"
    assert "error" in f.description and "command_failed:ssh.effective:255" in f.description
    assert outcome(SSH, ssh_errored_snapshot) == "inconclusive"


def test_unavailable_section_is_inconclusive_naming_the_reason():
    f = run_host_check(SSH, make_snapshot(ssh="needs_root"))
    assert f.state == "inconclusive" and "needs_root" in f.description
    assert "unavailable" in f.description


def test_an_inconclusive_ssh_never_reads_as_a_pass_in_the_container_case(container_snapshot):
    # the container exemption is the kernel check's; the ssh check still judges the box
    assert outcome(SSH, container_snapshot) == "clear"


# --- host-kernel-reboot-pending -----------------------------------------------------


def test_reboot_pending_fires_when_installed_newer(positive_snapshot):
    f = run_host_check(REBOOT, positive_snapshot)
    assert f.state == "highly_likely"  # the package-finding ceiling (spec 9)
    running, installed = f.evidence
    assert running_kernel(positive_snapshot) in running.data.output  # control
    assert newest_installed_kernel(positive_snapshot) in installed.data.output  # test
    assert "6.8.0-94-generic" in installed.data.output and "6.8.0-94.96" in installed.data.output
    assert running.data.receipt_ref.reason_id == "kernel.uname"
    assert installed.data.receipt_ref.reason_id == "packages.debian"
    assert installed.data.receipt_ref.command_index == 1
    assert "running" in running.control_rationale and "installed" in installed.control_rationale


def test_reboot_pending_is_never_confirmed_and_has_two_honest_classes(positive_snapshot):
    f = run_host_check(REBOOT, positive_snapshot)
    classes = {m.independence_class for m in f.detection_methods}
    assert len(classes) == 2  # a running-kernel reading and a package-database reading
    assert f.state != "confirmed"
    assert f.validation.attempted is False


def test_reboot_description_states_the_clock_and_does_no_wall_clock_arithmetic(positive_snapshot):
    f = run_host_check(REBOOT, positive_snapshot)
    assert "2026-10-29T09:50:04Z" in f.description
    assert "host clock" in f.description
    for banned in ("ago", "uptime", "days since"):
        assert banned not in f.description


def test_reboot_pending_silent_on_clean(clean_snapshot):
    assert run_host_check(REBOOT, clean_snapshot) is None
    assert outcome(REBOOT, clean_snapshot) == "clear"


def test_meta_package_and_non_kernel_packages_are_not_kernels():
    snap = make_snapshot(packages=[PKG_OLD, PKG_META, PKG_OTHER])
    assert outcome(REBOOT, snap) == "clear"  # linux-image-generic is a meta package


def test_release_numbers_compare_numerically_not_as_strings():
    old = {"name": "linux-image-6.8.0-99-generic", "version": "6.8.0-99.1"}
    new = {"name": "linux-image-6.8.0-100-generic", "version": "6.8.0-100.1"}
    snap = make_snapshot(packages=[old, new], running="6.8.0-99-generic")
    assert outcome(REBOOT, snap) == "reported"


def test_a_newer_upstream_version_outranks_a_higher_abi():
    old = {"name": "linux-image-6.8.0-99-generic", "version": "6.8.0-99.1"}
    new = {"name": "linux-image-6.11.0-2-generic", "version": "6.11.0-2.2"}
    assert (
        outcome(REBOOT, make_snapshot(packages=[old, new], running="6.8.0-99-generic"))
        == "reported"
    )


def test_only_the_running_flavour_is_compared():
    other = {"name": "linux-image-6.8.0-94-aws", "version": "6.8.0-94.96"}
    snap = make_snapshot(packages=[PKG_OLD, other])  # running 6.8.0-90-generic
    assert outcome(REBOOT, snap) == "clear"


def test_running_newer_than_everything_installed_is_clear():
    snap = make_snapshot(packages=[PKG_OLD], running="6.8.0-94-generic")
    assert outcome(REBOOT, snap) == "clear"


def test_unparseable_running_release_is_inconclusive():
    f = run_host_check(REBOOT, make_snapshot(running="weird-kernel"))
    assert f.state == "inconclusive" and "running_release" in f.description


def test_no_installed_kernel_of_the_running_flavour_is_inconclusive_not_clear():
    f = run_host_check(REBOOT, make_snapshot(packages=[PKG_OTHER]))
    assert f.state == "inconclusive" and "no installed kernel" in f.description


def test_reboot_not_applicable_on_container(container_snapshot):
    f = run_host_check(REBOOT, container_snapshot)
    assert f.state == "inconclusive"  # never a pass, never a positive
    assert "not_applicable" in f.description and "shared" in f.description
    assert f.severity == "low"
    assert outcome(REBOOT, container_snapshot) == "inconclusive"


def test_a_container_with_a_newer_package_is_still_not_a_positive(container_snapshot):
    assert container_snapshot["sections"]["packages"]["items"][1] == PKG_NEW
    assert run_host_check(REBOOT, container_snapshot).state != "highly_likely"


def test_unknown_kernel_ownership_is_not_applicable_too():
    f = run_host_check(REBOOT, make_snapshot(packages=[PKG_OLD, PKG_NEW], ownership="unknown"))
    assert f.state == "inconclusive" and "not_applicable" in f.description
    assert "unknown" in f.description


def test_only_own_ownership_runs_the_comparison():
    assert (
        outcome(REBOOT, make_snapshot(packages=[PKG_OLD, PKG_NEW], ownership="own")) == "reported"
    )


def test_packages_section_unavailable_is_inconclusive_naming_the_reason(clean_snapshot):
    def mutate(s):
        s["manifest"][3] = {
            "section": "packages",
            "status": "unavailable",
            "reason": "package_manager_unsupported",
        }
        del s["sections"]["packages"]

    snap = edited(clean_snapshot, mutate)
    snap["counts"]["sections_collected"] -= 1
    snap["counts"]["sections_unavailable"] += 1
    from host_snapshots import rehash

    f = run_host_check(REBOOT, rehash(snap))
    assert f.state == "inconclusive" and "package_manager_unsupported" in f.description


def test_a_non_dpkg_package_manager_is_inconclusive(clean_snapshot):
    snap = edited(clean_snapshot, lambda s: s["sections"]["packages"].update(manager="rpm"))
    f = run_host_check(REBOOT, snap)
    assert f.state == "inconclusive" and "rpm" in f.description


def test_truncated_package_list_is_inconclusive_not_clear(clean_snapshot):
    snap = edited(clean_snapshot, lambda s: s["sections"]["packages"].update(truncated=True))
    f = run_host_check(REBOOT, snap)
    assert f.state == "inconclusive" and "truncated" in f.description


# --- F3: evidence and honesty --------------------------------------------------------


def test_a_missing_receipt_line_is_inconclusive_naming_it(positive_snapshot):
    snap = edited(
        positive_snapshot,
        lambda s: s["receipt"].update(
            commands=[c for c in s["receipt"]["commands"] if c["reason_id"] != "ssh.effective"]
        ),
    )
    f = run_host_check(SSH, snap)
    assert f.state == "inconclusive" and "ssh.effective" in f.description


def test_a_snapshot_without_a_host_fingerprint_is_inconclusive_naming_it():
    f = run_host_check(SSH, make_snapshot(root_login="yes", fingerprint=None))
    assert f.state == "inconclusive" and "machine_id_fingerprint" in f.description


def test_all_unsupported_runtime_is_unassessed_and_named_never_clear():
    from agent import snapshot as agent_snapshot
    from agent.__main__ import unsupported_snapshot

    snap = unsupported_snapshot("2.7.18", "/usr/bin/python")
    snap["host"]["hostname"] = "old-box"
    snap["self_hash"] = agent_snapshot.compute_hash(snap)
    for check in (SSH, REBOOT):
        f = run_host_check(check, snap)
        assert f.state == "inconclusive"
        assert "unassessed" in f.description and "unsupported_runtime" in f.description
        assert "old-box" in f.description and "2.7.18" in f.description
        assert outcome(check, snap) == "inconclusive"


def test_no_check_sets_state_itself():
    root = pathlib.Path(__file__).parents[3] / "scanners" / "host"
    for name in ("checks.py", "scanner.py"):
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword):
                assert node.arg not in {"state", "id"}, f"{name} hand-sets {node.arg}"


def test_the_catalogue_declares_both_checks_passive_and_light():
    from scanners.host.checks import CHECKS

    assert set(CHECKS) == {SSH, REBOOT}
    for c in CHECKS.values():
        assert c.passive is True and c.mode == "light"
        assert c.justification.strip() and c.independence_classes


# --- end to end: a hostile snapshot value reaches a finding and renders inert --------------


def test_a_hostile_snapshot_value_survives_the_whole_path_as_inert_text():
    import json

    from host_snapshots import assess, rehash

    from scanners.host import render

    payload = "<script>alert(1)</script>\x1b[2J"
    snap = make_snapshot(packages=[PKG_OLD, PKG_NEW], root_login="yes")
    snap["sections"]["kernel"]["running_version_string"] = f"Linux 6.8.0-90-generic {payload}"
    result = assess(rehash(snap))
    text = "\n".join(
        e.data.output for f in result.findings for e in f.evidence if hasattr(e.data, "output")
    )
    assert payload in text  # it got in
    assert json.loads(render.to_json(result))["findings"]  # JSON parses
    assert "<script>" not in render.to_html(result) and "\x1b" not in render.to_terminal(result)
    assert b"\x1b" not in render.to_pdf(result)
