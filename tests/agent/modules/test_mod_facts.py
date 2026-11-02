"""D1/D2/D4: each module returns facts and a status, from a fake host tree."""

import hashlib

from agent.modules import host_identity, kernel, os_release, packages, ssh


def test_os_release_facts(host):
    _, runner, reader = host.tools()
    out = os_release.collect(runner, reader)
    assert out.status == "collected"
    assert out.body == {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.1 LTS"}


def test_os_release_absent_is_unavailable(host):
    host.remove("/etc/os-release")
    out = os_release.collect(*host.tools()[1:])
    assert out.status == "unavailable" and out.reason == "file_absent"


def test_kernel_running_release_and_own(host):
    out = kernel.collect(*host.tools()[1:])
    assert out.status == "collected"
    assert out.body["running_release"] == "6.8.0-90-generic"
    assert out.body["architecture"] == "x86_64"
    assert out.body["kernel_ownership"] == "own"


def test_kernel_shared_in_a_container(host):
    host.write("/.dockerenv", "")
    out = kernel.collect(*host.tools()[1:])
    assert out.body["kernel_ownership"] == "shared"
    assert out.body["ownership_basis"] == ["container.dockerenv"]


def test_kernel_ownership_unknown_when_a_marker_cannot_be_read(host):
    (host.root / ".dockerenv").symlink_to("/etc/hostname")  # a symlink is refused, not followed
    out = kernel.collect(*host.tools()[1:])
    assert out.body["kernel_ownership"] == "unknown"


def test_kernel_unparseable_uname_is_an_error(host):
    host.set_command("uname", "garbage\n")
    out = kernel.collect(*host.tools()[1:])
    assert out.status == "error"


def test_host_identity_fingerprint_never_the_raw_id(host):
    out = host_identity.collect(*host.tools()[1:], hostname="web-1")
    assert out.status == "collected" and out.body["hostname"] == "web-1"
    fp = out.body["machine_id_fingerprint"]
    assert fp.startswith("sha256:") and len(fp) == len("sha256:") + 16
    assert "0123456789abcdef" not in repr(out.body)
    assert fp != "sha256:" + hashlib.sha256(b"0123456789abcdef0123456789abcdef").hexdigest()[:16]


def test_host_identity_without_machine_id(host):
    host.remove("/etc/machine-id")
    out = host_identity.collect(*host.tools()[1:], hostname="web-1")
    assert out.status == "collected"
    assert out.body["machine_id_fingerprint"] is None


def test_packages_names_and_versions_only(host):
    out = packages.collect(*host.tools()[1:])
    assert out.status == "collected"
    items = out.body["items"]
    assert {"name": "bash", "version": "5.2.21-2ubuntu4"} in items
    assert {"name": "linux-image-6.8.0-100-generic", "version": "6.8.0-100.110"} in items
    assert all(set(i) == {"name", "version"} for i in items)
    assert not any(i["name"] == "ghost" for i in items)  # no version: not installed
    assert out.body["manager"] == "dpkg"


def test_packages_without_dpkg_is_unavailable(host):
    host.remove_command("dpkg-query")
    out = packages.collect(*host.tools()[1:])
    assert out.status == "unavailable" and out.reason == "package_manager_unsupported"


def test_ssh_effective_keys(host):
    out = ssh.collect(*host.tools(euid=0)[1:])
    assert out.status == "collected"
    assert out.body["source"] == "sshd -T"
    assert out.body["permitrootlogin"] == "yes"
    assert out.body["passwordauthentication"] == "no"
    assert "port" not in out.body  # only declared keys are kept


def test_ssh_needs_root(host):
    out = ssh.collect(*host.tools(euid=1000)[1:])
    assert out.status == "unavailable" and out.reason == "needs_root"


def test_ssh_not_installed(host):
    host.remove_command("sshd")
    out = ssh.collect(*host.tools(euid=0)[1:])
    assert out.status == "unavailable" and out.reason == "sshd_not_installed"


def test_ssh_command_failure_is_an_error_not_a_pass(host):
    host.set_command("sshd", "", code=255)
    out = ssh.collect(*host.tools(euid=0)[1:])
    assert out.status == "error" and "255" in out.error


def test_ssh_missing_key_is_an_error(host):
    host.set_command("sshd", "port 22\n")
    out = ssh.collect(*host.tools(euid=0)[1:])
    assert out.status == "error"
