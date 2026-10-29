"""E1: no canary secret appears in the snapshot BYTES (spec 6.5), error paths included.

The canaries are ours. They are planted in a fake host tree in every family the project
knows, in places the collector reads, parses, refuses and fails on. The assertion is on
the raw bytes the collector writes, not on the parsed structure.
"""

import json

from agent import collect, snapshot

AWS = "AKIA" + "CANARYAWSKEY0001"[:16]
GITHUB = "ghp_" + "canary" * 6
BEARER = "Bearer " + "canarybearer0123456789"
SLACK = "xoxb-" + "canary-slack-0123456789"
GOOGLE = "AIza" + "CanaryGoogleKey0123456789abcdefghij"[:35]
PEM_BODY = "MIIEcanaryPEMBODYcanary0001"
PEM = f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----"
SSHD_PASSWORD = "hunter2-canary-sshd-password"
ENV_SECRET = "DB_PASSWORD=canary-env-secret-9"
ENV_VALUE = "canary-env-secret-9"

# Values that must not appear anywhere. Token-shaped ones are caught by pattern; the
# password-shaped ones only by never being collected (allowlisted keys, spec 6.1).
CANARIES = (AWS, GITHUB, BEARER, SLACK, GOOGLE, PEM_BODY, SSHD_PASSWORD, ENV_VALUE)


def _bytes(snap):
    return snapshot.dumps(snap).encode("utf-8")


def _assert_clean(snap):
    raw = _bytes(snap)
    for c in CANARIES:
        assert c.encode() not in raw, f"canary leaked: {c[:12]!r}"
    assert snapshot.verify(snap)


def _plant(host):
    host.write("/etc/ssh/sshd_config", f"PermitRootLogin no\nDbPassword {SSHD_PASSWORD}\n# {AWS}\n")
    host.write("/etc/os-release", f'ID=ubuntu\nVERSION_ID="24.04"\nSECRET_TOKEN={GITHUB}\n')
    host.write("/home/u/.env", f"{ENV_SECRET}\n{SLACK}\n")
    host.write("/etc/ssh/ssh_host_ed25519_key", f"{PEM}\n")
    host.write("/root/.aws/credentials", f"aws_access_key_id={AWS}\n")
    host.set_command(
        "sshd",
        f"port 22\npermitrootlogin yes\nbanner {BEARER}\n"
        f"authorizedkeyscommand {GOOGLE}\n{PEM}\n{SSHD_PASSWORD}\n",
    )
    host.set_command("dpkg-query", f"bash\t5.2\nbroken line {GITHUB} {SLACK}\n")


def _run(host, euid=0):
    receipt, runner, reader = host.tools(euid=euid)
    # Refusals: the collector is asked for off-list and excluded paths and argv.
    for path in ("/home/u/.env", "/etc/ssh/ssh_host_ed25519_key", "/root/.aws/credentials"):
        reader.read(str(host.root) + path)
    reader.read("/etc/shadow")
    runner.request(["cat", "/etc/shadow", GITHUB])
    return collect.collect(receipt, runner, reader, hostname="web-1")


def test_no_canary_in_the_snapshot_bytes(host):
    _plant(host)
    _assert_clean(_run(host))


def test_no_canary_when_not_root_refusals_and_unavailable_paths(host):
    _plant(host)
    _assert_clean(_run(host, euid=1000))


def test_no_canary_on_a_command_failure_error_path(host):
    _plant(host)
    host.set_command("sshd", f"{GITHUB}\n{PEM}\n{SSHD_PASSWORD}\n", code=255)
    snap = _run(host)
    assert any(m["status"] == "error" for m in snap["manifest"])
    _assert_clean(snap)


def test_no_canary_on_a_parse_failure_error_path(host):
    # sshd output that lacks the required key: the error must name the key, not quote lines.
    _plant(host)
    host.set_command("sshd", f"port 22\nbanner {BEARER}\n{PEM}\n{SSHD_PASSWORD}\n")
    snap = _run(host)
    ssh = next(m for m in snap["manifest"] if m["section"] == "ssh")
    assert ssh["status"] == "error" and "key_missing_from_output" in ssh["error"]
    _assert_clean(snap)


def test_no_canary_when_a_module_raises_with_a_secret_in_its_message(host, monkeypatch):
    _plant(host)

    def boom(runner, reader):
        raise RuntimeError(f"parse failed at line: {GITHUB} {SSHD_PASSWORD}")

    monkeypatch.setattr(collect.ssh, "collect", boom)
    snap = _run(host)
    _assert_clean(snap)


def test_a_refused_path_records_the_path_and_never_the_content(host):
    _plant(host)
    receipt, _runner, reader = host.tools(euid=0)
    res = reader.read(str(host.root) + "/home/u/.env")
    assert res.status == "refused"
    blob = json.dumps(receipt.to_dict())
    assert ENV_VALUE not in blob and SLACK not in blob


def test_unparsed_config_values_are_never_collected(host):
    # Not a token shape: only the allowlist keeps it out.
    _plant(host)
    snap = _run(host)
    assert SSHD_PASSWORD.encode() not in _bytes(snap)
    assert "dbpassword" not in _bytes(snap).decode().lower()
