"""The collector's allowlists (spec 5), as DATA. Python 3.6 floor, stdlib only.

An exact allowlist, a reason per entry, enforced at runtime (agent/run.py,
agent/readfile.py). Nothing here is computed from collected data: every argument
and path is a constant, so an allowlist cannot become a shell.
"""

from typing import NamedTuple, Tuple

# Fixed binary directories (spec 5.1). Never PATH.
BIN_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec")

# The query-format arguments that are tool-native placeholders (dpkg-query, rpm).
# They are the only arguments allowed to contain $ { } %; the test pins this set.
DPKG_FORMAT = "-f=${Package}\t${Version}\n"
RPM_FORMAT = "%{NAME}\t%{VERSION}-%{RELEASE}\n"
NATIVE_FORMATS = (DPKG_FORMAT, RPM_FORMAT)


class CommandEntry(NamedTuple):
    reason_id: str
    argv: Tuple[str, ...]  # argv[0] is a bare binary name, resolved in BIN_DIRS
    reason: str  # why it is needed
    read_for: Tuple[str, ...]  # snapshot sections it feeds
    timeout_s: float
    max_bytes: int  # stdout cap; beyond it output is dropped and the truncation recorded
    needs_root: bool = False
    nonzero_ok: bool = False  # a non-zero exit is expected on some systems


class FileEntry(NamedTuple):
    reason_id: str
    path: str  # exact path, or a directory + fnmatch pattern in the final component
    reason: str
    judged_from: str  # what the platform will judge from it
    keys: Tuple[str, ...]  # the only keys that may be extracted
    fmt: str  # "space" (key value), "equals" (key=value) or "bare" (first line, kept as keys[0])
    max_bytes: int
    needs_root: bool = False


KB = 1024
MB = 1024 * 1024

COMMANDS = (
    CommandEntry(
        "kernel.uname",
        ("uname", "-srvm"),
        "Kernel release and architecture.",
        ("kernel",),
        5,
        4 * KB,
    ),
    CommandEntry(
        "packages.debian",
        ("dpkg-query", "-W", DPKG_FORMAT),
        "Installed package names and versions on Debian family hosts.",
        ("packages",),
        30,
        8 * MB,
        nonzero_ok=True,
    ),
    CommandEntry(
        "packages.rpm",
        ("rpm", "-qa", "--qf", RPM_FORMAT),
        "Installed package names and versions on RPM family hosts.",
        ("packages",),
        30,
        8 * MB,
        nonzero_ok=True,
    ),
    CommandEntry(
        "listening.ss",
        ("ss", "-ltnp"),
        "Listening TCP sockets.",
        ("listening",),
        10,
        MB,
        nonzero_ok=True,
    ),
    CommandEntry(
        "services.systemd",
        ("systemctl", "list-unit-files", "--type=service", "--no-pager"),
        "Installed service unit files and their enablement.",
        ("services",),
        10,
        MB,
        nonzero_ok=True,
    ),
    CommandEntry(
        "ssh.effective",
        ("sshd", "-T"),
        "Effective sshd configuration.",
        ("ssh",),
        10,
        256 * KB,
        needs_root=True,
        nonzero_ok=True,
    ),
)

FILES = (
    FileEntry(
        "host.machine_id",
        "/etc/machine-id",
        "Host identity, kept only as a one-way fingerprint (never the raw id).",
        "which host a snapshot came from",
        ("machine_id",),
        "bare",
        256,
    ),
    FileEntry(
        "container.dockerenv",
        "/.dockerenv",
        "Marker that the host is a container (a container shares its host's kernel).",
        "whether the running kernel is the box's own",
        ("marker",),
        "bare",
        4 * KB,
    ),
    FileEntry(
        "container.podman",
        "/run/.containerenv",
        "Marker that the host is a container (a container shares its host's kernel).",
        "whether the running kernel is the box's own",
        ("marker",),
        "bare",
        4 * KB,
    ),
    FileEntry(
        "container.systemd",
        "/run/systemd/container",
        "Container type recorded by systemd (a container shares its host's kernel).",
        "whether the running kernel is the box's own",
        ("marker",),
        "bare",
        256,
    ),
    FileEntry(
        "os.release",
        "/etc/os-release",
        "Distribution identity.",
        "which advisory feed applies",
        ("ID", "ID_LIKE", "NAME", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME"),
        "equals",
        16 * KB,
    ),
    FileEntry(
        "ssh.config",
        "/etc/ssh/sshd_config",
        "sshd settings as configured.",
        "SSH hardening posture",
        ("PermitRootLogin", "PasswordAuthentication", "X11Forwarding", "PermitEmptyPasswords"),
        "space",
        64 * KB,
    ),
    FileEntry(
        "ssh.config_d",
        "/etc/ssh/sshd_config.d/*.conf",
        "sshd drop-in settings.",
        "SSH hardening posture",
        ("PermitRootLogin", "PasswordAuthentication", "X11Forwarding", "PermitEmptyPasswords"),
        "space",
        64 * KB,
    ),
)

# Explicitly excluded, here so the exclusion is reviewable (spec 5.2).
# (fnmatch pattern against the full path, refusal code, why). Presence/mode of
# these is recorded elsewhere, never a byte of content.
EXCLUDED = (
    ("/etc/ssh/ssh_host_*_key", "excluded_private_key", "SSH host private keys"),
    ("*.pem", "excluded_private_key", "PEM key or certificate bundles"),
    ("*.key", "excluded_private_key", "private key files"),
    ("/etc/shadow*", "excluded_by_allowlist", "password hashes"),
    ("/etc/gshadow*", "excluded_by_allowlist", "group password hashes"),
    ("*/.ssh/*", "excluded_by_allowlist", "per-user SSH material"),
    ("*/.env", "excluded_by_allowlist", "environment files"),
    ("*/.env.*", "excluded_by_allowlist", "environment files"),
    ("*/.aws/*", "excluded_by_allowlist", "cloud credential files"),
    ("*/.config/gcloud/*", "excluded_by_allowlist", "cloud credential files"),
    ("*/.azure/*", "excluded_by_allowlist", "cloud credential files"),
    ("*/.kube/config", "excluded_by_allowlist", "cluster credentials"),
    ("*/.docker/config.json", "excluded_by_allowlist", "registry tokens"),
    ("*/.netrc", "excluded_by_allowlist", "stored credentials"),
    ("*/.git-credentials", "excluded_by_allowlist", "stored credentials"),
)
