# The single home of the runtime floor and the format constants (spec 3.2).
# Written in a dialect Python 2.7 can parse: the entry shim imports it before
# it knows whether the interpreter is new enough for anything else.

FLOOR = (3, 6)
"""Minimum Python 3 the real collector supports. Change here and in the floor
test's feature_version only (they read this constant)."""

SNAPSHOT_VERSION = 1
SCHEMA = "security-platform/host-snapshot"
COLLECTOR_VERSION = "0.1.0"

# Sections the manifest declares. Later tasks extend this tuple.
SECTIONS = ("os_release", "kernel", "host_identity", "packages", "ssh")

# Where an interpreter may be looked for (recorded in an unsupported-runtime snapshot).
SEARCHED = ("/usr/bin/python3", "/usr/libexec/platform-python", "/usr/bin/python")
