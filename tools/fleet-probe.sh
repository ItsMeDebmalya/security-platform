#!/bin/sh
#
# fleet-probe.sh - what Python, if any, is on each host.
#
# The host agent (ADR-035) is a stdlib-only Python collector, and its spec
# currently *assumes* a 3.6 floor: Ubuntu 18.04 ships 3.6.9, RHEL 8 ships
# 3.6.8 at /usr/libexec/platform-python. An assumption is not a fact, and the
# floor decides how much of the language the collector may use. This probe
# replaces the assumption with a count.
#
#     for h in $(cat hosts); do ssh "$h" 'sh -s' < tools/fleet-probe.sh --no-header; done
#
# Deliberately POSIX sh and not Python: the hosts this question is about may be
# exactly the ones without a usable Python, and a probe that needs the thing it
# is looking for answers nothing. No bashisms, no `local`, no `pipefail`
# (neither is POSIX); tested under dash and busybox sh.
#
# It is the smallest rehearsal of the collector's own discipline, and written
# that way on purpose:
#
#   - a fixed list of paths it may read, below, and nothing outside it;
#   - no PATH lookup for the interpreters it checks - absolute paths only, so
#     what it reports is the interpreter the agent would actually get;
#   - /etc/os-release is PARSED, never sourced. Sourcing it executes whatever
#     is in it; a value is text, and stays text (the agent spec's section 13);
#   - an honest `not_found` in the field rather than an empty column or
#     silence. That is the probe's own R2: a fleet report that quietly omits
#     the oldest, least-patched machines is the worst possible failure mode
#     for this product, and those machines are the entire reason to run this.
#
# READ-ONLY. No installation, no network call, nothing written anywhere -
# output goes to stdout only. `--explain` prints the full path list and reads
# nothing at all, so a fleet owner can see what it touches before trusting it.
#
# Output is tab-separated, one line per host, fields in header order. The
# header is a `#` comment so concatenated output from many hosts stays
# parseable; `--no-header` suppresses it for loops.

set -u

PROBE_VERSION="1.0.0"
NOT_FOUND="not_found"
FIELDS="hostname	os_id	os_version_id	python3	platform_python"

# --- the allowlist. Nothing outside this list is read or executed. -----------

# Read, in this order; the first that yields a key wins. Both are the paths the
# os-release specification itself defines, and no others are consulted.
OS_RELEASE_PATHS="/etc/os-release /usr/lib/os-release"

# Read for the host's own name, before falling back to uname.
HOSTNAME_PATH="/etc/hostname"

# Executed with a single read-only argument, `-V`, and nothing else. Absolute
# paths, never PATH: the agent will get these or nothing.
PYTHON3_PATHS="/usr/bin/python3 /usr/local/bin/python3"
PLATFORM_PYTHON_PATHS="/usr/libexec/platform-python"

# Used only if present; a hung interpreter must not hang the fleet sweep.
TIMEOUT_BIN="/usr/bin/timeout"
TIMEOUT_SECS="5"

# --- arguments ---------------------------------------------------------------

root=""
print_header=1
explain=0

usage() {
    echo "usage: fleet-probe.sh [--no-header] [--explain] [--root DIR]" >&2
    echo "  --no-header   omit the '#' header line (for loops over many hosts)" >&2
    echo "  --explain     print every path this probe may read, read nothing" >&2
    echo "  --root DIR    treat DIR as / (for testing; default is /)" >&2
}

while [ $# -gt 0 ]; do
    case $1 in
        --no-header) print_header=0 ;;
        --explain) explain=1 ;;
        --root)
            if [ $# -lt 2 ]; then
                echo "fleet-probe.sh: --root needs a directory" >&2
                exit 2
            fi
            root=$2
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            # An unknown option is a usage error, not a silent default. A probe
            # that ignores what it was asked to do reports something other than
            # what the asker thinks they asked for.
            echo "fleet-probe.sh: unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
    shift
done

if [ "$explain" -eq 1 ]; then
    echo "fleet-probe.sh ${PROBE_VERSION} - read-only. This run reads nothing."
    echo
    echo "Files it may read (and no others):"
    for p in $OS_RELEASE_PATHS; do
        echo "    ${p}          ID and VERSION_ID only, parsed, never sourced"
    done
    echo "    ${HOSTNAME_PATH}            the host's own name; falls back to uname -n"
    echo
    echo "Programs it may execute (absolute paths only, never via PATH),"
    echo "each with the single read-only argument -V and no other:"
    for p in $PYTHON3_PATHS $PLATFORM_PYTHON_PATHS; do
        echo "    ${p} -V"
    done
    echo
    echo "It writes nothing, installs nothing, and makes no network call."
    echo "Any value it cannot read is reported as '${NOT_FOUND}'; any value that"
    echo "is present but not safely printable is reported as 'unparsable'."
    echo "Neither is ever reported as an empty field, because an empty field"
    echo "reads as 'fine' and this probe exists to find the hosts that are not."
    exit 0
fi

# --- helpers ----------------------------------------------------------------

# Reduce a value to something that cannot break the output format or be
# mistaken for a shell word. A tab would add a column and shift every later
# field; a newline would invent a host. Anything outside this set is reported
# as present-but-unparsable, which is a different fact from absent.
sanitise() {
    case $1 in
        "") echo "$NOT_FOUND" ;;
        *[!A-Za-z0-9._+:~^-]*) echo "unparsable" ;;
        *) echo "$1" ;;
    esac
}

# Strip one layer of matching quotes, as os-release permits on values.
unquote() {
    v=$1
    case $v in
        \"*\") v=${v#\"}; v=${v%\"} ;;
        \'*\') v=${v#\'}; v=${v%\'} ;;
    esac
    echo "$v"
}

# Pull one key out of an os-release file WITHOUT sourcing it. Prints the raw
# value, or nothing. The last assignment wins, matching shell semantics without
# running a shell on the file.
os_release_key() {
    file=$1
    key=$2
    found=""
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            "${key}="*) found=${line#"${key}="} ;;
        esac
    done < "$file"
    [ -n "$found" ] && unquote "$found"
}

# `-V` on an allowlisted interpreter. python2 writes its version to stderr and
# python3 to stdout, so both are captured; only the first line is used.
interpreter_version() {
    bin=$1
    [ -x "$bin" ] || return 1
    if [ -x "$TIMEOUT_BIN" ]; then
        out=$("$TIMEOUT_BIN" "$TIMEOUT_SECS" "$bin" -V 2>&1) || return 1
    else
        out=$("$bin" -V 2>&1) || return 1
    fi
    out=$(echo "$out" | head -n 1)
    # "Python 3.6.9" -> "3.6.9"; anything else is passed to sanitise as-is.
    echo "${out#Python }"
}

# The first allowlisted path that answers. Distinguishes "no such file" from
# "the file is there and would not run", because those are different problems
# for whoever has to fix the host.
first_interpreter() {
    any_present=0
    for rel in $1; do
        bin="${root}${rel}"
        if [ -e "$bin" ]; then
            any_present=1
            if ver=$(interpreter_version "$bin"); then
                sanitise "$ver"
                return 0
            fi
        fi
    done
    if [ "$any_present" -eq 1 ]; then
        echo "present_but_failed"
    else
        echo "$NOT_FOUND"
    fi
}

# --- collect ----------------------------------------------------------------

# hostname. /etc/hostname first because reading a file is the smaller act; then
# uname -n, but only for a real run - under a test root, this box's name would
# be a lie about the host being described.
host_name="$NOT_FOUND"
if [ -f "${root}${HOSTNAME_PATH}" ]; then
    if [ -r "${root}${HOSTNAME_PATH}" ]; then
        host_name=$(sanitise "$(head -n 1 "${root}${HOSTNAME_PATH}" 2>/dev/null)")
    else
        host_name="unreadable"
    fi
fi
if [ "$host_name" = "$NOT_FOUND" ] && [ -z "$root" ]; then
    host_name=$(sanitise "$(uname -n 2>/dev/null)")
fi

# ID and VERSION_ID. "The file is there but I could not read it" is recorded as
# `unreadable`, not as absence - R2 again: "I could not look" and "it is not
# there" are different facts and must not collapse into one.
os_id="$NOT_FOUND"
os_version_id="$NOT_FOUND"
for rel in $OS_RELEASE_PATHS; do
    f="${root}${rel}"
    [ -f "$f" ] || continue
    if [ ! -r "$f" ]; then
        [ "$os_id" = "$NOT_FOUND" ] && os_id="unreadable"
        [ "$os_version_id" = "$NOT_FOUND" ] && os_version_id="unreadable"
        continue
    fi
    if [ "$os_id" = "$NOT_FOUND" ] || [ "$os_id" = "unreadable" ]; then
        raw=$(os_release_key "$f" ID) && [ -n "$raw" ] && os_id=$(sanitise "$raw")
    fi
    if [ "$os_version_id" = "$NOT_FOUND" ] || [ "$os_version_id" = "unreadable" ]; then
        raw=$(os_release_key "$f" VERSION_ID) &&
            [ -n "$raw" ] && os_version_id=$(sanitise "$raw")
    fi
done

python3_version=$(first_interpreter "$PYTHON3_PATHS")
platform_python_version=$(first_interpreter "$PLATFORM_PYTHON_PATHS")

# --- report ------------------------------------------------------------------

if [ "$print_header" -eq 1 ]; then
    echo "# fleet-probe.sh ${PROBE_VERSION} (read-only) tab-separated; '${NOT_FOUND}' means absent"
    echo "# ${FIELDS}"
fi

printf '%s\t%s\t%s\t%s\t%s\n' \
    "$host_name" "$os_id" "$os_version_id" \
    "$python3_version" "$platform_python_version"
