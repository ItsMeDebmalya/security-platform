#!/usr/bin/env bash
#
# Fetch testssl.sh, pinned by version and verified by checksum.
#
# testssl.sh is GPLv2. It is NEVER linked, imported, or copied into our tree -
# it runs as a separate process and we read its output (ADR-003, and the CI
# licence check enforces the isolation mode). It has two callers: the corpus
# cross-check (ADR-016), and, since D20, the tls scanner's four legacy-cipher
# checks in Standard mode (core/testssl.py), which run it under an exact
# argument allowlist (D56, ADR-023 amendment).
#
#     tools/fetch-testssl.sh
#
# Installs to tools/bin/, which is gitignored.

set -euo pipefail

VERSION="3.2.4"
SHA256="98528f8a0ac07f1e226efaa8ead438247df8efcb8fee4e056a937ab82a305490"
URL="https://github.com/drwetter/testssl.sh/archive/refs/tags/v${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/tools/bin"
TARGET="${DEST}/testssl.sh-${VERSION}"

if [ -x "${TARGET}/testssl.sh" ]; then
  echo "testssl.sh ${VERSION} already present at ${TARGET}"
  exit 0
fi

mkdir -p "${DEST}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

echo "fetching testssl.sh ${VERSION}"
curl -sSL -o "${tmp}/testssl.tar.gz" "${URL}"

actual="$(sha256sum "${tmp}/testssl.tar.gz" | cut -d' ' -f1)"
if [ "${actual}" != "${SHA256}" ]; then
  echo "checksum mismatch for testssl.sh ${VERSION}" >&2
  echo "  expected ${SHA256}" >&2
  echo "  got      ${actual}" >&2
  echo "Refusing to install. Do not work around this." >&2
  exit 1
fi

tar xzf "${tmp}/testssl.tar.gz" -C "${DEST}"
echo "installed ${TARGET}/testssl.sh"
