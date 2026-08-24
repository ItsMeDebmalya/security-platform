#!/usr/bin/env bash
#
# Authorise a domain you control for Standard/Deep mode scanning.
#
#   scripts/authorise-domain.sh codez.in
#   scripts/authorise-domain.sh codez.in --dry-run     # show, write nothing
#
# What it does, in order:
#   1. generates a single-use nonce and tells you exactly what to publish
#   2. WAITS, polling until it sees that nonce from two independent resolvers
#   3. only then writes the proof file and the authorisation row
#
# Step 3 never happens without step 2. That ordering is the whole point: the
# row in config/authorised_scope.yaml is the record produced if anyone asks by
# what right we touched a system, and it must not exist before the thing it
# asserts is true. See docs/09-ownership-verification.md.

set -euo pipefail

RESOLVER_A="1.1.1.1"
RESOLVER_B="8.8.8.8"
POLL_SECONDS="${SP_AUTHZ_POLL:-15}"
TIMEOUT_SECONDS="${SP_AUTHZ_TIMEOUT:-1800}"   # override when your DNS propagates fast
VALID_DAYS=90

die() { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[36m%s\033[0m\n' "$*"; }

# --- arguments --------------------------------------------------------------

DOMAIN="${1:-}"
DRY_RUN=0
[ "${2:-}" = "--dry-run" ] && DRY_RUN=1

[ -n "$DOMAIN" ] || die "usage: $0 <domain> [--dry-run]"

case "$DOMAIN" in
  *.example|*.test|*.invalid|*.localhost)
    die "$DOMAIN is an RFC 2606 reserved name; it cannot be verified by DNS.
       Reserved and loopback targets use method: self_owned instead - see
       the rows already in config/authorised_scope.yaml." ;;
esac

# --- preflight --------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCOPE="config/authorised_scope.yaml"
[ -f "$SCOPE" ] || die "$SCOPE not found. Run this from the repository."

command -v dig >/dev/null 2>&1 || die "dig is not installed.
       On Ubuntu/WSL:  sudo apt update && sudo apt install -y dnsutils"

if grep -q "value: $DOMAIN\b" "$SCOPE" 2>/dev/null; then
  die "$DOMAIN already appears in $SCOPE.
       To re-verify, remove the old row in a reviewed commit first - the file
       is append-only history, so removals should be deliberate."
fi

TODAY="$(date +%F)"
EXPIRES="$(date -d "+${VALID_DAYS} days" +%F)"
NONCE="sp-verify=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RECORD_NAME="_scanverify.${DOMAIN}"
PROOF_FILE="corpus/authz/${DOMAIN}-${TODAY}.txt"
AUTHZ_ID="authz_${TODAY}-$(printf '%03d' $(( ( RANDOM % 899 ) + 100 )))"

# --- 1. tell the operator what to publish -----------------------------------

cat <<EOF

  ┌──────────────────────────────────────────────────────────────────────────┐
  │  Publish this TXT record in the DNS zone for ${DOMAIN}
  └──────────────────────────────────────────────────────────────────────────┘

      Type   : TXT
      Name   : _scanverify
               (most control panels want just the label. If yours wants the
                full name, use: ${RECORD_NAME})
      Value  : ${NONCE}
      TTL    : 300  (or the lowest your provider allows)

  The nonce is single-use and generated fresh for this run. You can delete the
  record once verification succeeds.

EOF

if [ "$DRY_RUN" = "1" ]; then
  say "--dry-run: showing what would be written, then stopping."
  echo
  echo "--- would write ${PROOF_FILE} ---"
  echo "# Proof of control for ${DOMAIN}"
  echo "# Method: dns_txt   Nonce: ${NONCE}"
  echo "# (the two dig transcripts would follow)"
  echo
  echo "--- would append to ${SCOPE} ---"
  echo "- authz_id: ${AUTHZ_ID}"
  echo "  target: { type: domain, value: ${DOMAIN}, wildcard: false }"
  echo "  verified_at: ${TODAY}"
  echo "  expires_at: ${EXPIRES}"
  exit 0
fi

# --- 2. wait for it, and refuse to continue without it ----------------------

say "Waiting for the record to appear. Ctrl-C to abort."
echo "  polling ${RECORD_NAME} every ${POLL_SECONDS}s via ${RESOLVER_A} and ${RESOLVER_B}"
echo

seen_at=""
deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))

while [ "$(date +%s)" -lt "$deadline" ]; do
  a="$(dig +short TXT "$RECORD_NAME" "@${RESOLVER_A}" 2>/dev/null | tr -d '"' || true)"
  b="$(dig +short TXT "$RECORD_NAME" "@${RESOLVER_B}" 2>/dev/null | tr -d '"' || true)"

  if printf '%s' "$a" | grep -qF "$NONCE" && printf '%s' "$b" | grep -qF "$NONCE"; then
    seen_at="$(date -Iseconds)"
    printf '\033[32m  seen from both resolvers.\033[0m\n\n'
    break
  fi

  if printf '%s' "$a" | grep -qF "$NONCE"; then
    echo "  $(date +%H:%M:%S)  ${RESOLVER_A} yes, ${RESOLVER_B} not yet (propagating)"
  else
    echo "  $(date +%H:%M:%S)  not visible yet"
  fi
  sleep "$POLL_SECONDS"
done

[ -n "$seen_at" ] || die "gave up after ${TIMEOUT_SECONDS}s without seeing the nonce.
       Nothing was written. Check the record with:
           dig TXT ${RECORD_NAME} @${RESOLVER_A}"

# --- 3. capture the proof, then write the row -------------------------------

{
  echo "# Proof of control for ${DOMAIN}"
  echo "# Method: dns_txt (docs/09-ownership-verification.md)"
  echo "#"
  echo "# Nonce issued : ${NONCE}"
  echo "# Observed at  : ${seen_at}"
  echo "# Checked by   : operator:$(git config user.name 2>/dev/null || whoami)"
  echo "#"
  echo "# Seen from two independent resolvers. The nonce matches the one issued"
  echo "# for this verification, so control of the zone is established."
  echo "#"
  echo "\$ dig +noall +answer TXT ${RECORD_NAME} @${RESOLVER_A}"
  echo
  dig +noall +answer TXT "$RECORD_NAME" "@${RESOLVER_A}"
  echo
  echo "\$ dig +noall +answer TXT ${RECORD_NAME} @${RESOLVER_B}"
  echo
  dig +noall +answer TXT "$RECORD_NAME" "@${RESOLVER_B}"
} > "$PROOF_FILE"

cat >> "$SCOPE" <<EOF

# --- ${DOMAIN} ---------------------------------------------------------------
#     Verified ${TODAY} by publishing a nonce at ${RECORD_NAME}.

- authz_id: ${AUTHZ_ID}
  org_id: org_internal
  target: { type: domain, value: ${DOMAIN}, wildcard: false }
  method: dns_txt
  proof:
    observed: '${NONCE} at ${RECORD_NAME}'
    observed_at: ${seen_at}
    evidence_file: ${PROOF_FILE}
  verified_at: ${TODAY}
  expires_at: ${EXPIRES}
  verified_by: operator:$(git config user.name 2>/dev/null || whoami)
  attestation_ref: null
EOF

python3 -c "import yaml,sys; yaml.safe_load(open('$SCOPE'))" \
  || die "the updated $SCOPE is not valid YAML. Fix it before committing."

cat <<EOF
  Written:
    ${PROOF_FILE}
    ${SCOPE}   (authorisation ${AUTHZ_ID}, expires ${EXPIRES})

  Next:

    uv run pytest tests/core/test_live_authorised_scope.py -q
    uv run scan run email --target ${DOMAIN} --mode standard

    git add ${SCOPE} ${PROOF_FILE}
    git commit -m "Authorise ${DOMAIN} for standard-mode scanning"

  The row and its proof belong in ONE commit. The git history is the audit log.

EOF
