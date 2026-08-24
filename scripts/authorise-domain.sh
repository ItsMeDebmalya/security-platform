#!/usr/bin/env bash
#
# Authorise a domain you control for Standard/Deep mode scanning.
#
#   scripts/authorise-domain.sh codez.in
#   scripts/authorise-domain.sh codez.in --dry-run     # show, write nothing
#
# What it does, in order:
#   1. generates a single-use nonce and tells you exactly what to publish
#   2. WAITS, polling the zone's own authoritative nameservers, then confirming
#      through two independent public resolvers
#   3. only then writes the proof file and the authorisation row
#
# It polls the authoritative servers first for a reason: they are the zone
# speaking for itself. A public resolver cannot distinguish "you have not added
# the record yet" from "you added it and it is still spreading", and answering
# that question is most of what you need while you are waiting.
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
CHECK_ONLY=0
CHECK_NONCE=""
case "${2:-}" in
  --dry-run) DRY_RUN=1 ;;
  --check)   CHECK_ONLY=1; CHECK_NONCE="${3:-}" ;;
  "")        ;;
  *)         die "unknown option ${2}" ;;
esac

[ -n "$DOMAIN" ] || die "usage: $0 <domain> [--dry-run | --check [nonce]]"

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

# --- how we look things up --------------------------------------------------

authoritative_ns() {
  dig +short NS "$DOMAIN" "@${RESOLVER_A}" 2>/dev/null | head -3
}

# Does the zone itself publish this value at this name? Asking the
# authoritative servers skips every cache between us and the truth.
in_zone() {
  local want="$1" ns found=""
  for ns in $(authoritative_ns); do
    if dig +short TXT "$RECORD_NAME" "@${ns}" 2>/dev/null | tr -d '"' | grep -qF "$want"; then
      found="$ns"; break
    fi
  done
  printf '%s' "$found"
}

at_resolver() {
  dig +short TXT "$RECORD_NAME" "@${1}" 2>/dev/null | tr -d '"' | grep -qF "$2"
}

# --- --check: one pass, no waiting, no writing ------------------------------

if [ "$CHECK_ONLY" = "1" ]; then
  [ -n "$CHECK_NONCE" ] || die "usage: $0 $DOMAIN --check 'sp-verify=...'"
  say "Checking ${RECORD_NAME} for ${CHECK_NONCE}"
  echo
  ns_hit="$(in_zone "$CHECK_NONCE")"
  if [ -n "$ns_hit" ]; then
    echo "  zone (authoritative)  YES  via ${ns_hit}"
  else
    echo "  zone (authoritative)  no"
  fi
  for r in "$RESOLVER_A" "$RESOLVER_B"; do
    if at_resolver "$r" "$CHECK_NONCE"; then echo "  ${r}               YES"
    else echo "  ${r}               no"; fi
  done
  echo
  [ -n "$ns_hit" ] || die "the zone does not publish that value. Nothing to wait for."
  say "Present in the zone. Re-run without --check to complete the authorisation."
  exit 0
fi

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

NS_LIST="$(authoritative_ns | tr '\n' ' ')"
[ -n "$NS_LIST" ] || die "cannot find the nameservers for ${DOMAIN}."

say "Waiting for the record. Ctrl-C to abort."
echo "  zone is served by: ${NS_LIST}"
echo "  checking every ${POLL_SECONDS}s, giving up after $(( TIMEOUT_SECONDS / 60 )) minutes"
echo

seen_at=""
zone_has_it=""
nudged=0
deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))

while [ "$(date +%s)" -lt "$deadline" ]; do
  if [ -z "$zone_has_it" ]; then
    zone_has_it="$(in_zone "$NONCE")"
    if [ -n "$zone_has_it" ]; then
      printf '\033[32m  %s  in the zone (via %s). Waiting for public resolvers...\033[0m\n' \
        "$(date +%H:%M:%S)" "$zone_has_it"
    else
      echo "  $(date +%H:%M:%S)  not in the zone yet"
      nudged=$(( nudged + 1 ))
      if [ "$nudged" = "8" ]; then
        cat <<NUDGE

  Two minutes with nothing in the zone. The authoritative nameservers are
  answering, they just do not have this record - which means it has not been
  saved yet, rather than that it is still propagating.

  Worth re-checking in your DNS panel:
    - the record was actually saved (some panels need an explicit Save/Deploy)
    - the Name field is exactly:  _scanverify
      not _scanverify.${DOMAIN} if the panel appends the domain for you
    - the Value is exactly:  ${NONCE}
    - the type is TXT, not CNAME or SPF

NUDGE
      fi
    fi
  fi

  if [ -n "$zone_has_it" ]; then
    if at_resolver "$RESOLVER_A" "$NONCE" && at_resolver "$RESOLVER_B" "$NONCE"; then
      seen_at="$(date -Iseconds)"
      printf '\033[32m  confirmed from %s and %s.\033[0m\n\n' "$RESOLVER_A" "$RESOLVER_B"
      break
    fi
    echo "  $(date +%H:%M:%S)  in the zone, public resolvers catching up"
  fi

  sleep "$POLL_SECONDS"
done

[ -n "$seen_at" ] || die "gave up after ${TIMEOUT_SECONDS}s. Nothing was written.

       $( [ -n "$zone_has_it" ] \
            && echo "The record IS in the zone but public resolvers had not picked it
       up yet. This is usually negative caching; try again shortly with:
           $0 ${DOMAIN} --check '${NONCE}'" \
            || echo "The record was never in the zone. Add the TXT record shown
       above, then check it in one pass with:
           $0 ${DOMAIN} --check '${NONCE}'" )"

# --- 3. capture the proof, then write the row -------------------------------

{
  echo "# Proof of control for ${DOMAIN}"
  echo "# Method: dns_txt (docs/09-ownership-verification.md)"
  echo "#"
  echo "# Nonce issued : ${NONCE}"
  echo "# Observed at  : ${seen_at}"
  echo "# Checked by   : operator:$(git config user.name 2>/dev/null || whoami)"
  echo "#"
  echo "# Seen in the zone itself (authoritative: ${zone_has_it}) and confirmed"
  echo "# through two independent public resolvers. The nonce matches the one"
  echo "# issued for this verification, so control of the zone is established."
  echo "#"
  echo "\$ dig +noall +answer TXT ${RECORD_NAME} @${zone_has_it}   # authoritative"
  echo
  dig +noall +answer TXT "$RECORD_NAME" "@${zone_has_it}"
  echo
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
