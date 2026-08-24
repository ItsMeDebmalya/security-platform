#!/usr/bin/env bash
#
# Light-mode sweep over a list of domains, one line of output each.
#
# Light mode is passive - it reads public DNS and sends nothing to the target -
# so this needs no authorisation and is safe to point at any domain.
#
#   printf 'example.com\nexample.org\n' | scripts/scan-many.sh
#   scripts/scan-many.sh < domains.txt
#
# Requires jq.

set -uo pipefail

printf '%-30s %s\n' "DOMAIN" "RESULT"
printf '%-30s %s\n' "------------------------------" "------"

while read -r domain; do
  domain="${domain%%#*}"                       # strip comments
  domain="$(echo "$domain" | tr -d '[:space:]')"
  [ -z "$domain" ] && continue

  if ! out=$(uv run scan run email --target "$domain" --mode light --format json 2>/dev/null); then
    printf '%-30s %s\n' "$domain" "ERROR    scan could not run"
    continue
  fi

  printf '%-30s %s\n' "$domain" "$(printf '%s' "$out" | jq -r '
    [.findings[] | select(.state == "confirmed" or .state == "highly_likely")] as $claims
    | [.findings[] | select(.state == "inconclusive")] as $unknown
    | (if ($claims | length) == 0 then "CLEAN   " else "ISSUES  " end)
      + ([$claims[] | .check_id] | join(", "))
      + (if ($unknown | length) > 0
         then "  (+\($unknown | length) inconclusive)"
         else "" end)
  ')"
done
