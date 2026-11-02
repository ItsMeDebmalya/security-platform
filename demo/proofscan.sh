#!/usr/bin/env bash
#
# ProofScan — Tier-B live demo wrapper.
#
# THEATRE ONLY. This script does not change how the product works. It prints a
# banner, then runs two things that already exist, locally on this host:
#   1. the read-only agent  -> writes one JSON snapshot   (python3 -m agent)
#   2. the platform         -> judges that snapshot        (uv run scan run host)
# The agent itself is unmodified: stdlib-only, read-only, writes pure JSON.
#
# Run it from anywhere inside the repo checkout:  demo/proofscan.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SNAP="${SNAP:-/tmp/proofscan-snapshot.json}"
SHOW_PLAN="${SHOW_PLAN:-1}"      # set SHOW_PLAN=0 to skip the "what it will do" beat
PACE="${PACE:-0.4}"              # seconds between steps; set PACE=0 for instant

CY=$'\033[36m'; DIM=$'\033[2m'; B=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; Z=$'\033[0m'

pause() { [ "$PACE" = "0" ] || sleep "$PACE"; }
step()  { printf '  %s[*]%s %s\n' "$CY" "$Z" "$1"; pause; }

banner() {
  clear 2>/dev/null || true
  printf '%s%s' "$B" "$CY"
  cat <<'ART'
  ██████╗ ██████╗  ██████╗  ██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██████╔╝██║   ██║██║   ██║█████╗  ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██╔══██╗██║   ██║██║   ██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ██║  ██║╚██████╔╝╚██████╔╝██║     ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
ART
  printf '%s' "$Z"
  printf '     %sread-only host agent%s  ·  collects once  ·  %snever guesses%s\n\n' "$DIM" "$Z" "$DIM" "$Z"
}

banner
step "host:  $(hostname)"
step "mode:  read-only  —  no writes, no network, no exploitation"

if [ "$SHOW_PLAN" = "1" ]; then
  echo
  step "before touching anything, here is everything it can do:"
  python3 -m agent --explain-plan 2>/dev/null | sed -n '1,12p' | sed "s/^/      ${DIM}/; s/\$/${Z}/"
  echo
fi

step "collecting snapshot ..."
# The one privileged read is the effective sshd config (sudo sshd -T); the rest
# are unprivileged. Running the whole collect under sudo keeps it one step.
sudo python3 -m agent --output "$SNAP" >/dev/null 2>&1
sudo chown "$(id -u):$(id -g)" "$SNAP" 2>/dev/null || true
step "snapshot written  ->  $SNAP"

echo
step "handing the snapshot to the platform for judgement ..."
echo
printf '%s' "$DIM"; printf '  ──────────────────────────────────────────────────────────────────────\n'; printf '%s' "$Z"

OUT="$(uv run scan run host --snapshot "$SNAP" -t "$(hostname)" --target-type host 2>&1 || true)"
printf '%s\n' "$OUT" | sed 's/^/  /'

printf '%s' "$DIM"; printf '  ──────────────────────────────────────────────────────────────────────\n'; printf '%s' "$Z"
echo

# Verdict line: count finding rows whose state is a claim (not inconclusive).
CLAIMS=$(printf '%s\n' "$OUT" | awk '/^(critical|high|medium|low)[[:space:]]/ && $3!="inconclusive"{c++} END{print c+0}')
INCONC=$(printf '%s\n' "$OUT" | awk '/^(critical|high|medium|low)[[:space:]]/ && $3=="inconclusive"{c++} END{print c+0}')
if [ "$CLAIMS" -eq 0 ] && [ "$INCONC" -eq 0 ]; then
  printf '  %s%s VERDICT: clean — nothing to report on this host %s\n' "$GRN" "$B" "$Z"
elif [ "$CLAIMS" -eq 0 ]; then
  printf '  %s%s VERDICT: no claims; %s check(s) inconclusive — it declined to guess %s\n' "$YEL" "$B" "$INCONC" "$Z"
else
  printf '  %s%s VERDICT: %s finding(s) with evidence %s' "$RED" "$B" "$CLAIMS" "$Z"
  [ "$INCONC" -gt 0 ] && printf '%s (+%s inconclusive)%s' "$DIM" "$INCONC" "$Z"
  echo
fi
echo
