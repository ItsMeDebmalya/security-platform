#!/usr/bin/env bash
#
# ProofScan demo — the live "break it" beat.
# Enables root SSH password login by dropping one config file and reloading sshd.
# Instant and seamless; re-run proofscan.sh afterwards to see it detected.
#
# Reset: revert the VMware CLEAN snapshot (preferred), or run demo/reset-ssh.sh.
#
set -euo pipefail

CY=$'\033[36m'; GRN=$'\033[32m'; B=$'\033[1m'; Z=$'\033[0m'

printf '%s%s[*]%s enabling root SSH login (PermitRootLogin yes) ...\n' "$B" "$CY" "$Z"
echo 'PermitRootLogin yes' | sudo tee /etc/ssh/sshd_config.d/99-rootlogin.conf >/dev/null
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd

printf '%s%s[+]%s effective sshd config now says: ' "$B" "$GRN" "$Z"
sudo sshd -T | grep -i '^permitrootlogin'
echo
printf '  Now re-run: %sdemo/proofscan.sh%s\n' "$B" "$Z"
