#!/usr/bin/env bash
#
# ProofScan demo — undo break-it.sh (fallback if you are not reverting a VMware
# snapshot). Removes the root-login drop-in and reloads sshd.
#
set -euo pipefail
GRN=$'\033[32m'; B=$'\033[1m'; Z=$'\033[0m'

sudo rm -f /etc/ssh/sshd_config.d/99-rootlogin.conf
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
printf '%s%s[+]%s drop-in removed; effective sshd config now: ' "$B" "$GRN" "$Z"
sudo sshd -T | grep -i '^permitrootlogin'
