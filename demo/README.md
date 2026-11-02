# ProofScan — Tier-B live demo runbook

Everything runs **locally on the VMware Ubuntu 22.04 VM**. VMware snapshots are the
reset button. Three scripts:

- `demo/proofscan.sh` — banner + collect + judge, prints the findings (the thing you run on stage).
- `demo/break-it.sh` — flips root SSH login on, live (the dramatic beat).
- `demo/reset-ssh.sh` — undo break-it (fallback if you are not reverting a VMware snapshot).

The story in one line: **collect once, judge centrally, never bluff.**

---

## A. One-time setup on the VM (do this before demo day, needs network once)

```bash
# 1. Clone the repo and check out the demo branch
git clone https://github.com/ItsMeDebmalya/security-platform.git
cd security-platform
git checkout demo/tier-b-live

# 2. Install uv (the Python toolchain the platform uses)
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"          # or open a new shell

# 3. Build the platform environment (pulls Python 3.13 + deps)
uv sync

# 4. Mark the scripts executable
chmod +x demo/*.sh

# 5. Warm-up dry run (first `uv run` compiles; makes the stage run instant)
demo/proofscan.sh        # expect: clean verdict on a fresh box
```

Keep the VM **on the newest kernel** for the clean baseline — reboot and pick the
default (highest) kernel if unsure:

```bash
uname -r                 # want the HIGHEST installed, e.g. 6.8.0-138-generic
```

---

## B. Build the two VMware snapshots (once)

### Snapshot `CLEAN` — a correctly configured box
```bash
demo/reset-ssh.sh                      # ensure root SSH login is OFF (ok if "not found")
uname -r                               # must be the newest kernel (running == newest installed)
sudo sshd -T | grep -i permitrootlogin # expect: without-password  (or prohibit-password)
```
→ In VMware: **Take Snapshot → name it `CLEAN`.**

### Snapshot `VULNERABLE` — both findings present
```bash
demo/break-it.sh                       # root SSH login ON
# Boot an OLDER kernel so a newer one is installed-but-not-running:
#   reboot, hold SHIFT (BIOS) / tap ESC (UEFI) -> Advanced options for Ubuntu
#   -> choose "Ubuntu, with Linux 6.8.0-40-generic"
uname -r                               # must now show the OLDER kernel, e.g. 6.8.0-40-generic
sudo sshd -T | grep -i permitrootlogin # expect: yes
```
→ In VMware: **Take Snapshot → name it `VULNERABLE`.**

---

## C. On-stage runbook

Run once at the start of your session so sudo won't prompt mid-demo (lasts ~15 min):
```bash
sudo -v
```

**Act 1 — a clean box.** Revert the `CLEAN` VMware snapshot, then:
```bash
demo/proofscan.sh
```
> *"A read-only agent looks at the box once and hands a snapshot to the platform.
> It even tells you up front everything it will ever do — all reads, no writes.
> Verdict: clean."*

**Act 2 — break it, live.** On the same clean box:
```bash
demo/break-it.sh
demo/proofscan.sh
```
> *"One config change — root can now log in over SSH. Same agent, same snapshot
> pipeline. Now it reports it: HIGH, with the exact evidence line it read."*

**Act 3 — the fuller picture.** Revert the `VULNERABLE` VMware snapshot, then:
```bash
demo/proofscan.sh
```
> *"This box also has a newer kernel installed than the one it's running — fixes
> that aren't in effect until reboot. Two findings now, each with its control-vs-test
> evidence and a computed severity."*

**Optional Act 4 — it knows when NOT to claim.** (Uses a committed sample, no VM change.)
```bash
uv run scan run host --snapshot corpus/fixtures/host/shared-kernel/snapshot.json -t 19d46a1420a9 --target-type host
```
> *"Point it at a container — shared kernel, no SSH server. A lesser tool would
> false-positive. Ours returns **inconclusive**: the honest 'I can't tell from here.'"*

---

## D. Reset between takes

- Preferred: **revert the VMware snapshot** (`CLEAN` or `VULNERABLE`).
- Without reverting: `demo/reset-ssh.sh` undoes the SSH change (the kernel beat still
  needs a reboot into the newest kernel to clear).

## Knobs (optional)
- `SHOW_PLAN=0 demo/proofscan.sh` — skip the "here's what it will do" beat.
- `PACE=0 demo/proofscan.sh` — no pauses (instant).
- `PACE=0.8 demo/proofscan.sh` — slower, more theatrical.

## Notes
- The banner wrapper is theatre only; the agent is the unmodified read-only
  collector and writes pure JSON. Nothing here changes how the product works.
- The agent step runs under `sudo` for one privileged read (`sshd -T`); everything
  else it reads is unprivileged.
