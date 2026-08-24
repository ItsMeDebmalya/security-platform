# 13 — Test targets

*What we scan to prove the scanners work, where it runs, and what we deliberately do not scan.*

The corpus tiers are defined in [10-measurement.md](10-measurement.md). This document is the operational half: which real applications fill those tiers, how to bring them up, and why the list is shorter than it could be.

---

## The rule that shapes this list

> **Never point an active scan at something you do not run.**

Standard and Deep modes require a verified authorisation record ([09-ownership-verification.md](09-ownership-verification.md)), enforced deny-by-default. That constraint is what makes this list *self-hosted only*. Every target below is a container you start yourself, published to `127.0.0.1`, on the same machine as the scanner.

Light mode is passive and needs no authorisation, so it may be pointed at anything — including the public test sites in §5.

---

## 1. The targets

| Target | Tier | Fills | Licence | Port |
|---|---|---|---|---|
| **OWASP Juice Shop** | vulnerable | Web scanner (Phase 2) — OWASP Top 10 in a modern SPA | MIT | `3000` |
| **DVWA** | vulnerable | Web scanner — classic PHP injection, access control, adjustable difficulty | GPL-3.0 | `4280` |
| **VAmPI** (`vulnerable=1`) | vulnerable | API scanner (Phase 3) — BOLA, broken auth, mass assignment, weak JWT | MIT | `5000` |
| **VAmPI** (`vulnerable=0`) | **known-good** | The same API with the flaws off | MIT | `5001` |
| **badssl.test** | vulnerable | TLS analyser (Tool 2) — one broken thing per subdomain | Apache-2.0 | `443` |

**The VAmPI pair is the most valuable thing here.** The same application, one instance vulnerable and one not, is what turns a recall measurement into a precision measurement — anything reported against `:5001` is a false positive by definition. Most vulnerable-app corpora give you planted bugs and no negative population at all, which is why [10-measurement.md](10-measurement.md) calls the benchmark tier mandatory before the web scanner ships.

**badssl is the Tool 2 corpus.** Dozens of subdomains, each broken in exactly one known way — `expired`, `self-signed`, `wrong.host`, `rc4`, `dh512`, `sha1-intermediate`, `incomplete-chain`. Each is its own ground-truth case with a knowable right answer, which is rare and worth a lot.

All five are registered in [`tools/registry.yaml`](../tools/registry.yaml) with their licences. DVWA is GPL-3.0 and is declared `isolation: service`: its own container, talked to over HTTP, never imported. The CI licence check fails the build if that is ever changed to `library`.

---

## 2. Where this runs

**The scanner and the targets run on the same machine.** That is not incidental — it is what makes `127.0.0.1` the right address and `self_owned` an honest authorisation method. Clone the repo onto the host that runs the containers, and run the CLI from there.

A WSL2 distro is a good place for both. Docker and the scanner live inside the distro; nothing is published beyond its loopback interface.

```bash
# inside the WSL distro
sudo apt update && sudo apt install -y python3.12 python3.12-venv git curl
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone git@github.com:satwik-001/security-platform.git
cd security-platform
make install
make test          # 480+ tests, no network needed
make corpus        # the accuracy gate

make targets-up    # bring up the vulnerable applications
make targets-status
```

`make targets-status` should show every port bound to `127.0.0.1`:

```
NAME            STATUS          PORTS
sp-juice-shop   Up 12 seconds   127.0.0.1:3000->3000/tcp
sp-dvwa         Up 12 seconds   127.0.0.1:4280->80/tcp
sp-vampi        Up 12 seconds   127.0.0.1:5000->5000/tcp
sp-vampi-safe   Up 12 seconds   127.0.0.1:5001->5000/tcp
```

### WSL specifics worth knowing before you lose an afternoon

- **Docker Desktop with WSL integration, or Docker inside the distro — either works.** In both cases a port published to `127.0.0.1` is reachable from the CLI running in that same distro. If you run the containers in one distro and the CLI in another, loopback is *not* shared and the addresses in `config/authorised_scope.yaml` will not resolve to your targets.
- **Windows can reach these too.** Docker Desktop forwards published ports to the Windows host, so `http://localhost:3000` works in a Windows browser. That is convenient and also means "bound to loopback" is protecting you from the network, not from your own desktop.
- **`/etc/hosts` is regenerated on every WSL boot** unless you turn that off. badssl.test needs hosts entries, so before adding them:

  ```ini
  # /etc/wsl.conf
  [network]
  generateHosts = false
  ```

  Then `wsl --shutdown` from PowerShell and start the distro again. Without this the badssl entries vanish on reboot and every TLS case turns into a DNS failure. The scanner will correctly call that `inconclusive` rather than inventing a TLS finding — but you will have lost the corpus and the numbers will look like a regression.
- **`restart: "no"` is deliberate.** These are exploitable applications by design; they should never come back on their own after a reboot. Start them when you need them.

### badssl needs a separate clone

It builds its own certificate authority, so it is not a plain image:

```bash
git clone https://github.com/chromium/badssl.com
cd badssl.com
make list-hosts        # append the output to /etc/hosts
make serve
```

Add `certs/sets/test/gen/crt/ca-root.crt` to the trust store of whatever is scanning. Skip that and every case reads as “untrusted issuer”, which masks the more specific findings underneath.

---

## 3. Authorisation

All five targets have rows in [`config/authorised_scope.yaml`](../config/authorised_scope.yaml), `method: self_owned`, each citing a proof file in `corpus/authz/`.

For a loopback container the proof cannot be a nonce observation — there is nobody to ask and nothing to observe. The proof is the service definition itself: `docker-compose.yml` plus the operator's own `make targets-status`. That makes the authorisation portable to any checkout, which is correct, because the claim it makes is *“the operator may scan what they themselves started on their own loopback.”*

The rows still expire after 90 days. Renew them deliberately rather than extending the dates.

### The guard

`tests/core/test_live_authorised_scope.py` enforces, as a build failure:

- a `self_owned` row may only target loopback or an RFC 2606 reserved name (`.test`, `.example`, `.invalid`, `.localhost`)
- a publicly resolvable target needs a real verification method and evidence
- every row cites a proof file that exists on disk
- no authorisation runs longer than 90 days
- `authz_id`s are unique

Adding `testphp.vulnweb.com` with `method: self_owned` fails the build with:

```
authz_2026-08-24-999 claims self_owned for 'testphp.vulnweb.com', which is a
publicly resolvable name. Prove control with a dns_txt nonce, or remove the row.
```

---

## 4. Verifying the safety property

Before scanning, confirm nothing is listening beyond loopback:

```bash
$ ss -ltn | grep -E ':(3000|4280|5000|5001)'
LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:4280 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:5000 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:5001 0.0.0.0:*
```

If any line shows `0.0.0.0` or `::`, **stop**. A known-exploitable application is listening on every interface the machine has. DVWA's own README puts it plainly: *“Do not upload it to your hosting provider's public html folder or any Internet facing servers, as they will be compromised.”* Fix the ports mapping in `docker-compose.yml` before going further.

---

## 5. What we deliberately do not scan

Public test sites are tempting and mostly off-limits for anything active. They belong to other people.

| Site | Why not |
|---|---|
| `scanme.nmap.org` | Nmap does publish permission — but scoped to *“scanning with Nmap”*, explicitly not exploits or DoS, and *“please do not initiate more than a dozen scans against that host per day.”* We do not use Nmap, and a corpus run that executes on every commit is not what that invitation contemplates. |
| `testphp.vulnweb.com` and the other `vulnweb.com` hosts | Hosted by Acunetix/Invicti as public demo targets. No verified permission to us, and pointing our scanner at a competitor's infrastructure on every CI run is a poor idea on more than one axis. |
| Hosted Juice Shop demos | Run by the Juice Shop team on their own budget. Run your own; the image is free and the whole point is that it is disposable. |
| `badssl.com` (the public site) | Run by other people. Self-host it instead — the repo is Apache-2.0 and `make serve` is one command. |
| Anything belonging to a customer or prospect | Requires the full verification flow in [09-ownership-verification.md](09-ownership-verification.md), not a row someone added because it was convenient. |

**A published invitation is not a verification.** It may well make a one-off manual scan reasonable, and Light mode — passive, no authorisation required — can be pointed at any of these today. What it does not do is give us an authorisation record, and the allowlist is the place where we assert we have one.

If we ever do want an active scan against a target that publishes permission, the honest route is an ADR adding a `published_permission` method to `docs/09`, with the published text captured as the evidence file and re-checked on the same 90-day cycle. That is a decision to take deliberately, not a row to slip in.

---

## 6. Status

Only two scanners exist today — `email` and the `example` reference — and both take `domain` targets. **The rows for Juice Shop, DVWA and VAmPI authorise scans that nothing can yet perform.** They are wired up now because [04-phase-0-foundations.md](04-phase-0-foundations.md) task 0.5 asks for the docker-composed targets, and because getting the authorisation shape right before there is pressure to cut a corner is the entire point of doing it early.

`badssl.test` is the one that gets used next: it is the corpus for Tool 2.
