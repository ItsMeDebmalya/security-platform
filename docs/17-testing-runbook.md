# 17 — Testing & Lab Runbook

*Copy-paste commands for running the test suite, the accuracy corpus, the local labs, and CI. Written to be used from WSL with no thinking required.*

**Scope boundary, so this does not drift into its neighbour:** [12-cli-runbook.md](12-cli-runbook.md) owns *how to run a scan* — every `scan` command, its options, and how to read a result. **This document owns *how to prove the scanners are correct*** — the test layers, the corpus, the labs, and CI. If you are pointing the tool at a target, you want 12. If you are checking the tool still works, you want this.

---

## The one-liner

```bash
make check && make corpus
```

`make check` runs lint, typecheck, unit tests and the licence policy. `make corpus` scores the scanners against ground truth. If both are green, nothing you did broke anything that is currently measured.

Everything below is what those two commands are made of, and what they cannot tell you.

---

## 1. The layers, and what each one actually catches

There are more than two. Only one of them measures accuracy.

| # | Layer | Command | Catches |
|---|---|---|---|
| 1 | Unit tests | `make test` | Logic bugs in isolation. The SPF/DMARC/DKIM parsers are tested as parsers before anything touches DNS |
| 2 | Architecture tests | (inside `make test`) | **Rule** violations, not behaviour: a scanner importing another scanner, `core/` importing a scanner, a GPL tool registered as linkable |
| 3 | Types and style | `make typecheck`, `make lint` | `mypy --strict` across every source file, plus ruff |
| 4 | Licence policy | `make licence-check` | A dependency whose licence breaks [ADR-003](02-decisions.md) |
| 5 | The corpus | `make corpus` | **Accuracy regressions** — precision, recall, inconclusive rate |
| 6 | Cross-check | `make crosscheck` | Where our TLS engine disagrees with testssl.sh. Slow, optional, **not a gate** |
| 7 | Live runs | you, §5 below | **New failure modes.** The only layer that has ever found one |
| 8 | Reading the fixtures | your eyes | Ground truth that is wrong in the same direction as the scanner. Nothing automated can do this |

**The corpus proves regression, not correctness.** Every case was written by the same person as the code, so it passes by agreeing with it. Six real defects have survived it at precision 1.000 — three of them were bugs *in the TLS lab itself*, which made every case quietly easier than intended while the gate stayed green. Layers 7 and 8 are not optional polish; [ADR-017](02-decisions.md) makes live verification part of a tool's definition of done.

---

## 2. The daily loop

```bash
# after any change
make test                 # fast, run this constantly
make check                # before you commit
make corpus               # before you commit, if you touched a scanner
```

Formatting:

```bash
make format               # rewrites files
make lint                 # checks without rewriting (what CI runs)
```

Run one test file, or one test:

```bash
uv run pytest tests/core/test_tls.py -q
uv run pytest -k "wildcard" -q
uv run pytest tests/core/test_tls.py::test_a_healthy_server_is_reachable_and_reports_its_protocol -q
```

Useful flags: `-x` stop at first failure · `-q` quiet · `--lf` re-run only last failures · `-vv` show full assertion diffs.

---

## 3. The corpus

### Reading the output

```bash
make corpus
```

```
scanner     checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
email          240   21    0    0      1.000    1.000   0.0%    0.8%  PASS
tls            134    5    0    0      1.000    1.000   6.0%    0.0%  PASS
```

- **precision** — of what we claimed, how much was real
- **recall** — of what was really there, how much we caught
- **inconc%** — shrugs ÷ checks that ran, **capped at 15%**; without the cap a scanner could score perfectly by declining to answer everything
- **susp%** — hedged findings. Read this column: they are excluded from precision on both sides, so a high `susp%` means the precision figure rests on fewer claims than `checks` suggests

**Read the claim count with the number.** TLS's 1.000 rests on **5 claims out of 220 checks**. Email's rests on 21 out of 240. Both pass; they are not the same weight of evidence.

### The gate, as CI runs it

```bash
uv run python -m cli.corpus --check-baseline
```

Fails on: any precision drop · any rise in the inconclusive rate · **any** new false positive on a known-good target (a single one, no threshold). A recall drop only *warns* — a recall regression is usually a deliberate precision trade, and failing it would push authors to over-report.

### After a deliberate change

```bash
# 1. did queries change? re-record the fixtures
uv run python -m corpus.generators.email
uv run python -m corpus.generators.tls

# 2. score it
make corpus

# 3. ONLY if you have read the numbers and believe them
uv run python -m cli.corpus --update-baseline
```

> **Never update the baseline to turn a red build green.** It is a claim about accuracy, not a checkbox.

### Adding a case

`corpus/targets/<scanner>.yaml` — the case:

```yaml
- id: my-new-case
  tier: vulnerable          # vulnerable | known_good | benchmark
  source: frozen            # frozen = replayed from fixtures; what CI gates on
  mode: standard
  target: { type: domain, value: corpus-thing.example }
  fixtures: corpus/fixtures/email/my-new-case
```

`corpus/expected/<scanner>.yaml` — the known-correct answer. An empty list means *must report nothing*:

```yaml
my-new-case:
  - { check_id: dmarc-policy-none, location: "$" }
```

Rules that are not negotiable:

- **A new detection needs both a positive and a negative case**, an `independence_class`, and a hand-assigned prior with a written justification.
- **Every scanner needs at least one `known_good` case.** Anything reported there is a false positive by definition.
- `expect_inconclusive: true` for a target where no definite answer is possible (a SERVFAIL fixture). It is excluded from the inconclusive-rate denominator and asserted separately instead.

---

## 4. The labs

### The vulnerable web/API targets

```bash
make targets-up           # Juice Shop, DVWA, VAmPI (flaws on), VAmPI (flaws off)
make targets-status
make targets-down
```

```
NAME            STATUS          PORTS
sp-juice-shop   Up 12 seconds   127.0.0.1:3000->3000/tcp
sp-dvwa         Up 12 seconds   127.0.0.1:4280->80/tcp
sp-vampi        Up 12 seconds   127.0.0.1:5000->5000/tcp
sp-vampi-safe   Up 12 seconds   127.0.0.1:5001->5000/tcp
```

> **Check the binding before scanning anything.** If `ss -ltn` shows `0.0.0.0` or `::` on those ports, stop — a known-exploitable application is listening on every interface the machine has. DVWA's own README: *"Do not upload it to your hosting provider's public html folder or any Internet facing servers, as they will be compromised."*

```bash
ss -ltn | grep -E '3000|4280|5000|5001'   # every line must say 127.0.0.1
```

**The VAmPI pair is the valuable part.** Same application, flaws on (`:5000`) and off (`:5001`). Anything reported against `:5001` is a false positive by definition — that pair is what turns a recall measurement into a precision measurement.

### The TLS lab

No container and no hosts file — it runs in-process and mints certificates with whatever defect you ask for:

```bash
uv run python -m corpus.generators.tls        # regenerate the TLS corpus fixtures
```

Used by `tests/core/test_tls.py` directly. It shells out to the `openssl` binary for the SHA-1 case only (fixture generation; nothing ships).

### testssl.sh cross-check

```bash
make crosscheck           # fetches testssl.sh 3.2.4 on first run, then compares
```

Slow, optional, **not a gate**. A disagreement is a finding *about us*. GPLv2, so it runs as a subprocess and is never linked ([ADR-016](02-decisions.md)).

### Two WSL details that cost an afternoon

- **Loopback is per-distro.** Containers in one WSL distro and the CLI in another do not share `127.0.0.1`.
- **`/etc/hosts` is regenerated on every WSL boot** unless you disable it, and `badssl.test` needs entries there. Put this in `/etc/wsl.conf`, then `wsl --shutdown`:

```ini
[network]
generateHosts = false
```

Without it the entries vanish, every TLS case becomes a DNS failure, and the scanner correctly calls that `inconclusive` — but you have lost the corpus and the numbers read as a regression.

---

## 5. Live verification — the layer that finds real bugs

Required before any tool is "done" ([ADR-017](02-decisions.md)). Everything here is **Light mode, which is passive and needs no authorisation** — see [09-ownership-verification.md](09-ownership-verification.md).

```bash
# a sweep for false positives — clean domains should come back clean
printf 'google.com\nmicrosoft.com\npaypal.com\npython.org\ngo.dev\nnpmjs.com\n' \
  | ./scripts/scan-many.sh
```

```bash
# your own infrastructure, where the real findings are
uv run scan run email --target <operator domain B> --mode standard
uv run scan run tls   --target https://your-host.example --mode standard
```

**What to look for, in this order:**

1. **Anything reported on a domain you believe is clean.** That is a false positive and it matters more than any corpus number.
2. **Does the evidence contain the claim?** Open `--format json` and read the evidence block. A finding whose description asserts something its own evidence does not show is the worst defect this product can have — it has happened once already, with a fabricated SPF quote.
3. **Is `inconclusive` being used honestly**, or is the scanner guessing?
4. **Wall time.** A sweep that suddenly takes minutes per domain means something is rate-limiting the wrong thing — that exact bug turned 50 domains from 40 minutes into 33 seconds once found.

Paste anything surprising back. A pasted transcript is a bug report.

### Authorising your own assets (needed only for active checks)

Today that is three TLS checks; email has none. Light needs nothing at all.

```bash
# you control DNS: publish a nonce and prove it
./scripts/authorise-domain.sh example.com

# you cannot publish DNS (Cloudflare zone managed elsewhere): attest instead
./scripts/authorise-domain.sh --self-owned \
  "owned and operated by us; DNS managed outside our direct control" \
  <operator domain A> <operator ERP host> <operator domain B>

./scripts/authorise-domain.sh --check example.com   # 5-second feedback loop
```

Then commit the row and its proof together — the git history of `config/authorised_scope.yaml` is the audit record:

```bash
uv run pytest tests/core/test_live_authorised_scope.py -q
git add config/authorised_scope.yaml corpus/authz/
git commit -m "Authorise example.com (self-owned attestation)"
```

> **An attestation is not a verification.** Nothing is checked — a named person states they control the asset and takes responsibility. Right for your own infrastructure; **wrong for a customer's, a prospect's, or anyone who merely publishes an invitation to scan.** Those need the nonce flow, and if that is impossible the scan does not happen.

---

## 6. CI

**A normal GitHub repository is all you need.** GitHub Actions is built in — nothing to host, no runner to manage. Public repos get unlimited minutes; private repos get 2,000 free minutes a month, and this suite takes about two minutes a run.

`.github/workflows/ci.yml` runs the same commands you run locally, on every push to `main` and every pull request: lint → typecheck → licence policy → unit tests → `corpus --check-baseline`.

### Making it actually run

A workflow that has never run is indistinguishable from one that does not work — that was **D1** in the ledger for a week. To trigger one by hand:

```bash
git push origin main
```

Then open **`github.com/debmalya-dey/security-platform` → Actions**, and watch the run. Or trigger without pushing: **Actions → CI → Run workflow** (the `workflow_dispatch` trigger exists for exactly this).

With the GitHub CLI:

```bash
gh workflow run ci.yml      # trigger by hand
gh run list --limit 5       # recent runs
gh run watch                # follow the current one
gh run view --log-failed    # just the failing step's output
```

### When it fails

The corpus scores are kept as a build artifact whether the run passed or failed — **Actions → the run → Artifacts → `corpus-results`**. Read the numbers there rather than re-running locally and hoping you reproduced it.

The likeliest first-run failures, in order:

| Symptom | Cause |
|---|---|
| `uv sync --locked` fails | `uv.lock` is out of date with `pyproject.toml`. Run `uv sync` locally and commit the lockfile |
| Corpus fails, passes locally | The committed baseline is stale. Check `corpus/results/baseline.json` against a local `make corpus` |
| Typecheck fails, passes locally | Your local mypy cache is hiding it. `rm -rf .mypy_cache && make typecheck` |
| A test needing the vulnerable containers | It should not — nothing in `make test` requires `make targets-up`. If one does, that is the bug |

### Reproducing CI exactly

```bash
rm -rf .mypy_cache .pytest_cache .ruff_cache
uv sync --locked
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run python -m cli.licences
uv run pytest
uv run python -m cli.corpus --check-baseline
```

---

## 7. Before you commit

```bash
make check && make corpus
```

- [ ] `make test`, `make lint`, `make typecheck`, `make licence-check` green
- [ ] `make corpus` shows no precision regression on any scanner
- [ ] New detections have **both** a positive and a negative corpus case
- [ ] New dependencies are in `tools/registry.yaml` with a licence
- [ ] No new HTTP/DNS/TLS client constructed outside `core/`
- [ ] `scanner_version` bumped if results changed
- [ ] Evidence for new findings is replayable and redacted
- [ ] Nothing sends a state-changing request to a target
- [ ] `state` is derived, not hand-set
- [ ] Zero findings on the known-good tier — a single one fails the build
- [ ] **A live run against a real target, hand-verified** ([ADR-017](02-decisions.md)) — the corpus has never found a bug on its own

Full rules: [06-guidelines.md](06-guidelines.md). Measurement definitions: [10-measurement.md](10-measurement.md).
