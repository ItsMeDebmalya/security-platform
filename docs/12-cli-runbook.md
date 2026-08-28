# 12 — CLI Runbook

*How to operate the `scan` tool. Every command and every block of output in this document was run against the committed tree; nothing here is illustrative.*

Audience: whoever is running scans or changing a scanner. Assumes no security background — the concepts are explained where they come up.

Related: [how-to-add-a-scanner.md](how-to-add-a-scanner.md) for writing a new scanner, [10-measurement.md](10-measurement.md) for how the numbers are computed, [09-ownership-verification.md](09-ownership-verification.md) for the legal gate on active scans.

---

## 1. Setup

Requires **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/).

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh    # if uv is not installed
make install
```

```
uv sync
Resolved 40 packages in 0.96ms
Checked 39 packages in 0.57ms
```

Verify the install:

```bash
$ uv run scan list
name         version    modes                    target types
email        1.0.0      light,standard           domain
example      1.0.0      light,standard           domain
tls          1.0.0      light,standard           domain,ip,url
```

`example` is the reference scanner — a deliberately trivial "does this domain have an A record" check that exists to exercise the plumbing. `email` is Tool 1 and `tls` is Tool 2; both pass their accuracy gates.

> Every command below is written as `uv run scan …`. If you have activated the venv (`source .venv/bin/activate`) you can drop the `uv run` prefix.

---

## 2. The commands

| Command | What it does |
|---|---|
| `scan list` | Registered scanners, versions, modes |
| `scan run <scanner> --target <t>` | Run one scanner against one target |
| `make test` | Unit tests |
| `make lint` / `make typecheck` | ruff / mypy --strict |
| `make licence-check` | Fail if a dependency's licence breaks [ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves) |
| `make corpus` | Score every scanner against its ground-truth corpus |
| `uv run python -m cli.corpus --check-baseline` | The CI gate: fail on any regression |
| `make targets-up` / `make targets-down` | The vulnerable applications, on loopback ([13-test-targets.md](13-test-targets.md)) |
| `make crosscheck` | Compare our TLS observations against testssl.sh. Optional, slow, not a gate. |

### `scan run` options

| Option | Meaning |
|---|---|
| `--target`, `-t` | The thing to scan. Required. |
| `--target-type` | `domain` (default), `url`, `ip`, `cidr`, `repo`, … |
| `--mode`, `-m` | `light` (default), `standard`, `deep` |
| `--format` | `table` (default, for humans) or `json` |
| `--out`, `-o` | Write the full ScanResult JSON to a file |
| `--record <dir>` | Run live and freeze every DNS answer into `<dir>` |
| `--replay <dir>` | Run offline from a frozen `<dir>`. Never touches the network. |
| `--fail-on <severity>` | Exit 2 if a **reported** finding is at or above this severity |
| `--scope-file` | Authorisation allowlist (default `config/authorised_scope.yaml`) |

---

## 3. Your first scan

```bash
$ uv run scan run email --target python.org --mode light
```

Progress goes to **stderr**, results to **stdout**, so the JSON format pipes cleanly.

```
[   5%] checking the zone for wildcards
[  25%] reading SPF, DMARC and MX
[  50%] looking for DKIM selectors
[  90%] simulating the receiver decision
[ 100%] done

email 1.0.0 light python.org -> succeeded

severity  conf   state          check                            location
high      0.96   confirmed      spoofing-possible                $
medium    0.98   confirmed      dmarc-policy-none                $

9 check(s) ran, 0% inconclusive, 8 request(s)
```

### Reading that

- **`location: $`** is a reserved value meaning "the target as a whole", as opposed to a specific URL or DNS name.
- **9 checks ran** — not 17. Checks whose subject does not exist are not run and are not counted. `dmarc-pct-partial` needs a DMARC record to have a `pct` tag; on a domain with no DMARC record it has nothing to evaluate, so it is absent rather than reported as "clear".
- **Rows are sorted by `severity × confidence`**, which is the triage order the product is built around.

### Severity, confidence and state are three different things

Do not collapse them. This is the single most common mistake when reading scanner output.

| | Question it answers | Set by |
|---|---|---|
| **severity** | How bad would this be *if it is true*? | The check, from the vulnerability class and context. Never adjusted for how sure we are. |
| **confidence** | How sure are we that it *is* true? | `core/confidence.py`, in log-odds |
| **state** | The derived label | `core/state.py`. Never by a scanner. |

The five states:

| State | Meaning | Counts as a claim? |
|---|---|---|
| `confirmed` | Validation ran and passed, confidence ≥ 0.95 | **Yes** |
| `highly_likely` | Two independent methods agree, confidence ≥ 0.75 | **Yes** |
| `suspected` | One signal, or validation failed | No — an honest hedge |
| `informational` | True but not dangerous (`severity: info`) | No |
| `inconclusive` | The check ran and could not tell | No |

Only `confirmed` and `highly_likely` are claims we make to a user. That is what `--fail-on` acts on and what precision is computed over ([10-measurement.md](10-measurement.md)).

**`inconclusive` is a real answer, not an error.** A SERVFAIL from a resolver is not the same as "the record is missing", and the scanner never conflates them.

---

## 4. JSON output

```bash
$ uv run scan run email --target python.org --format json
$ uv run scan run email --target python.org --out result.json    # to a file
```

Top level:

```
scanner, scanner_version, target, mode, findings, errors,
telemetry, started_at, finished_at, killed, outcome
```

Each finding:

```
id, org_id, scanner, scanner_version, check_id, renamed_from, title,
target, location, instance_key, severity, confidence,
confidence_provisional, state, no_verdict_reason, detection_methods,
validation, evidence, related_assets, status, status_history,
description, impact, remediation, references, taxonomy,
first_seen, first_seen_scan_id, last_seen, last_seen_scan_id, cost
```

### The evidence is the point

A real finding from the run above, trimmed to the parts that matter:

```json
{
  "check_id": "dmarc-policy-none",
  "severity": "medium",
  "confidence": 0.9756,
  "confidence_provisional": true,
  "state": "confirmed",
  "detection_methods": [
    {
      "method": "dns_record_parse",
      "likelihood_ratio": 40.0,
      "independence_class": "dns",
      "prior": 0.5,
      "prior_justification": "the p= tag is read directly from a record that parsed"
    }
  ],
  "validation": {
    "attempted": true,
    "outcome": "passed",
    "method": "independent_resolver"
  },
  "evidence": [
    {
      "kind": "dns_answer",
      "label": "TXT at _dmarc.python.org",
      "test": {
        "query": { "name": "_dmarc.python.org", "rrtype": "TXT", "resolver": "1.1.1.1" },
        "answer": {
          "rcode": "NOERROR",
          "records": ["v=DMARC1; p=none; pct=100; rua=mailto:re+shb8ybr70a3@dmarc.postmarkapp.com; sp=none; aspf=r;"],
          "ttl": 2572
        }
      },
      "control": {
        "query": { "name": "sp-wildcard-probe-c5f4141a.python.org", "rrtype": "TXT", "resolver": "1.1.1.1" },
        "answer": { "rcode": "NXDOMAIN", "records": [], "ttl": null }
      },
      "control_rationale": "a random-label probe in the same zone; without it a wildcard would make every lookup under this domain appear to succeed"
    },
    {
      "kind": "dns_answer",
      "label": "independent re-query via 8.8.8.8",
      "test": {
        "query": { "name": "_dmarc.python.org", "rrtype": "TXT", "resolver": "8.8.8.8" },
        "answer": { "rcode": "NOERROR", "records": ["v=DMARC1; p=none; ..."], "ttl": 3356 }
      },
      "control": null,
      "control_rationale": "the control for this re-query is the first resolver's answer, captured above"
    }
  ]
}
```

Three things to notice, because they are the product:

1. **Every piece of evidence carries a control.** Here the control is a random-label DNS probe proving the zone has no wildcard. Without it, a zone that answers *every* name would make every lookup look successful. "The record was there" is not evidence; "the record was there and this made-up name was not" is.
2. **`validation.outcome: passed`** is what earned `confirmed`. A high confidence score alone never earns it — the finding was re-read through a second, independent resolver, and both agreed. If they had disagreed, the finding would be downgraded to `suspected` with confidence capped at 0.5, **not** deleted.
3. **`confidence_provisional: true`** and it will stay true for a long time. Confidence comes from hand-assigned priors until calibration in Phase 4, and for low-volume checks it may be permanent. Do not present these numbers as calibrated probabilities.

### The same idea in TLS

The TLS analyser gets its control-vs-test pair from the design rather than from extra work. It makes **two** connections: one with a deliberately permissive client that will talk to anything, and one with a strict client that behaves like a browser.

```bash
$ uv run scan run tls --target https://expired.badssl.com --mode light

tls 1.0.0 light https://expired.badssl.com -> succeeded

severity  conf   state          check                            location
critical  1.00   highly_likely  tls-cert-expired                 expired.badssl.com:443

7 check(s) ran, 0% inconclusive, 1 request(s)
```

```jsonc
"evidence": [{
  "kind": "tls_handshake",
  "test":    { "protocol": "TLSv1.2",
               "certificate": { "not_after": "2015-04-12T23:59:59+00:00", … } },
  "control": { "trusted": false, "verify_code": 10,
               "verify_message": "certificate has expired" },
  "control_rationale": "the verdict of a strictly-configured client against the same
                        server; the observation was taken permissively so the
                        handshake could complete at all"
}]
```

**The permissive client is not carelessness — it is the point.** A client carrying the normal safety floor *refuses to complete a handshake* with a server running TLS 1.0, and those servers are exactly what this scanner exists to find. A scanner that inherits the floor reports "connection failed" for every insecure server and looks like it is working.

That client accepts forged and expired certificates by design, so it **observes and never fetches** ([06-guidelines.md](06-guidelines.md)). Reusing it to retrieve content would silently disable HTTPS for that request.

The state is `highly_likely` from two independence classes: we read the date out of the certificate, and path building independently refused it.

### Piping

```bash
# just the reported claims
uv run scan run email -t example.com --format json 2>/dev/null \
  | jq '.findings[] | select(.state=="confirmed" or .state=="highly_likely") | .check_id'

# what did each check conclude?
uv run scan run email -t example.com --format json 2>/dev/null \
  | jq -r '.telemetry.checks_run[] | "\(.outcome)\t\(.check_id)"'
```

---

## 5. The authorisation gate — a per-check declaration, not a mode setting

**As of docs/03-roadmap.md 0b.6, the gate is not "Light is exempt, Standard and Deep are not."** It asks the scanner what its checks actually do. Every `Check` in `scanners/*/checks.py` carries a `passive: bool` with no default, and `core/authz.checks_require_authorisation()` reads that catalogue rather than trusting the mode label.

**Passive is what an ordinary client does** — one normal connection, nothing the target would not serve to any visitor. **Active is deliberately abnormal input** — offering obsolete protocols or a weak/legacy cipher list to see what a server will accept, not what it ordinarily negotiates, or sending payloads. A connection to the target is not itself what makes a check active — "finding a server is passive, reading its admin panel is not," and finding a server requires connecting to it.

- **Email is pure DNS in every mode.** Every check reads a public authoritative answer we queried ourselves; nothing touches the target's own infrastructure. So email needs **no authorisation in Standard mode**, exactly as it needed none in Light:

  ```bash
  $ uv run scan run email --target corpus-good.example --mode standard \
      --replay corpus/fixtures/email/known-good
  [   5%] checking the zone for wildcards
  [  25%] reading SPF, DMARC and MX
  [  50%] looking for DKIM selectors
  [  75%] resolving the SPF include chain
  [  90%] simulating the receiver decision
  [ 100%] done

  email 1.0.0 standard corpus-good.example -> succeeded
  no findings

  17 check(s) ran, 0% inconclusive, 8 request(s)
  ```

- **TLS's Light checks, and three of its six Standard checks, read only the certificate an ordinary handshake already presents** — the same bytes any browser gets. So TLS still needs **no authorisation in Light mode**, unchanged from before this task and consistent with docs/00-context.md's product-wide contract that Light "may be pointed at anything" (docs/13-test-targets.md):

  ```bash
  $ uv run scan run tls --target https://localhost:14400 --mode light \
      --replay corpus/fixtures/tls/healthy
  [  20%] connecting to localhost:14400
  [  50%] checking the certificate
  [ 100%] done

  tls 1.0.0 light https://localhost:14400 -> succeeded
  no findings

  8 check(s) ran, 0% inconclusive, 1 request(s)
  ```

- **TLS's other three Standard checks force deliberately abnormal input.** `tls-protocol-obsolete` opens separate handshakes pinned to obsolete protocol versions; `tls-weak-cipher` and `tls-no-forward-secrecy` read the cipher negotiated when the client offered a deliberately permissive, weak-inclusive cipher list (`core.tls.PERMISSIVE_CIPHERS`) specifically to see whether the server would pick something weak. So **Standard mode does need authorisation for TLS**, even against the same target that just ran unauthorised in Light mode:

  ```bash
  $ uv run scan run tls --target https://localhost:14400 --mode standard \
      --replay corpus/fixtures/tls/healthy
  authorisation denied: no authorisation record for localhost in config/authorised_scope.yaml
  $ echo $?
  1
  ```

  Some Standard checks needing no authorisation while others in the same mode do is 0b.6 working as intended, not a bug — the same shape as email's Standard checks all being passive.

A scanner that has not migrated to a `Check` catalogue with `passive` declarations (only the reference `example` scanner, today) falls back unchanged to the old mode-based rule: Light exempt, Standard/Deep gated. `BaseScanner.requires_authorisation()` returns `None` for it, and `None` is never read as "passive" — the only way to skip the gate is an explicit `passive=True` on a specific check.

This is still a legal requirement, not a product setting, and it is still enforced deny-by-default in `core/authz.py`.

That denial is the correct outcome. **Do not add an allowlist entry for a domain you do not control** — the git history of that file is the audit record, and a row asserting verification you did not perform is worse than no scanner at all.

### Authorising a target you do own

1. Prove control. For a domain, publish a TXT record containing a nonce at `_scanverify.<domain>` and save the DNS answer as a file.
2. Add a row to `config/authorised_scope.yaml` **with its proof file committed alongside**. `core/authz.py` refuses to load a row that does not name an `evidence_file` at all. It does **not** currently check that the file exists on disk — that is enforced by review, and by the test on the worked example.

A fully annotated, runnable example of all five row shapes — verified, self-owned, TLS-lab, expired, revoked — is committed at `config/authorised_scope.example.yaml`. Try it without touching the live file, authorising the TLS lab's Standard-mode scan from §5 above:

```bash
$ uv run scan run tls --target https://localhost:14400 --mode standard \
    --replay corpus/fixtures/tls/healthy \
    --scope-file config/authorised_scope.example.yaml
[  20%] connecting to localhost:14400
[  50%] checking the certificate
[  75%] enumerating protocols
[ 100%] done

tls 1.0.0 standard https://localhost:14400 -> succeeded

severity  conf   state          check                            location
info      0.97   informational  tls-no-certificate-transparency  localhost:14400

14 check(s) ran, 0% inconclusive, 5 request(s)
```

The row that authorises it:

```yaml
- authz_id: authz_2026-08-28-005
  org_id: org_internal
  target: { type: domain, value: localhost, wildcard: false }
  method: self_owned
  proof:
    observed: 'local TLS lab started by corpus/generators/tls.py on this machine'
    observed_at: 2026-08-28T00:00:00Z
    evidence_file: corpus/authz/localhost-2026-08-28.txt
  verified_at: 2026-08-28
  expires_at: 2026-11-26        # 90 days. Domains change hands.
  verified_by: operator:satwik
  attestation_ref: null
```

For a domain you actually own, the shape is the same but `method: dns_txt` with a real proof file:

```yaml
- authz_id: authz_2026-08-24-001
  org_id: org_internal
  target: { type: domain, value: your-domain.example, wildcard: false }
  method: dns_txt
  proof:
    observed: 'sp-verify=7f3a… at _scanverify.your-domain.example'
    observed_at: 2026-08-24T00:00:00Z
    evidence_file: corpus/authz/your-domain.example-2026-08-24.txt
  verified_at: 2026-08-24
  expires_at: 2026-11-22        # 90 days. Domains change hands.
  verified_by: operator:satwik
  attestation_ref: null
```

**Modes are still additive where authorisation is not the question:** Standard returns everything Light returns plus more, for both scanners. A higher mode never gives a different answer to the same check; it only ever runs more checks.

Authorisation is refused for an entry that is expired, revoked, or absent. `wildcard: false` means the record covers `your-domain.example` and **not** `api.your-domain.example`.

**An authorisation is about an asset, so the form you type does not matter** — a bare domain, a URL and a `host:port` all match the same row, and authorising `example.com` covers `https://example.com/path`.

**A port names a service.** A row for `http://10.0.0.5:3000` authorises that service and nothing else — not `:5000` on the same host. A row with no port is about the host and covers everything on it. Name the port when a host runs services you do not control; leave it off for a domain you own.

**No asset may be authorised twice.** The first matching row wins, so a duplicate silently shadows the later one — including its expiry and its revocation. A test fails the build on duplicates, because an append-only file merged carelessly is exactly how you get one.

---

## 6. Record and replay

The reason corpus tests are fast, deterministic, and not rude to third parties.

```bash
# run live, freeze every DNS answer
$ uv run scan run email --target news.ycombinator.com --record ./fixtures/hn
severity  conf   state          check                            location
high      0.98   confirmed      dmarc-missing                    $
high      0.96   confirmed      spoofing-possible                $
medium    0.98   confirmed      spf-missing                      $
medium    0.98   confirmed      mx-missing                       $
medium    0.50   inconclusive   dkim-missing                     $

5 check(s) ran, 20% inconclusive, 24 request(s)

$ ls ./fixtures/hn | wc -l
24
```

Replay reproduces it byte-for-byte with the network unplugged:

```bash
$ uv run scan run email --target news.ycombinator.com --replay ./fixtures/hn
# ...identical output, 24 requests, all served from disk
```

Notes:

- One JSON file per `(name, rrtype, resolver)`. Verbose on purpose — ground-truth data has to be auditable by a human reading a diff.
- The **resolver is part of the key**. Independent re-query through a second resolver is a real validation step, and collapsing the two would silently turn validation into a no-op on replay.
- The wildcard probe uses a random DNS label on the wire (a fixed one would be cached and could be special-cased by a target). Fixture naming canonicalises that random part, or no probe could ever be replayed.
- **A replay run never falls back to the wire.** An unrecorded query is a hard error, by design.

---

## 7. Using it in CI

```bash
uv run scan run email --target your-domain.example --replay ./fixtures --fail-on high
```

| Exit code | Meaning |
|---|---|
| `0` | The scan ran. There may still be findings below the threshold, or hedged ones. |
| `1` | The scan could not run — unknown scanner, denied authorisation, missing fixture, bad mode |
| `2` | The scan ran **and** reported a claim at or above `--fail-on` |

Observed against the news.ycombinator.com fixtures above (which contain a `high`):

```bash
$ scan run email -t news.ycombinator.com --replay ./fixtures/hn --fail-on high      # exit 2
$ scan run email -t news.ycombinator.com --replay ./fixtures/hn --fail-on critical  # exit 0
$ scan run email -t news.ycombinator.com --replay ./fixtures/hn                     # exit 0
```

**`--fail-on` only counts `confirmed` and `highly_likely`.** A `suspected` or `inconclusive` finding will never break your build. That is deliberate: breaking a build on a hedge is how a team learns to ignore a scanner.

---

## 8. The corpus — the thing that decides whether a scanner is done

A scanner is not finished because it runs. It is finished when it hits three numbers against targets whose correct answer we already know.

```bash
$ make corpus
scanner     checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
----------------------------------------------------------------------------
email          240   21    0    0      1.000    1.000   0.0%    0.8%  PASS
           recall is absolute (the true set is knowable for this scanner)
example          3    2    0    0      1.000    1.000   0.0%    0.0%  PASS
           recall is absolute (the true set is knowable for this scanner)
tls            121    5    0    0      1.000    1.000   6.6%    0.0%  PASS
           recall is absolute (the true set is knowable for this scanner)
```

**Read the suspected column, not just precision.** The TLS row's 1.000 rests on **5 claims, not 121 checks** — most TLS findings sit on a single independence class and surface as `suspected`, which the gate excuses from both true positives and false negatives. The numbers are honest; they are also thinner than they look, and `susp%` is where that shows.

- **precision** = of what we claimed, how much was real
- **recall** = of what was really there, how much we caught
- **inconclusive%** = shrugs ÷ checks that ran, **capped at 15%**. Without the cap, a scanner could score perfect precision by declining to answer everything.
- The **recall is absolute / corpus-relative** line is mandatory. For email the check set is finite and RFC-defined, so recall is a real number. For subdomain enumeration it never will be, and publishing a corpus-relative figure as if it were absolute is the dishonesty this product exists to avoid.

Results are written to `corpus/results/latest.json`.

### The CI gate

```bash
uv run python -m cli.corpus --check-baseline
```

Compares against the committed `corpus/results/baseline.json` and **fails** on:

- any drop in precision
- any rise in the inconclusive rate
- **any** new false positive on a known-good target — a single one, no threshold

A recall drop *warns* rather than failing: a recall regression is usually a deliberate precision trade, and failing it would push authors to over-report.

Here is what a real failure looks like — produced by deliberately breaking the reference scanner so it fires on a correctly configured target:

```
Regressions against the baseline:
  - example: 1 false positive(s) on a known-good target. A single one fails the build.

Scanners below their gate:
  - example: 1 finding(s) on a known-good target, where anything reported is a false positive by definition

scanner     checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
----------------------------------------------------------------------------
example          3    2    0    0      1.000    1.000  33.3%    0.0%  FAIL
           recall is absolute (the true set is knowable for this scanner)
           why: 1 finding(s) on a known-good target, where anything reported is a false positive by definition
```

Note that precision still reads 1.000. The false positive surfaced as `suspected` (the independent re-query disagreed with it), and `suspected` is excluded from precision by design. **On a known-good target it still counts as a false positive** — there is nothing to be uncertain about on an asset we know is correct, so a hedge there is a false positive wearing a hedge. That rule exists because this exact scenario slipped through the first version of the check.

### The second opinion

The TLS analyser is our own engine, not a wrapper around `testssl.sh` ([ADR-016](02-decisions.md#adr-016--build-our-own-tls-engine-keep-testsslsh-as-a-cross-check)) — but testssl.sh is kept as an independent cross-check. It compares **observations, not verdicts**: whether a 1024-bit key is "high" or "critical" is an opinion we are entitled to hold; whether the key *is* 1024 bits is a fact, and two implementations disagreeing about a fact means one has a bug.

```
$ make crosscheck
  healthy              11/11 facts agreed  (55 testssl findings)
  expired              11/11 facts agreed
  expiring-soon        11/11 facts agreed
  weak-key             11/11 facts agreed
  self-signed          12/12 facts agreed
  obsolete-protocol    11/11 facts agreed

67 facts compared across 6 cases
no disagreements
```

The comparison that carries the others is the **certificate fingerprint**: if both tools report the same SHA-256, they are demonstrably looking at the same certificate.

Not part of any gate — testssl.sh is GPLv2, runs as a separate process, is slow, and a gate depending on a third-party tool being installed breaks on someone else's machine.

### Updating the baseline

Only after you have looked at the numbers and believe them:

```bash
uv run python -m cli.corpus --update-baseline
git add corpus/results/baseline.json
```

The baseline is a claim about accuracy. Do not update it to make a red build go green.

---

## 9. Changing a scanner

Full guide: [how-to-add-a-scanner.md](how-to-add-a-scanner.md). The operational loop:

```bash
make test                                       # unit tests first
uv run python -m corpus.generators.email        # re-record fixtures if queries changed
make corpus                                     # score it
uv run python -m cli.corpus --update-baseline   # only if the numbers are right
make lint typecheck licence-check
```

**Bump `scanner_version` whenever results change.** Patch = no result change. Minor = same checks, better detection. Major = a check changed *meaning*, which is a `check_id` rename plus a `renamed_from` entry, not a silent redefinition.

### Adding a corpus case

`corpus/targets/<scanner>.yaml`:

```yaml
- id: my-new-case
  tier: vulnerable          # vulnerable | known_good | benchmark
  source: frozen            # frozen = replayed; what CI gates on
  mode: standard
  target: { type: domain, value: corpus-thing.example }
  fixtures: corpus/fixtures/email/my-new-case
```

`corpus/expected/<scanner>.yaml` lists the `check_id` + `location` pairs the case must report. An empty list means "must report nothing".

Two extras worth knowing:

- **`expect_inconclusive: true`** — for a target where no definite answer is possible (a SERVFAIL fixture). The case is excluded from the inconclusive-rate denominator, which is measured "where a definite answer is expected", and asserted separately instead: the scanner *must* return inconclusive there, and must not error.
- **Every scanner needs at least one `known_good` case.** Anything reported there is a false positive by definition.

A new detection is not shippable without **all four**: a positive case, a negative case, a stated `independence_class`, and a hand-assigned prior with a written justification.

---

## 10. Troubleshooting

Every message below is real output.

**`no scanner named 'tls'; registered: email, example`** — exit 1.
Typo, or the scanner package is not registered. Scanners register on import of `scanners/<name>/__init__.py`; check the `@register` decorator is on the class.

**`authorisation denied: no authorisation record for X in config/authorised_scope.yaml`** — exit 1.
Working as intended for any check declared active (§5) — which, since 0b.6, is not simply "Standard or Deep": TLS's `tls-protocol-obsolete`, `tls-weak-cipher` and `tls-no-forward-secrecy` are active and gated in Standard mode, but TLS's Light mode and its other three Standard checks are passive and need no authorisation at all. `--mode light` still works with no scope file for TLS. Authorise a target you actually control instead.

**`error: unknown mode 'aggressive'; expected light, standard or deep`** — exit 1.

**`no recorded answer for … (resolver 1.1.1.1) in ./fixtures. Record it with --record before replaying; a replay run never falls back to the wire.`** — exit 1.
You are replaying fixtures that do not cover a query the scanner makes. Re-record them. This is common and expected after changing which names a scanner queries.

**`make corpus` reports errored cases:**

```
why: cases that errored: known-good, null-mx, spf-invalid, … If the fixtures do not
     cover a query the scanner now makes, re-record them
     (uv run python -m corpus.generators.<scanner>).
```

Same cause as above, at corpus scale. Run the generator and re-run `make corpus`.

**A finding you expected is `suspected` instead of `confirmed`.**
Almost always: validation did not run. Every check in the email scanner observes one channel (DNS), so with a single `independence_class`, `confirmed` requires validation to have run *and* passed. Check that the check passes a `validates=` predicate, and that two resolvers are configured — with only one, validation reports `unavailable` and the finding correctly stops at `suspected`.

**`dkim-missing` always comes back `inconclusive`.**
That is correct and deliberate. DKIM selectors are chosen freely by the sender and cannot be enumerated; failing to guess one of the seventeen common selectors proves nothing at all. The check reaches a verdict only when it *finds* a key. Reporting "no DKIM" from a failed guess would be a false positive by construction.

**A domain with a wildcard DNS zone gives odd results.**
Presence-based conclusions are downgraded to `inconclusive` there, because a zone answering every name makes any lookup appear to succeed. Absence findings still stand — a real record wins over a wildcard, so absence remains knowable.

---

## 11. Rules an operator must not break

1. **Never add an allowlist entry for an asset you do not control.** The git history of `config/authorised_scope.yaml` is the audit record.
2. **Never update the corpus baseline to make a build pass.** It is a claim about accuracy.
3. **Never run Standard or Deep against a third party.** Light is passive and always safe; the other two are not, and this is a legal line, not a policy preference.
4. **Do not present confidence as calibrated.** `confidence_provisional: true` means the number is a hand-assigned prior.
5. **Never say "compliant."** Only "compliance readiness" ([ADR-011](02-decisions.md#adr-011--compliance-readiness-never-compliance)).

---

## 12. What this does not do yet

Stated plainly so nobody plans around a capability that is not there.

| Not built | Why |
|---|---|
| `open-relay`, `mail-tls-weak` | Need an SMTP connection — active, not passive, and belongs behind the authorisation gate |
| `lookalike-domain` | Needs RDAP over HTTP plus a permutation engine; larger than the rest of Tool 1 combined |
| BIMI checks | Its absence is a branding gap, not a security finding |
| HTTP record/replay | DNS only so far. The HTTP client captures redacted, size-capped pairs but has no replay backend. |
| DNS enumeration, web scanning | Tools 3 and 4. Two of four in Phase 1 are done. |
| The A+ to F TLS grade | Deferred by decision — a grade is an opinion and opinions get argued with; "expires in 5 days" does not. Easier to add later than to change once people have built expectations on a score. |
| HSTS checks | An HTTP response header, so it needs HTTP record/replay first |
| A `tls-weak-cipher` corpus case | RC4 and 3DES are compiled out of OpenSSL 3, so the lab cannot serve one at any security level — verified by trying, not assumed |
| Calibrated confidence | Phase 4. Everything is `confidence_provisional: true`. |
| The OOB callback server | Phase 2a. The client is a stub that raises, and a scanner meeting it must return `inconclusive`. |

**On the corpus:** the 16 email cases are synthetic zones written by us. Precision 1.000 against them proves the checks do what was intended — not that the intent matches the real world. The stronger evidence is a live run against twelve real domains with zero false positives, and twelve is still a small number. [05-phase-1-first-tools.md](05-phase-1-first-tools.md) asks for ~50 real domains recorded and hand-labelled as a frozen tier; that is owed.
