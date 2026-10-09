# How to add a new scanner

*Written by building `scanners/example/`. If a step here is wrong or missing, fix it while it is fresh — this file is the thing that keeps scanner #7 shaped like scanner #1.*

The contract is frozen ([01-architecture.md](01-architecture.md)). You are writing checks, not plumbing.

---

## 0. Before you write anything

A new detection is not shippable without all four of these ([10-measurement.md](10-measurement.md)):

1. a **positive** corpus case — it fires when it should
2. a **negative** corpus case — it stays silent when it should
3. a stated **`independence_class`** for its detection method
4. a **hand-assigned prior with a one-line justification**

If you cannot write the negative case, the detection has no measurable precision and does not ship.

---

## 1. The directory

```
scanners/<tool>/
├── __init__.py     # exports the scanner class
└── scanner.py      # the class itself
```

Rules enforced by `tests/architecture/`:

- **Never import `httpx`, `dns`, `socket` or `requests`.** Clients come from `ctx`. This is how rate limiting, scope enforcement and the kill switch stay guaranteed rather than remembered.
- **Never import another scanner.** Shared logic moves to `core/`.

## 2. The class

```python
@register
class MyScanner(BaseScanner):
    name = "mytool"
    version = "1.0.0"                                  # semver
    supported_modes = frozenset({"light", "standard"})
    target_types = frozenset({"domain"})

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        ...
```

`run()` must:

- call `ctx.check_alive()` before anything that touches the network
- report progress via `ctx.progress(message, fraction)`
- return a `ScanResult` whose `telemetry.checks_run` lists **every check that executed**, with what it concluded

## 3. Emit a finding

Never construct `Finding(...)` directly — use `Finding.create(...)`, which derives the `id` and the `state`. Passing `state` or `id` raises.

```python
result = ConfidenceEngine().combine([
    Signal(
        method="dns_txt_parse",
        prior=0.5,
        likelihood_ratio=12.0,
        independence_class="dns",
        prior_justification="DMARC records are unambiguous when they parse",
    )
])

finding = Finding.create(
    org_id=ctx.org_id,
    scanner=self.name, scanner_version=self.version,
    check_id="dmarc-policy-none",
    title="DMARC policy is set to 'none'",
    target=target,
    location="$",            # "$" means the target as a whole
    severity="medium",       # how bad IF TRUE. Never adjusted for how sure we are.
    confidence=result.confidence,
    confidence_provisional=result.provisional,
    detection_methods=result.detection_methods,
    validation=validation,
    evidence=[...],
    description=..., impact=..., remediation=...,
    first_seen=now, first_seen_scan_id=ctx.scan_id,
    last_seen=now, last_seen_scan_id=ctx.scan_id,
)
```

### The three separate axes

| | What it means | Who sets it |
|---|---|---|
| **severity** | how bad it would be *if true* | you, from the vulnerability class |
| **confidence** | how sure we are it *is* true | `core/confidence.py` |
| **state** | the derived label | `core/state.py`. **Never you.** |

`confirmed` requires validation to have actually run and passed. A high score alone never earns it.

## 4. Evidence

Every finding needs a **control alongside its test**. "The server errored" is not evidence.

- DNS: `dns_evidence(...)` — the control is normally the wildcard probe
- HTTP: `capture_http_pair(...)` — redacted and size-capped for you
- out-of-band: the control is a token that was *not* hit
- timing: the control is the baseline sample set, and one before/after pair is not enough

If no control is possible, say why in `control_rationale`. An empty rationale is refused.

## 5. Say "I don't know" out loud

A check that ran but reached no verdict — timeout, SERVFAIL, WAF block, a missing prerequisite, the OOB server unavailable — emits a finding with `no_verdict_reason` set. That makes its state `inconclusive`.

```python
Finding.create(..., no_verdict_reason="servfail")
```

The distinction that matters: **"there is no record" and "we could not find out" are different answers.** `DnsResponse.is_definite()` is how you tell them apart.

A scanner that could not execute **at all** is different again: zero findings, a `ScanError(fatal=True)` in `errors[]`, and the run's outcome becomes `errored`.

## 6. Wire up the corpus

`corpus/targets/<tool>.yaml`:

```yaml
gate:
  precision: 0.99
  recall: 0.95
  inconclusive_max: 0.15
  recall_definition: absolute      # or corpus_relative - state which, always
cases:
  - id: policy-none
    tier: vulnerable               # vulnerable | known_good | benchmark
    source: frozen                 # frozen = replayed, what CI gates on
    mode: light
    target: { type: domain, value: corpus-broken.example }
    fixtures: corpus/fixtures/<tool>/policy-none
```

`corpus/expected/<tool>.yaml` lists the `check_id` + `location` pairs each case must produce. An empty list means "must report nothing".

Record the fixtures once:

```
scan run <tool> --target <t> --record corpus/fixtures/<tool>/<case>
```

Then `make corpus`. Then `uv run python -m cli.corpus --update-baseline` once the numbers are right, and commit the baseline.

**At least one `known_good` case per scanner.** Anything reported there is a false positive by definition — including a `suspected` one.

## 7. Before you open the PR

- [ ] `make lint`, `make typecheck`, `make test` green
- [ ] `make corpus` shows no precision regression
- [ ] new detections have a positive *and* a negative corpus case
- [ ] every new check has **fired against a real positive**: a live target or a recording of one, hand-verified and cited here. A corpus positive we wrote does not count. With no real positive, it ships marked UNDETERMINED with the reason, or not at all ([ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done), ledger D37)
- [ ] every RFC the check cites is **current**: confirmed against the RFC Editor's "Obsoleted by" field, and `make rfc-check` passes for it. If an RFC has been obsoleted, implement the successor and say which one the check follows ([ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done), ledger D44)
- [ ] any new dependency is in `tools/registry.yaml` with a licence
- [ ] `scanner_version` bumped if results changed
- [ ] `state` is derived, not hand-set
- [ ] evidence is redacted and replayable. Core redacts everything it stores (ADR-028), so do not write your own redactor. To shorten text, use `core.redaction.cap_text` or `cap_prefix`, never a raw slice (`text[:n]`), which can split a secret below what redaction recognises. A check reads raw data; it never decides from stored, redacted text
- [ ] nothing sends a state-changing request to a target

## 8. Standard mode

Every check declares `passive: bool` — there is no default, so a check that omits it fails at construction rather than being quietly permitted (0b.6). An **active** check runs only against a target with a valid record in `config/authorised_scope.yaml`, in any mode; `core/authz.py` denies by default and the CLI exits 1. A passive check needs no record, also in any mode.

Passive means what an ordinary client does: one normal connection, no state change, nothing the target would not serve any visitor. Active means deliberately abnormal input. Connecting is not what makes a check active — finding a server is passive, reading its admin panel is not. If you are unsure, declare it active. See [09-ownership-verification.md](09-ownership-verification.md).

Modes are additive: Standard returns everything Light returns plus more. Never a *different* answer for the same check at a higher mode.

## 9. Reading a third-party service (CT logs, RDAP, …)

A scanner that queries a public *service* it does not own — `crt.sh`, an RDAP endpoint — hits a wall: `HttpClient` scope-checks every host and refuses anything but the target. That is correct for the target's own infrastructure, but a CT log is the HTTP analogue of a DNS resolver: something we ask *about* the target, not the target itself.

Declare those hosts on the scanner: `service_hosts: frozenset[str] = frozenset({"crt.sh", "rdap.org"})` (`domscout` is the first to do this). `cli/main.py` and `cli/corpus.py` union them into the HTTP scope. This **never widens the target scope and confers no authorisation** — it is a fixed, code-reviewed allowlist of read-only public services, and `core/authz.py` remains the only gate. Keep the list minimal and justified; each host is part of the scanner's audited definition, like its checks.

**Enumeration/inventory is not a vulnerability.** If your scanner's output is an asset list (subdomains, records), those findings are `severity: info` → `informational`, and `docs/10-measurement.md` excludes them from precision/recall by design. Do not invent a confidence score for inventory. Gate only the actual security findings; guard inventory against *false discovery* (a known-good/wildcard case that must report nothing false), and assess completeness live against a competitor, never as a frozen-corpus number (`domscout`, ledger 2026-09-03).

## 10. Three lessons from Tool 4a (`web`)

Each of these is a trap that looks fine in a green corpus. The third was a real defect found in review, three times over.

1. **A replayed probe path must be deterministic.** If you probe a path to get a control (a URL that should not exist), derive it from the target — never from `random` or a clock. Replay looks fixtures up by URL, so a random path is a different URL on every run and replay can never find what was recorded. `web`'s 404-control path is a function of the target.
2. **Never swallow `MissingFixtureError`.** It means the scanner asked for something the frozen fixtures do not hold — a corpus gap, not a target failure. A broad `except Exception` turns it into an `inconclusive` that the gate quietly absorbs. domscout does this today: see [the standing observation](14-progress-ledger.md#a-broad-except-can-turn-a-corpus-gap-into-an-inconclusive-2026-10-06). Catch the specific errors you can explain, and let this one propagate (`web` re-raises it).
3. **Redact everything you store that came from the target.** Core redacts the *captures* it makes, not the strings you write: finding descriptions, header names and values, request URLs and locations all reach storage as you wrote them. And core's header redaction goes by header *name* only, so a secret inside an ordinary header value is stored raw by any scanner ([ledger D21](14-progress-ledger.md#d-deferred-register)). `web` redacts all of these itself until D21 is fixed in core. Redact at capture time, not at display time.
