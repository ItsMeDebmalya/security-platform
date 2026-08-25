# 14 — Progress Ledger

*What has actually been built, what broke along the way, and what is owed. Append-only.*

The planning documents say what we intend to do. This one says what happened — including the parts that did not go to plan, which are usually the parts worth remembering.

**How to use it.** Append a dated entry when a phase or a tool reaches a stopping point. Each entry carries four things:

- **Built** — what exists now that did not before
- **Found & fixed** — bugs, wrong assumptions, and what the fix was. This is the most valuable section; a bug found once and forgotten is a bug found twice.
- **Decided** — judgement calls made during implementation that the plan left open. Contract changes go in [08-changelog.md](08-changelog.md) as well.
- **Deferred** — owed work, with the reason. Consolidated in §D at the bottom.

Do not rewrite history here. If something recorded turns out to be wrong, append a correction.

---

## 2026-08-22 → 08-24 · Phase 0 — Foundations

**Plan:** [04-phase-0-foundations.md](04-phase-0-foundations.md) · **Status: complete**

### Built

| Task | What landed |
|---|---|
| 0.1 | Python 3.12 + `uv`, ruff, mypy `--strict`, pytest, Makefile, `.env.example` |
| 0.2 | **The Scanner Contract, frozen.** `contracts/*.schema.json` (finding, evidence, scanresult, scanrun), `core/models.py`, `BaseScanner`, registry, `ScanContext`, kill switch, cost meter |
| 0.3 | `core/` services: `authz`, `dns`, `http`, `evidence`, `confidence`, `state`, `ratelimit`, `cost`, `killswitch` |
| 0.4 | `scan` CLI — `list`, `run`, `--format`, `--record`/`--replay`, `--out`, `--fail-on`, exit codes |
| 0.5 | `core/measurement.py` + `cli/corpus.py` — precision, recall, inconclusive rate, baseline comparison |
| 0.6 | `tools/registry.yaml`, licence policy check, architectural-invariant tests, CI workflow |
| 0.7 | `scanners/example/` reference scanner + `docs/how-to-add-a-scanner.md` |

The five design checks from task 0.2 were written as failing tests **before** the contract existed, and they remain its acceptance criteria.

### Found & fixed

**`checks_run` rejected the ordinary case.** The first version was a list of `check_id`s, and the ScanResult validator demanded a finding or a suppression record for each. That wrongly rejected a check that ran, found nothing wrong, and correctly said nothing. Now a list of `{check_id, location, outcome}` where `clear` is the honest name for that outcome. *Caught while writing the reference scanner — the first scanner to have a check that passes.*

**A `suspected` finding on a known-good target slipped the gate.** Deliberately broke the reference scanner so it fired on a correctly configured target. The injected false positive came back `suspected` (the independent re-query disagreed), and `suspected` is excluded from precision by design — so precision still read 1.000 and the build went green. Fixed: on a known-good target, hedges count as false positives. There is nothing to be uncertain about on an asset we know is correct, so a hedge there is a false positive wearing a hedge.

**The wildcard probe could never be replayed.** It uses a random DNS label on the wire, which is correct — a fixed one would be cached and could be special-cased by a target. But it meant no recorded corpus case was replayable. Fixture naming now canonicalises the random component; the recorded answer keeps the real name it used.

**`ruff format` reformatted the specification.** It rewrote a Python block inside `01-architecture.md`. Reverted, and `docs/` is now excluded from the formatter. The document set is the spec.

### Decided

- **Three additive contract fields** — `no_verdict_reason`, `telemetry.checks_run`, `analysis` on `dns_answer` evidence. All recorded with revert instructions in [08-changelog.md](08-changelog.md) §v3.2, because ADR-002 makes a contract change a migration rather than an edit.
- **State and ID are enforced, not just computed.** A `Finding` whose stored `state`, capped `confidence` or `id` disagrees with `core/state.py` is rejected outright. Hand-setting either is a loud failure.
- **Two truth-table orderings** the architecture document leaves ambiguous, fixed in `core/state.py`: the `< 0.40` reporting floor applies to every row after `inconclusive`, and `severity: info` is decided before validation outcome.
- **`expect_inconclusive` corpus cases.** [10-measurement.md](10-measurement.md) measures the inconclusive rate "where a definite answer is expected". A SERVFAIL fixture is not that, so those cases are excluded from the rate and asserted separately instead.

### Deferred

- CI workflow written but **never executed** — no remote existed at the time. → D1
- No docker-compose for the vulnerable targets. → resolved 2026-08-24, see below
- HTTP record/replay — DNS only. → D2
- Benchmark corpus tier wired as a concept only, per the plan's explicit deferral. → D3

---

## 2026-08-22 → 08-24 · Tool 1 — Email Security Scanner

**Plan:** [05-phase-1-first-tools.md](05-phase-1-first-tools.md) · **Gate: precision ≥ 0.99, recall ≥ 0.95, inconclusive ≤ 15%** · **Status: passing**

```
scanner   checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
email        240   21    0    0      1.000    1.000    0.0%     0.8%  PASS
```

Plus a live sweep of **50 real domains: 8 flagged, all hand-verified true positives, zero false positives**, inconclusive rate 3.4% across 444 real checks.

### Built

- **RFC parsers, written as parsers rather than regexes** — SPF (7208), DMARC (7489), DKIM (6376). Each pure and separately tested before anything touched DNS.
- **17 checks** — 9 in Light, 8 more in Standard, all passive DNS.
- `resolve_spf_chain()` walks `include:`/`redirect=` recursively, detects loops, and returns `definite=False` when a SERVFAIL stopped it partway.
- DKIM key strength measured from the DER modulus, since no tag states it.
- 16-case ground-truth corpus, recorded by running the scanner itself through a recording resolver.

### Found & fixed

**Six checks were silently scoring zero recall.** Generating the corpus revealed them returning `suspected` rather than reported. Correct behaviour, badly configured: every check in this scanner observes one channel (DNS), so with a single `independence_class`, `confirmed` requires validation to have run *and* passed — and those six had no validation predicate. Each now re-tests through an independent resolver. `spf-lookup-limit` re-walks the **entire** include chain through the second resolver, because the finding rests on every record in it.

**A fabricated quote in a finding.** For `jpmorganchase.com` the description asserted *"Its SPF record is `v=spf1 -all`"*. Their record authorises nine IP ranges. Two causes: the no-mail test only looked for `include:` terms (they use `a:` and `ip4:`), and the description hardcoded the string instead of quoting what was read. **Putting words in a target's mouth is worse than reporting nothing.** Fixed by requiring every SPF term to be `all` before calling a domain silent, and by quoting the record as read. *Found only by the live sweep — invisible to the synthetic corpus.*

**Rate limiting the wrong thing.** A 50-domain sweep ran at ~50 seconds per domain. One limiter at 2 req/s was throttling DNS to `1.1.1.1`, and an email scan is ~25 lookups. The limit exists to protect systems we scan; a public recursive resolver is not one, and its cache is what keeps our lookups off the target's own nameservers. Split into `for_target()` (2/s) and `for_resolver()` (25/s), adaptive backoff unchanged on both. **50 domains: 40 minutes → 33 seconds.**

**`gov.uk` exposed a framing bug.** No MX is a true positive, but reporting *"medium: mail cannot be delivered"* against a domain publishing `v=spf1 -all` and `p=reject` is noise — that domain has said it sends no mail and is missing only the null MX that declares it. Severity is now keyed to whether an enforcing DMARC policy exists.

**A stale fixture crashed the whole corpus run.** Changing a scanner so it makes a new DNS query is ordinary mid-change work, but `MissingFixtureError` escaped and printed a stack trace from inside the resolver. Each case now catches it and reports as errored, and the message names the command that fixes it.

### Decided

- **`dkim-missing` can never be a confident finding.** DKIM selectors are chosen freely by the sender and cannot be enumerated; failing to guess one of 17 common names proves nothing. The check reaches a verdict only when it *finds* a key — otherwise `inconclusive` by construction. This is the single most likely place for a competitor to ship a false positive.
- **Wildcard zones downgrade presence, not absence.** A wildcard cannot mask a record that exists — a real answer wins over it — so absence findings stand, and downgrading them would cost recall for no honesty gained.
- **A check whose subject does not exist is not recorded in `checks_run` at all.** `dmarc-pct-partial` on a domain with no DMARC record did not run. Calling it `clear` would claim we checked and found nothing wrong; calling it `inconclusive` would bury the one finding that matters under five restatements.
- **Null MX (RFC 7505 `MX 0 .`) is recognised as the deliberate statement it is.**

### Deferred

- `open-relay`, `mail-tls-weak` — need an SMTP connection, which is active rather than passive. → D4
- `lookalike-domain` — needs RDAP over HTTP plus a permutation engine. → D5
- BIMI — its absence is a branding gap, not a security finding. Deliberately out of scope, not deferred.
- The ~50 real-domain frozen corpus tier the plan asks for. → D6

---

## 2026-08-24 · Supporting work

Not on the plan, built because the work needed it.

- **`docs/12-cli-runbook.md`** + published artifact — every command with real captured output.
- **`docs/13-test-targets.md`** + `docker-compose.yml` — Juice Shop, DVWA, VAmPI (vulnerable and safe), badssl. Closes the Phase 0.5 docker-compose item.
- **`config/authorised_scope.example.yaml`** — all four row shapes, annotated, runnable, and tested.
- **`scripts/authorise-domain.sh`** — issues a nonce, polls the zone's own authoritative nameservers, and writes the authorisation row **only after** seeing it. Verified: on timeout it writes nothing.
- **`scripts/scan-many.sh`** — Light-mode sweep over a domain list.
- **Guard tests** (`test_live_authorised_scope.py`) — a `self_owned` row may only target loopback or an RFC 2606 reserved name; public targets need real proof; every cited evidence file must exist; nothing runs past 90 days.

### Found & fixed

**A 30-minute wait for a record that was never saved.** `authorise-domain.sh` polled public resolvers, which cannot distinguish "you have not added it" from "you added it and it is spreading" — the one question that matters while waiting. It now polls the zone's authoritative nameservers first and says so within two minutes, and `--check` turns the feedback loop into five seconds.

---

## 2026-08-24 · Tool 2 — SSL/TLS Analyzer

**Plan:** [05-phase-1-first-tools.md](05-phase-1-first-tools.md) · **Gate: precision ≥ 0.98, recall ≥ 0.95, inconclusive ≤ 15%** · **Status: passing**

```
scanner   checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
tls          121    5    0    0      1.000    1.000    6.6%     0.0%  PASS
```

Plus **67 facts cross-checked against testssl.sh across 6 servers, no disagreements**, and live verification against six `badssl.com` subdomains.

### Built

- **[ADR-016](02-decisions.md#adr-016--build-our-own-tls-engine-keep-testsslsh-as-a-cross-check)** — build our own TLS engine rather than wrapping `testssl.sh`. Reverses the phase plan, so it got an ADR. Answers Q12b.
- `core/tls.py` — **two contexts that do opposite jobs**. `_observing_context()` is deliberately permissive so obsolete servers can be observed at all; `_verifying_context()` uses the real trust store and reports OpenSSL's own reason. Running both against one server *is* the control-vs-test pair the contract requires, so the evidence falls out of the design rather than being reconstructed.
- `corpus/generators/tls_lab.py` — mints certificates with any named defect and serves them over real TLS on loopback, including three-level chains.
- **13 checks** — 7 Light, 6 Standard. 14-case frozen corpus.
- `tls_handshake` evidence gained a real shape (contract addition, [08-changelog.md](08-changelog.md)).
- `corpus/crosscheck/testssl.py` + `tools/fetch-testssl.sh` — the independent second opinion, pinned by SHA-256.

### Found & fixed

**A correctly configured TLS client is blind to the servers we are paid to find.** Python's default client refuses to handshake with a server running TLS 1.0 — the exact misconfiguration worth reporting. A scanner inheriting that safety floor reports "connection failed" for every insecure server and looks like it is working. **The corpus would not have caught it**, because the cases would have been built on the same assumption. Found by spiking before writing the scanner; the pair of tests asserting both halves is in `tests/core/test_tls.py`.

**`untrusted-root.badssl.com` was reported as a self-signed certificate.** Its subject is `CN=*.badssl.com` and its issuer `CN=BadSSL Untrusted Root CA` — plainly different. OpenSSL code 19 is `SELF_SIGNED_CERT_IN_CHAIN`, which says a root in the chain signs for itself, and **every root does**. Code 18 is the one that means the *leaf* does. Split into `tls-untrusted-root`, a different problem with different remediation.

**The same conflation, made twice.** The first draft of the testssl cross-check read `cert_chain_of_trust` — "failed (self signed CA in chain)" — as "the leaf is self-signed", and generated five false disagreements. Two files, one afternoon, one misunderstanding. Both now carry a test named after it.

**A hostname mismatch had no second opinion.** Only our own RFC 6125 matcher had a view, so it sat at `suspected`. Added an independent probe: trust the system store *and* the server's own leaf, with hostname checking on — trust is then satisfied either way, so the only thing OpenSSL can still object to is the name. Two implementations of one rule, and when they disagree the finding stays at one signal, which is the right response to not knowing which is wrong.

**Anchoring on the leaf alone was not enough**, and the lab hid it. That works for a self-signed certificate but a real chain needs its issuer, so the lab passed while `wrong.host.badssl.com` produced no verdict at all. Later the same probe was found ignoring the *configured* anchor, so private certificates got no second opinion either.

**The scheme, not the declared type, decides how a target is parsed.** `--target-type` defaults to `domain`, so a pasted URL made the host the literal string `https://www.google.com`: every check inconclusive on a site with nothing wrong, and the scope refusing its own target as third-party. Same root cause in `_endpoint()` and `Scope.for_target()`.

**Three faults in the ground truth, not the scanner.** The lab CA had no `basicConstraints: CA:TRUE`, so OpenSSL would not use it to sign and path building failed at the first step — every case was silently an untrusted-chain case. Lab servers ran at `@SECLEVEL=0` (needed to serve weak keys at all) and therefore also accepted TLS 1.0, making every case an obsolete-protocol case. And a two-level chain cannot express an incomplete chain: if the signer *is* the trusted root, no intermediate is needed and the path builds fine. **Ground truth that is wrong produces a green gate and a scanner nobody should trust.**

**`--severity LOW` made the cross-check nearly useless.** It drops findings rated OK — precisely the facts we agree on. Removing it took the comparison from 6 facts to 67.

### Decided

- **The permissive context observes; it never fetches.** Recorded as an engineering rule in [06-guidelines.md](06-guidelines.md). It accepts forged and expired certificates by design, so reusing it to retrieve content silently disables HTTPS for that request.
- **Expiry is read from the certificate, not from the verify verdict.** OpenSSL reports only its *first* objection — an expired and self-signed certificate comes back as "self-signed" alone.
- **Chain completeness is detected behaviourally.** Python 3.12 exposes no certificate chain (`get_unverified_chain()` is 3.13), so we ask whether a verifying context can build a path. That measures what a visitor experiences rather than what the bytes contain, and is the better check regardless of the library limitation.
- **Replay computes days-until-expiry against `observed_at`.** Otherwise every frozen fixture silently becomes an expiry finding as it ages and the corpus rots untouched.
- **The cross-check compares observations, not verdicts**, and is not part of any gate — GPLv2, slow, and a gate depending on a third-party tool being installed breaks on someone else's machine.

### Honest limits

- **Precision 1.000 rests on 5 claims, not 121 checks.** The other findings surface as `suspected` because they rest on a single independence class: `expiring-soon` is arithmetic on one certificate field, and `untrusted-root` and `chain-incomplete` are only knowable from path building. [10-measurement.md](10-measurement.md) excuses hedged findings from both true positives and false negatives, so this does not distort the numbers — but the numbers are thinner than they look.
- **`tls-weak-cipher` has no positive case and will not get one here.** RC4 and 3DES are compiled out of OpenSSL 3 — verified by trying to serve them, not assumed. → D11

---

## 2026-08-25 · Operator testing session

Live testing of both scanners against the operator's own infrastructure and a spread of public targets.

### Found & fixed

**Thirteen findings about a certificate that was never seen.** A host that does not speak TLS produced one inconclusive finding per certificate check — seven rows of "critical / inconclusive / tls-cert-expired" against `httpforever.com`, which accepts TCP on 443 and then refuses the handshake. Each row was individually honest and the wall of them was not. Now one `tls-no-handshake` finding, and the certificate checks are not recorded as having run — a certificate check on a host with no certificate did not run, and counting them let one closed port swamp the inconclusive rate.

**Authorisation compared raw target strings.** Authorising `expired.badssl.com` still denied a scan of `https://expired.badssl.com`. An authorisation is about an asset, and a bare domain, a URL and a `host:port` all name the same one. `core/authz.host_of()` normalises them; the denial message names the host rather than echoing the URL; `authz_ref` records the asset rather than the typed string.

### Decided

- **`--self-owned "<note>"` attestation**, with batch and `--wildcard` forms. For assets we control but cannot prove control of by publishing DNS. [09-ownership-verification.md](09-ownership-verification.md) permits it as an explicit row with a note; the note is mandatory, written into the proof file with the operator's name, and the file states plainly that nothing was verified.
- **The live-scope guard was relaxed to match.** It previously refused `self_owned` on any public target, which blocked the legitimate case. It now requires a self_owned row on a public target to cite a proof file containing a written attestation — verified it still fails a careless `testphp.vulnweb.com` row.

### Worth remembering

**I nearly filed a false-positive bug against a correct finding.** The scanner reported `tls-protocol-obsolete` on two of the operator's hosts. Checking with `openssl s_client -tls1` said the handshake was refused, which looked like our bug. It was not: **openssl's own default security level blocks TLS 1.0**, so the refusal came from the verifying client, not the server. Adding `-cipher ALL:@SECLEVEL=0` showed both hosts accepting it.

That is the exact blind spot `core/tls.py` exists to avoid — a client with a safety floor cannot observe the servers worth reporting — and I walked into it while checking `core/tls.py`. **A verification tool with the same blind spot as the thing it is verifying confirms nothing.**

### True positives on the operator's own infrastructure

- `erp.codez.in` serves a Let's Encrypt certificate that expired **2026-05-10** — confirmed by hand.
- Both ERP hosts still accept **TLS 1.0**.
- `kinetrix.in` publishes `p=none`, so mail can be forged as it today.

### Deferred

- **Certificate revocation is not checked at all.** `revoked.badssl.com` returns no findings, which reads as a pass and is a gap. Needs OCSP or CRL, which means an outbound HTTP request to the CA. → D12

---

## D. Deferred register

Single source of truth for what is owed. Move an item out only when it lands.

| # | Item | Why deferred | Blocks |
|---|---|---|---|
| **D1** | Verify CI actually runs | No remote existed when it was written; one exists now, but no run has been observed | Nothing yet — but every gate claim rests on it |
| **D2** | HTTP record/replay | DNS only so far. The HTTP client captures redacted, size-capped pairs but has no replay backend | Tool 4 (Website Light) |
| **D3** | Benchmark corpus tier (OWASP Benchmark, WAVSEP) | Explicitly deferred by the plan until it has a consumer | Phase 2 web scanner |
| **D4** | `open-relay`, `mail-tls-weak` | Need SMTP connections — active, not passive; belong behind the authorisation gate | Nothing; Tool 1 passes without them |
| **D5** | `lookalike-domain` | Needs RDAP over HTTP plus a permutation engine; larger than the rest of Tool 1 combined | Nothing |
| **D6** | ~50 real domains recorded as a frozen corpus tier | The 16 committed cases are synthetic zones we wrote. Precision 1.000 against them proves the checks do what was intended, not that the intent matches the world | Confidence in the published number |
| **D7** | **CoreDNS container serving a local authoritative zone** | Standard-mode testing needs a zone we control. A local authoritative server on a reserved name (`sptest.test`) would make `self_owned` honest, exercise the real dnspython path instead of a fake resolver, and let us author any scenario — 11-lookup chains, weak DKIM keys, malformed DMARC — against real DNS. ~1 hour. Not built because Light-mode sweeps proved higher value first | Standard-mode live testing; a better Tool 1 corpus |
| **D9** | The A+–F TLS grade | Deferred 2026-08-24 by decision. A grade is an opinion, and opinions get argued with; facts ("expires in 5 days", "accepts TLS 1.0") do not. Easy to add later, hard to change once customers have built expectations on a score. If it ships, [05-phase-1-first-tools.md](05-phase-1-first-tools.md) requires the full rubric be visible | Nothing |
| **D10** | HSTS checks in Tool 2 | [05-phase-1-first-tools.md](05-phase-1-first-tools.md) lists HSTS under TLS Standard, but it is an HTTP response header, so it needs an HTTPS GET and therefore HTTP record/replay (**D2**) before its corpus cases can be frozen | Nothing; Tool 2 gates without it |
| **D11** | A positive corpus case for `tls-weak-cipher` | RC4 and 3DES are compiled out of OpenSSL 3, so the lab cannot serve one at any security level — verified by trying. Needs either a different TLS implementation for the lab, or a recorded handshake from a real server still offering one | Nothing; Tool 2 gates without it |
| **D12** | Certificate revocation checking | `revoked.badssl.com` currently returns nothing, which reads as a pass. Needs OCSP or CRL — an outbound HTTP request to the issuing CA, so it also needs a decision about whether that counts as passive | Nothing; Tool 2 gates without it, but it is a visible gap in a demo |
| **D8** | `evidence_file` existence check in `core/authz.py` | The loader checks the field is present, not that the file exists, so a scope file stays loadable outside the repo. Enforced on the committed file by test instead | Nothing; it is a belt-and-braces item |

---

## Next

**Tool 3 — DNS & Subdomain Enumeration (Light).** Gate: precision ≥ 0.95, **recall ≥ 0.80 corpus-relative**.

The recall figure is the thing to get right before writing any of it. "All subdomains that exist" is not a knowable set, so recall here is measured against the corpus's known set only, and [10-measurement.md](10-measurement.md) requires every published number to say which kind it is. Reporting corpus-relative recall as though it were absolute is the specific dishonesty this product exists to avoid.

This tool also matters disproportionately because **it produces the asset list every other tool scans** — its output is Tool 2's input.
