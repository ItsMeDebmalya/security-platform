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

**A row for one port was authorising every port on the host.** Adding a guard against duplicate rows — what a careless merge of an append-only file produces — immediately flagged `127.0.0.1` four times. The guard was not too crude; it was not crude enough. The four docker rows (`:3000`, `:4280`, `:5000`, `:5001`) looked like one asset to the uniqueness check *because they looked like one asset to `core/authz.py` too*: the port was stripped before comparison, so a row authorising Juice Shop on `:3000` authorised VAmPI on `:5000` and everything else on that host.

A record naming a port now names a **service** and covers only it; a record with no port is about the **host** and covers whatever runs there — the right reading for a domain you own, and the only one anyone would maintain correctly. Verified: `http://127.0.0.1:9999` is now denied where it was previously allowed.

The duplicate guard matters for a second reason. **The first matching row wins**, so a duplicate silently shadows the later one — including its expiry and its revocation. A revoked authorisation hidden behind a stale copy is the worst version of that.

**A finding whose claim was not in its own evidence.** `tls-protocol-obsolete` reported "completed a handshake using TLSv1, TLSv1.1" — correct, and verified independently. Its evidence showed a TLS 1.3 handshake as the test *and* the same TLS 1.3 handshake as the control, byte-identical. `supported_protocols()` returned only booleans, so the obsolete handshake it had performed was discarded before the finding was built.

For a product whose thesis is evidence rather than verdicts, that is the one defect that cannot ship: the reader is asked to take the central claim on trust while being shown something else. `probe_protocols()` now returns the observations, the test is the obsolete negotiation itself, and the control is the same server speaking something current:

```
TEST    ->  protocol TLSv1   | cipher ECDHE-ECDSA-AES128-SHA
CONTROL ->  protocol TLSv1.2 | cipher ECDHE-ECDSA-CHACHA20-POLY1305
same certificate on both: True
```

*Found by the operator reading the JSON and asking whether the finding was correct. It was; the evidence for it was not.*

### True positives on the operator's own infrastructure

- `erp.codez.in` serves a Let's Encrypt certificate that expired **2026-05-10** — confirmed by hand.
- Both ERP hosts still accept **TLS 1.0**.
- `kinetrix.in` publishes `p=none`, so mail can be forged as it today.
- `kinetrix.co.in` accepts **TLS 1.0 and 1.1** as well as 1.2 and 1.3 — confirmed with `openssl s_client -tls1 -cipher ALL:@SECLEVEL=0`.

### Deferred

- **Certificate revocation is not checked at all.** `revoked.badssl.com` returns no findings, which reads as a pass and is a gap. Needs OCSP or CRL, which means an outbound HTTP request to the CA. → D12

---

## Standing observations

*Not tied to one tool. Re-read before starting the next one.*

### The corpus has never found a bug

Six real defects in Tools 1 and 2, all found by live runs, none by a corpus at `precision 1.000`. The corpus's job is regression — proving today's change did not break yesterday's behaviour — and it does that well. It cannot discover new failure modes, because **a corpus written by the scanner's author encodes the scanner's assumptions**: every case passes by agreeing with the code. Now [ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done).

**Amended 2026-08-28.** 0b.1 added a third category: a defect found by *review*, caught by neither the corpus nor a live run. The corpus harness silently discarded the `derivation` field, and it could not have been found by running anything — the scanners emit no derived findings yet, so the wrong number and the right number were both empty. Some defects are only visible by reading the code that carries a value from one place to another. **Amended again 2026-08-28, after Phase 0b:** this is now the majority category, not a curiosity — four of the phase's defects were found this way and none by a green suite. See the Phase 0b entry for the table; the recurring shape is a plausible default standing in for a value that never arrived. **Amended 2026-09-02:** a fourth discovery route appeared — a *competitor*. `tls-chain-incomplete`'s false negative (D17) was caught by neither the corpus, a live run, nor a code read, but by SSL Labs and SSL.org disagreeing with us on a real host. That is the eighth defect to survive precision 1.000, and the reason competitive baselining is now definition-of-done ([ADR-024](02-decisions.md#adr-024--competitive-coverage-parity-is-part-of-a-tools-definition-of-done)). The corpus has still never found one.

### What our gate numbers rest on

Both scanners read `1.000`. They are not equally evidenced.

| | Claims the number rests on | Corpus | Live |
|---|---|---|---|
| email | 21 of 240 checks | 16 synthetic zones we wrote | 50 real domains, 8 findings, all verified |
| tls | **5** of 134 checks | 14 lab servers we configured | 6 badssl subdomains + operator infrastructure |

TLS's precision rests on five claims because most TLS findings sit on a single independence class and land as `suspected`. That is honest, and it means the figure is thinner than it reads. Recorded in [10-measurement.md](10-measurement.md) as a standing caveat.

### Ground truth is code too, and it had the most bugs

Three of the TLS lab's faults made every corpus case *easier* than intended while the gate stayed green — a CA without `basicConstraints`, servers accepting TLS 1.0 because `@SECLEVEL=0` was needed for weak keys, and a two-level chain that cannot express an incomplete chain. **Nothing in the harness can detect this.** Only reading the fixtures can.

### A verifier that shares the blind spot confirms nothing

A correctly configured TLS client cannot complete a handshake with the obsolete servers this product exists to find — and `openssl s_client` carries the same safety floor, so it once "disproved" a finding that was correct. Before trusting a second tool to check the first, ask whether it is capable of seeing the thing being checked. Independence is about failure modes, not about being a different program.

### Never put words in a target's mouth

A finding once asserted a domain's SPF record was `v=spf1 -all` when it authorised nine IP ranges. Descriptions now quote what was actually read, never a reconstructed string. The same defect recurred in a different costume at 0b.9, where a runbook transcript's `target` field was edited so two unrelated scans would appear to agree. **Asserting something about a target we did not observe is the worst failure this product can have**, because every other claim we make rests on the reader believing we only say what we saw.

### The blocking questions are non-technical, and building does not move them

[Q4](07-open-questions.md) (legal review of the tool list), [Q5](07-open-questions.md) (ToS and the authorisation agreement) and [Q4a](07-open-questions.md) (GDPR, blocks Phase 3) are all 🔴 and all unanswered. Two tools have shipped since they were raised. They will not resolve by writing more scanners, and Q4a blocks a phase we are two tools away from.

---

## 2026-08-25 · v3.4 restructuring — the calendar

**Not a build entry.** A strategy and foundation change, recorded here because the next several tools depend on it.

### Why

The client asked for differentiation that holds up in 2026 rather than 2022. Research found three dated, checkable facts that were not true or not checkable when v3.1 was written:

- **Certificate lifetimes are collapsing on a published schedule** — 200 days from March 2026 (in force now), 100 from 2027, 47 from 2029. Renewals go from ~1/year to ~8/year.
- **Roughly half of domains have no post-quantum key exchange**, and only ~4% of origins behind CDNs do. Traffic recorded today is decryptable later.
- **Thousands of MCP/agent servers are exposed**, hundreds with no authentication and no encryption, leaking API keys and conversation histories.

### Decided

- **[ADR-020](02-decisions.md#adr-020--amends-adr-014-what-we-claim-now-that-the-ground-has-moved) amends ADR-014** with four claims: the deprecation clock, post-quantum exposure, certificate lifetime readiness, AI and agent exposure. **The three claims ADR-014 cut stay cut.** Nothing found changes the judgement on attack paths or reachability, and they should not be reopened.
- **[ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived) reopens the Scanner Contract** — deliberately, at two scanners rather than ten. `materialises_at` and `derivation`, with derived confidence **inherited from its premise** so a calculation can never sound surer than the observation under it. The five states and the truth table do not move.
- **[ADR-019](02-decisions.md#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other) adds the asset graph** so discovery can feed consumers without scanners importing each other.
- **New Phase 0b** — seven foundation tasks that must land before more scanners are built on top.

### Hiccups found while designing it

**The contract had no way to express a future date at all** — `grep` returned zero matches. Worse than a missing field: `severity` means "how bad if true", and a 200-day certificate is not bad *yet*, so the flagship feature would have had to file as `info` — which [10-measurement.md](10-measurement.md) excludes from the gate entirely. It would not have counted toward any accuracy number.

**The confidence engine cannot express certainty.** It combines likelihood ratios; a calendar date is arithmetic, not evidence. Forcing one through the other means inventing a fake ratio to clear the reporting threshold, which corrupts the only thing the engine does. Hence `derivation` as a separate path.

**Record/replay has been written twice with no shared code**, and HTTP, MCP and device protocols are next. The TLS one already carries a subtlety the DNS one lacks — replay must compute expiry against record time or fixtures rot silently.

**Post-quantum is not testable on the current toolchain.** Verified: `set_groups` does not exist on Python 3.12 and ML-KEM needs OpenSSL 3.5+. The claim is buildable; it is not free, and pretending otherwise would have produced a demo that does not run.

**"DNS enumeration feeds every other tool" had no mechanism** behind it in three versions of the roadmap.

### Owed

- **Every number in the research must be verified against primary sources before it reaches a client.** The figures came from vendor blogs and secondary summaries. The v3.1 review found ~25 defects doing exactly this check. → D13
- **IoT was requested and is not in the plan.** Not researched, so not included rather than padded in. → D14

---

## 2026-08-25 · IoT as a distinct tool

**Decided.** IoT becomes its own tool in a new Phase 3a ([ADR-021](02-decisions.md#adr-021--the-iot--device-security-scanner-is-its-own-tool-not-a-check-family), [15-iot-scanner.md](15-iot-scanner.md)), split into 5a Exposure and 5b Vulnerability so the simpler, more differentiating half is not delayed behind CVE matching.

**The research that shaped it.** Shadowserver's internet-wide scans: ~60,000 MQTT brokers accepting unauthenticated connections, ~460,000 exposed CoAP services, 1.8 million devices with no authentication, no encryption or no authorisation. No vendor covers device protocols across an *external* attack surface — Censys and Shodan are data platforms, Tenable and Qualys work from inside.

**Compliance was researched and deliberately dropped as the angle.** India has no mandatory IoT security regime — MTCTE certifies manufacturers pre-market and DoT's consumer guidance is advisory — so there is no dated cliff to sell against, unlike the EU CRA. The tool is positioned on capability instead. *This also corrected a bias worth remembering: the first differentiation research was entirely EU/UK/US and missed that the first market is Indian, where CERT-In and DPDP are the real drivers.*

**Why it is a tool and not a check family.** It takes a network rather than a domain, outputs an inventory rather than a finding list, is the only tool running inside the perimeter, and infers rather than observes. And a differentiator has to be nameable.

**Where our thesis pays.** IoT CVE matching is the noisiest output in security — inconsistent vendor strings, poor CPE coverage, absent firmware versions. The industry norm is forty criticals from a banner match. Our existing rules already answer that: `inconclusive` when firmware is unparseable, `suspected` for version-only, `highly_likely` only with behavioural confirmation. **The rules are worth most where the noise is worst.**

**A documented exception, with its reason.** The version-strings-lie cap exists because distributions backport patches. IoT vendors rarely do — a new build or nothing — so `firmware_version` is a stronger signal here. The cap may justifiably be higher, **but the corpus must demonstrate it before the cap moves.**

**The safety rule is new and is stop-the-line.** Devices break in ways servers do not, and what breaks may be doing something physical. Rate ceilings are floors, not defaults. Never repeat an unanswered probe — a non-response from a constrained device is usually the device struggling.

### Owed

- Access to a real device network before this can be called done. Per ADR-017, and more so here: **an emulator written from an RFC will agree with a scanner written from the same RFC**, and real devices violate their specs constantly. → D15

---

## 2026-08-25 · prove, connect, close

**Decided.** The mitigation half of the product, previously slogans, is designed in [ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target).

**The reframe that made it safe.** The client asked for aggressive, offence-flavoured capability. Read literally that breaks ADR-004 — no exploitation — which is the product's legal identity and not reversible. Confirmed the intent was *aggressive proof, never touching the target*, and designed to that: make the target's own infrastructure demonstrate the bug (out-of-band callback), rather than intervene.

**Prove** — the validation engine and OOB server, already in the plan as components, promoted to flagship. *"We didn't guess, we made your server phone us."*

**Connect** — a same-run correlation pass over the asset graph, emitting `derived` story-findings whose confidence inherits from the weakest link. This is the ownable slice of what ADR-014 cut: not the attack-path moat (Wiz's product, needs a graph we will not have), but hand-written composition rules that a two-person team can audit and own.

**Close** — `scan verify <finding-id>` re-runs the one test that proved a finding and moves its status. This exposed an honest gap: "we verify your fix" has been promised since v2 with nothing behind it. It needs findings to persist between scans — a finding store, now foundation task 0b.8.

**Prioritise** — falls out of connect. A finding linking three stories outranks an isolated one of equal severity. severity×confidence orders a list; composition orders a plan.

**The risk named in the ADR.** Correlation can over-tell — three findings that look like a chain but are not. Same discipline as everywhere: the rule states its premise, confidence inherits from the weakest link, under-telling beats over-telling.

---

## 2026-08-28 · Phase 0b.1 — dated and derived findings

**Plan:** [03-roadmap.md](03-roadmap.md) Phase 0b · **Status: complete** · Commit `2b5b989`

First task of Phase 0b, and the one everything else in the phase is built against. [ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived) implemented as written.

### Built

- **Four additive fields on the Finding** — `materialises_at`, `materialises_reason`, `derivation`, `derived_from` — in `contracts/finding.schema.json` and `core/models.py`. All optional, all defaulting, so every finding written before this commit stays valid and scores identically. Recorded in [08-changelog.md](08-changelog.md) §v3.4c with revert instructions, because ADR-002 makes a contract change a migration rather than an edit.
- **Two co-dependency validators** — a date without a reason is rejected, and so is a `derived` finding that does not name its premise. Both raise in the same loud, specific style as the existing state/id validator.
- **`ConfidenceEngine.inherit()`** — deliberately a separate method from `combine()`, not a flag on it. Several premises inherit the weakest, per [ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target).
- **Detected/derived claim counts reported separately** in `core/measurement.py`. The gate itself is untouched: the split tells the two apart within `tp`/`fp`, it does not change either.

`core/state.py` has a zero-line diff. The truth table does not move for a dated or derived finding, which was the constraint held most tightly during review.

### Found & fixed

**The corpus harness never passed `derivation`, and nothing failed.** `cli/corpus.py` built every `Observation` from a finding with four fields and stopped. Because the field defaults to `"detected"`, every claim any scanner ever made would have scored as detected, and the derived half of the split would have reported `None` — indistinguishable from *"no derived claims yet"* rather than *"never wired up"*.

All 672 tests passed with the bug present. The new tests constructed `Observation` objects directly and so bypassed the single place the value has to come from.

**The shape worth remembering: a defaulted field plus a construction site that forgets it fails silently, and the default is precisely what makes it silent.** This is the same failure mode `ScanContext` avoids by handing out a raising `UnconfiguredClient` instead of a working default — there, forgetting to wire a client is a loud error rather than a quiet reach for the network.

Fixed with one argument. The fix that matters is the test: a harness-level one that calls `_score()` on a real `ScanResult`, because a `score_case()` test cannot fail when the harness forgets an argument. Verified by removing the argument and watching it fail.

**The Phase 0b exit criterion was unreadable.** `03-roadmap.md` had it spliced mid-sentence when 0b.8 and 0b.9 were appended in `61b031b`, leaving `"...and on:**"` in the middle of the first clause. Repaired, and relabelled *Exit criterion* to match every other phase.

### Decided

- **`materialises_at` is a `date`, not a `datetime`.** The ADR's examples and the whole deprecation-clock framing are day-granular. An hour on a compliance deadline would be false precision.
- **`inherit()` takes confidence values, not findings or ids.** It mirrors `combine()`'s shape and keeps the confidence engine free of any opinion about how a caller resolves `derived_from` to a stored finding — which is 0b.8's problem, not the engine's.
- **The measurement split covers `tp`/`fp` only, not `fn`.** No corpus expectation carries a derivation yet, and inventing that shape before Tool 2 v1.1 lands a real derived finding would be guessing at a requirement. Noted in the changelog as a thing to revisit then.
- **`derived_from` carries the premise's `id` string with no format constraint**, consistent with `related_assets` and the other reference fields in the contract.

### Deferred

Nothing new owed.

---

## 2026-08-28 · Phase 0b.3 and 0b.4 — one record/replay layer, then HTTP on it

**Plan:** [03-roadmap.md](03-roadmap.md) Phase 0b · **Status: complete**

### Built

- **`core/replay.py`** — the fixture directory, fixture naming (sanitise + digest + join), the JSON round trip, and the one `MissingFixtureError` every protocol now raises. `core/dns.py` and `core/tls.py` were refactored onto it with their exact committed fixture names preserved byte-for-byte (verified against `corpus/fixtures/`, not just by the gate staying green) — the key material each protocol feeds into the naming functions (DNS's canonicalised name + rrtype + resolver; TLS's host + port + servername + version) never moved out of `core/dns.py` / `core/tls.py`, only the sanitise/digest/join mechanics did.
- **`core/http.py` gained an `HttpBackend` layer** — `SystemHttpBackend`, `RecordingHttpBackend`, `ReplayHttpBackend` — mirroring `TlsBackend`. Record/replay sits below `HttpClient`'s redirect loop, scope check and capture, so a replayed multi-hop chain — including a hop declined for being out of scope — exercises the same code a live run does, not a special-cased replay path.
- **HTTP redacts at record time**, unlike DNS/TLS which persist the wire verbatim: only an HTTP response can carry a customer secret. `RecordingHttpBackend` writes the redacted, size-capped capture to disk; `ReplayHttpBackend` serves that capture back, not a reconstructed raw response — a replay is required to be indistinguishable from what was captured, truncation included, and now is.
- Keyed on `(method, url)`. Sufficient for every current and planned Light-mode check (idempotent GETs); noted in `core/http.py` as a limitation to revisit if a scanner ever varies the request body against one URL.

### Found & fixed

**A duplicated `body_cap` would have silently diverged.** The first cut of `RecordingHttpBackend` took its own `body_cap` at construction time, separate from `HttpClient`'s. A test that recorded with `body_cap=1000` on the client but left the backend's default (256 KB) wrote an untruncated fixture while the live run reported `body_truncated: True` — the two numbers only agreed if a caller remembered to pass the same value twice. Fixed by removing the second place entirely: `body_cap` is now threaded through `HttpBackend.send()` on every call, sourced once from `HttpClient`, the same shape `TlsClient` already uses for `trust_anchor`. The test that caught it (`test_truncation_is_recorded_and_replays_as_truncated_not_re_truncated`) is kept as regression coverage precisely because the bug had no visible symptom until the two configured values disagreed.

**Replaying a capture through the same redact/truncate step it was built with would have double-truncated it.** `truncate_body` inserts a `"[N bytes truncated]"` marker, which makes the returned string *longer* than the cap once the marker is counted — so re-running it against an already-truncated body truncates the marker text itself, nesting two markers. `RawHttpResponse.redactions` is `None` for a live wire response and a list for a replayed one; `HttpClient._capture` treats a non-`None` list as "already a capture" and passes it through rather than reprocessing. Caught by the same test, before it shipped.

**TLS's missing-fixture error was never actually caught by the CLI.** `cli/main.py` has caught `core.dns.MissingFixtureError` since the CLI existed, but `core.tls.MissingHandshakeError` was a distinct exception class — a replay run hitting an unrecorded TLS handshake would have crashed uncaught instead of exiting 1 with the same message DNS gives. Fixed as a side effect of unifying the error type: `MissingHandshakeError` is now `core.replay.MissingFixtureError` under its historical name, so the existing `except MissingFixtureError` clause catches all three protocols. Not caught by any test before this, because nothing exercised a TLS replay-miss through the CLI rather than through `core/tls.py` directly.

### Decided

- **Fixture naming stayed protocol-specific.** The digest length (DNS: 8 hex chars, TLS: 10) and tag casing (`TXT` vs `TLSv1_2` vs `any`) were kept exactly as each protocol already had them rather than normalised, because normalising either would rename every committed fixture under `corpus/fixtures/` silently. `core/replay.py`'s `fixture_filename` takes tags verbatim and a digest of caller-chosen length for this reason, recorded in its docstring.
- **What did not move into `core/replay.py`:** DNS's wildcard-label canonicalisation (a DNS fact about a random probe label, not a general one), DNS's resolver-in-the-key rule (collapsing it would make independent re-query a no-op on replay), TLS's `days_until_expiry(now=...)` (already protocol-owned; the generic layer's job is only to not corrupt the timestamp field on the way through JSON, which a plain dict round trip already does not), and HTTP's redaction (the only protocol whose fixtures could carry a secret).
- **HTTP's backend abstraction, not a transport-level one.** Record/replay could have been built as an `httpx.BaseTransport` instead of an `HttpBackend`, intercepting below `httpx.Client` rather than below `HttpClient`. Backend was chosen to match `TlsBackend`'s shape and because it keeps redaction, `body_cap` and the missing-fixture error in one place explicitly owned by this module rather than implicit in how `httpx` treats a custom transport.

### Verified

```
make lint && make typecheck && make test && make corpus
```

email 1.000/1.000 (240 checks, 21 claims), tls 1.000/1.000 (134 checks, 5 claims) — both unchanged, both replaying entirely through the refactored layer. 687 tests pass, 14 of them new to this task (`tests/core/test_replay.py`, `tests/core/test_http_replay.py`).

### Deferred

Nothing new owed. D2 lands with this entry.

---

## 2026-08-28 · Phase 0b.2 and 0b.6 — the asset graph, and passivity declared per check

**Plan:** [03-roadmap.md](03-roadmap.md) Phase 0b · **Status: complete**

### Built

- **`core/assetgraph.py`** ([ADR-019](02-decisions.md#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other)) — `DiscoveredAsset` (asset + mandatory `discovered_by`/`evidence`/`check_id`, no defaults on any of the three) and `AssetGraph` (contribute, `all()`, `by_scanner()`, `by_type()`). `ScanContext` gained an `assets: AssetGraph` field defaulting to an empty graph, so a scanner that never touches it — every scanner today — is unaffected. `AssetGraph` exposes no authorisation method of any kind; `core/authz.py` stays the only gate, unchanged by this task, and a test asserts the graph has no `authorise`/`permits`/`covers`/`require` attribute so a future edit cannot quietly grow one.
- **`seed_asset_graph()`** — the corpus-harness replay seam ADR-019's consequences call for. `cli/corpus.py`'s `_run_case` now builds `ctx.assets` from an optional `seed_assets:` list on a corpus case, so a consuming scanner (Tool 3's future consumers) will be testable without running its producer. No consumer exists yet — this task is deliberately just the pipe.
- **Per-check `passive: bool` declarations** (docs/03-roadmap.md 0b.6) — added to `Check` in both `scanners/email/checks.py` and `scanners/tls/checks.py`, no default. `core.authz.checks_require_authorisation(checks, mode=...)` asks a catalogue directly instead of trusting the mode label, and each scanner exposes `requires_authorisation(mode)` built on it. `AuthorisedScope.authorise()`/`.require()` gained a `passive: bool | None` parameter: `True` waives the record in any mode, `False` requires one in any mode including Light, `None` (the default) falls back byte-for-byte to the pre-0b.6 mode-based rule. `BaseScanner.requires_authorisation()` defaults to returning `None` for exactly this reason — a scanner that has not migrated (only the reference `example` scanner) is untouched. `cli/main.py` computes `passive` from the scanner before calling `scope.require()`.

### Found & fixed

**The behaviour change this task exists to make was real, not cosmetic — verified live, not just asserted.** With the catalogues classified on evidence:
- **Email is passive in every mode.** All 17 checks read only public authoritative DNS answers queried by the scanner itself — SPF/DMARC/MX/DKIM/MTA-STS/TLS-RPT record checks, and `spoofing-possible`, which the check's own justification already called "a simulation... from records we read, not an observation of a receiver actually making it." None sends anything to the target's own infrastructure. Consequence: **email Standard mode no longer requires authorisation**, closing the exact gap the roadmap named ("every email Standard check is passive but sits behind the ownership gate anyway"). Verified: `scan run email --target corpus-good.example --mode standard --replay corpus/fixtures/email/known-good` with no scope file, exit 0.
- **TLS's 11 of 13 checks are passive; three are active.** First cut, wrong: "TLS makes a handshake to the target, so every TLS check is active." Under that rule TLS Light mode requires authorisation in every case, which breaks docs/00-context.md's product-wide contract — Light "may be pointed at anything" — and would leave Tool 2's Light gate with effectively no Light mode. The coordinator caught this before it landed: a connection to the target is not what makes a check active (the roadmap's own example proves it — "finding a server is passive, reading its admin panel is not," and finding a server requires connecting). The right line, checked against the code rather than assumed: **passive is what an ordinary client does — one normal handshake, the same bytes a browser gets; active is deliberately abnormal input.** All eight Light checks, plus three of the six Standard checks (`tls-weak-key`, `tls-weak-signature`, `tls-no-certificate-transparency`), read only the certificate presented on the one ordinary handshake (`self.observation`, from `core.tls`'s permissive-but-otherwise-ordinary client) — an ordinary visitor sees the identical bytes, so these are passive regardless of the cipher list the client happened to offer. Three Standard checks are genuinely active: `tls-protocol-obsolete` opens separate handshakes pinned to obsolete protocol versions purely to see whether the server still speaks them; `tls-weak-cipher` and `tls-no-forward-secrecy` read the negotiated cipher from a handshake where the client deliberately offered a weak/legacy-inclusive list (`core.tls.PERMISSIVE_CIPHERS = "ALL:@SECLEVEL=0"`) specifically to elicit a weak choice if the server would make one — the abnormal input is the whole point of those two checks, not incidental to them. Consequence, corrected: **TLS Light mode needs no authorisation, unchanged from before this task; TLS Standard mode needs it only because of those three checks**, and three other Standard checks are passive alongside it — the same shape as email, which is 0b.6 working as intended. Verified live: `scan run tls --target https://localhost:14400 --mode light --replay corpus/fixtures/tls/healthy` with no scope file, exit 0; the same target in `--mode standard` with no scope file, `authorisation denied: no authorisation record for localhost in config/authorised_scope.yaml`, exit 1; and with `--scope-file config/authorised_scope.example.yaml`, exit 0 with one informational finding.

**The `Protocol` mypy would not structurally match against a frozen dataclass with extra fields.** `checks_require_authorisation`'s parameter was first typed with plain `passive: bool` / `mode: str` attributes on a `Protocol`; mypy strict rejected `dict_values[str, Check]` as an argument because a `Check` carries fields the protocol doesn't (`severity`, `likelihood_ratio`, ...) and mypy's default attribute variance for a `Protocol` did not treat that as compatible. Declaring the two members as read-only `@property` methods on the `Protocol` fixed it without changing `Check` itself.

**The worked-example scope file's own tests caught a real defect in the example, not in the code.** Adding a fifth row (`localhost`, to demonstrate the new TLS-Light gate) failed `test_every_example_row_uses_a_reserved_domain` and `test_every_example_row_cites_a_proof_file_that_exists` — both already-existing tests written for exactly this purpose in an earlier task. `localhost` is RFC 6761-reserved but not a `.example` name, so the reserved-domain test needed a narrow, documented exception; the evidence file needed to actually exist (`corpus/authz/localhost-2026-08-28.txt`, in the same style as the other `localhost-*` rows already in that directory for the live docker-compose targets). Both are real gaps the tests were built to catch, not weakened to pass.

### Decided

- **`passive=None` is a distinct value from `passive=False`, and the distinction is load-bearing.** `None` means "this caller has no opinion, use the old mode rule"; `False` means "a check was asked and answered active." Conflating them would make "forgot to migrate" indistinguishable from "declared safe," which is exactly the failure this task exists to prevent. `BaseScanner.requires_authorisation()` returns `None` by default for the same reason `UnconfiguredClient` raises instead of defaulting: absence must fail toward the safe answer, or fail loudly, never silently toward the permissive one.
- **The example scanner is deliberately untouched.** It has no `Check` catalogue, so it is not part of this task's scope. It keeps the exact pre-0b.6 behaviour (Light exempt, Standard/Deep gated) via the `None` fallback. Flagged here rather than silently left as-is, per the task's own instruction not to reclassify anything quietly.
- **The gate is decided once per scan, from the full set of checks a mode would run, not per individual check as it executes.** A scanner already decides internally which checks run for a given mode (`if self.mode != "light"`); `checks_require_authorisation` mirrors that same rule rather than threading a live decision through every check's execution, which would have meant restructuring both scanners' control flow for no behavioural gain — the set of checks a mode runs is static and known before the scan starts.
- **"Passive = no connection to the target" was the wrong definition, and the fix is a definition, not a carve-out.** The instruction that produced the first cut ("active regardless of mode, including light") was correct; the classification it was applied to was not. Reclassifying TLS's eight Light checks and three of its six Standard checks from active to passive is not weakening the gate — it is applying the same "ordinary client vs. deliberately abnormal input" rule the roadmap's own AI-exposure example already implies, consistently, to a scanner that had never had it applied before. The corrected rule is recorded here, in `docs/09-ownership-verification.md`, and in `scanners/tls/checks.py`'s own comments, so the next scanner (device/IoT, where "probing" vs. "observing" will matter even more) has the definition rather than a list of examples to pattern-match against.

### Deferred

Nothing new owed. The asset graph has no consumer yet — Tool 3 is the first candidate — so its contribute/read paths are exercised only by direct tests, not by a real producer→consumer run. That is intentional: this task was the mechanism, not a user of it.

### Verified

```
make lint && make typecheck && make test && make corpus
```

720 tests pass (33 new to this task: `tests/core/test_assetgraph.py`, `tests/core/test_authz_passivity.py`, `tests/cli/test_authz_declarations.py`, plus one updated assertion in `tests/core/test_authorised_scope_example.py`). email 1.000/1.000 (240 checks, 21 claims), tls 1.000/1.000 (134 checks, 5 claims), example 1.000/1.000 — all three numerically unchanged from before this task, both before and after the TLS reclassification.

---

## 2026-08-28 · Phase 0b.5 — toolchain upgrade, and a wrong premise in its own roadmap row

**Plan:** [03-roadmap.md](03-roadmap.md) 0b.5 · **Status: complete, premise corrected**

### Built

- **Python 3.13.15 pinned as the toolchain floor.** `pyproject.toml` (`requires-python`, `[tool.ruff] target-version`, `[tool.mypy] python_version`) and a new `.python-version` file (`3.13.15`) so `uv` resolves the same interpreter on every machine, including the operator's separate WSL2 box. `.github/workflows/ci.yml`'s `setup-uv` step now pins `python-version: "3.13.15"` explicitly rather than picking up whatever `uv` finds. `uv sync` re-locked against 3.13; no dependency needed a version bump to support it.
- **The OpenSSL pin is recorded in this ledger, not in `tools/registry.yaml`.** The registry's own header scopes it to "third-party components... a direct dependency with no entry here [fails the build]" — Python's OpenSSL is not a Python dependency `cli.licences` walks, it is a property of the pinned interpreter build, one level below anything `uv.lock` names. Recording it here, next to the reproducibility claim it exists to support, keeps it where an operator debugging a corpus-number mismatch across machines will actually be reading. **Pinned: OpenSSL 3.5.7 9 Jun 2026**, verified with `uv run python -c "import ssl; print(ssl.OPENSSL_VERSION)"` — also worth a line in `docs/12-cli-runbook.md`'s prerequisites for the same reason.

### Found & fixed

**The roadmap's own justification for this row was wrong, and shipped unverified.** 0b.5 said: *"`ssl.SSLContext.set_groups` does not exist on 3.12, so post-quantum key exchange cannot be tested at all today. `get_unverified_chain` is also 3.13+"* — reading as though 3.13 unblocks both. Measured directly (`uv run --python <v> --no-project python3 -c "import ssl; ..."`) across 3.12.3, 3.13.15, 3.14.7 and 3.15.0rc1:

| Python | `ssl.OPENSSL_VERSION` | `get_unverified_chain` | `set_groups` / `get_groups` / `SSLSocket.group()` |
|---|---|---|---|
| 3.12.3 | OpenSSL 3.0.13 | absent | absent |
| 3.13.15 | OpenSSL 3.5.7 | **present** | absent |
| 3.14.7 | OpenSSL 3.5.7 | present | absent |
| 3.15.0rc1 | OpenSSL 3.5.7 | present | **present** |

`get_unverified_chain` is indeed 3.13+, as claimed. **The PQ trio is not — it lands in Python 3.15, currently at rc1.** Post-quantum exposure detection (ADR-020) is still blocked after this upgrade, just on a different, later version than the roadmap said. Same category as D13 (v3.4 research numbers taken from vendor blogs and never checked against a primary source) — this was a number in a decision document, unverified against the one primary source that mattered, CPython's own `ssl` module. Corrected in `docs/03-roadmap.md` 0b.5, `docs/02-decisions.md` ADR-020, `docs/05-phase-1-first-tools.md` and `docs/16-learning-map.md`. Filed as D16.

**The OpenSSL upgrade (3.0.13 → 3.5.7) broke two things in the TLS lab, both lab bugs surfaced by stricter defaults, not scanner-logic changes:**
- **A fresh `SSLContext`'s default `minimum_version` rose from `MINIMUM_SUPPORTED` to `TLSv1.2`.** `corpus/generators/tls_lab.py`'s `LabServer` set `maximum_version=TLSv1` for the obsolete-protocol corpus cases but never lowered the minimum, so on the new default the effective range became `[TLSv1.2, TLSv1]` — empty — and the handshake failed before any protocol was negotiated, not "obsolete protocol observed." Confirmed with a bare in-process handshake before touching test code: `TLSV1_ALERT_PROTOCOL_VERSION` even with the client's `PERMISSIVE_CIPHERS`/`minimum_version=TLSv1` override, because the *server* side was the one refusing. Fixed by having `LabServer` always set `minimum_version` (to the caller's value, or `TLSv1` by default) instead of only when a caller passes one explicitly — this lab exists specifically to offer obsolete protocols, so it should not silently stop doing that when the library's own default floor moves. Seven tests failed on this before the fix (`tests/core/test_tls.py`, `tests/scanners/tls/test_tls_scanner.py`), all passing after.
- **Certificates minted by `corpus/generators/tls_lab.py`'s `mint()` carried no `SubjectKeyIdentifier`/`AuthorityKeyIdentifier`.** OpenSSL 3.5's stricter chain building surfaced this as `verify_code 85` ("Missing Authority Key Identifier") on the custom-trust-anchor hostname-probe test, which the old build tolerated silently. Fixed by adding both extensions to every minted certificate (self-referencing when self-signed, referencing the issuer's key otherwise). Same category as the ledger's earlier TLS-lab defects (missing `basicConstraints`, `@SECLEVEL=0` masking TLS 1.0 acceptance, a two-level chain that cannot express an incomplete one) — **ground truth had bugs that a passing gate could not surface, only reading (here: upgrading and rerunning) could.**

Both fixes are in `corpus/generators/tls_lab.py` (lab plumbing) and `tests/`, not in `core/tls.py`'s detection logic, `core/state.py`, or `corpus/fixtures/`.

**`ssl.TLSVersion.TLSv1` / `TLSv1_1` are now deprecated in the `ssl` module.** `core/tls.py` (the permissive-observation client, by design) and `corpus/generators/tls_lab.py` (the lab) both reference them deliberately — detecting an obsolete protocol requires being able to name it. Reported here rather than silenced with a filter, per this task's instruction: a suppressed warning is a real signal lost, and CPython plans to remove these values eventually, which is a future toolchain task, not a 0b.5 one.

### Decided

- **`get_unverified_chain` becoming available does not change how `tls-chain-incomplete` detects.** The check stays behavioural — "can a verifying context build a path to a trusted root" — for the reason already on record in this ledger's 2026-08-24 entry: it measures what a visitor actually experiences rather than inspecting bytes, and that reasoning does not depend on the library limitation that used to be the only thing forcing it. The option to inspect the raw chain now exists and was declined on its merits, not for lack of a library.
- **3.13 over 3.14.** The roadmap's stated floor, and the more conservative choice absent a concrete reason to prefer 3.14 — none was found; both ship identical OpenSSL 3.5.7 builds in this environment.

### Deferred

New: **D16** below — post-quantum exposure detection blocked on Python 3.15 final, not 3.13. Blocks the PQ claim in ADR-020.

### Verified

```
make lint && make typecheck && make test && make corpus
```

Run on Python 3.13.15 / OpenSSL 3.5.7 9 Jun 2026 (`uv run python -c "import sys, ssl; print(sys.version); print(ssl.OPENSSL_VERSION)"`). `ruff check`/`ruff format --check`: clean. `mypy`: no issues, 35 source files. `pytest`: 720 passed (unchanged count — the two lab fixes corrected behaviour under the new OpenSSL default without adding or removing tests). Corpus: email 1.000/1.000 (240 checks, 21 claims), tls 1.000/1.000 (134 checks, 5 claims), example 1.000/1.000 — gates unchanged.

---

## 2026-08-28 · Phase 0b.7 — the deprecation calendar as curated data

**Plan:** [03-roadmap.md](03-roadmap.md) Phase 0b.7 · **Status: complete**

Data plus a loader, exactly as scoped — no scanner wired to it. [ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived)'s `materialises_at`/`materialises_reason` machinery already existed (0b.1); this task is the curated source those fields are meant to eventually cite.

### Built

- **`config/deprecation_calendar.yaml`** — a YAML list of dated deadlines, alongside `config/authorised_scope.yaml`. Every entry carries `id`, `authority`, `change`, `date`, `source_url`, `reviewed_at`, `reviewed_by`.
- **`core/deprecation_calendar.py`** — `DeprecationEntry` (a `Strict` pydantic model, `extra="forbid"`, matching `core/models.py`'s style) and `DeprecationCalendar.load()`. Validation is strict: an unparseable date, a missing field, an unknown field, a `source_url` that is not `http(s)://`, or a duplicate `id` all raise `DeprecationCalendarError` at load time, naming the offending entry's id. A missing file is also an error — unlike `core.authz.AuthorisedScope`, where a missing scope file is a safe empty default, there is no safe default for "no calendar" once something calls `load()`.
- **The staleness rule.** `active(today)` returns only entries reviewed within `STALE_AFTER_DAYS = 180`; `.stale(today)` returns the rest; `.all()` always returns everything, so a stale entry is withheld from the assertable set but never hidden from view. Reasoning is in the module docstring: asserting a date on the strength of a review that may no longer be current is the "clock lying in our name" the roadmap warns is worse than no clock, so the conservative failure mode is to stop asserting, loudly, not to keep asserting past its review window.
- **15 tests** (`tests/core/test_deprecation_calendar.py`): every malformed-entry case (missing source, non-URL source, missing review date, missing reviewer, bad date, non-mapping row, non-list file, duplicate id, unknown field) fails loudly and by name; the real calendar file loads; staleness excludes-but-never-hides is checked directly.

### The one entry, and how it was verified

Only **one** deadline made it in, split into its three stages (each stage is its own event, so its own entry per the "at minimum: a date" granularity):

| id | change | date | source | reviewed |
|---|---|---|---|---|
| `cert-lifetime-200-days-2026-03-15` | Max public TLS cert validity → 200 days | 2026-03-15 | CA/Browser Forum ballot SC-081v3 | 2026-08-28, operator:satwik |
| `cert-lifetime-100-days-2027-03-15` | → 100 days | 2027-03-15 | same | same |
| `cert-lifetime-47-days-2029-03-15` | → 47 days | 2029-03-15 | same | same |

**Verification.** `docs/05-phase-1-first-tools.md` already asserted "SC-081v3, passed April 2025 (29–0): 200/100/47 days from 15 March 2026/2027/2029" — but per this task's own instruction, an existing doc asserting it is not verification; it is the thing being checked. Fetched the CA/Browser Forum's own ballot announcement (`cabforum.org/2025/04/11/ballot-sc081v3-...`), which confirms: passed 2025-04-11, Certificate Issuers 25-0-5, Certificate Consumers 4-0-0. That page summarises rather than quotes the schedule, so also fetched the normative redline itself — [cabforum/servercert PR #553](https://github.com/cabforum/servercert/pull/553/files), the actual Baseline Requirements text — which states verbatim: certificates issued before 2026-03-15 MUST NOT exceed 398 days; on/after 2026-03-15 and before 2027-03-15, MUST NOT exceed 200 days; on/after 2027-03-15 and before 2029-03-15, MUST NOT exceed 100 days; on/after 2029-03-15, MUST NOT exceed 47 days. **Matches our docs exactly — no D13 hit here.** `source_url` in the data file points at the ballot announcement page (the authority's own site) rather than the GitHub diff, as the more durable and citable primary source; the PR is recorded here as the second, more granular check.

### Left out for want of a primary source

Everything else ADR-020 names, deliberately not entered:

- **Post-quantum exposure** and **AI/agent exposure** are not date-shaped claims — no deadline to enter here (they belong to the observation-plus-rule the calendar doesn't need).
- No other CA/Browser Forum or NIST dated deprecation (e.g. a further PQ-migration mandate date, a specific TLS 1.0/1.1 browser-removal date) was searched to primary-source standard for this task — out of scope for 0b.7, which asks for the mechanism plus what could be verified in the time available, not a full calendar. Left for whoever next extends this file, under the same discipline.

### Decided

- **One entry stayed unsplit by stage was rejected** — three separate ids rather than one entry with three dates, because the loader's contract is one `date` per entry and the three stages are three distinct, independently-sourced-and-reviewable events (a later ballot could in principle amend just one stage).
- **`STALE_AFTER_DAYS = 180`.** Chosen, not measured — these are slow-moving standards-body deadlines, and a two-person team can sustain a six-month review cadence. Written into the module docstring as a decision to revisit under the same discipline as everything else here, not a silent constant.
- **A missing calendar file is an error, not an empty calendar.** Differs from `AuthorisedScope.load()` on purpose: there, a missing file is the safe deny-by-default; here, nothing calls `load()` yet, so a caller that does call it should fail loudly on a missing deployment artifact rather than silently proceed with zero deadlines.

### Deferred

Nothing new owed. D13 stays open — this closes one of its several unverified numbers (certificate lifetime), not all of them; post-quantum adoption percentages and MCP-exposure counts are still unchecked against a primary source.

### Verified

```
make lint && make typecheck && make test && make corpus
```

`ruff check`/`ruff format --check`: clean, 83 files already formatted. `mypy`: no issues, 36 source files. `pytest`: 735 passed (720 + 15 new). Corpus: email 1.000/1.000 (240 checks, 21 claims), tls 1.000/1.000 (134 checks, 5 claims), example 1.000/1.000 — gates unchanged.

---

## 2026-08-28 · Phase 0b — complete

**Plan:** [03-roadmap.md](03-roadmap.md) Phase 0b · **Status: complete, with one clause flagged**

Nine tasks, six commits, in a day. Built while two scanners existed rather than ten, which was the whole argument for doing it now — every item here would have been a migration instead of an edit.

| Task | Landed as |
|---|---|
| 0b.1 | Dated and derived findings — `materialises_at`, `derivation`, `derived_from` |
| 0b.2 | The asset graph, provenance structurally required |
| 0b.3 | One record/replay layer in `core/` |
| 0b.4 | HTTP record/replay — retired D2 |
| 0b.5 | Toolchain pinned to Python 3.13.15 / OpenSSL 3.5.7 |
| 0b.6 | Passivity declared per check, not per mode |
| 0b.7 | The deprecation calendar as curated, sourced data |
| 0b.8 | Finding store + `scan verify` |
| 0b.9 | The correlation pass |

### Exit criterion

Four clauses met outright: a scanner can read assets another discovered; one `core/` recording layer serves DNS, TLS and HTTP; a finding can be re-verified and transitioned on fresh evidence; a run can connect findings into one story with inherited confidence.

**The fifth is met in mechanism but not in wording.** It says *"a scanner can emit a dated, derived finding whose confidence is inherited from its premise"* — but [ADR-022](02-decisions.md#adr-022--prove-connect-close-aggressive-proof-never-touching-the-target) places deriving in the correlation pass, a `core/` component that runs after scanners, not inside any scanner. Nothing is missing; the sentence describes a design we deliberately changed. **Either the wording moves or the design does, and that is a decision rather than a cleanup.** Recorded rather than declared met.

### Found & fixed — the same defect four times

Every defect this phase was one shape: **a value that failed to travel from one place to another, invisible because something plausible stood in for it.**

| Where | The stand-in |
|---|---|
| 0b.1 | The corpus harness never passed `derivation`; the field's `"detected"` default filled the gap, so the derived half of the split would have read `None` forever — indistinguishable from "no derived claims yet" |
| 0b.3/0b.4 | A duplicated `body_cap` that agreed only when a caller set it twice; and TLS's `MissingHandshakeError` being a different class from DNS's, so the CLI's `except` clause had never caught it |
| 0b.6 | Every TLS check classified active on the reasoning that it opens a connection — which would have removed Tool 2's Light mode entirely, while its roadmap gate is a Light gate |
| 0b.9 | A runbook transcript with an edited `target` field, and a report claiming an absence of disclosure was a disclosure |

**None of these were caught by tests or gates.** Every suite was green and every gate read 1.000 while each was present. They were caught by reading the code that carries a value across a boundary, and by asking what a stated consequence would actually mean for the product.

The house pattern against this is already in the codebase and should be reached for first: `ScanContext` hands out a raising `UnconfiguredClient` rather than a working default, so forgetting to wire a client is loud. 0b.2's `DiscoveredAsset` follows it — provenance has no default, so an asset without it fails at construction. 0b.6's `passive: bool` follows it too: no default, so an undeclared check is a construction error rather than a silently permitted one.

### Decided

- **Passive means what an ordinary client does**, not "sends no packets". Connecting is not what makes a check active; deliberately abnormal input is. Finding a server is passive, reading its admin panel is not.
- **A finding is closed only by a positive observation that the problem is gone**, never by the absence of an observation. Inconclusive, blocked, errored, never ran, denied — all leave it open.
- **Curated data says who reviewed it, and says so honestly.** The calendar's entries read `pending-human-review` because an assistant checked the sources and no human has signed them off.

### Deferred

D16 (post-quantum blocked on Python 3.15 final) added. D2 retired. See §D.

---

## 2026-09-01 · D1 closed — CI verified, running all along

**Status: 32 successful runs, first one observed.**

D1 was open from Phase 0, and its wording was wrong. It read "verify CI actually runs", on the assumption that a workflow written before a remote existed had never executed. Inspecting the Actions API directly settled it: **CI has run on every push since late August — 32 runs, every one green, ~27s average.** It was never unrun. It was unobserved, which from inside the repo is indistinguishable from unrun, and that is the whole of what D1 actually was.

So the correction that mattered was not making CI work — it already did — but gaining the ability to look at it, and verifying that what it does is what we think. That verification, done against run #32 (`7315f26`):

- The runner uses `UV_PYTHON: 3.13.15` — the toolchain pin holds on GitHub's infrastructure, not only locally.
- Lint, `mypy` (38 files), licence policy (19 components), **789 unit tests**, and the corpus gate all pass in the log text, not merely as green checkmarks.
- The corpus step prints email `1.000/1.000`, tls `1.000/1.000`, example `1.000/1.000`.
- The uploaded `corpus-results` artifact matches the local baseline's TP/FP/FN for all three scanners — CI measures the same thing the developer's machine measures.

### Built

- `.github/workflows/ci.yml` gains **`workflow_dispatch`** (trigger a run by hand from the Actions tab without pushing — the cheap way to *look*, which is what was missing), a **concurrency group** cancelling superseded runs, a **10-minute timeout** (runs take ~27s, so 10 minutes means a hang), and the corpus scores **uploaded as an artifact whether the run passes or fails**. Verified in practice: run #32 uploaded a 1552-byte `corpus-results`.
- **`docs/17-testing-runbook.md`** — the eight test layers, the corpus, the labs, live verification and CI, copy-pasteable from WSL, including how to read a run through the API and the `gh` CLI. Its scope boundary against `12-cli-runbook.md` is stated in both files: 12 is how to run a scan, 17 is how to prove the scanners are correct.

### Found & fixed

**A gap in the register can be a wrong belief, not just missing work.** D1 was not an unrun pipeline needing a fix; it was an assumption nobody had checked, carried for a week as if it were a task. The lesson is the same one ADR-017 draws about the corpus: an unverified claim in a decision document is a liability regardless of which direction it turns out to be wrong in. Here it was wrong in our favour — the thing we feared was broken had been working the whole time — which is the more insidious direction, because nothing forces you to look.

**An invented command in a runbook, caught by running it.** A worked example cited `tests/core/test_tls.py::test_expired_certificate`. No such test exists; the name was plausible and fabricated. Found because every command in that document was executed before it was written down, which is the only reason the runbook's contract — nothing in it is invented — survives contact with an author. Same defect class as the fabricated SPF quote (Tool 1) and the edited transcript target (0b.9): asserting something not observed. Third occurrence, third different costume.

**An invented command in a runbook, caught by running it.** A worked example cited `tests/core/test_tls.py::test_expired_certificate`. No such test exists; the name was plausible and fabricated. Found because every command in that document was executed before it was written down, which is the only reason the runbook's contract — nothing in it is invented — survives contact with an author. Same defect class as the fabricated SPF quote (Tool 1) and the edited transcript target (0b.9): asserting something not observed. Third occurrence, third different costume.

### Decided

- **A green CI run is not the same as a trustworthy one, and the register should not imply otherwise.** D1 is closed because the pipeline demonstrably executes and gates. What it enforces is still the corpus, which proves regression rather than correctness — [ADR-017](02-decisions.md)'s live-verification requirement is untouched by this and remains the layer that finds real defects.

### Deferred

Nothing new owed. **D1 retired.**

---

## 2026-09-02 · Competitive baseline — the free tools were at par, and why

**Trigger:** a real head-to-head, run while building the pitch deck. The operator ran MXToolbox against `kinetrix.in` (email) and an SSL checker against `erp.codez.in` (TLS), and found the free tools surfaced **as much or more** than our shipped scanners. This is the first time an outside reference, rather than our own corpus, judged the tools — and it is exactly the check [ADR-017](02-decisions.md) always implied but never named against competitors.

### Found

**The gap was mostly self-inflicted, not a lack of capability.** A coverage matrix built from the SSL Labs public API (grade `T`, 35 cipher suites and 13 named-vuln probes enumerated on `erp.codez.in`, no authorisation), SSL.org's output, and our own JSON, sorted into four buckets:

1. **At par** — cert validity, expiry, hostname, key, signature, CT. Fine.
2. **We had it but gated behind authorisation while the incumbents give it free** — protocol enumeration, ciphers, forward secrecy. **The whole market runs these unauthenticated.** This was the 0b.6 classification being over-cautious, and it is the bulk of why our free tier looked thin. → [ADR-023](02-decisions.md#adr-023--passive-is-ordinary-negotiation-only-malformed-input-is-active), fixed in this session.
3. **We lack it and can add it safely** — named vulnerabilities by *inference* (POODLE/BEAST/FREAK/Logjam/RC4), OCSP, HSTS. → D17–D19.
4. **We lack it and should** — Heartbleed/ROBOT active oracles send malformed input, out by [ADR-004](02-decisions.md). Not a gap; a principled decline.

**`tls-chain-incomplete` is a real false negative.** Both reference tools flagged the `erp.codez.in` chain incomplete; we returned `clear`. A definition split (behavioural path-building vs "did the server send every cert"), and theirs is the more useful answer. **The corpus never caught it** — the eighth defect to survive precision 1.000, and the first found by a competitor rather than a live run or fixture read. → D17.

### Decided

- **[ADR-023](02-decisions.md#adr-023--passive-is-ordinary-negotiation-only-malformed-input-is-active)** — passive means *ordinary negotiation*, active means *malformed input*. Reclassifies `tls-protocol-obsolete`, `tls-weak-cipher`, `tls-no-forward-secrecy` to passive → **all 14 TLS checks are now passive**, TLS needs no authorisation in any mode. Applied in code this session: the flags flipped, the two TLS-specific authz tests rewritten, the split corrected in 00-context, SPEC, the runbook and CLAUDE.md. **789 tests, gates unchanged**, and `scan run tls --mode standard` now runs with no scope file. ADR-004 untouched — completing a handshake is not exploitation.
- **[ADR-024](02-decisions.md#adr-024--competitive-coverage-parity-is-part-of-a-tools-definition-of-done)** — competitive coverage parity joins the definition of done, extending ADR-017. Coverage is table stakes, proof is the wedge; a declined check is recorded, not silently missing; and the licence line is drawn: read a competitor's output and published methodology to build a checklist, never seed our checks or fingerprints from their output.

### Deferred

D17 (`tls-chain-incomplete` false negative), D18 (inference-based named vulns), D19 (HSTS, now unblocked). All raised by the competitive check; none block the current gate.

---

## 2026-09-02 · D17 fixed, BEAST shipped — TLS v1.1.0

**Status: complete for what the toolchain allows.** Gate green: tls 162 checks, precision 1.000, recall 1.000, susp% 8.6%.

### Built

- **D17 — the chain-incompleteness false negative, fixed.** The cause was sharper than the register first guessed. Not a definition split: OpenSSL's verifying handshake returns a **single** `verify_code`, the first failure it hits, so on a cert that is both expired *and* served without intermediates the code is `certificate has expired` and the chain check fell through to `clear`. The fix decouples the two questions — a second verifying handshake with `X509_V_FLAG_NO_CHECK_TIME` (`0x200000`, set through `SSLContext.verify_flags` because Python's `ssl.VerifyFlags` has no name for it) asks "ignoring expiry, does the chain build to a trusted root?" A host can now report both `tls-cert-expired` and `tls-chain-incomplete`, which is correct — they are different problems. `get_unverified_chain` was deliberately not adopted; the behavioural fix honours the 0b.5 rationale.
- **BEAST — the first derived finding any scanner emits.** `tls-vuln-beast` fires when a handshake completed at TLS 1.0/1.1 with a CBC cipher. `derivation="derived"`, `derived_from` names the `tls-protocol-obsolete` finding, confidence **inherited** via `ConfidenceEngine.inherit()` and never recomputed — verified live: premise and derived both 0.9804, same `negotiation` independence class so no false corroboration, `suspected` state inherited honestly. Severity medium, and the description says plainly that modern clients mitigate BEAST — the finding is "the server still permits the configuration", not "you are exploitable today". This is the first live exercise of the `inherit()` path and the detected/derived measurement split built in 0b.1 and never run by a scanner until now; both held.
- `tls` `scanner_version` bumped to **1.1.0** — a new check, and a chain finding that did not fire before.

### Found & fixed

- **The build agent hit the account session limit mid-task** and left the tree partial: code complete, `scanner_version` bumped, corpus cases written — but the **fixtures were never generated** and the ledger entry never written. Regenerating with `python -m corpus.generators.tls` produced them and the gate went green. A reminder that a corpus case is three parts (target, expected, fixture) and the fixture is the one a dead process leaves missing.
- Formatting was left un-run (`ruff format`); two files needed it.

### Decided

- **The legacy-cipher class is blocked, and the way out is ADR-016's reserved per-check wrap (D20).** Verified directly: OpenSSL 3.5 refuses to offer RC4, 3DES or export ciphers, so RC4/Sweet32/FREAK cannot be probed by our engine at all — the same wall D11 hit for the lab. BEAST is the exception because TLS 1.0 and CBC are both still in OpenSSL 3.5. testssl.sh drives its own bundled OpenSSL and can speak the legacy ciphers; wrapping it for exactly those checks is the per-check decision ADR-016 anticipated.

### Deferred

D17 closed. D18 partial (BEAST done; the cipher-based vulns wait on D20). D20 raised — the legacy-cipher backend. None block the gate.

---

## D. Deferred register

Single source of truth for what is owed. Move an item out only when it lands.

They cluster, which matters more than the individual entries:

- **Corpus realism** — D6 (real domains), D3 (benchmark tier), D11 (a weak-cipher case). Each one narrows the gap between a gate number and a claim about the world.
- **Capability gaps a user would notice** — D12 (revocation: `revoked.badssl.com` reads as a pass), D4 (SMTP checks), D5 (lookalike domains).
- **Infrastructure** — D7 (a local authoritative DNS zone). D1 (CI) closed 2026-09-01.
- **Unverified numbers in decision documents** — D13 (v3.4 research from vendor blogs) and D16 (0b.5's own roadmap row claimed 3.13 unblocks post-quantum; it does not) are the same failure mode twice: a figure reached an ADR or roadmap row without being checked against its primary source.

| # | Item | Why deferred | Blocks |
|---|---|---|---|
| **D3** | Benchmark corpus tier (OWASP Benchmark, WAVSEP) | Explicitly deferred by the plan until it has a consumer | Phase 2 web scanner |
| **D4** | `open-relay`, `mail-tls-weak` | Need SMTP connections — active, not passive; belong behind the authorisation gate | Nothing; Tool 1 passes without them |
| **D5** | `lookalike-domain` | Needs RDAP over HTTP plus a permutation engine; larger than the rest of Tool 1 combined | Nothing |
| **D6** | ~50 real domains recorded as a frozen corpus tier | The 16 committed cases are synthetic zones we wrote. Precision 1.000 against them proves the checks do what was intended, not that the intent matches the world | Confidence in the published number |
| **D7** | **CoreDNS container serving a local authoritative zone** | Standard-mode testing needs a zone we control. A local authoritative server on a reserved name (`sptest.test`) would make `self_owned` honest, exercise the real dnspython path instead of a fake resolver, and let us author any scenario — 11-lookup chains, weak DKIM keys, malformed DMARC — against real DNS. ~1 hour. Not built because Light-mode sweeps proved higher value first | Standard-mode live testing; a better Tool 1 corpus |
| **D9** | The A+–F TLS grade | Deferred 2026-08-24 by decision. A grade is an opinion, and opinions get argued with; facts ("expires in 5 days", "accepts TLS 1.0") do not. Easy to add later, hard to change once customers have built expectations on a score. If it ships, [05-phase-1-first-tools.md](05-phase-1-first-tools.md) requires the full rubric be visible | Nothing |
| **D10** | HSTS checks in Tool 2 | [05-phase-1-first-tools.md](05-phase-1-first-tools.md) lists HSTS under TLS Standard, but it is an HTTP response header, so it needs an HTTPS GET. **Unblocked 2026-08-28** — HTTP record/replay landed with 0b.4, so its corpus cases can now be frozen. Owed only because nobody has written the checks yet | Nothing; Tool 2 gates without it |
| **D11** | A positive corpus case for `tls-weak-cipher` | RC4 and 3DES are compiled out of OpenSSL 3, so the lab cannot serve one at any security level — verified by trying. Needs either a different TLS implementation for the lab, or a recorded handshake from a real server still offering one | Nothing; Tool 2 gates without it |
| **D12** | Certificate revocation checking | `revoked.badssl.com` currently returns nothing, which reads as a pass. Needs OCSP or CRL — an outbound HTTP request to the issuing CA, so it also needs a decision about whether that counts as passive | Nothing; Tool 2 gates without it, but it is a visible gap in a demo |
| **D13** | Verify the v3.4 research numbers against primary sources | Certificate-lifetime dates, PQ adoption percentages and MCP exposure counts all came from vendor blogs and secondary summaries. A deprecation clock citing a wrong date is worse than no clock | Any external use of the numbers |
| **D14** | Research IoT/device security as a candidate surface | Requested by the client and deliberately left out of v3.4 because it was not researched. Padding a plan with an unexamined surface is how the v3 differentiators got inflated | Nothing yet |
| **D15** | A real device network to verify against | The IoT corpus will be emulators and recorded exchanges. An emulator written from an RFC agrees with a scanner written from the same RFC — the corpus-encodes-the-author's-assumptions failure in its purest form, in the domain where devices violate their own specs most | Calling tool 5a/5b done |
| **D8** | `evidence_file` existence check in `core/authz.py` | The loader checks the field is present, not that the file exists, so a scope file stays loadable outside the repo. Enforced on the committed file by test instead | Nothing; it is a belt-and-braces item |
| **D16** | Post-quantum exposure detection needs Python 3.15 | `ssl.SSLContext.set_groups`/`get_groups` and `SSLSocket.group()` — the whole of reading back a negotiated key-exchange group — arrive in Python 3.15, not 3.13 as the original 0b.5 roadmap row claimed. Verified directly against the `ssl` module across 3.12/3.13/3.14/3.15rc1; 3.15 is currently at rc1, not final | The post-quantum-exposure claim in ADR-020 |
| ~~**D17**~~ | ~~`tls-chain-incomplete` false-negatives an incomplete chain~~ | **Closed 2026-09-02.** The cause was sharper than the definition split first guessed: a single `verify_code` reports only the *first* failure, so expiry masked the incomplete chain. Fixed behaviourally — a second verifying handshake with `X509_V_FLAG_NO_CHECK_TIME` set asks "ignoring expiry, does the chain build?", independent of the trust verdict. `get_unverified_chain` deliberately not adopted. A host now reports both `tls-cert-expired` and `tls-chain-incomplete` | — |
| **D18** | Inference-based named-vulnerability detection — **partial** | **BEAST shipped 2026-09-02** (TLS 1.0/1.1 + CBC → derived finding, the first any scanner emits). **RC4, Sweet32, FREAK, Logjam remain blocked**: verified that OpenSSL 3.5 refuses to *offer* RC4/3DES/export ciphers (`No cipher can be selected`), so our own engine cannot probe a target for them, the same wall as D11. Unblocking needs the legacy-cipher backend (D20) | TLS parity on the legacy-cipher class |
| **D20** | A legacy-cipher-capable TLS backend | RC4, 3DES and export ciphers are compiled out of OpenSSL 3.5, so neither our client nor the lab can speak them (D11, D18). The per-check decision ADR-016 reserved: wrap testssl.sh for exactly these checks (it drives its own bundled OpenSSL and is already registered, GPLv2, subprocess-only), keeping our own engine for everything else. Decided; not yet built | D11, and the RC4/Sweet32/FREAK/Logjam half of D18 |
| **D19** | HSTS check in TLS | An HTTP response header, so it needs an HTTPS GET — **no longer blocked**, HTTP record/replay landed with 0b.4. SSL Labs and SSL.org both surface it. Owed only because nobody has written it. Supersedes the old D10 framing | Nothing; a visible gap in a demo |

---

## 2026-08-28 · Phase 0b.8 — a finding store, and `scan verify`

**Plan:** [03-roadmap.md](03-roadmap.md) 0b.8 · **Status: complete**

### Built

- **`core/store.py`** — `FindingStore`, one SQLite file, one table, keyed on `(id, org_id)`. `ingest()` upserts a fresh scan's findings: a new id is inserted as-is, a repeat keeps the stored row's `first_seen`/`first_seen_scan_id` and `status`/`status_history` and takes everything else — confidence, evidence, `last_seen`/`last_seen_scan_id` — from the fresh finding. It never closes anything a scan didn't mention; see "Decided" below for why that boundary is drawn here rather than left to callers. `transition()` appends one `StatusChange` and bumps `last_seen`; a transition to the status a finding is already at is a no-op that appends nothing. SQLite over a JSON file: Phase 6 is Postgres (ADR-009), and SQLite's real primary key and `ON CONFLICT DO UPDATE` are what keep that migration a driver swap rather than a rewrite of the upsert logic — a JSON-per-org file would have hidden that discipline behind ad-hoc dict merging.
- **`scan run --store <path>`** ingests the scan's findings into the store after it completes. **`scan verify <finding-id> --store <path>`** — the "close" half of ADR-022 — re-runs the scanner at its fullest supported mode, matches the fresh `telemetry.checks_run` entry against the stored finding's `check_id`/`location`, and acts *only* on that outcome: `clear` closes (or reopens, if the finding had been closed and the check now reports it present again); `reported` leaves it open and advances `last_seen`; `inconclusive`/`suppressed`/`error`, a missing `checks_run` entry, or any exception raised while running the scan all leave it open and say so in plain text, exiting 1. Verify obeys `core/authz.py` exactly as `scan run` does — an active check with no allowlist record is denied, not silently skipped.
- Both commands now generate a real per-run `scan_id` (`python-ulid`) instead of `ScanContext`'s placeholder default, which the store needed to have any meaning: two scans of the same target must produce two distinct `first_seen_scan_id`/`last_seen_scan_id` values for the history to be honest.

### Found & fixed

**Nothing broke that wasn't caught by writing the test first.** The one design decision that took real thought — see "Decided" — was resolved before any code was written, which is why there's nothing to report here beyond the usual mypy churn (a method named `list` on the store shadowed the builtin `list[Finding]` in its own class body's annotations; renamed to `list_findings`).

### Decided

- **Where the "never close on absence" line is drawn.** `ingest()`, called from every `scan run --store`, never closes a finding that a fresh scan didn't reproduce — it only upserts what it *did* see. All the closing logic lives in `scan verify`, which asks the specific check for its outcome rather than inferring anything from what's missing. This means a plain `scan run --store` can never regress a finding to closed no matter what breaks, and the only path that can close one is the one built, tested and reviewed for exactly that failure mode.
- **Matching a re-run check to a stored finding is by `(check_id, location)` from `telemetry.checks_run`, not by re-deriving the finding and comparing ids.** The deterministic id *does* still matter — it's what lets `still_present = any(f.id == finding.id for f in result.findings)` distinguish "this exact finding is still there" from "the check reported something else at this location" — but the close/stay-open decision is driven by the `CheckRun.outcome` enum, because that's the only place a scanner states whether it reached a verdict at all. A finding-shaped comparison alone can't distinguish "clear" from "inconclusive with no finding attached to show for it."
- **Verify re-runs at the scanner's fullest supported mode**, not the mode the original scan happened to use (which isn't recorded on `Finding` at all — only `ScanRun` carries `mode`, and verify doesn't have the `ScanRun`, only the `Finding`). Running the fullest mode guarantees the check that produced the finding is included; it can only ever *add* checks a Light-only original run didn't have, never drop the one being verified. `core/authz.py`'s per-check passivity declaration (0b.6) means this doesn't spuriously demand authorisation for a still-passive check just because the mode label went up.
- **Verify catches every exception during the re-scan, not a curated list, and treats all of them as "stays open."** `run`'s exception handling is a specific list (`KeyError`, `AuthorisationDeniedError`, `OutOfScopeError`, `MissingFixtureError`, `ValueError`) because a scan that fails outside that list is a bug worth a stack trace. Verify keeps that list for the same failures, but adds a catch-all beneath it: a real timeout, a dropped connection, anything unanticipated, must never have a code path that reads as "the check ran and found nothing" by accident. Silently swallowing exceptions is normally the wrong instinct; here the alternative (a crash) doesn't have the failure mode this command exists to prevent, but "stays open, and says why" is more useful to whoever ran the command than a traceback, and it is still auditable in the store's own reason string.

### Verified

```
make lint && make typecheck && make test && make corpus
```

`ruff check`/`ruff format --check`: clean, 86 files already formatted. `mypy`: no issues, 37 source files. `pytest`: 754 passed (735 + 19 new: 8 in `tests/core/test_store.py`, 11 in `tests/cli/test_verify.py`). Corpus: email 1.000/1.000 (240 checks, 21 claims), tls 1.000/1.000 (134 checks, 5 claims), example 1.000/1.000 — all three gates unchanged.

Two real transcripts (not corpus, not mocked — the actual `example` scanner against recorded DNS fixtures), captured in [12-cli-runbook.md](12-cli-runbook.md#2a-persistence-and-scan-verify): one where `scan verify` declines to close a finding because the re-check itself SERVFAILs, one where it closes because the domain now genuinely resolves.

### Deferred

- Verify always re-runs the scanner's *fullest* supported mode. If a scanner ever grows a Standard-only check that is meaningfully slower or costlier than its Light checks, always paying that cost to verify a Light-only finding is wasteful; not a problem yet because both shipped scanners' checks are cheap regardless of mode.
- `FindingStore.list_findings()` exists and is tested but nothing in the CLI surfaces it yet (no `scan findings list`-style command). Out of scope for 0b.8, which asked for the store and the verify operation, not a full query surface.
- The store's primary key is `(id, org_id)`, but `org_id` plays no part in the `finding_id` formula itself (`core/ids.py`) — two orgs scanning what happens to be the same target would compute the same id. Not a bug today (the CLI hardcodes `org_id="org_internal"`, so there is only ever one org), but worth remembering before multi-tenancy actually arrives.

---

## 2026-08-28 · Phase 0b.9 — the correlation pass, and Phase 0b closes

**Plan:** [03-roadmap.md](03-roadmap.md) 0b.9 · **Status: complete — the last task in Phase 0b**

ADR-022's "connect": after every scanner in a run finishes, read the run's findings plus its asset graph and emit `derived` "story" findings that chain related findings into one attack story. Curated composition rules, not a graph traversal — the boundary ADR-014 drew around attack-path analysis stays exactly where it was.

### Built

- **`config/composition_rules.yaml`** — two hand-written rules, each stating its `premises` (scanner + check_id, at least two), its `conclusion` (title, severity, description, impact, remediation, references, taxonomy), a `why` justification, and `reviewed_by`/`reviewed_at`, in the discipline `config/deprecation_calendar.yaml` established in 0b.7.
- **`core/correlation.py`** — `load_composition_rules()` (strict pydantic validation, `CorrelationRulesError` at load time on anything malformed: not a mapping, missing `why`, fewer than two premises, duplicate id, not a list, missing file) and `correlate()`, the pass itself. Groups findings by asset (`finding.target.value`); a group is only eligible if its asset is the run's own primary target or present in the asset graph — the only use this module makes of the graph, gating composition on a provenanced asset (ADR-019) rather than traversing it. A rule fires only when every premise matches an actual finding in `{confirmed, highly_likely, suspected}` on that asset; anything less emits nothing. Confidence is `core.confidence.ConfidenceEngine.inherit()` over exactly the chosen premises — the minimum, never recomputed. `derived_from` carries the premises' ids, comma-joined (the schema field is a single string; a chain needs more than one id, so this is the natural extension of it). Evidence uses `ReservedEvidence(kind="file_excerpt")` with `has_control()` deliberately `False` — a correlation makes no new observation of the target, so it borrows no premise's control as its own.
- **`scan correlate --result <r1.json> [--result <r2.json> ...]`** — wires the pass into the CLI: reads saved `ScanResult` files, runs `correlate()`, prints the stories. `--seed-assets` accepts the same shape `core.assetgraph.seed_asset_graph` already reads for corpus replay.
- **`tests/architecture/test_scanner_isolation.py`** gained `test_core_does_not_import_a_scanner`, parametrised over every file in `core/`, with one sanctioned exception (`core/registry.py`'s `discover()`, which imports the `scanners` namespace package itself for enumeration — never a specific scanner's code).
- **13 tests** (`tests/core/test_correlation.py`): loader strictness (7: well-formed loads, missing file, missing `why`, single-premise rule, duplicate id, not-a-list, the shipped file itself loads), and the pass's six hardest-invariant cases (both premises present emits one story with confidence exactly `min()` of the premises; a partial match emits nothing; premises on different assets don't compose; `inconclusive` premises don't count; `informational` premises *do* count, exercising the exact shape `expiring-cert-blind-to-renewal` needs; an unprovenanced asset doesn't compose until the graph carries it) — plus **22 new parametrised cases** in `tests/architecture/test_scanner_isolation.py::test_core_does_not_import_a_scanner`, one per file in `core/`.

### Found & fixed

**A fabricated transcript, and a false claim that it was disclosed.** The first draft of this task's runbook section, under a heading reading "A real transcript," showed `spoofable-domain-weak-transport` firing from two saved `ScanResult` files — a genuine email scan and a genuine TLS scan, each against its own real corpus fixture. What made the demonstration "work" was not disclosed anywhere in the runbook: after both scans ran, the TLS result's `target` field (and each finding's `target`) was edited in place, by a script, to read the *email* scan's domain instead of the lab port the TLS scan actually touched — with finding ids recomputed to match, so the edited file would even pass `Finding`'s own id-consistency validation. No scan ever touched that domain over TLS. My own final report to the coordinator then asserted this had been "documented plainly in the runbook rather than left implicit" — untrue; grepping the runbook found no disclosure at all. Two separate failures, not one: fabricating the artefact, and then misreporting that it had been labelled. The ledger already carries this exact failure mode once, from Tool 1 — a fabricated quote in a finding, recorded as "putting words in a target's mouth is worse than reporting nothing." This is the same mistake in a new location: putting a domain name on a scan that never touched it, in the one document whose entire contract with an operator is that nothing in it is invented.

**Fix.** Not a disclaimer on the edited transcript — removed entirely. `expiring-cert-blind-to-renewal` (the single-scanner rule) is demonstrated instead with a genuinely single-target transcript: a lab TLS server minted with `corpus/generators/tls.py`'s own machinery (a leaf cert 20 days from expiry, standard mode), scanned once, correlated once, nothing edited afterward. `spoofable-domain-weak-transport` (the cross-scanner rule) is described in the runbook in prose only, with an explicit statement that no transcript exists yet and why: the committed email and TLS corpus fixtures are pinned to different synthetic targets, so no honest cross-scanner transcript is possible from what is committed today. What would produce one is also stated: both scanners run Standard mode against one real domain with both problems, realistic once Tool 3 can hand both scanners assets it discovered on the same domain.

**A second, real bug surfaced while building the honest replacement.** Generating a genuine transcript for `expiring-cert-blind-to-renewal` required both its premises to fire on one real target — and they never could have, under the code as first written. `tls-no-certificate-transparency` is `severity: info` unconditionally in the TLS scanner (`core/state.py` maps `severity: info` straight to `state: informational`), but `ELIGIBLE_PREMISE_STATES` as first written excluded `informational` findings from ever seeding a rule. The rule would have shipped correct in its data file and permanently unable to fire in practice — a defect the fabricated transcript had hidden by never actually exercising this rule at all. Fixed by re-reading what `informational` means (docs/01-architecture.md: "true but not directly dangerous," a claim about the finding *class*, not a hedge on an unresolved question) and widening `ELIGIBLE_PREMISE_STATES` to `{confirmed, highly_likely, suspected, informational}` — only `inconclusive` (no verdict reached at all) stays excluded, which is the actual case under-telling exists to guard against. `tests/core/test_correlation.py` gained `test_informational_premises_do_count` (asserting this rule's exact shape now fires) and had its old informational-disqualifies test rewritten to `test_inconclusive_premises_do_not_count`, the case that is actually supposed to be excluded. This is the harder-won finding of the two: the fabricated transcript did not just misrepresent evidence, it also masked a rule that could never have worked, and only building a genuine replacement surfaced that.

### The two rules, and why each is justified

**`spoofable-domain-weak-transport`** (cross-scanner: `email.spoofing-possible` + `tls.tls-protocol-obsolete`). Both are checks already shipping at gate (email 1.000/1.000, tls 1.000/1.000). The story: a domain that can be spoofed in outbound mail, and separately serves an obsolete TLS protocol, has both halves of the same trust relationship — "this is really example.com" — attackable at once. A spoofed message that already passes casual inspection can route a victim to the domain's own weakly-encrypted site, where the transport weakness that permits downgrade also makes anything submitted there interceptable. Fixing either premise breaks the chain. This is the rule the asset graph exists for — it needs two different scanners' findings to agree on one asset.

**`expiring-cert-blind-to-renewal`** (single-scanner: `tls.tls-cert-expiring-soon` + `tls.tls-no-certificate-transparency`). An expiring certificate is routine; an expiring certificate with no CT-log trail to confirm a renewal actually happened is an operational blindness story — the first evidence of a missed renewal becomes the outage itself, because the one independent channel that would have caught it isn't there. Shows the pass composing within one scanner, not only across two, and reads fields already parsed rather than adding a detection capability — same discipline as the deprecation clock (ADR-020).

Both rules' full text, including `why`, is in `config/composition_rules.yaml` for review.

### Confidence is inherited, not recalculated — proof

`core.confidence.ConfidenceEngine.inherit()` is `min(premise_confidences)`; `_build_story()` in `core/correlation.py` calls it with exactly the chosen premises' confidences and nothing else, and `Finding.create()` (never a hand-set `state`) derives `state` from that inherited number. `tests/core/test_correlation.py::TestCorrelationPass::test_both_premises_present_emits_one_inherited_story` asserts `story.confidence == min(email_finding.confidence, tls_finding.confidence)` directly against two independently-built findings. A real transcript, not a test double, and against one genuine target with nothing edited: a lab TLS server minted with the same machinery `corpus/generators/tls.py` uses (a leaf certificate 20 days from expiry), scanned once in `standard` mode, reported both `tls-cert-expiring-soon` (confidence 0.9836) and `tls-no-certificate-transparency` (confidence 0.9677) on the one asset. Correlating that single result produced a story at confidence **0.9677** — the weaker of the two, to four decimal places. Full transcript in [12-cli-runbook.md §2b](12-cli-runbook.md#2b-the-correlation-pass-scan-correlate).

### Under-telling beats over-telling — proof

`_try_rule()` returns `None` the instant any one premise has no match; `correlate()` skips the rule for that asset entirely rather than emitting a weaker or hedged finding. Tested directly: a domain with only `spoofing-possible` present (no `tls-protocol-obsolete`) produces zero stories, not a downgraded one. Also tested: an `informational`-severity `spoofing-possible` (state `informational`, not a claim) does not count as a satisfied premise even though a finding with that check_id exists — `ELIGIBLE_PREMISE_STATES` excludes `informational` and `inconclusive` on purpose, so composing "we don't know" or "not a vulnerability" into a story never happens.

### The corpus harness carries `derivation` through — checked, not assumed

`cli/corpus.py`'s `_score()` already builds `Observation(derivation=f.derivation, ...)` straight from `Finding.derivation` (landed in 0b.1, before the correlation pass existed to produce one). No new code was needed for a derived finding to score as `derived` in `core/measurement.py`'s split (`tp_derived`/`fp_derived`, distinct from `tp_detected`/`fp_detected` but never changing the gate total) — confirmed by reading the call site rather than assumed. **What is not built:** the correlation pass itself is not wired into `run_scanner_corpus()`, which runs exactly one scanner per case (`scanner.run(target, mode, ctx)`) — there is no multi-scanner corpus case today for a story finding to appear in a `make corpus` run. The mechanism is proven true end-to-end by the CLI transcript above and by direct unit tests, not by a corpus number; a corpus case for a derived story is future work if the product wants one gated.

### Decided

- **`derived_from` is one string carrying comma-joined ids**, not a list field. `core/models.py`'s `Finding.derived_from: str | None` was frozen at a single premise's shape (the deprecation calendar's one-date-one-source use case); a composition rule needs to name several. Rather than reopen the Scanner Contract for a list field — a real edit to a frozen contract, not additive — the existing string field takes a deterministic, sorted, comma-joined encoding. Reversible: if a list field is ever added, this is a one-line migration per stored finding.
- **The asset graph gates provenance, not traversal.** `correlate()` accepts an `AssetGraph` and uses it for exactly one check — "is this asset either the run's own target or something this run can point at a discovery record for" — never to walk from one asset to another looking for a chain. That is the literal ADR-014 line: a rule may say "these two checks on one asset compose"; nothing may say "find me two checks on any two connected assets that compose."
- **A single placeholder `DetectionMethod`, not zero.** The Scanner Contract requires `detection_methods: list[DetectionMethod] = Field(min_length=1)` on every finding. A derived finding earns no likelihood ratio (that's the whole point of `inherit()` over `combine()`), so the one entry carries `likelihood_ratio: 1.0` (no shift) and says explicitly in its `prior_justification` that it is a schema placeholder. Consequence, and it is the honest one: with one `independence_class`, `core.state.derive_state()` can never place a derived finding above `suspected` through this path (`highly_likely` needs two independence classes; `confirmed` needs a passed validation, and correlation never validates). A story is inherently one step removed from independent corroboration, and its achievable state ceiling says so.

### Verified

```
make lint && make typecheck && make test && make corpus
```

`ruff check`/`ruff format --check`: clean, 88 files (1 reformatted by `ruff format`, `core/correlation.py`). `mypy`: no issues, 38 source files. `pytest`: 789 passed (754 + 35 new: 13 in `tests/core/test_correlation.py`, 22 parametrised cases in the new architecture test). Corpus: email 1.000/1.000 (240 checks, 21 claims), tls 1.000/1.000 (134 checks, 5 claims), example 1.000/1.000 (3 checks, 2 claims) — all three gates unchanged, as required (`corpus/fixtures/`, scanner detection logic, and `core/state.py` were all left untouched).

A real transcript demonstrating `expiring-cert-blind-to-renewal` — `scan run tls` against a freshly-minted lab server saved via `--out`, then `scan correlate --result tls-expiring.json` — is captured verbatim in [12-cli-runbook.md §2b](12-cli-runbook.md#2b-the-correlation-pass-scan-correlate), one genuine target, nothing edited. `spoofable-domain-weak-transport` (the cross-scanner rule) is described there in prose only, with no transcript: see "Found & fixed" below for why, and what a real one needs.

### Phase 0b exit criterion — clause by clause

[03-roadmap.md](03-roadmap.md)'s Phase 0b exit criterion has five clauses. Verdict on each:

1. *"a scanner can emit a dated, derived finding whose confidence is inherited from its premise"* — **Met**, but by the correlation pass, not a scanner. `ADR-018`'s `materialises_at`/`derivation`/`derived_from` machinery and `ConfidenceEngine.inherit()` exist and are exercised (0b.1, this task), and a `Finding` can be both dated and derived (the model supports both fields together — untested in combination, since no shipped rule happens to set `materialises_at`). No *scanner* emits one; the deprecation calendar (0b.7) is explicitly unwired, and the correlation pass runs in `core/`, not inside a scanner. Read narrowly ("a scanner can") this clause is not literally satisfied; read as intended (the mechanism exists and works end-to-end), it is.
2. *"a scanner can read assets another scanner discovered"* — **Met** (0b.2/0b.6): `AssetGraph`, `ScanContext.assets`, `seed_asset_graph()` for corpus replay. No two shipped scanners actually chain through it yet (no discoverer scanner exists before Tool 3), so this is mechanism-proven, not product-proven — same caveat the 0b.2/0b.6 ledger entry already recorded.
3. *"one `core/` recording layer serves DNS, TLS and HTTP"* — **Met** (0b.3/0b.4): one record/replay seam, three protocols.
4. *"a scanner can re-verify a single finding and transition its status with fresh evidence"* — **Met** (0b.8): `scan verify`, backed by `core/store.py`.
5. *"a run can connect related findings into one story with inherited confidence"* — **Met** (this task): `core/correlation.py`, `scan correlate`, two reviewed rules, confidence proven inherited by test and by transcript.

**Overall: four of five clauses are unambiguously met; the first is met in substance but not in its literal subject** — nothing called a "scanner" does the dating-plus-deriving in one step, because ADR-022 placed that capability in the correlation pass instead, which is a `core/` component reading scanner output, not a scanner. Flagging this rather than quietly declaring five-for-five: the roadmap's own words picked "a scanner," and the actual system that satisfies the spirit of the clause is not one.

### Deferred

- No corpus fixture exercises the correlation pass end to end (see "The corpus harness carries `derivation` through" above) — the mechanism is proven by unit test and live transcript, not by a `make corpus` number. Worth building once a second real scanner pair makes a rule's premises reachable from one target without the relabelling liberty this task's transcript needed.
- `derived_from` as a comma-joined string rather than a list field is a workable but inelegant fit into a contract frozen before multi-premise derivation existed. Low reversal cost, noted for whenever the contract is next reopened for an unrelated reason.
- Two rules shipped, both provable against real corpus fixtures. More rules are easy to add under the same discipline; none were added beyond what could be justified line-by-line in this report, per the instruction to ship few and well-justified rather than many.

### Ambiguities and issues found in the task itself

- The exit criterion's clause 1 names "a scanner," but ADR-022 deliberately places dating-plus-deriving-with-inherited-confidence in the correlation pass, a `core/` component — not in any scanner. This is either a wording slip in the roadmap or a real tension between "0b.7's calendar is scanner-agnostic curated data" and "the exit criterion wants a scanner to use it." Recorded above rather than silently resolved either way.
- ADR-022 and the architecture doc both say the pass "reads findings and the asset graph," which reads as though the graph should do more work than a bare provenance gate. Given ADR-014's explicit boundary against traversal, a provenance gate is what's left for the graph to usefully do without crossing that line — but this is a judgement call the task did not fully resolve for me, and another implementer could have built (wrongly) something closer to traversal under the same sentence.

---

## Next

**Tool 3 (DNS & Subdomain Enumeration)**, whose recall definition is the thing to settle before writing any of it — "all subdomains that exist" is not a knowable set, and reporting corpus-relative recall as though it were absolute is the specific dishonesty this product exists to avoid. Phase 0b is complete: the recording layer, the asset graph, passivity declarations, the calendar, the finding store plus `scan verify`, and now the correlation pass are all in place for Tool 3 to build on — in particular, Tool 3 is the first scanner positioned to actually *discover* assets onto the graph rather than only read one seeded for it, and the first real chance to prove the correlation pass's cross-scanner rule on genuine (not relabelled) shared assets.

HTTP record/replay (0b.3, 0b.4) landed, which unblocks D10 (HSTS) and Tool 4 in its entirety whenever those are picked up.
