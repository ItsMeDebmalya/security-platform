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

**Amended 2026-08-28.** 0b.1 added a third category: a defect found by *review*, caught by neither the corpus nor a live run. The corpus harness silently discarded the `derivation` field, and it could not have been found by running anything — the scanners emit no derived findings yet, so the wrong number and the right number were both empty. Some defects are only visible by reading the code that carries a value from one place to another.

### What our gate numbers rest on

Both scanners read `1.000`. They are not equally evidenced.

| | Claims the number rests on | Corpus | Live |
|---|---|---|---|
| email | 21 of 240 checks | 16 synthetic zones we wrote | 50 real domains, 8 findings, all verified |
| tls | **5** of 134 checks | 14 lab servers we configured | 6 badssl subdomains + operator infrastructure |

TLS's precision rests on five claims because most TLS findings sit on a single independence class and land as `suspected`. That is honest, and it means the figure is thinner than it reads. Recorded in [10-measurement.md](10-measurement.md) as a standing caveat.

### Ground truth is code too, and it had the most bugs

Three of the TLS lab's faults made every corpus case *easier* than intended while the gate stayed green — a CA without `basicConstraints`, servers accepting TLS 1.0 because `@SECLEVEL=0` was needed for weak keys, and a two-level chain that cannot express an incomplete chain. **Nothing in the harness can detect this.** Only reading the fixtures can.

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

## D. Deferred register

Single source of truth for what is owed. Move an item out only when it lands.

They cluster, which matters more than the individual entries:

- **Corpus realism** — D6 (real domains), D3 (benchmark tier), D11 (a weak-cipher case). Each one narrows the gap between a gate number and a claim about the world.
- **Capability gaps a user would notice** — D12 (revocation: `revoked.badssl.com` reads as a pass), D4 (SMTP checks), D5 (lookalike domains).
- **Infrastructure** — D1 (CI has never run) and D7 (a local authoritative DNS zone).
- **Unverified numbers in decision documents** — D13 (v3.4 research from vendor blogs) and D16 (0b.5's own roadmap row claimed 3.13 unblocks post-quantum; it does not) are the same failure mode twice: a figure reached an ADR or roadmap row without being checked against its primary source.

| # | Item | Why deferred | Blocks |
|---|---|---|---|
| **D1** | Verify CI actually runs | No remote existed when it was written; one exists now, but no run has been observed | Nothing yet — but every gate claim rests on it |
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

---

## Next

**Tool 3 (DNS enumeration)**, whose recall definition is the thing to settle before writing any of it — "all subdomains that exist" is not a knowable set, and reporting corpus-relative recall as though it were absolute is the specific dishonesty this product exists to avoid.

HTTP record/replay (0b.3, 0b.4) landed, which unblocks D10 (HSTS) and Tool 4 in its entirety whenever those are picked up.
