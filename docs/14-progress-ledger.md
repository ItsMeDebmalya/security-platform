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

**Correction, 2026-10-08 (corpus-fidelity audit):** the email row's "Live" column cannot be reproduced. The sweep's domain list and results were not archived, `docs/12-cli-runbook.md` calls the same evidence "twelve real domains", and it was Light mode only. Until D35 closes, email is **corpus-validated, live-unverified**, and its 1.000 is not quoted.

### Only real recorded traffic passed the fidelity audit (2026-10-08)

**Of four scanners, only `web` came out of the corpus-fidelity audit clean, and `web` is the only one built from real recorded traffic plus live hand-verified hosts and an external cross-check. Tool 4a's method is now the standard for every scanner** ([ADR-027](02-decisions.md#adr-027--a-fixture-may-stand-in-for-a-real-service-only-on-recorded-evidence)). `domscout`'s generator wrote two third-party services as they do not behave, and two advertised checks are broken in production while the gate passes (D28, D31). `email`'s confirmation step cannot fail in its corpus (D35). `tls` is real software, but one stack and one failure shape (D32, D33). A gate number is worth what its fixtures are worth.

### 63 shipped checks: 23 work, 3 are broken, 37 are unproven (2026-10-08)

**The scanner catalogue's own count, stated so that nobody has to derive it.** The four shipped scanners run 63 checks. **23 are WORKING**: each fired correctly on a real, live target and was checked by hand. **3 are BROKEN**: D28's two expiry checks, and D31's S3 and Heroku takeover fingerprints. **37 are UNDETERMINED**: no known defect, and no live evidence that meets the standard. **59% of our shipped checks (37 of 63) have no evidence either way that they work in production, and with the 3 known broken, 63% (40 of 63) have no evidence that they work.** Seventeen of the 37 are `email`'s, pending D35's live re-verification. The figure is owned by [SPEC.md](../SPEC.md#status-summary-table) and comes from [the catalogue](21-scanner-catalogue.md). It changes only when the catalogue is regenerated.

### Four checks that never fire is a category, not a coincidence (2026-10-08)

`domain-expiring` and `domain-expired` (D28), the S3 and Heroku takeover fingerprints (D31), and `dkim-missing` (D37) are all advertised checks that cannot report a positive in production. Every one passed its gate. Two were hidden by fabricated fixtures, and one was built that way. A gate counts the checks that ran, not whether any of them could ever fire. **Standing review item:** no new check ships until it has been shown to fire against a real positive. That means a live target or a recording of one, hand-verified, cited in the PR. A corpus positive we wrote does not count. Where no real positive can be found, the check ships as UNDETERMINED with that said, or does not ship. Now a clause of [ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done), and an item in [how-to-add-a-scanner §7](how-to-add-a-scanner.md#7-before-you-open-the-pr).

### Ground truth is code too, and it had the most bugs

Three of the TLS lab's faults made every corpus case *easier* than intended while the gate stayed green — a CA without `basicConstraints`, servers accepting TLS 1.0 because `@SECLEVEL=0` was needed for weak keys, and a two-level chain that cannot express an incomplete chain. **Nothing in the harness can detect this.** Only reading the fixtures can.

### A verifier that shares the blind spot confirms nothing

A correctly configured TLS client cannot complete a handshake with the obsolete servers this product exists to find — and `openssl s_client` carries the same safety floor, so it once "disproved" a finding that was correct. Before trusting a second tool to check the first, ask whether it is capable of seeing the thing being checked. Independence is about failure modes, not about being a different program.

### Never put words in a target's mouth

A finding once asserted a domain's SPF record was `v=spf1 -all` when it authorised nine IP ranges. Descriptions now quote what was actually read, never a reconstructed string. The same defect recurred in a different costume at 0b.9, where a runbook transcript's `target` field was edited so two unrelated scans would appear to agree. **Asserting something about a target we did not observe is the worst failure this product can have**, because every other claim we make rests on the reader believing we only say what we saw.

### The blocking questions are non-technical, and building does not move them

[Q4](07-open-questions.md) (legal review of the tool list), [Q5](07-open-questions.md) (ToS and the authorisation agreement) and [Q4a](07-open-questions.md) (GDPR, blocks Phase 3) are all 🔴 and all unanswered. Two tools have shipped since they were raised. They will not resolve by writing more scanners, and Q4a blocks a phase we are two tools away from.

### A broad `except` can turn a corpus gap into an `inconclusive` (2026-10-06)

Found while planning Tool 4a, by reading rather than running. **Recorded, not fixed — domscout is unchanged.** `scanners/domscout/scanner.py` wraps each of its HTTP calls (crt.sh, RDAP, the takeover fetch) in `except Exception`. On replay, a URL with no recorded fixture raises `MissingFixtureError`, and that catch swallows it: the check reports `inconclusive` / `blocked_prerequisite` and the scan finishes normally. A missing fixture is a corpus defect, not a target condition, and `cli/corpus.py` exists to fail loudly on it ("fixtures do not cover this scanner version").

Verified directly on 2026-10-06. Replaying the `servfail` case, `ReplayHttpBackend` raised `MissingFixtureError` for both `https://crt.sh/?q=%25.corpus-broken.test&output=json` and `https://rdap.org/domain/corpus-broken.test`. The scan still returned `subdomains-ct-log` and `domain-expiring` as `inconclusive` / `blocked_prerequisite`. **That case's expected inconclusive outcome currently *depends* on this masking.** Its generator simulates a failed fetch, a failed fetch writes no HTTP fixture, and the gap is what the scanner reads on replay.

The consequence: if a future domscout change requests a URL the frozen fixtures do not cover, its corpus would degrade to more `inconclusive` rather than error. The inconclusive-rate gate would catch a large drift, but not a small one. It is the "plausible default standing in for a value that never arrived" shape from the Phase 0b defects. `web` (Tool 4a) re-raises `MissingFixtureError` and `ScanKilledError` and catches only transport failures. Fixing domscout means re-raising in its three handlers **and** giving `servfail` a recordable failure. HTTP replay cannot represent a transport failure today, so that second part may need a `core/replay.py` extension. It is a separate, reviewed change.

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

## 2026-09-02 · D20 built — the testssl.sh runtime wrap, legacy ciphers unblocked (mostly) — TLS v1.2.0

**Status: D20 closed. D18 now closes at three of four checks; the fourth (`tls-vuln-freak`) ships without a corpus positive — deferred honestly, not faked.** Gate green: tls 220 checks, precision 1.000, recall 1.000, susp% 7.7%, inconc% 12.3%.

### Built

- **`core/testssl.py`** — the runtime wrap ADR-016 reserved as a per-check reversal. Three backends matching every other protocol client's shape: `LiveTestsslClient` (the real subprocess — `--vulnerable --quiet --jsonfile-pretty`, reusing the invocation shape `corpus/crosscheck/testssl.py` established), `RecordingTestsslClient` and `ReplayTestsslClient` (both through `core.replay.FixtureStore`, same as `core.tls`/`core.dns`). Everything that can go wrong — binary missing, subprocess error, timeout, unparsable JSON, nothing recorded on replay — collapses to one `TestsslUnavailableError`, mirroring `core.context.OobUnavailableError`/`StubOobClient`. 13 unit tests in `tests/core/test_testssl.py`, all offline; the live subprocess path is exercised only by `corpus/generators/testssl.py`, run by hand.
- **Four new checks**: `tls-vuln-rc4`, `tls-vuln-sweet32`, `tls-vuln-freak`, `tls-vuln-logjam` — all `mode="standard"`, `passive=True` (reading what a server offers is ordinary negotiation, ADR-023, even when a second tool does the reading). A new independence class, `EXTERNAL_PROBE`, named and justified in `scanners/tls/checks.py`: distinct from `NEGOTIATION` because our own engine and testssl.sh can disagree about the same server (ours structurally cannot see RC4 at all), so collapsing them into one class would let "we didn't look" and "we looked and disagree" corroborate each other, which is wrong.
- **`ScanContext.testssl`**, defaulting to `StubTestsslClient` (Phase-0-style: nothing reaches a subprocess a caller did not explicitly wire up). Wired for real in `cli/main.py` (`LiveTestsslClient` live, `Recording`/`ReplayTestsslClient` under `--record`/`--replay`, same directory the DNS/TLS/HTTP fixtures already share) and in `cli/corpus.py` (a new optional `testssl_fixtures` key per corpus case, `StubTestsslClient` everywhere else — no special-casing, `TestsslUnavailableError` degrading to `inconclusive` is the correct answer for every case that never recorded one).
- **The early-return fix.** `_Scan.execute()` returned before any Standard-mode check ran whenever the base handshake failed (`_no_handshake()` then `return`). RC4-only and 3DES-only servers — exactly what `rc4.badssl.com`/`3des.badssl.com` are — fail our own engine's handshake outright (OpenSSL 3.5 cannot select any cipher they offer), so without this fix the one channel that *can* see them never ran. `_check_legacy_ciphers()` now also runs on the no-handshake path in Standard mode; it needs only `self.host`/`self.port`, nothing from the failed handshake. Found by trying to record the corpus, not by inspection — the first `corpus/generators/testssl.py` run against `rc4.badssl.com` produced zero testssl fixtures until this landed.
- **Real corpus recordings, three of four positive.** `corpus/generators/testssl.py` records both fixture sets a Standard scan needs (our own engine's handshakes via `RecordingTlsBackend`, testssl's verdicts via `RecordingTestsslClient`) against public badssl.com weak endpoints — the lab cannot serve any of these, same wall as D11. `legacy-cipher-rc4` (`rc4.badssl.com`), `legacy-cipher-sweet32` (`3des.badssl.com`) and `legacy-cipher-logjam` (`dh512.badssl.com`) each recorded a genuine positive; `legacy-cipher-clean` (`mozilla-modern.badssl.com`) is the negative control and reports none of the four. End-to-end verified live, not just replayed: `cli.main run tls --target https://rc4.badssl.com --mode standard --record <dir>` ran the real testssl.sh subprocess (70.6s) and emitted `tls-vuln-rc4`; replaying from the same directory afterward reproduced the identical finding at `suspected`, 0.98, in well under a second, with zero network access.
- `tls` `scanner_version` bumped to **1.2.0**.

### Found & fixed

- The early-return bug above.
- **`FREAK` has no live positive endpoint left.** `export.badssl.com` was the obvious target; as of this recording it no longer negotiates an export-grade RSA suite against either our engine or testssl.sh's bundled OpenSSL — badssl.com appears to have quietly retired the actual export cipher from that endpoint while keeping the hostname. This is itself worth stating plainly: **the 2015-era named-vulnerability demo infrastructure is disappearing.** `tls-vuln-freak` ships — the code path is real and unit-tested — but carries no corpus positive. Per the explicit instruction not to fabricate a fixture (the defect recorded twice already: a hand-written fixture is not evidence), it is listed in `test_every_tls_check_has_a_corpus_case`'s documented-uncovered set with the reason inline, the same way `tls-weak-cipher` already was for the adjacent D11 wall.

### Decided

- **ADR-016 amended**, not superseded: the own-engine thesis holds for fourteen of eighteen checks; the reserved per-check reversal is exercised for exactly four, Standard mode only. See the amendment appended to ADR-016 in `docs/02-decisions.md`.
- **`tools/registry.yaml`'s testssl.sh entry updated**: purpose is no longer "NOT a runtime dependency" — it now names the four checks it backs at runtime, and remains the corpus cross-check for everything else.

### Deferred

- **D11** unchanged — `tls-weak-cipher` (our own engine's negotiated-suite check) still has no positive case; D20 does not touch it, since it wraps testssl for a different, disjoint set of checks.
- **D18** now closes at three of four: RC4/Sweet32/Logjam done, real corpus positives. FREAK remains open — not on our engine (unaffected by D20's mechanism), but on the absence of any live public endpoint to record a real positive from. Owed: find or stand up a FREAK-capable endpoint, or accept the check as corpus-unproven indefinitely and say so wherever its coverage is cited.
- **D20 closed.**

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
| ~~**D10**~~ | ~~HSTS checks in Tool 2~~ | ~~[05-phase-1-first-tools.md](05-phase-1-first-tools.md) lists HSTS under TLS Standard, but it is an HTTP response header, so it needs an HTTPS GET. **Unblocked 2026-08-28** — HTTP record/replay landed with 0b.4, so its corpus cases can now be frozen. Owed only because nobody has written the checks yet~~ | **Closed 2026-10-07.** Covered by the `web-hsts-*` checks in Tool 4a (`web`), where the HTTPS GET lives — not in `tls`. HSTS on a host with no working HTTPS is `inconclusive`, never "missing" (see D23) |
| **D11** | A positive corpus case for `tls-weak-cipher` | RC4 and 3DES are compiled out of OpenSSL 3, so the lab cannot serve one at any security level — verified by trying. Needs either a different TLS implementation for the lab, or a recorded handshake from a real server still offering one. **Unaffected by D20**: that wraps testssl.sh for a disjoint set of checks (`tls-vuln-*`), not this one, which reads what *our own engine* negotiated | Nothing; Tool 2 gates without it |
| **D12** | Certificate revocation checking | `revoked.badssl.com` currently returns nothing, which reads as a pass. Needs OCSP or CRL — an outbound HTTP request to the issuing CA, so it also needs a decision about whether that counts as passive | Nothing; Tool 2 gates without it, but it is a visible gap in a demo |
| **D13** | Verify the v3.4 research numbers against primary sources | Certificate-lifetime dates, PQ adoption percentages and MCP exposure counts all came from vendor blogs and secondary summaries. A deprecation clock citing a wrong date is worse than no clock | Any external use of the numbers |
| **D14** | Research IoT/device security as a candidate surface | Requested by the client and deliberately left out of v3.4 because it was not researched. Padding a plan with an unexamined surface is how the v3 differentiators got inflated | Nothing yet |
| **D15** | A real device network to verify against | The IoT corpus will be emulators and recorded exchanges. An emulator written from an RFC agrees with a scanner written from the same RFC — the corpus-encodes-the-author's-assumptions failure in its purest form, in the domain where devices violate their own specs most | Calling tool 5a/5b done |
| **D8** | `evidence_file` existence check in `core/authz.py` | The loader checks the field is present, not that the file exists, so a scope file stays loadable outside the repo. Enforced on the committed file by test instead | Nothing; it is a belt-and-braces item |
| **D16** | Post-quantum exposure detection needs Python 3.15 | `ssl.SSLContext.set_groups`/`get_groups` and `SSLSocket.group()` — the whole of reading back a negotiated key-exchange group — arrive in Python 3.15, not 3.13 as the original 0b.5 roadmap row claimed. Verified directly against the `ssl` module across 3.12/3.13/3.14/3.15rc1; 3.15 is currently at rc1, not final | The post-quantum-exposure claim in ADR-020 |
| ~~**D17**~~ | ~~`tls-chain-incomplete` false-negatives an incomplete chain~~ | **Closed 2026-09-02.** The cause was sharper than the definition split first guessed: a single `verify_code` reports only the *first* failure, so expiry masked the incomplete chain. Fixed behaviourally — a second verifying handshake with `X509_V_FLAG_NO_CHECK_TIME` set asks "ignoring expiry, does the chain build?", independent of the trust verdict. `get_unverified_chain` deliberately not adopted. A host now reports both `tls-cert-expired` and `tls-chain-incomplete` | — |
| **D18** | Inference-based named-vulnerability detection — **partial, mostly closed 2026-09-02** | **BEAST shipped 2026-09-02** (TLS 1.0/1.1 + CBC → derived finding). **RC4, Sweet32, Logjam shipped 2026-09-02** via the testssl.sh runtime wrap (D20), each with a real corpus positive recorded against a public badssl.com endpoint. **FREAK remains open**: the check ships and is unit-tested, but `export.badssl.com` no longer negotiates an export-grade suite against either engine, so no live endpoint exists to record a real positive from — deferred, not faked | A live FREAK-capable endpoint, or accepting the check as corpus-unproven |
| **D20** | A legacy-cipher-capable TLS backend | **Closed 2026-09-02.** `core/testssl.py` wraps testssl.sh at runtime for `tls-vuln-rc4`/`sweet32`/`freak`/`logjam`, Standard mode only, per ADR-016's amendment. Three of four have real corpus positives (badssl.com recordings); FREAK does not (see D18) | D11 unaffected (disjoint check); the RC4/Sweet32/Logjam third of D18 closed, FREAK open |
| ~~**D19**~~ | ~~HSTS check in TLS~~ | ~~An HTTP response header, so it needs an HTTPS GET — **no longer blocked**, HTTP record/replay landed with 0b.4. SSL Labs and SSL.org both surface it. Owed only because nobody has written it. Supersedes the old D10 framing~~ | **Closed 2026-10-07.** Covered by the `web-hsts-*` checks in Tool 4a (`web`), where the HTTPS GET lives — not in `tls`. HSTS on a host with no working HTTPS is `inconclusive`, never "missing" (see D23) |
| **D21** | `core.evidence.redact_headers` redacts by header **name** only | Found 2026-10-07 by the Tool 4a review. `redact_headers` (`core/evidence.py`) replaces the value of headers whose *name* is on `SENSITIVE_HEADERS` and leaves every other header untouched — it never pattern-matches values. So a secret inside a non-sensitive header value (`Server: nginx AKIA…`, `X-Powered-By: … ghp_…`, a token inside a CSP source URL) is stored unredacted in HTTP evidence. **This affects every scanner that captures HTTP evidence (`email`, `tls`, `domscout`, `web`), not only `web`.** `web` works around it scanner-side (`scanners/web/scanner.py`: header names and values, request URLs and finding locations are run through `redact_body` before anything is stored); **that workaround should be removed once core/ is fixed.** Not fixed in Tool 4a deliberately: changing `core/` mid-task would invalidate the Task 1–11 reviews, and `core/` is shared with three validated scanners. The fix needs **its own branch and its own ADR, after Tool 4a's Task 14**, with a regression check that email/tls/domscout corpus numbers are unchanged. **Also (final review, 2026-10-07):** core's `private_key` pattern redacts only the `-----BEGIN … PRIVATE KEY-----` line, so a key's base64 body survives in every scanner's HTTP evidence **and** in `RecordingHttpBackend` fixtures on disk; `web` (v1.0.2) cuts whole PEM private-key blocks scanner-side, in evidence bodies, the error-page excerpt and every description, until core is fixed. **Re-examine when core is fixed — do not assume this path was always safe (operator, 2026-10-08):** `web` v1.0.3 has a `pre_redacted` path in `scanners/web/scanner.py` (`_emit(pre_redacted=True)`, used for the error-page excerpt and the robots list). Those two descriptions are stripped of keys once by the scanner when they are built. When they are emitted, they get **core's patterns only**: a second scanner strip would mistake its own marker for an unterminated key. Core's patterns are exactly what this row documents as insufficient. The path is safe today only because of the earlier scanner-side strip, which the v1.0.3 security re-review checked. When core's redaction changes, re-check both callers, and remove the scanner-side workaround only after this path has been re-proven | Hard constraint 5 ("never store customer secrets") for every scanner; scheduled follow-up after Tool 4a |
| **D22** | `dvwa` and `vampi` (both instances) run on floating `:latest` tags in `docker-compose.yml` | Recorded 2026-10-07 while pinning the web Light lab images to digests. A floating tag on a deliberately-vulnerable target breaks reproducibility as soon as corpus cases are built against it: the "known vulnerable version" can change under the test, so a case can start passing or failing without any change on our side. `juice-shop` is already pinned (`v19.0.0`). Deliberately not fixed now - nothing gates on these targets yet. **Fix when the offensive (Standard/Deep) work starts:** pin each to a version tag and digest, record the digest in `tools/registry.yaml`, and treat a re-pin like a corpus re-record (a reviewed change) | Reproducible offensive corpus cases against dvwa/vampi |
| **D23** | **HIGH PRIORITY for Tool 4b/4c — "no working HTTPS" is never stated** | Found by the Tool 4a live cross-check (2026-10-07). On HTTP-only or TLS-broken sites (testasp/testaspnet/rest.vulnweb.com time out on 443; httpforever.com fails the TLS handshake) `web` correctly returns `inconclusive` for HSTS and the HTTPS redirect (spec §3.1: never claim missing HSTS on a host without HTTPS), and Mozilla Observatory fails both. But **no check of ours states the underlying fact — this site has no working HTTPS — definitively**, and it is one of the most valuable things a web scanner can say. Deferred, not dropped, because it is a scope change (spec + likely ADR) and **the hard part is separating "port filtered / host unreachable" from "no HTTPS service"**: a timeout on 443 proves neither, so an honest check needs a second signal (e.g. HTTP answers while 443 refuses vs times out, the tls scanner's result, a reachability pre-check per the v4 plan's pre-scan gate) before it may claim anything. Do not let it be rediscovered later as an embarrassment | Tool 4b/4c scope; owner to schedule |
| **D24** | Headers on redirect hops are invisible to scanners | Found 2026-10-07: `https://mozilla.org/` answers 301 → `https://www.mozilla.org/` carrying `Strict-Transport-Security: max-age=60; includeSubDomains`; `web` judged HSTS on the final `www.` response (one year) and raised nothing, and Observatory passed it too. A browser that first visits the apex gets a 60-second HSTS policy for it. Cause: `core.http.HttpClient` follows in-scope redirects itself and returns only the final response, so no scanner can see a hop's headers. A real but minor gap; fixing it needs `core/` to expose the redirect chain (its own change, like D21) | Apex-HSTS and other redirect-hop header checks |
| **D25** | Cost metering does not count failed request attempts — **not cosmetic** | Found 2026-10-07: scanning the unreachable `testphp.vulnweb.com` took 90 s of wall time and made ~10 connection attempts, yet `telemetry.requests` was **0** — `core.cost.CostMeter` records a request only when a send *completes*, so timeouts, refusals and TLS failures are uncounted. That makes scanning a dead or blackholing host look free: rate limiting reasons about load it cannot see, and when per-scan cost feeds billing (v4 Phase 1 Free/Pro tiers) the cheapest-looking scans are the slowest. Needs `core/` to count attempts as well as completions (its own change) | Accurate rate limiting; billing on per-scan cost |
| **D26** | **REQUIRED BEFORE BETA — the `web` request cap: declaration and behaviour disagree** | The Tool 4a spec and plan declare "at most 12 GETs per run". `web` enforces 12 *scanner-issued* GETs, but `core.http.HttpClient` follows in-scope redirects (up to `MAX_REDIRECTS`=5 per GET) on top, and `CostMeter` counts every hop: **mozilla.org used 23 requests, kinetrix.in 18, codez.in 13** in the 2026-10-07 live runs. A cap that can be exceeded ~2× is not a cap, and restraint is the product's core claim. Behaviour deliberately unchanged in Tool 4a (Task 9 ruling). Two honest options to decide before beta: **(a)** count redirect hops toward the 12, or **(b)** re-declare the limit as "12 target requests, redirects additional, hard ceiling N" and enforce N (needs `core/` to expose hop counts or accept a per-call hop budget). Until decided, every document that states the cap must say redirects are additional | Beta |
| **D27** | **The authorisation gate is unexercised by any production scanner** — a test-coverage gap in our most important safety control | Recorded 2026-10-08 (operator), found while preparing the Tool 4a demo. Since ADR-023 every check in `email`, `tls`, `domscout` and `web` is `passive=True`, so **no real scan reaches `core/authz.py`'s deny path**. The gate is built and tested only against synthetic active checks (`tests/core/test_authz_passivity.py`), the CLI tests and the reference `example` scanner, which has no `Check` catalogue and falls back to the mode rule. It has never had to stop a real scanner's check. Until one does, "deny-by-default" is a claim about the mechanism, not about any shipped scanner. **The first active check (the Website Scanner's Standard-mode payload checks, or any Tool 4b check declared active) must ship with an end-to-end test: that scanner, a real `config/authorised_scope.yaml` with no row, CLI exit 1, zero requests sent to the target; plus the allowed case with a valid row.** Runbook §5 states the gap to operators; the Tool 4a demo shows the gate only through the reference scanner, with this caveat spoken | Hard constraint 2 (no active scan without verified ownership); blocks the first active check from shipping |
| **D28** | **HIGH PRIORITY — `domain-expiring` has never read an expiry date live, for any TLD.** A check we advertise. Most prospects have `.in` domains, so the market-visible answer today is "we can't tell you when your domain expires", but this affects every customer, not only `.in` | Found 2026-10-08 (operator query on an operator-owned `.in` domain: `inconclusive`, "carries no expiration event"). **Not a registry gap. Our fetch fails.** Measured 2026-10-08. Through `curl -L https://rdap.org/domain/<d>`, six unrelated `.in`/`.co.in` domains (amazon.in, airtel.in, zomato.in, nic.in, sbi.co.in, irctc.co.in) **all** publish an `expiration` event from `rdap.nixiregistry.in`. So do the controls example.com (Verisign), wikipedia.org and python.org (PIR), and the operator's domain itself. `scan run domscout` returned `inconclusive` "carries no expiration event" for amazon.in, example.com **and** wikipedia.org alike. **Cause:** rdap.org is a bootstrap redirector. It answers `302` with an empty body and a `Location` on the registry's own RDAP server. `core.http.HttpClient` (`core/http.py:288`) correctly declines to follow a redirect out of scope. domscout's `service_hosts` are only `crt.sh` and `rdap.org`, so it gets the 302 back. `_check_expiry` (`scanners/domscout/scanner.py`) handles only 404/429/5xx, parses the empty body, and reports "no expiration event". The parser itself is fine: `rdapp.parse_rdap` reads the expiry from every live body above. **The root cause is a corpus validity failure, not a parser bug: a generator that fabricates a third party's behaviour can make a scanner pass its gate while it is broken in production.** The parser, the scope rule and the gate each did their job. The gate measured the scanner against a version of rdap.org that does not exist. **Why every gate missed it:** `corpus/generators/domscout.py` models rdap.org as answering `200` with the RDAP JSON itself, the author's assumption frozen into all 9 fixtures. The Tool 3 live run saw the symptom and misattributed it to `.in` (the Tool 3 live-verification entry, corrected in place). It is the ADR-017 lesson again: the corpus encoded the assumption, and a live disagreement found it. **WHOIS (port 43), as asked:** `whois.nixiregistry.in` (IANA's referral for `.in`) returns `Registry Expiry Date:` for `.in` and `.co.in`, the operator's domain included. But `.in` RDAP carries the same date, so **no WHOIS fallback is needed for `.in`**. **Fix (not implemented, operator ruling: investigate and record only):** (1) query the registry's RDAP server directly, from a vendored copy of IANA's bootstrap (`https://data.iana.org/rdap/dns.json`, which lists `https://rdap.nixiregistry.in/rdap/` for `in`), or follow rdap.org's redirect only to a host listed there. Either way that widens domscout's `service_hosts`, so it lands with the `service_hosts` ADR already owed from Tool 3. (2) Treat an unfollowed 3xx as its own `inconclusive`, worded as what happened: "rdap.org redirected to the registry's RDAP server (`<host>`), which this scan may not contact, so expiry was not read". Never "carries no expiration event", which reads as the registry's fault. (3) A corpus case with a recorded 302, and re-record the 9 fixtures against the real two-hop shape. (4) Re-run live on `.in`, `.com` and `.org` domains, then bump `scanner_version`. domscout is on the do-not-regenerate list: this is a targeted change to `_check_expiry`, not a rebuild | The advertised domain-expiry check (SPEC A4 lists RDAP domain-expiry under Light); the `domain-expiring`/`domain-expired` gate numbers, which are fixture-only until (3) |
| **D29** | `scan list` shows the reference `example` scanner to customers | Found 2026-10-08 preparing the Tool 4a demo. `example 1.0.0` sits beside the four products in `scan list`. A customer should not see our test scaffolding. **Keep the scanner:** it is the Scanner Contract's reference implementation, the tests use it, and it is the only scanner with an active check (D27, demo beat R4). **Proposed fix (not implemented, it is a CLI change):** mark internal/reference scanners and have `scan list` omit them by default, with `scan list --all` to show them. Note `tools/registry.yaml` is the third-party **licence** registry, not the scanner registry. Scanners are found by `core/registry.py` `discover()`. So the marker belongs either on the scanner class (an additive, defaulted attribute like `service_hosts`; it touches `BaseScanner`, so per CLAUDE.md it needs an ADR), or in a CLI-side list of internal names (no contract change, but a second place to keep in sync). Prefer the attribute. Until then the demo filters it out of beat 1, and the run sheet says so | Customer-facing CLI and, later, the `api/` scanner listing |
| **D30** | Candidate WordPress fingerprint gap: **checked 2026-10-08, no gap on the evidence** | Raised 2026-10-08 (operator). On an operator-owned site, robots.txt disallows `/wp-admin/` and `/wp-includes/`, but `web-technology` reported only Apache httpd. **Inferring WordPress from robots.txt alone would be exactly the weak evidence our standard rejects.** A disallow line is a statement about paths, not proof that anything is installed, and is often stale or copied from a template. Investigation: `web` **already** fingerprints WordPress from its own evidence. In `scanners/web/data/fingerprints.yaml`, `match.generator` is `^WordPress…` and `match.asset` is `/wp-(?:content\|includes)/`. That site's homepage, fetched 2026-10-08 (87 KB), carries **no** WordPress generator tag and **zero** `/wp-content/` or `/wp-includes/` references. So "Apache httpd" only is the correct, under-claiming answer. The likeliest explanation is a robots.txt left over from a former WordPress install. **Residual candidate, not scheduled:** WordPress hidden behind a plugin that strips the generator tag and rewrites asset paths would evade both signals. Its own evidence (a `Link: <…/wp-json/>` header, or `/wp-json/` answering) would need either a header we already receive or one extra GET from the 12-request budget (D26). Decide only if a hand-verified miss appears | Fingerprint recall on hardened CMS installs |
| **D31** | **`domscout` S3 and Heroku takeover fingerprints can never fire live.** A second D28: a generator fabricated the providers' behaviour | Found 2026-10-08 by the corpus-fidelity audit. `scanners/domscout/takeover.py`'s `S3Fingerprint` and the Heroku fingerprint decide on DNS alone: an abandoned target "NXDOMAINs". `del http` discards the HTTP response. The `takeover-positive` case (`corpus/generators/domscout.py`, `bucket-abandoned.s3.amazonaws.com` → `NXDOMAIN`) was written to match. **Measured 2026-10-08 with random names nobody owns, through 1.1.1.1:** `<random>.s3.amazonaws.com`, `<random>.s3-website-us-east-1.amazonaws.com`, `<random>.herokuapp.com` and `<random>.herokudns.com` all answer **NOERROR** with addresses. The S3 one answers HTTP `404` with `NoSuchBucket`. So the precondition never occurs on a real domain. The GitHub Pages fingerprint is correct: it judges the body, and the real service resolves and answers `404` "There isn't a GitHub Pages site here". Findings cap at `suspected`, so **no precision number is affected. This is a broken advertised feature, not a false positive.** Fix (not scheduled): judge S3 by its `NoSuchBucket` body and Heroku by its own no-such-app response, each from a cited recording ([ADR-027](02-decisions.md#adr-027--a-fixture-may-stand-in-for-a-real-service-only-on-recorded-evidence)). Re-record `takeover-positive` from real responses, then bump `scanner_version`. A targeted change, not a rebuild | The advertised subdomain-takeover check for two of its three providers |
| **D32** | `tls` "unreachable" is only ever an instantly refused port | Found 2026-10-08 by the corpus-fidelity audit. The `unreachable` corpus case is a closed port on 127.0.0.1, which refuses the connection at once. On the internet an unreachable host is just as often **filtered**: packets dropped, the connection times out. That is the exact condition D23 is about (testasp.vulnweb.com times out on 443). No corpus case exercises the timeout path: wall time, the inconclusive reason, or whether a timeout is worded differently from a refusal. Fix: a lab case that accepts nothing and never answers (a black-holed port), with an expected inconclusive and its reason | The tls inconclusive path on real filtered hosts; feeds D23 |
| **D33** | Every `tls` lab server is OpenSSL 3.5, so server diversity is untested | Found 2026-10-08 by the corpus-fidelity audit. All 15 lab servers in `corpus/generators/tls.py` (16 cases; `unreachable` has none) are Python `ssl` servers on the host's OpenSSL 3.5. They are real software (ADR-027 clause 2), but one implementation. Real targets run older OpenSSL, BoringSSL, SChannel, Java/JSSE, embedded stacks, load balancers. Their differences in handshake behaviour, alert codes, cipher ordering and which errors they send are never in the corpus. The four legacy-cipher cases (badssl.com, real recordings) and live runs are the only exposure to anything else. Fix: add lab servers on other implementations (older OpenSSL builds, a Java server, a Go `crypto/tls` server), each recorded, before calling the TLS corpus representative | Confidence that tls verdicts hold beyond one TLS stack |
| **D34** | **crt.sh's real response shape is UNVERIFIED, not checked** | 2026-10-08: during the corpus-fidelity audit crt.sh answered `502` and `404` to every attempt (badssl.test, badssl.com and an unrelated .co.in domain) and could not be checked. The `domscout` fixtures write crt.sh as a JSON list carrying only `name_value`, one name per entry, with no wildcards, duplicates or other fields, and an empty control query. In mitigation: `ct.py` handles the real multi-name and `*.` format, and the Tool 3 live run got real crt.sh data. Neither shows the frozen fixtures match the service. **Retry later** and record the real shape (fields, multi-name entries, headers, status on no results). Re-record the fixtures per ADR-027 if they differ. The `502` the audit kept getting is itself a real failure mode no fixture contains; the `servfail` case simulates a connection exception instead | Validity of every `domscout` corpus case; ADR-027 clause 1 for crt.sh |
| **D35** | **`email` is corpus-validated, live-unverified: do not quote its 1.000** | Operator ruling, 2026-10-08. email's 21 corpus claims are our largest gate number, and the corpus cannot test the mechanism behind them. Every one reached `confirmed` by second-resolver agreement. `FakeResolver` ignores which resolver is asked (`core/dns.py`), so in the corpus the second resolver can never disagree and validation passes by construction. **The earlier live evidence does not meet the Tool 4a standard.** The Tool 1 entry records a Light sweep of 50 real domains (8 flagged, all verified, 0 FP), but its domain list and results were not archived. `docs/12-cli-runbook.md` describes "twelve real domains" for the same evidence, so the two documents disagree. It was Light mode, so the 8 Standard checks were never run live. Second-resolver agreement was never examined. Also never exercised: a 2048-bit DKIM key is frozen as one TXT string over 255 bytes, which real DNS cannot carry, so the real chunk-join path (`join_txt_chunks`) is not in the corpus. **To close:** live runs on an operator-approved domain list. Every non-informational finding is hand-verified with `dig` against more than one resolver and recorded as true, false or correctly inconclusive. Explicit evidence on whether the two resolvers agree live. An external cross-check of email posture. Raw results archived. Until then the email number is not quoted | The email gate number; any public accuracy claim that includes it |
| **D36** | **Second-source confirmation has a conceptual limit: two sources that fail together are not independent evidence** | Recorded 2026-10-08 (operator), from the corpus-fidelity audit. `email` and `domscout` reach `confirmed` by re-asking a second public resolver (1.1.1.1, then 8.8.8.8). **Both validate DNSSEC**, so on a domain with broken DNSSEC (dnssec-failed.org) they fail **together**: same SERVFAIL, same missing answer. More generally, both are recursive caches reading the **same authoritative servers**, so they can only disagree about transport, caching or validation, never about what the zone publishes. In the 2026-10-08 pre-screen, MX, TXT and `_dmarc` agreed on **36 of 36** domains. So agreement rules out a transient glitch at one resolver. **It does not independently corroborate the record**, the way `web`'s test/control pair corroborates a header on two different pages. **This applies to every future check built on second-source confirmation:** before a second source is called independent ([`independence_class`](01-architecture.md)), ask what failure would make both wrong at once. That is the standing observation "a verifier that shares the blind spot confirms nothing", applied to DNS. **Owed:** measure the live disagreement rate in the email re-verification (D35), and, if it is near zero, propose finding-description wording that says what the agreement shows. Confidence values are unchanged until the operator rules | Every `confirmed` reached by second-resolver agreement (email's 21 corpus claims, domscout's `dnssec-status`); the design of any future second-source check |
| **D37** | **`dkim-missing` can never report a positive. It is the fourth check that never fires, the same class as D28 and D31** | Recorded 2026-10-08 (operator), from the scanner catalogue. The check is advertised ("No DKIM key found", severity medium, SPEC A7 "DKIM detection") but its code has only two outcomes. It clears when one of 17 common selectors answers with a key, and otherwise reports `inconclusive`. That is deliberate and correct as far as it goes: selector names are chosen freely and cannot be enumerated, so a failed search proves nothing (`scanners/email/scanner.py`, `_check_dkim`). But a medium-severity check that cannot fire is not detecting anything. **It differs from D28 and D31 in one way:** those are defects, because the check was meant to fire and a fabricated fixture hid that it can't. This one cannot fire by design, and its corpus never pretended otherwise. The customer sees the same thing in all three: a check in the list that will never tell them they have the problem. **The catalogue status stays UNDETERMINED**, not BROKEN, because the code does what it was designed to do; the defect is that the design is advertised as a detection. **Candidate fix, not built:** a definite positive exists where `_domainkey.<domain>` itself returns NXDOMAIN. Under RFC 8020, NXDOMAIN means no name exists beneath it, so no selector can hold a key. That would be a real positive, but only on a zone whose authoritative servers follow RFC 8020 and have no wildcard, so it needs live evidence first. Otherwise, retitle and reclassify the check as DKIM key discovery, which is what it is. **Owed:** decide which, and give it a live positive before it is advertised as a detection again | `email` `dkim-missing`; SPEC A7's "DKIM detection"; every check that can only clear or shrug |
| **D38** | **Open question about the contract: `state` uses "a validation step ran" as its proxy for strength of evidence, and the two can come apart** | Recorded 2026-10-08 (operator), from the TLS wording discussion. `core/state.py` makes `confirmed` reachable only through a passed validation, a second observation of the same thing. Without one, `highly_likely` is the ceiling, however strong the evidence. `tls` shows the gap. Its best findings rest on **two independent readings** (our certificate parse, and OpenSSL's trust-path verdict: different code, different failure modes), yet they top out at `highly_likely`. `web`'s `confirmed` rests on **one origin read twice, through the same edge**. `email`'s rests on two resolvers that fail together (D36). By independence the TLS evidence may well be stronger, but the state machine ranks it lower. **This is not a TLS issue.** It will recur for any future check with strong independent evidence and no same-origin second response, such as a passive fingerprint corroborated by a different protocol. **Not decided, and not a change to the frozen contract.** Options are an ADR that lets ≥2 independence classes plus a stated independence argument reach `confirmed`, or a rename of what `confirmed` means. Either is a contract migration. Until then, quote `confirmed` as "re-observed", not as "strongest" | `core/state.py`; every scanner's ceiling; how claims are quoted (SPEC A3 "not the same kind of evidence") |
| **D-W1** | Cookie checks and cookie-name fingerprints for `web` | Deferred from Tool 4a. Blocked on D21: they need value-only `Set-Cookie` redaction and multi-value header preservation in `core/evidence.py`, a core change with its own review. Real-world evidence that the gap matters: `testasp`/`testaspnet.vulnweb.com` set session cookies without `Secure`, and Mozilla Observatory docked 40 points for it (2026-10-07), while `web` said nothing | Cookie-flag findings; cookie-name technology fingerprints |
| **D-W2** | A frozen real challenge-page recording for `web` | Real-world evidence is recorded in the 2026-10-07 checkpoint-1 section (`www.ox.ac.uk` Cloudflare challenge; `www.tesla.com`, `www.fda.gov`, `www.usda.gov` Akamai blocks). Not frozen as corpus fixtures because they are third-party pages, and a hand-written lab page would encode our assumptions. Needs a challenge recorded from an operator-controlled CDN. Until then the `waf_block` path is unit-tested only | A corpus-level proof of the `waf_block` path |
| **D-W3** | Re-review `web`'s fingerprint and EOL data every 180 days | Vendor dates and fingerprint strings go stale. CI enforces the cadence through the freshness check in `tests/scanners/web/test_data.py`; the re-review itself is a manual, sourced task | Stale EOL claims |

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

## 2026-09-03 · Tool 3 — DNS & Subdomain Enumeration (`domscout`, Light)

**Plan:** `docs/superpowers/plans/2026-09-03-domscout-dns-enum.md` · **Spec:** `docs/superpowers/specs/2026-09-03-domscout-dns-enum-design.md` · **Gate: precision ≥ 0.95, recall ≥ 0.80, inconclusive ≤ 15%** · **Status: built, gated, and live-verified against operator infrastructure**

```
scanner    checks   TP   FP   FN  precision   recall   susp%  inconc%  gate
domscout       50    1    0    0      1.000    1.000    4.0%     0.0%  PASS
```

**Read the number with its claim count: the gate rests on ONE confirmed claim** (`dnssec-status`, validated by an independent second resolver). That is thinner than TLS's five, and deliberately so — see the recall decision below.

### Built

- **`scanners/domscout/`** — the first scanner that *discovers assets onto the shared graph* (ADR-019) rather than reading a seeded one. Pure parsers first (`ct.py` CT-name normalization + crt.sh parsing; `rdapp.py` RDAP→`RegistrationInfo`; `dnssec.py` delegation-state reasoning; `takeover.py` provider fingerprint adapters), then `checks.py` (6 checks, all Light, all passive) and `scanner.py` (orchestration).
- **Six checks:** `subdomains-ct-log`, `dns-records` (both `info` → informational inventory), `dnssec-status`, `domain-expiring`/`domain-expired`, `subdomain-takeover`.
- **Discovery discipline:** only names under the apex that resolve to an address (A/AAAA), canonicalized, are contributed to `ctx.assets`; a CNAME to a third-party host and an MX target are recorded as `related_assets`, **not** as scannable graph assets — so a later scanner is never handed someone else's host. A CT-log name that does not resolve is an enumeration observation, never a graph asset.
- **`BaseScanner.service_hosts`** (additive, defaulted) — a passive scanner's allowlist of read-only third-party service hosts (`crt.sh`, `rdap.org`), unioned into the HTTP scope by the CLI (`cli/main.py`, `cli/corpus.py`). The HTTP analogue of scoping the DNS resolver, not the names. Confers no authorisation; `core/authz.py` stays the only gate. Empty for email/tls, so they are unchanged. **This touches the scope model — flagged for an ADR (see Deferred).**
- **9-case frozen corpus** recorded by `corpus/generators/domscout.py` (DNS via `RecordingResolver`, HTTP via `RecordingHttpBackend` — crt.sh/RDAP/takeover). Cases: three no-false-discovery (`known-good`, `takeover-negative`, `wildcard-zone`), `enum-basic` (three direct-A subdomains) and `enum-cname` (a resolving CNAME'd subdomain + an internal alias, both contributed), `dnssec-insecure` (the one confirmed claim), `domain-expired` + `takeover-positive` (honest `suspected`), `servfail` (all inconclusive).

### The recall decision — and how it changed under implementation

The spec's headline decision was a **two-number recall** (enumeration corpus-relative + finite true). **Building the corpus proved that wrong, and the operator agreed the honest fix:** subdomain enumeration is **informational inventory, not a vulnerability**, so we do not attach a confidence score to it and do not gate precision/recall on it at all (`core/state.py` maps `severity: info` → `informational`, which `docs/10-measurement.md` excludes entirely). **The gate applies only to the real security findings.** Enumeration is guarded instead by (a) the no-false-discovery corpus cases — we must never invent or wildcard-confirm a subdomain — and (b) the *live* subfinder/crt.sh disagreement analysis (owed), reported as a comparison, never a score. This **supersedes §1 of the design spec**; recorded here rather than by rewriting the spec's history.

Consequence: the two-family measurement machinery added in the plan's Task 1 (`core/measurement.py` per-family precision/recall) is now **unused** — domscout gates as an ordinary scanner. It is guarded and harmless (email/tls/example byte-identical); flagged as a YAGNI-removal candidate for a cleanup pass rather than reverted mid-branch.

### Found & fixed

- **Every domscout finding was landing at `suspected` (single independence class, no validation)** — so the gate had zero reported positives and could not compute precision/recall at all. This is the email lesson recurring ("six checks silently scored zero recall until re-tested through an independent resolver"). Fixed the same way: `dnssec-status` re-queries DS/DNSKEY through an independent second resolver and reaches `confirmed` when they agree. Expiry (single RDAP source) and takeover (never proven by taking it) stay `suspected` honestly.
- **`domain-expiring` would have rotted as a frozen fixture** — the scanner compares expiry against wall-clock `date.today()`, so a fixed near-future date drifts from "expiring" to "expired" as the corpus ages (the exact TLS `observed_at` lesson). The corpus freezes `domain-expired` (a fixed *past* date, stable forever) instead; the expiring path is covered by unit tests, not a frozen case.
- **A plan interface defect:** the plan assumed `Check` carried `prior`/`independence_class`. The real `Check` does not — those are per-`Signal` at emit time (the email pattern). Caught at Task 6; the implementer mirrored the real dataclass, and findings attach priors/classes per `Signal` in the scanner.
- **The stale committed baseline** (pre-D20 tls: `0.0` inconclusive / 134 checks) made `--check-baseline` red on this branch before any Tool 3 work. Refreshed with this tool's baseline update; `--check-baseline` is green again.
- **CNAME'd subdomains were dropped from the discovered inventory — found by the live cross-check, not the corpus.** The first cut contributed only names with a *direct* A/AAAA: an internal alias (`www` → apex) was skipped, and a third-party CNAME (`accounts` → `customer-books.zoho.com`) recorded only its *target* as a related asset, never the source name. Against `codez.in` that lost 8 live owned subdomains (`www`, `accounts`, `assessment`, `bots`, `domains`, `interviews`, `share`, `uptime`). Fixed: any in-apex name that resolves to an address — directly or by following its CNAME, and not a wildcard shadow — is a discovered subdomain and is contributed; the CNAME target stays a related asset (we never scan a third party's host); a dangling CNAME (target NXDOMAIN) still has no address, so it is not contributed and is left to the takeover check. **The frozen corpus could not have caught this** — its cases were built from direct-A subdomains, encoding the same assumption the code had. Eighth-plus instance of the standing rule: the corpus proves regression, a competitor comparison finds the bug. Re-verified live: `codez.in` discovery went 8 → 16, `www`/`accounts` now present (ADR-022 *close* — re-ran the exact scan that exposed it).

### Live verification (ADR-017 / ADR-024)

Run against operator infrastructure, cross-checked against `subfinder` + crt.sh.

- **`codez.in`** — `dnssec-status: confirmed` (unsigned zone) **hand-verified true** with `dig DS`/`dig DNSKEY` (both empty). `domain-expiring` `inconclusive`, attributed at the time to `.in` RDAP being unreachable through the `rdap.org` bootstrap. **Corrected 2026-10-08: that diagnosis was wrong.** `.in` RDAP works and publishes expiry. The check is inconclusive for **every** TLD, because rdap.org's 302 to the registry is never followed. See D28. Discovery (after the CNAME fix): 16 live subdomains, all resolving, including real hosts (`erp`, `banktransfer`, `openproject`, `support`).
- **Disagreement analysis vs `subfinder` 2.16.0** (run in-session; both scanners on `codez.in`, then every subfinder-only name categorised by resolves? × in-crt.sh?): subfinder 60, domscout 16, domscout-only 0. The 44 subfinder-only names, **after** the CNAME fix:
  - **`resolves AND in CT logs` = 0** — the decisive number: domscout misses **no** live subdomain that appears in the CT logs. The CNAME fix closed the real bug completely.
  - **`resolves but NOT in CT logs` = 8** (`mail`, `ns1a`–`ns1d`, `ns2018a/b`, `bkp2017`) — nameservers, mail, a backup host: live, but no TLS cert, so invisible to a CT-only seed. This *is* D-DS1, quantified.
  - **`does not resolve` = 36** (`blog`, `store`, `vps`, `cpanel.*`, `webmail.*`, many `www.*` variants) — dead/historical names subfinder carries from CT history; domscout **correctly** excludes them from a live-asset inventory.
  - The honest read: domscout reports 16 subdomains, **all live**; subfinder reports 60, of which **36 are dead**. It trades breadth for precision — the right trade for a scan-target list — and its only real recall gap is the 8 non-CT live hosts. A competitor-unique *resolving* name is a false negative to chase; a non-resolving one is not.
- **Corroborated by a second, independent tool combo** (operator-run `sublist3r` + `dnsx` for resolution + `httpx` for liveness, 22 resolving subdomains): of the **9** resolving names it found that domscout missed, **0 are in domscout's crt.sh seed** — every miss is the D-DS1 coverage gap, confirming there is no resolution bug. domscout also found **3** the combo missed (`banktransfer`, `monitoringbackup`, `vps2018`), so it is not a strict subset. The gap includes live, important hosts — `mail`/`webmail`/`docs` (Google Workspace), `ftp`, the nameservers — several of which `subfinder` also missed but `sublist3r`'s brute-force found. This sharpens D-DS1: single-source crt.sh is a real recall ceiling on assets a user cares about, so adding a passive-DNS source (and a common-name wordlist in Standard) should be prioritised, not merely noted.

### Decided

- **Subdomain existence is `informational`, not a confidence-scored claim.** Inventory is not a vulnerability; we score confidence and recall only where there is an actual security flaw. (Operator's call, 2026-09-03.)
- **Takeover caps at `suspected`** and is detected passively — a dangling CNAME plus a recognised fingerprint, at most one ordinary HTTPS GET, never registering or claiming the resource (ADR-004).
- **A passive scanner may declare `service_hosts`** — a fixed, audited allowlist of read-only public service endpoints — the HTTP counterpart of the DNS resolver being scoped rather than the names.

### Deferred

- **D-DS1 — single-source enumeration coverage.** Discovery seeds from **crt.sh only**. A subdomain with no certificate in the CT logs (and not the apex) is never seen, so recall is materially below a multi-source tool like `subfinder` (which layers CT from several providers, passive DNS and APIs). This is a *coverage* limitation, not an incorrectness — everything we report is real. **The path to close it:** add more passive sources under the same passivity/replay rules — certspotter's free CT API first, then a passive-DNS source — deduplicating aggressively, exactly as the research says the best tools do. Stated plainly wherever coverage is cited (SPEC A4); not a gate blocker, but the honest ceiling on Light-mode recall today.
- **D-DS2 — `kinetrix.in` / `kinetrix.co.in` not yet live-run.** `codez.in` was verified end-to-end; the two kinetrix domains (and a DNSSEC-*signed* reference for the positive DNSSEC path) are still owed for full ADR-017 coverage.
- **An ADR for `service_hosts`** — it extends the scope model (additively, passive-only), so it should be recorded as a decision with `docs/08-changelog.md`, not left only in code. Owed.
- **Remove the unused two-family measurement machinery** (plan Task 1) — YAGNI, guarded/harmless today.
- **Session-limit note:** the shared-account limit killed the Task 7 implementer subagent mid-run; the scanner and Tasks 8/10 plus the CNAME fix were completed and reviewed **inline** by the coordinator rather than via the usual fresh-subagent review loop. Task 7's independent whole-branch review is therefore still owed — flagged for the final review.

---

## 2026-10-07 · Tool 4a (`web`, Light) — checkpoint 1: fingerprint and EOL sources verified

**In progress — the full Tool 4a entry follows when the tool ships.** Every source in `scanners/web/data/` was fetched and checked against the vendor's own page on 2026-10-07, before the data was trusted.

- **Source tiers, enforced by test.** Every fingerprint and EOL entry now names a tier: `vendor` (a primary vendor page, URL required) or `observed` (our own live capture: host, UTC date and the exact header or markup string seen, all required). `tests/scanners/web/test_data.py` rejects an entry without one. EOL dates must be `vendor` tier.
- **Confirmed against vendor pages:** 8 PHP, 3 Drupal and 2 Bootstrap end-of-life dates; 8 fingerprints (nginx, Apache, PHP, jQuery, AngularJS, Bootstrap, Fastly, Vercel).
- **Corrected:** the three IIS end-of-life dates were each a day early (7.5 → 2020-01-15; 8.0 and 8.5 → 2023-10-11) and were sourced from the Windows Server pages, which never mention IIS; they now come from Microsoft's IIS lifecycle page. IIS 8.5 deliberately uses the Windows Server 2012 R2 date, not the earlier Windows 8.1 one — the reason is recorded in the data file.
- **Observed, not documented:** IIS, ASP.NET, Next.js, WordPress, Drupal, Joomla, Cloudflare, CloudFront and Akamai, each with host, date and the exact string seen. Cloudflare and CloudFront were first marked confirmed and then reclassified: their docs describe `Cf-Ray` / `X-Amz-Cf-Id` as headers added to requests forwarded to the origin, not response headers.
- **Gap — AngularJS 1.x end-of-life row dropped.** docs.angularjs.org states only "AngularJS support has officially ended as of January 2022": a month, no day. No day was substituted. The AngularJS fingerprint stays; a detected AngularJS 1.x is reported as inventory, not as end-of-life, until a vendor page gives a date.
- **Gap — Express fingerprint dropped.** The Express docs confirm `X-Powered-By` is sent by default but never show its value, expressjs.com strips it, and no live example turned up in a sweep of ~120 hosts on 2026-10-07. Nothing depended on it.
- **Evidence for D-W2 (challenge-page signatures, registered with the full Tool 4a entry):** `www.ox.ac.uk`, 2026-10-07 — HTTP 403, `cf-mitigated: challenge`, `server: cloudflare`, `<title>Just a moment...` — `scanners/web/challenge.detect` returned "Cloudflare challenge". `www.tesla.com`, `www.fda.gov`, `www.usda.gov`, 2026-10-07 — HTTP 403, `Server: AkamaiGHost`, `<TITLE>Access Denied` — the exact shape of the Akamai edge-block signature. Real-world evidence for both signatures; not yet frozen as corpus fixtures (third-party pages).

## 2026-10-07 · Tool 4a — Website Scanner, Light (`web` v1.0.1)

Plan: [superpowers/plans/2026-10-06-web-light.md](superpowers/plans/2026-10-06-web-light.md). Spec: [superpowers/specs/2026-10-02-web-light-design.md](superpowers/specs/2026-10-02-web-light-design.md). Sources checked before the data was trusted: the checkpoint-1 section above.

**Gate (`make corpus`, 2026-10-07):** `web 234 checks, TP 10, FP 0, FN 0, precision 1.000, recall 1.000, susp 3.4%, inconc 0.9%, PASS` — **10 claims** over 11 frozen lab cases. Recall is **corpus-relative** (a corpus we wrote; never an absolute number). 1.000 over ten claims is a regression result, not proof of correctness; the evidence for correctness is the live verification below. Full suite: 1096 tests pass (1118 at v1.0.3). Numbers in their canonical home: [SPEC.md A1](../SPEC.md).

### Built

- `scanners/web/`: `fetch` (bounded fetch plan), `headers`, `csp`, `html`, `disclosure` (version strings, error/debug signatures, secret kinds), `listing`, `challenge`, `fingerprint` and `eol` (tiered data, each entry names its source), `scanner`.
- 21 checks, all passive.
- A bounded fetch plan with a deterministic 404 control: the probe path is derived from the target, so a replayed run asks for exactly the URL it recorded.
- 404-control validation: a header or error claim is `confirmed` only against a readable, distinct, same-origin, same-scheme control response.
- A corpus lab (nginx 1.27.5, Django 5.2.18, a stdlib traceback server; images pinned by digest) and 11 frozen cases. How to run it: [13-test-targets.md](13-test-targets.md).

### Found & fixed (by review, before any live run)

Each of these was a false-claim or secret-leak path **in the plan's own code**, caught by task review. The corpus caught none of them — the same pattern as the standing observation "[the corpus has never found a bug](#the-corpus-has-never-found-a-bug)".

- **Task 2:** the HTML extractor raised on unparseable URLs. The spec requires it never to raise; it now skips the attribute and treats an unparseable URL as never same-origin.
- **Task 4:** a CSP using `'strict-dynamic'` (the recommended nonce policy) was graded weak, because host and scheme sources are ignored by CSP3 browsers under `'strict-dynamic'`. They no longer count when it is present.
- **Task 6:** a directory listing was detected from a `<title>` alone, and absolute parent links (`/a/` under `/a/b/`) became phantom entries (nginx, Apache, IIS). Detection now needs a second server-generated marker and drops parent links.
- **Task 10 (four fix rounds):** `confirmed` claims resting on an unusable control — a 5xx probe, a challenged/429/5xx/downgraded HTTPS control, a probe redirected back to the root, a different origin, and a raw-string URL compare that a bare origin, fragment, query or index file defeated. Fixed once, centrally: **a control must be a readable, distinct, same-origin, same-scheme response**, compared on normalised URLs.
- **Task 11 (three rounds):** **CRITICAL** — secrets copied into stored descriptions (core redacts captures, never a scanner's own strings), then secrets in header values, in URL paths and in header names. Every description, header name and value, request URL and location is now redacted before storage. The root cause is in core: see D21. Also fixed: a 5xx on robots/directories/security.txt treated as a definite absence (only 404 is), error claims emitted without a usable control, and an SRI false positive on explicit default ports (`:443`).

### Found & fixed (by the live run)

- A failed request said "could not be fetched (blocked_prerequisite)" with no cause. Version 1.0.1 names it: `TLS certificate verification failed (…)`, `TLS handshake failed (…)`, `connection timed out`, `DNS lookup failed`. Re-verified live against expired and self-signed badssl hosts and httpforever.com.

### Found & fixed (final review and hard-constraint-5 leak fixes, v1.0.2–v1.0.3)

- **v1.0.2 (14c4d9f):** private-key bodies were stored in evidence, because core's `private_key` pattern redacts only the BEGIN line (D21). `web` now cuts whole PEM private-key blocks itself. A 3xx root produced page-content claims about a redirect body; page checks are now `inconclusive` on a redirected root.
- **v1.0.3 (e0b92e9, b43c638):** two leaks the operator ruled must close before merge.
  - **Replay leaked key bodies.** A recorded fixture already carries core's `[redacted]:private_key` in place of the BEGIN line, so the BEGIN-anchored strip missed the body on `--replay` and corpus runs. The strip now also anchors on the marker. It also removes runs of 2+ bare 60–76-column base64 lines, for a key whose BEGIN and END both fell in core's truncation gap.
  - **The robots description was capped before it was redacted,** so a secret straddling the cut escaped the pattern. It is now redacted first and then capped. Every other truncation site in `scanners/web/` was audited for the same order.
  - Both are tested record-then-replay. No corpus number moved.
  - **Still open in core (D21):** `RecordingHttpBackend` fixtures on disk still hold key bodies.

### Live verification and competitor parity (ADR-017, ADR-024)

13 hosts, hand-verified claim by claim, **zero false positives**: [verification.md](../corpus/crosscheck/web-light/verification.md). The vulnweb hosts fired IIS 8.5 and PHP 7.1 end-of-life correctly, and ASP.NET 2.0.50727 and Apache 2.4 were correctly left alone. Disagreements with Mozilla Observatory, analysed one by one: [crosscheck.md](../corpus/crosscheck/web-light/crosscheck.md). Honest gaps: `testphp.vulnweb.com` was down on both attempts, so the PHP 5.x fingerprints and EOL entries were never exercised live; `securityheaders.com` refused automation (403), so that comparison was not made. **The raw live traffic is not committed** (operator, 2026-10-08). It was scanned for every secret pattern, and cookie values were redacted. The rest is gitignored and kept locally. `corpus/crosscheck/web-light/raw-manifest.sha256` commits the SHA-256 of each file, so the evidence can be proven unchanged.

### Decided

- **Validation on the 404 control states its limit** in the finding description: it is one origin-wide edge answering twice, not two independent observers.
- **A declined off-scope 3xx probe still counts as a control** — a readable, distinct, same-origin response. Weaker evidence, and the whole-branch review is to weigh it. **The final review upheld it for the probe** (the root's own deficiency is the observed fact; the probe only rules out a per-route quirk) and fixed the root-side case. **Candidate for revisit (operator, 2026-10-07):** this is the only ruling whose stated cost is a potentially weaker claim — a `confirmed` header finding validated on a redirect response rather than a page — so it is kept visible here rather than treated as settled. Revisit with real-world data: how often a live scan's 404 probe ends on an off-scope 3xx, and whether those validated claims hold up.
- **The request cap counts scanner-issued GETs.** Redirect hops are additional: see **D26 (required before beta)**.
- **HTTPS transport-failure reason:** the more specific code (`timeout` for a timeout, `blocked_prerequisite` otherwise). The design spec's §3.1 and §5.5 disagreed about this; both now say it ([spec](superpowers/specs/2026-10-02-web-light-design.md)).
- **An inconclusive finding pairs the failed request with itself** as its evidence pair — nothing was received to contrast it with — and the delta says so.
- **Mixed content is gated** on a usable, non-downgraded HTTPS page.
- **Lab images pinned to digests** (the licence sign-off names a digest, and fixtures were recorded against those builds).
- **Permissions-Policy is declined**, with the reason, in the design spec §3.2.

### Spec deviations

1. Transport-failure cases (timeout, HTTPS unavailable) are unit tests, not frozen cases: a failed request writes no fixture, and replaying an unrecorded URL raises `MissingFixtureError`, which `web` deliberately re-raises. domscout's `servfail` case depends on its scanner swallowing that error — see [the standing observation](#a-broad-except-can-turn-a-corpus-gap-into-an-inconclusive-2026-10-06); `web` does not do that.
2. The challenge-page case is unit-tested only (D-W2): a hand-written page in the lab would encode our assumptions.
3. `web-debug-mode` covers Django's `DEBUG=True` technical 404, not the Werkzeug debugger, which renders only on an unhandled exception that a Light 404 probe never provokes.
4. The error-page lab positive is a real Python traceback from a stdlib server, not PHP — the PHP licence is not on the approved list.

### Deferred

- **D-W1, D-W2, D-W3** — cookie checks and cookie-name fingerprints; a frozen real challenge-page recording; the 180-day fingerprint/EOL re-review. All three are registered in [the deferred register](#d-deferred-register).
- The rest are in the register: D21 (core redaction, scheduled follow-up), D22 (floating dvwa/vampi tags), D23 (no working HTTPS is never stated, high priority), D24 (redirect-hop headers invisible), D25 (cost meter ignores failed attempts), D26 (request cap vs redirects, required before beta).
- Minor review findings, deferred without a register row: the CSP `script-src-elem`/`-attr` directives are not considered; `xcto_ok("nosniff, sniff")` is false though the fetch honours the first value (a possible false positive on `web-xcto-missing`); robots/security.txt are still fetched when the root is dead or challenged (politeness); an excerpt is not hard-capped in length. **Minor, for Tool 4b or the D21 change (operator, 2026-10-08):** when a private key with no END line swallows a traceback excerpt, the error-disclosure description shows an empty excerpt (`""`). It should say the evidence was withheld for redaction. The finding still fires, and no corpus number depends on it.

---

## 2026-10-08 · Corpus-fidelity audit — which fixtures reproduce a real service, and which we wrote

**Why.** D28 showed a corpus validating a scanner against fiction, with the gate passing. Before any scanner's numbers are quoted, every generator in `corpus/generators/` was read, and each external service it stands in for was checked against what the real service does. Findings were reported first; nothing in a scanner or a fixture was changed.

| Generator | Service stood in for | What the fixture is | Verdict |
|---|---|---|---|
| `testssl.py` | badssl.com + testssl.sh | Real recordings. It refused to fake a FREAK positive | **Real** |
| `tls.py` / `tls_lab.py` | TLS servers | Real OpenSSL handshakes against lab certificates we minted | Real software. Gaps: unreachable means refused only (D32); one TLS stack (D33) |
| `web.py` | Web servers | Real nginx, Django and Python servers we configured | **Real.** No third-party service is faked. The `eol` case's `X-Powered-By: PHP/7.4.33` comes from nginx, and its Drupal tag is hand-written, but the fingerprint patterns come from real observed sites |
| `domscout.py` | rdap.org | Hand-written: `200` with the record | **Fiction.** The real service answers `302` to the registry (D28) |
| | S3, Heroku | Hand-written: abandoned target → `NXDOMAIN` | **Fiction.** The real services resolve every name (D31) |
| | crt.sh | Hand-written: `name_value` only, one name per entry | **Unverified.** crt.sh was down all session (D34) |
| | every HTTP response | Hand-written with `headers: {}` | **Structural.** A fake with no headers can never contain a redirect, and that is what hid D28 |
| | GitHub Pages | Hand-written live-blog body | Fine. The real signal (resolves plus a `404` body) matches the fingerprint |
| `email.py`, `domscout.py` | DNS resolvers | Hand-written zones; record formats match dnspython's | Mostly faithful. The second resolver can never disagree, so validation passes by construction (D35). Long TXT records are never split (D35) |
| `corpus/fixtures/example/` | DNS | Hand-written | Reference scanner only; no product claim |

**Conclusion.** Of four scanners, only `web` came out clean, and it is the only one built from real recorded traffic plus live hand-verified hosts and an external cross-check. That method is now binding: [ADR-027](02-decisions.md#adr-027--a-fixture-may-stand-in-for-a-real-service-only-on-recorded-evidence).

**What may be quoted, pending D35 and the domscout fixes:**
- `web`: 1.000 over 10 claims, with its 13 live hosts.
- `tls`: 1.000 over 5 claims, cross-checked against testssl.sh.
- `email`: nothing until D35 closes.
- `domscout`: nothing.

**Deferred.** D31–D35 in the register. The ADR-027 header contract test lands with the domscout re-record.

---

## 2026-10-08 · Email v1.1.0 — three claim defects fixed before the live re-verification

**Why.** The operator ruled that the three wording defects found while screening (D35) be fixed before the live run, so that hand-verification is done once, against a tool that does not already misstate things. Test-first: 23 new tests, 22 of which failed before the fix (the `+all` wording was already right). Rule applied throughout: **never assert what other people's software does unless a spec says it.** The RFC text was read from rfc-editor.org (RFC 7208, 7489, 6376, 8301), not recalled.

| Check | Was | Now | Spec basis |
|---|---|---|---|
| `spf-too-permissive` (`?all`) | "tells receivers that mail from any server is acceptable"; title "permits any sender" | Says what Neutral is: an explicit non-assertion, which receivers MUST treat exactly like no SPF policy. Its own title. **Severity unchanged (high)** until the operator rules on the DMARC-dependent mapping | RFC 7208 §2.6.2, §8.2 |
| `dkim-weak-key` | Medium; judged only the **first** selector found; an Ed25519 key (256 bits) would have been called weak | **Low** at 1024–2047 bits ("meets the RFC 8301 minimum of 1024 bits, below the recommended 2048"); medium below 1024. Every common selector read; the weakest is reported. Where stronger keys coexist, it names them and says we cannot tell which one signs. Ed25519 and revoked keys are not judged by size | RFC 8301 §3.1–3.2; RFC 6376 §6.1.2 (the signature's `s=` names the key) |
| `dmarc-invalid` | "Receivers ignore a record like this entirely" for every error | Classified by what RFC 7489 says. **No usable policy:** no DMARC processing, or treat as `p=none` when a valid `rua` exists (§6.6.3 step 6), still `confirmed`. **Malformed optional tag:** RFC says discard the tag and keep the record (§6.3), `suspected`. **Duplicate tag or misplaced `p=`:** forbidden, but the RFC does not define receiver handling, so the finding says implementations vary, `suspected` | RFC 7489 §6.3, §6.6.3; RFC 6376 §3.2 (duplicate tags, adopted by 7489 §6.3) |

**The duplicate-tag question was settled from the RFC text, not researched further.** RFC 7489 adopts DKIM's tag-value syntax, under which a duplicated tag makes the tag-list invalid, but it defines no receiver behaviour for that case. That one sentence decides the wording, so the check stays in the live run.

**Gate effect.** `make corpus`: email 1.000 / 1.000, now **20 claims** (was 21). The `dmarc-malformed` case puts `p=` after `rua=`, so it is now `suspected`, which the gate excludes on both sides. Fixtures were re-recorded by the generator because the scanner now queries every selector. 1173 tests pass. The number stays unquotable until D35 closes.

**Second pass, same day (operator-approved), before the run:**
- **`spf-too-permissive` severity mapping for `?all`.** Low when DMARC is `p=reject` or `p=quarantine` at 100%. Medium for `p=none`, a partial `pct`, a record treated as `p=none`, an unusable or undefined record, no record, or a failed lookup. `+all` stays high in every posture.
  - **`~all` and `-all` do not fire, by decision**, and the code and the catalogue now say so.
  - Under `p=quarantine` the text says forged mail is still delivered, to a spam folder (RFC 7489 §6.3).
- **The double count is named, not suppressed.** When DMARC is not enforced, `spf-too-permissive` and the DMARC finding (`dmarc-policy-none`, `-pct-partial`, `-missing` or `-invalid`) now name each other and say "count the two as one". `core/correlation.py` only *adds* derived story findings and has no suppression, so it cannot do this. Suppression would be a core change, and is proposed to the operator instead.
- **`spoofing-possible`, as proposed.**
  - `?all` is no longer a reason.
  - `+all` is, worded as an explicit pass that DMARC counts as authentication.
  - Invalid DMARC counts only where RFC 7489 says the record is not applied. Treat-as-`p=none` gives the `p=none` reason, and a malformed optional tag is simulated with its default.
  - A duplicate or misplaced tag as the only reason holds the finding at `suspected`.
  - Both checks now read one shared helper, `_dmarc_posture`.
- **`dmarc-invalid` treat-as-`p=none`** is now medium, and its text says an operator with this record believes the domain is protected, and it is not.
- **Gate:** 1199 tests pass. `make corpus`: email 1.000 / 1.000 over **19 claims**, down from 20. `dmarc-malformed`'s `spoofing-possible` rests only on an undefined-handling error, so it is now `suspected`.

**Blast radius of "`?all` accepts any sending server" (operator asked, 2026-10-08).**
- **Origin.** It came from a document, not code. The v2 catalogue (`docs/reference/product-spec.md:321`) says "SPF too-permissive check (`+all` or `?all` is dangerous)". The phase plan copied it (`docs/05-phase-1-first-tools.md:44`). The scanner then implemented it **twice by copy**, in `_check_spf_standard` and `_spoofing_reasons`, each with its own condition and its own sentence. There was no shared helper. Both now read `_dmarc_posture`, and only `+all` is treated as a pass.
- **The sibling premise had the same shape.** "Receivers ignore a malformed DMARC record" lived in four copied places: the `dmarc.py` docstring, two parser error strings, the `dmarc-invalid` text, and the spoofing reason. All four are fixed.
- **Other consumers of the wider premise, "a weak SPF lets forged mail through whatever DMARC says". Found, not fixed:**

| # | Where | What is wrong | Spec |
|---|---|---|---|
| 1 | `spoofing-possible` | "No SPF record" is a standalone reason, so it fires on a domain with no SPF and `p=reject`. With no SPF, the result is None and the mail fails DMARC alignment, so `p=reject` applies | RFC 7208 §2.6.1; RFC 7489 §3.1.2, §6.6.2 |
| 2 | `spf-missing` impact | "a message forged from any server passes SPF by default". It does not: no record gives the result None, not Pass | RFC 7208 §2.6.1 |
| 3 | `spf-too-permissive` | A record with no `all` and no `redirect=` defaults to Neutral, "just as if `?all` were specified", but the check keys on syntax and never fires on it | RFC 7208 §4.7 |
| 4 | `spf-too-permissive`, `spoofing-possible` | `all_qualifier` reads only the root record. A `redirect=` to a record ending in `+all` or `?all` is never evaluated | RFC 7208 §6.1 |
| 5 | `spoofing-possible`, `mx-missing` | "Quarantine is enforcement": `spoofing-possible` clears under `p=quarantine`, but quarantined mail is still delivered to a spam folder. The clear prints no text, but its implicit claim is "not spoofable" | RFC 7489 §6.3 |

**The pattern behind today's three propagations.** Each was **a sentence copied rather than a function shared**: D28's fabricated RDAP behaviour, the receiver-ignores premise, and this one. A claim about how other people's software behaves should live in exactly one place, with its RFC citation, so that one fix reaches every consumer. `_dmarc_posture` is the first such place.

## Next

**Watch (no action now):** `tls` runs at **12.3% inconclusive** on its corpus — inside the 15% gate but the closest of any scanner to it (see the `make corpus` table in SPEC.md). A small rise would fail the gate; look at it before the next TLS change.

**After Tool 4a (2026-10-07):**

1. **Operator decision pending** on the raw live-run traffic in `corpus/crosscheck/web-light/raw/` and `collected.md` (audited, not committed).
2. **Scheduled follow-up D21:** fix `core.evidence.redact_headers` on its own branch with its own ADR, **before Tool 4b starts**, then remove `web`'s scanner-side redaction workaround.
3. **Tool 4b — AI/agent exposure.** Its spec starts with the passivity ADR. D23 ("no working HTTPS") is high priority on the 4b/4c list.
4. Then `scan all`, which closes Phase 1.

*(Historical note — the pre-Tool-4a "Next", kept as history:)* **Finish Tool 3's owed items, then the PR:** the `service_hosts` ADR + changelog entry, the `kinetrix.in`/`kinetrix.co.in` live runs (D-DS2), removing the unused two-family measurement machinery, and the whole-branch review (Task 7 got inline review only). D-DS1 (single-source coverage, add certspotter/passive-DNS) is a genuine follow-up, not a blocker. Then the next tool per the roadmap.

*(Historical note — the pre-Tool-3 "Next", now superseded:)* **Tool 3 (DNS & Subdomain Enumeration)**, whose recall definition is the thing to settle before writing any of it — "all subdomains that exist" is not a knowable set, and reporting corpus-relative recall as though it were absolute is the specific dishonesty this product exists to avoid. Phase 0b is complete: the recording layer, the asset graph, passivity declarations, the calendar, the finding store plus `scan verify`, and now the correlation pass are all in place for Tool 3 to build on — in particular, Tool 3 is the first scanner positioned to actually *discover* assets onto the graph rather than only read one seeded for it, and the first real chance to prove the correlation pass's cross-scanner rule on genuine (not relabelled) shared assets.

HTTP record/replay (0b.3, 0b.4) landed, which unblocks D10 (HSTS) and Tool 4 in its entirety whenever those are picked up.
