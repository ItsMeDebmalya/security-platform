# 10 — Measurement Specification

*How precision, recall and the accuracy gates are actually computed. Written because the plan set numeric gates on output that is confidence-scored and five-stated, where plain binary precision/recall does not apply.*

---

## The problem

Every phase's exit criterion is "passes its accuracy gate," expressed as precision and recall. But a scanner emits five states and a continuous confidence, not a binary verdict. Without a rule, three things are undefined:

- Does an `inconclusive` finding count as a miss, a false positive, or neither?
- Is a `suspected` finding at 0.6 that turns out true a success or a failure?
- Is the confidence *number* itself under test, or only presence/absence?

Answer these once, centrally, or every scanner author invents their own and the numbers stop being comparable — which defeats the point of having gates.

---

## Definitions

**Reported positive** = a finding in state `confirmed` or `highly_likely`.
These are the claims we are making to the user. They alone count in the gate.

| Output | Counts as |
|---|---|
| `confirmed` / `highly_likely`, in expected set | **True positive** |
| `confirmed` / `highly_likely`, not in expected set | **False positive** |
| In expected set, nothing reported at all | **False negative** |
| `suspected` | Excluded from the gate. Tracked separately as *suspected rate*. |
| `informational` | Excluded entirely. Not a vulnerability claim. |
| `inconclusive` | Excluded from numerator and denominator. Tracked as *inconclusive rate*. |
| A check whose outcome is `not_applicable` (ADR-032) | Excluded from everything: never a TP, FP or FN, and **outside the inconclusive rate's denominator**, because it judged nothing. Counted on its own and **always shown**, in the `not-app` column of `make corpus` and in `scan run`'s summary. Never a pass: it cannot close a finding. |

```
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
```

**`suspected` is excluded because it is an honest hedge, not a claim.** Counting it as a positive would punish the calibrated behaviour we want; counting it as a miss would push authors to over-claim. Its rate is tracked so we can see a scanner hiding behind it.

---

## The inconclusive-rate guard

Excluding `inconclusive` creates an obvious exploit: a scanner returning `inconclusive` for everything scores perfect precision on the one thing it reports. So the gate has a second half.

**Every accuracy gate is a pair.** A scanner passes only if:

```
precision ≥ target   AND   recall ≥ target   AND   inconclusive_rate ≤ 0.15
```

where `inconclusive_rate = inconclusive / (all checks that ran)`, measured on the known-good and known-vulnerable corpus tiers where a definite answer is expected.

A rising inconclusive rate on frozen fixtures is a regression and fails CI, exactly like falling precision. On *live* targets a high rate may be legitimate (WAFs, blocks) — which is why the gate is measured on the frozen tier.

**`not_applicable` is not a way around this guard (ADR-032).** It is for a target the check cannot be asked about at all, such as registration expiry for a special-use name, which has no registry. Its reasons are a fixed list: registered in `core/applicability.py`, enumerated by the schema, and declared per check in the scanner's `CHECKS` table. A contract test (`tests/contract/test_not_applicable_contract.py`) fails if any corpus run uses a reason its check did not declare. A hard case is `inconclusive`, never `not_applicable`.

---

## What a gate number actually rests on

A row in the table above compresses three things that should be read separately. Both shipped scanners look identical at `precision 1.000` and rest on very different amounts of evidence.

**Precision is computed over claims, not over checks.** Only `confirmed` and `highly_likely` count. A scanner running 220 checks and making 5 claims has a precision denominator of 5. TLS is exactly that: most of its findings rest on a single `independence_class` and land as `suspected`, which is honest and which the gate excuses from both sides. **`1.000` over five claims and `1.000` over five hundred are the same number and not the same evidence.** Read the `susp%` column beside it, and state the claim count when publishing.

**A corpus authored alongside the scanner measures internal consistency.** Email's 1.000 is against 16 synthetic zones we wrote. That proves the checks do what was intended; it cannot prove the intent matches the world, because the same person decided both. See [ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done) — six real defects survived corpora at 1.000, and live runs found all six.

**A tier label is not a difficulty rating.** A case is only as hard as the fixture makes it. Three faults in the TLS lab (a CA without `basicConstraints`, servers accepting TLS 1.0, a two-level chain standing in for an incomplete one) each made every case *easier* than intended while the gate stayed green. **Ground truth that is wrong produces a passing gate and a scanner nobody should trust**, and nothing in the harness can detect it — only reading the fixtures can.

**Detected and derived claims are counted separately.** A `derived` finding ([ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived)) is arithmetic applied to an observation — a deadline, a threshold. Its correctness partly measures a rule *we wrote*, not the world, so precision `1.000` across derived claims is a weaker statement than the same figure across detected ones. Report the split; never merge them into one number.

**When publishing a number, publish what it rests on:** the claim count, the detected/derived split, whether the corpus is synthetic or captured, and whether it has been checked against live targets.

---

## Recall is not always definable — say so per scanner

Recall requires knowing the complete true set. That is knowable for some scanners and not others.

| Scanner | Is recall well-defined? | What we measure instead |
|---|---|---|
| Email security | **Yes.** RFC-defined, finite check set per domain. | True recall. |
| TLS | **Yes.** Finite protocol/cipher/cert surface. | True recall. |
| DNS/subdomain enum | **No.** "All subdomains" is unknowable. | Recall against the corpus's *known* set only. Never a claim about completeness. |
| Web (Light) | **No.** "All header misconfigurations on a site you don't fully understand" has no ground truth. | Recall against the corpus's known set only. Same caveat as enumeration. |
| Web (Standard) | **Partially.** Defined on benchmark corpora with planted vulnerabilities; undefined on live sites. | True recall on benchmarks; corpus-relative elsewhere. |

**Any published recall number must state which of these it is.** Reporting corpus-relative recall as if it were absolute is the kind of dishonesty the product exists to avoid.

---

## The corpus tiers

| Tier | Purpose | Contents |
|---|---|---|
| **Benchmark** | Statistically meaningful precision/recall | OWASP Benchmark, WAVSEP |
| **Vulnerable** | Realistic end-to-end behaviour | OWASP Juice Shop, DVWA, VAmPI, badssl.com, own fixtures |
| **Known-good** | False-positive measurement | Correctly configured assets we control. **Anything reported here is a false positive.** |
| **Frozen** | Determinism | Recorded traffic replayed offline. All CI gating runs here. |

**Benchmark tier is mandatory for the Website Scanner, and it was missing from the original plan.** Juice Shop and DVWA carry tens of planted vulnerabilities; finding 8 of 10 is not a meaningful recall figure and has no negative-case population to compute precision against. WAVSEP alone provides 816 path-traversal, 108 RFI, 66 reflected XSS, 80 error-based and 46 blind SQLi cases with known ground truth *including negatives*. OWASP Benchmark is purpose-built for scoring scanners. Both are free and permissively licensed.

Known caveat: both benchmarks are synthetic and a scanner can overfit to them. They establish a floor, not real-world performance. That is why the vulnerable and known-good tiers stay in the mix.

---

## Confidence calibration metrics

Separate from precision/recall, reported per **(scanner × detection_method)** bucket — never per `check_id`, which will be undersampled forever at our volume.

- **Reliability diagram** — predicted confidence vs observed frequency, decile buckets.
- **Brier score** — mean squared error of predictions. Lower is better; report against a baseline of always predicting the base rate.
- **Expected Calibration Error** — weighted mean gap between predicted and observed.

A bucket needs **≥ 30 labelled outcomes** before a fitted calibration replaces its prior. Below that the prior stands and `confidence_provisional` remains `true`. Platt-style scaling only in the small-sample regime; isotonic regression needs several hundred samples and must not be used below that.

---

## What `make corpus` prints

```
scanner  tier    checks  TP  FP  FN  precision  recall  suspected%  inconclusive%  not-app  gate
email    frozen     412  38   0   1     1.000    0.974        4.1%           2.2%        0  PASS
tls      frozen     280  61   1   3     0.984    0.953        6.4%           5.0%        0  PASS
web      bench     1104 402  71  96     0.850    0.807        11.2%          9.8%        0  FAIL (precision)
```

(Illustrative numbers. `checks` excludes `not_applicable` runs; `not-app` counts them.)

Written to `corpus/results/latest.json`. CI compares against the committed baseline and fails on:

- any drop in precision,
- any rise in inconclusive rate on the frozen tier,
- any new false positive on the known-good tier — **this one fails on a single occurrence**, no threshold.

Recall drops warn rather than fail: a recall regression is usually a deliberate precision trade, and forcing it to fail would push authors to over-report.

---

## Adding a detection

Not shippable without all four:

1. A positive corpus case (the check fires when it should).
2. A negative corpus case (it stays silent when it should).
3. A stated `independence_class` for its detection method.
4. A hand-assigned prior with a one-line justification, recorded in the check's definition.
