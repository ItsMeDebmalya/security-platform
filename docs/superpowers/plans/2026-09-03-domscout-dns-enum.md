# DomScout (Tool 3, DNS & Subdomain Enumeration, Light) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `scanners/domscout/` — a passive Light-mode DNS & subdomain enumeration scanner that discovers assets onto the shared graph, with an honest two-number recall model.

**Architecture:** Follows the frozen Scanner Contract and the email/TLS scanner shape exactly: pure parser modules (`ct`, `rdapp`, `dnssec`, `takeover`) tested in isolation, a `checks.py` catalogue with per-check `passive`/`independence_class`/priors, and a `scanner.py` orchestrator that gathers observations then judges them. One core change: per-recall-family precision/recall in `core/measurement.py`. One additive contract extension: `BaseScanner.service_hosts` so a passive scanner can read fixed third-party service endpoints (crt.sh, RDAP) the way DNS scopes its resolver.

**Tech Stack:** Python 3.13.15, uv, ruff, mypy --strict, pytest. dnspython (via `core/dns.py`), `core/http.py`, `core/replay.py`, pydantic models in `core/models.py`.

**Spec:** `docs/superpowers/specs/2026-09-03-domscout-dns-enum-design.md` (read it alongside this plan — every task argues from it).

## Global Constraints

- **Python 3.13.15**, pinned in `.python-version`; deps via `uv`. Run tools with `uv run`.
- **Scanners never construct their own HTTP/DNS/TLS clients** — everything ambient comes from `ScanContext`. Never `import httpx`, `import dns`, `import socket`, `import requests` in `scanners/`.
- **Scanners never import another scanner.** Shared logic goes in `core/`.
- **`state` is derived by `core/state.py`, never hand-set.** Build findings only via `Finding.create(...)` — passing `state`/`id` raises.
- **Every finding needs a control-vs-test evidence pair**, or a non-empty `control_rationale`. "The server errored" is not evidence.
- **`inconclusive` is correct, never a guess or a silent drop.** SERVFAIL/timeout/429/5xx/missing-prerequisite → a finding with `no_verdict_reason` set. `DnsResponse.is_definite()` distinguishes "no record" from "could not find out".
- **Provenance is mandatory on every discovered asset** — `DiscoveredAsset(discovered_by=..., evidence=..., check_id=...)`, no defaults.
- **Discovery confers no authorisation.** Never treat the asset graph as scope. `core/authz.py` stays the only gate.
- **No exploitation** (ADR-004): never register/claim a dangling resource; takeover caps at `suspected`.
- **Passive = ordinary negotiation** (ADR-023): every domscout check declares `passive=True`; the scanner needs no authorisation in any mode.
- **A new detection needs a positive AND a negative corpus case, an `independence_class`, and a justified prior.** No exceptions.
- **Recall labels are mandatory:** enumeration recall is `corpus_relative` and must never be published as absolute; finite-check recall is true recall.
- **Bump `scanner_version` whenever results change** (it starts at `1.0.0`).
- **Commit as** `satwik <satwik@<operator domain A>>`; trailers per the active session instruction (`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01TDbfdXwHkteDbQntXr5sq7`).

---

## File structure

**Create:**
- `scanners/domscout/__init__.py` — exports `DomscoutScanner`.
- `scanners/domscout/scanner.py` — `DomscoutScanner(BaseScanner)` + `_Scan` orchestration.
- `scanners/domscout/checks.py` — `Check` dataclass instances (catalogue), `CHECKS`, `requires_authorisation(mode)`, independence-class + prior constants.
- `scanners/domscout/ct.py` — pure CT-name normalization + crt.sh JSON parsing.
- `scanners/domscout/rdapp.py` — pure RDAP JSON → `RegistrationInfo`.
- `scanners/domscout/dnssec.py` — pure DNSSEC-state reasoning from DNS answers.
- `scanners/domscout/takeover.py` — `TakeoverFingerprint` protocol, the fingerprint list, `evaluate(...)`.
- `tests/scanners/domscout/test_ct.py`, `test_rdapp.py`, `test_dnssec.py`, `test_takeover.py`, `test_domscout_scanner.py`.
- `tests/core/test_measurement_families.py`.
- `corpus/targets/domscout.yaml`, `corpus/expected/domscout.yaml`, `corpus/fixtures/domscout/<case>/…`.

**Modify:**
- `core/measurement.py` — per-family precision/recall (Task 1).
- `core/scanner.py` (`BaseScanner`) — add `service_hosts: frozenset[str] = frozenset()` (Task 6).
- `cli/main.py` — construct `HttpClient` with scope = target ∪ scanner `service_hosts`; wire it for `run`/`verify` (Task 7).
- `cli/corpus.py` — wire a replay `HttpClient` into `_run_case`; pass `enumeration_check_ids` into scoring (Tasks 1, 8).
- `SPEC.md`, `docs/03-roadmap.md`, `docs/14-progress-ledger.md`, `docs/02-decisions.md` + `docs/08-changelog.md` (if an ADR is touched), `docs/how-to-add-a-scanner.md`, `docs/09-ownership-verification.md` (Task 11).

---

## Task 1: Per-family precision/recall in `core/measurement.py`

**Files:**
- Modify: `core/measurement.py`
- Modify: `cli/corpus.py` (thread `enumeration_check_ids` into `_score`, and add family sub-dict to report)
- Test: `tests/core/test_measurement_families.py`

**Interfaces:**
- Consumes: existing `Observation`, `Expected`, `CaseScore`, `TierSummary`, `Gate`, `score_case`, `summarise`.
- Produces:
  - `score_case(*, observations, expected, checks_run, enumeration_check_ids: frozenset[str] = frozenset()) -> CaseScore`
  - `CaseScore` gains: `tp_enum:int=0, fp_enum:int=0, fn_enum:int=0, tp_finite:int=0, fp_finite:int=0, fn_finite:int=0`
  - `TierSummary` gains the same six fields + properties `recall_enumeration`, `recall_finite`, `precision_enumeration`, `precision_finite` (each `float|None`)
  - `Gate` gains: `finite: dict[str, float] | None = None` (keys `precision`,`recall`), `enumeration_check_ids: list[str] = field(default_factory=list)`. When `finite` is set, `evaluate` gates each family instead of the single combined recall.

- [ ] **Step 1: Write the failing test — family bucketing splits tp/fn by check_id**

```python
# tests/core/test_measurement_families.py
from core.measurement import (
    Expected, Gate, Observation, TierSummary, score_case, summarise,
)

ENUM = frozenset({"subdomains-ct-log", "dns-records"})

def test_score_case_buckets_by_family():
    obs = [
        Observation("dns-records", "api.x.test", "highly_likely", "info"),   # enum TP
        Observation("dnssec-status", "$", "highly_likely", "medium"),        # finite TP
    ]
    exp = [Expected("dns-records", "api.x.test"), Expected("dnssec-status", "$"),
           Expected("subdomains-ct-log", "gone.x.test")]  # enum FN (never found)
    score = score_case(observations=obs, expected=exp, checks_run=3, enumeration_check_ids=ENUM)
    assert (score.tp_enum, score.fn_enum) == (1, 1)
    assert (score.tp_finite, score.fn_finite) == (1, 0)
    # combined totals unchanged by the split
    assert score.tp == 2 and score.fn == 1
```

- [ ] **Step 2: Run it, expect failure**

Run: `uv run pytest tests/core/test_measurement_families.py::test_score_case_buckets_by_family -v`
Expected: FAIL — `score_case() got an unexpected keyword argument 'enumeration_check_ids'`.

- [ ] **Step 3: Implement the family split in `score_case` + `CaseScore`**

Add the six fields to `CaseScore` (defaults 0). In `score_case`, after computing `tp_keys`/`fp_keys` and `fn` keys, partition each by membership of its `check_id` in `enumeration_check_ids`:

```python
def _fam(key: tuple[str, str]) -> str:
    return "enum" if key[0] in enumeration_check_ids else "finite"

fn_keys = expected_keys - claimed - excused
return CaseScore(
    tp=len(tp_keys), fp=len(fp_keys), fn=len(fn_keys),
    suspected=len(hedged), inconclusive=len(unresolved), checks_run=checks_run,
    tp_detected=len(tp_keys & detected_keys), fp_detected=len(fp_keys & detected_keys),
    tp_derived=len(tp_keys & derived_keys), fp_derived=len(fp_keys & derived_keys),
    tp_enum=sum(_fam(k) == "enum" for k in tp_keys),
    fp_enum=sum(_fam(k) == "enum" for k in fp_keys),
    fn_enum=sum(_fam(k) == "enum" for k in fn_keys),
    tp_finite=sum(_fam(k) == "finite" for k in tp_keys),
    fp_finite=sum(_fam(k) == "finite" for k in fp_keys),
    fn_finite=sum(_fam(k) == "finite" for k in fn_keys),
)
```

Add the `enumeration_check_ids: frozenset[str] = frozenset()` keyword param to `score_case`.

- [ ] **Step 4: Run the test, expect pass**

Run: `uv run pytest tests/core/test_measurement_families.py::test_score_case_buckets_by_family -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test — TierSummary family properties + Gate two-family evaluate**

```python
def test_tier_summary_family_properties_and_gate():
    obs = [Observation("dns-records", "a.x.test", "highly_likely", "info")]
    exp = [Expected("dns-records", "a.x.test"), Expected("subdomains-ct-log", "b.x.test")]
    score = score_case(observations=obs, expected=exp, checks_run=2, enumeration_check_ids=ENUM)
    summary = summarise({"frozen": [score]})["frozen"]
    assert summary.recall_enumeration == 0.5      # 1 of 2 enum found
    assert summary.recall_finite is None          # no finite expectations
    gate = Gate(precision=0.95, recall=0.80, recall_definition="corpus_relative",
                finite={"precision": 0.95, "recall": 0.95},
                enumeration_check_ids=list(ENUM))
    result = gate.evaluate(summary)
    assert result.passed is False                 # enum recall 0.5 < 0.80
    assert "enumeration recall" in result.reason
```

- [ ] **Step 6: Run it, expect failure**

Run: `uv run pytest tests/core/test_measurement_families.py::test_tier_summary_family_properties_and_gate -v`
Expected: FAIL — `TierSummary` has no `recall_enumeration`.

- [ ] **Step 7: Implement TierSummary fields/properties, summarise, and Gate.evaluate branch**

Add the six family fields to `TierSummary`; add:

```python
@property
def recall_enumeration(self) -> float | None:
    actual = self.tp_enum + self.fn_enum
    return self.tp_enum / actual if actual else None

@property
def recall_finite(self) -> float | None:
    actual = self.tp_finite + self.fn_finite
    return self.tp_finite / actual if actual else None

@property
def precision_enumeration(self) -> float | None:
    claimed = self.tp_enum + self.fp_enum
    return self.tp_enum / claimed if claimed else None

@property
def precision_finite(self) -> float | None:
    claimed = self.tp_finite + self.fp_finite
    return self.tp_finite / claimed if claimed else None
```

Update `summarise` to sum the six new fields. Add a `"families"` block to `TierSummary.to_dict()` (enum/finite precision+recall). In `Gate`, add `finite`/`enumeration_check_ids`; in `evaluate`, when `self.finite is not None`, replace the single combined-recall check with per-family checks:

```python
if self.finite is not None:
    re = summary.recall_enumeration
    if re is None or re < self.recall:
        failures.append(f"enumeration recall {_fmt(re)} < {self.recall:.3f}")
    pe = summary.precision_enumeration
    if pe is None or pe < self.precision:
        failures.append(f"enumeration precision {_fmt(pe)} < {self.precision:.3f}")
    rf = summary.recall_finite
    if rf is not None and rf < self.finite["recall"]:
        failures.append(f"finite recall {_fmt(rf)} < {self.finite['recall']:.3f}")
    pf = summary.precision_finite
    if pf is not None and pf < self.finite["precision"]:
        failures.append(f"finite precision {_fmt(pf)} < {self.finite['precision']:.3f}")
    # inconclusive still checked below, combined precision/recall not gated here
else:
    # existing combined precision + recall checks, unchanged
    ...
```

Keep the existing inconclusive-rate check for both branches.

- [ ] **Step 8: Run the family tests, expect pass**

Run: `uv run pytest tests/core/test_measurement_families.py -v`
Expected: PASS.

- [ ] **Step 9: Guard — email/TLS numbers must be byte-identical**

Thread `enumeration_check_ids` into `cli/corpus.py`'s `_score` (default `frozenset()` from `gate.enumeration_check_ids`), and add the family sub-dict to the per-scanner report only when families are configured.

Run: `uv run python -m cli.corpus`
Expected: email `1.000/1.000` (240 checks, 21 claims), tls `1.000/1.000`, example `1.000/1.000` — identical to the committed baseline. Then `uv run python -m cli.corpus --check-baseline` exits 0.

- [ ] **Step 10: Full gates green**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q`
Expected: all green; test count = previous + 2.

- [ ] **Step 11: Commit**

```bash
git add core/measurement.py cli/corpus.py tests/core/test_measurement_families.py
git commit -m "measurement: per-family precision/recall, gated separately

DomScout needs enumeration recall (corpus-relative, 0.80) reported apart
from finite-check recall (true, 0.95). Family is derived from check_id, so
Observation/Expected and every shipped scanner's numbers are untouched.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TDbfdXwHkteDbQntXr5sq7"
```

---

## Task 2: `scanners/domscout/ct.py` — CT-name normalization & crt.sh parsing (pure)

**Files:**
- Create: `scanners/domscout/ct.py`, `scanners/domscout/__init__.py` (empty exports stub for now)
- Test: `tests/scanners/domscout/test_ct.py`

**Interfaces:**
- Produces:
  - `normalize_name(raw: str, apex: str) -> str | None` — lowercased, trailing-dot stripped, leading `*.` stripped, IDNA→A-label; returns `None` if the result is not within `apex` (suffix-on-labels) or is the bare apex-as-wildcard artifact.
  - `is_within_apex(name: str, apex: str) -> bool` — label-boundary suffix match (rejects `example.com.evil.com`).
  - `parse_crtsh(json_text: str, apex: str) -> list[str]` — parses crt.sh `output=json` (list of objects with `name_value`, possibly newline-joined, possibly wildcarded), returns sorted unique in-apex names **excluding the bare apex** (apex bookkeeping is the caller's concern).

- [ ] **Step 1: Write failing tests for normalization + apex rejection**

```python
# tests/scanners/domscout/test_ct.py
from scanners.domscout.ct import normalize_name, is_within_apex, parse_crtsh

def test_normalize_lowercases_strips_dot_and_wildcard():
    assert normalize_name("API.Example.COM.", "example.com") == "api.example.com"
    assert normalize_name("*.api.example.com", "example.com") == "api.example.com"

def test_rejects_names_not_within_apex():
    assert normalize_name("example.com.evil.com", "example.com") is None
    assert normalize_name("notexample.com", "example.com") is None
    assert is_within_apex("a.b.example.com", "example.com") is True
    assert is_within_apex("example.com.evil.com", "example.com") is False

def test_idna_punycode():
    assert normalize_name("xn--e1afmkfd.example.com", "example.com") == "xn--e1afmkfd.example.com"
    assert normalize_name("пример.example.com", "example.com") == "xn--e1afmkfd.example.com"

def test_parse_crtsh_dedupes_splits_and_drops_apex():
    payload = '[{"name_value": "a.example.com\\n*.a.example.com"}, ' \
              '{"name_value": "example.com"}, {"name_value": "b.example.com"}]'
    assert parse_crtsh(payload, "example.com") == ["a.example.com", "b.example.com"]
```

- [ ] **Step 2: Run, expect failure** — `uv run pytest tests/scanners/domscout/test_ct.py -v` → ModuleNotFound.

- [ ] **Step 3: Implement `ct.py`** — pure functions only, no network, no scanner imports. Use `str.encode("idna")` for A-label conversion (guard `UnicodeError` → return `None`). `is_within_apex(name, apex)` returns `name == apex or name.endswith("." + apex)`. In `normalize_name`, reject when the normalized name equals the apex (that is apex bookkeeping, not a subdomain) — return `None`.

- [ ] **Step 4: Run, expect pass** — `uv run pytest tests/scanners/domscout/test_ct.py -v`.

- [ ] **Step 5: Commit** (`git add scanners/domscout/ct.py scanners/domscout/__init__.py tests/scanners/domscout/test_ct.py` + message `domscout: CT-name normalization and crt.sh parsing`).

---

## Task 3: `scanners/domscout/rdapp.py` — RDAP → RegistrationInfo (pure)

**Files:**
- Create: `scanners/domscout/rdapp.py`
- Test: `tests/scanners/domscout/test_rdapp.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class RegistrationInfo: expiry: date | None; registrar: str | None; statuses: list[str]; created: date | None; source: str = "rdap"`
  - `parse_rdap(json_text: str) -> RegistrationInfo` — reads `events[]` (`eventAction: "expiration"` / `"registration"` → dates), `entities[]` for the registrar role, `status[]`. Missing fields → `None`, never raises on a well-formed-but-sparse RDAP body.
  - `EXPIRING_WITHIN_DAYS = 30`
  - `expiry_verdict(info: RegistrationInfo, today: date) -> Literal["expired", "expiring", "ok", "unknown"]`

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/domscout/test_rdapp.py
from datetime import date
from scanners.domscout.rdapp import parse_rdap, expiry_verdict, RegistrationInfo

RDAP = '{"events":[{"eventAction":"expiration","eventDate":"2026-10-01T00:00:00Z"},' \
       '{"eventAction":"registration","eventDate":"2010-01-01T00:00:00Z"}],' \
       '"status":["client transfer prohibited"],' \
       '"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Acme Registrar"]]]}]}'

def test_parse_rdap_extracts_expiry_registrar_status():
    info = parse_rdap(RDAP)
    assert info.expiry == date(2026, 10, 1)
    assert info.registrar == "Acme Registrar"
    assert info.statuses == ["client transfer prohibited"]
    assert info.created == date(2010, 1, 1)

def test_expiry_verdict_thresholds():
    info = RegistrationInfo(expiry=date(2026, 9, 20), registrar=None, statuses=[], created=None)
    assert expiry_verdict(info, date(2026, 9, 3)) == "expiring"     # 17 days
    assert expiry_verdict(info, date(2026, 10, 1)) == "expired"
    assert expiry_verdict(RegistrationInfo(date(2027,1,1),None,[],None), date(2026,9,3)) == "ok"
    assert expiry_verdict(RegistrationInfo(None,None,[],None), date(2026,9,3)) == "unknown"

def test_sparse_rdap_does_not_raise():
    assert parse_rdap("{}") == RegistrationInfo(None, None, [], None)
```

- [ ] **Step 2–4:** run→fail, implement (pure; parse ISO dates with `date.fromisoformat(s[:10])`), run→pass.
- [ ] **Step 5: Commit** `domscout: RDAP parsing into a structured RegistrationInfo`.

---

## Task 4: `scanners/domscout/dnssec.py` — DNSSEC-state reasoning (pure)

**Files:**
- Create: `scanners/domscout/dnssec.py`
- Test: `tests/scanners/domscout/test_dnssec.py`

**Interfaces:**
- Consumes: `core.dns.DnsResponse`.
- Produces:
  - `dnssec_state(ds: DnsResponse, dnskey: DnsResponse) -> Literal["signed", "insecure", "bogus", "inconclusive"]`
  - Rules (per spec §10.2): if either response is **not** `is_definite()` → `"inconclusive"`. If DS has records **and** DNSKEY has records → `"signed"` (full RRSIG validation needs a validating resolver — out of Light scope, so we do not emit `"bogus"` from these two answers; `"bogus"` is reserved and returned only if a future validating path is added). If DS empty (definite) and DNSKEY empty (definite) → `"insecure"`. If DS present but DNSKEY absent (definite) → `"bogus"` (delegation points at a key that is not served).

- [ ] **Step 1: Write failing tests**

```python
# tests/scanners/domscout/test_dnssec.py
from core.dns import DnsResponse
from scanners.domscout.dnssec import dnssec_state

def _ans(records, rcode="NOERROR"):
    return DnsResponse(name="x.test", rrtype="DS", rcode=rcode, records=records)

def test_signed_when_ds_and_dnskey_present():
    assert dnssec_state(_ans(["12345 13 2 ABCD"]), _ans(["257 3 13 KEY"])) == "signed"

def test_insecure_when_both_definite_and_empty():
    assert dnssec_state(_ans([]), _ans([])) == "insecure"

def test_bogus_when_ds_present_dnskey_absent():
    assert dnssec_state(_ans(["12345 13 2 ABCD"]), _ans([])) == "bogus"

def test_inconclusive_on_servfail():
    assert dnssec_state(_ans([], rcode="SERVFAIL"), _ans([])) == "inconclusive"
```

- [ ] **Step 2–4:** run→fail, implement (pure), run→pass.
- [ ] **Step 5: Commit** `domscout: DNSSEC delegation-state reasoning`.

---

## Task 5: `scanners/domscout/takeover.py` — fingerprint adapters (pure)

**Files:**
- Create: `scanners/domscout/takeover.py`
- Test: `tests/scanners/domscout/test_takeover.py`

**Interfaces:**
- Consumes: `core.http.CapturedResponse` (for the body/status fingerprint).
- Produces:
  - `@dataclass(frozen=True) class FingerprintResult: matched: bool; needs_http: bool; detail: str`
  - `class TakeoverFingerprint(Protocol): name: str; service: str; source: str; def matches_cname(self, target: str) -> bool: ...; def evaluate(self, cname_target_nxdomain: bool, http: CapturedResponse | None) -> FingerprintResult: ...`
  - `FINGERPRINTS: list[TakeoverFingerprint]` — start with GitHub Pages, AWS S3, Heroku, each with a public `source` string.
  - `match_cname(target: str) -> TakeoverFingerprint | None`

- [ ] **Step 1: Write failing tests** — one positive (GitHub Pages: CNAME → `*.github.io`, target NXDOMAIN, body contains "There isn't a GitHub Pages site here" → `matched=True`), one negative (same CNAME target but a live 200 with real content → `matched=False`), one DNS-only positive (S3: CNAME → `*.s3.amazonaws.com`, target NXDOMAIN → `matched=True, needs_http=False`).

```python
# tests/scanners/domscout/test_takeover.py
from core.http import CapturedResponse
from scanners.domscout.takeover import match_cname, FINGERPRINTS

def _resp(status, text):
    return CapturedResponse(status_code=status, text=text, headers={}, captured={}, url="https://x")

def test_github_pages_positive_needs_http_body():
    fp = match_cname("victim.github.io")
    assert fp is not None and fp.service == "github-pages"
    r = fp.evaluate(cname_target_nxdomain=False,
                    http=_resp(404, "There isn't a GitHub Pages site here."))
    assert r.matched is True

def test_github_pages_negative_live_site():
    fp = match_cname("victim.github.io")
    r = fp.evaluate(cname_target_nxdomain=False, http=_resp(200, "<html>real site</html>"))
    assert r.matched is False

def test_s3_positive_is_dns_only():
    fp = match_cname("bucket.s3.amazonaws.com")
    assert fp is not None
    r = fp.evaluate(cname_target_nxdomain=True, http=None)
    assert r.matched is True and r.needs_http is False
```

- [ ] **Step 2–4:** run→fail, implement (pure; every fingerprint carries a `source` URL/advisory string; `CapturedResponse` import is a type import only, no network), run→pass. Confirm `CapturedResponse`'s constructor signature against `core/http.py:66` before writing the helper.
- [ ] **Step 5: Commit** `domscout: subdomain-takeover fingerprint adapters (GitHub Pages, S3, Heroku)`.

---

## Task 6: `scanners/domscout/checks.py` + `BaseScanner.service_hosts`

**Files:**
- Create: `scanners/domscout/checks.py`
- Modify: `core/scanner.py` (add `service_hosts: frozenset[str] = frozenset()` class attr on `BaseScanner`)
- Test: `tests/scanners/domscout/test_checks.py` (create), and extend an architecture test if one asserts every check declares `passive`.

**Interfaces:**
- Consumes: the same `Check` shape email/TLS use (read `scanners/email/checks.py` first and mirror the dataclass — `check_id`, `mode`, `passive`, `severity`, `independence_class`, `likelihood_ratio`, `prior`, `prior_justification`, `title`/`description`/`remediation` as those scanners carry them).
- Produces:
  - `CHECKS: list[Check]` — `subdomains-ct-log`, `dns-records`, `dnssec-status`, `domain-expiring`, `domain-expired`, `subdomain-takeover`. All `mode="light"`, `passive=True`.
  - `ENUMERATION_CHECK_IDS = frozenset({"subdomains-ct-log", "dns-records"})`
  - `SERVICE_HOSTS = frozenset({"crt.sh", "rdap.org"})`
  - `requires_authorisation(mode) -> bool` — returns `False` (all passive), via `core.authz.checks_require_authorisation(CHECKS, mode=mode)`.
  - Independence-class constants: `CT_LOG="ct_log"`, `DNS_RESOLUTION="dns_resolution"`, `RDAP="rdap"`, `HTTP_FINGERPRINT="http_fingerprint"`.

- [ ] **Step 1:** Read `scanners/email/checks.py` fully; mirror its `Check` dataclass import and construction style exactly (do not invent fields).
- [ ] **Step 2: Write failing test** — every check declares `passive is True`; `requires_authorisation("standard") is False`; `ENUMERATION_CHECK_IDS ⊂ {c.check_id for c in CHECKS}`; each check has a non-empty `prior_justification`.
- [ ] **Step 3:** Add `service_hosts: frozenset[str] = frozenset()` to `BaseScanner` in `core/scanner.py` (additive, defaulted — email/tls unaffected).
- [ ] **Step 4:** Implement `checks.py` with justified priors (one line each, per measurement.md).
- [ ] **Step 5:** Run tests + `uv run mypy`; commit `domscout: check catalogue + BaseScanner.service_hosts`.

---

## Task 7: `scanners/domscout/scanner.py` — orchestration, findings, discovery, evidence

**Files:**
- Create: `scanners/domscout/scanner.py`; finish `scanners/domscout/__init__.py` (`from scanners.domscout.scanner import DomscoutScanner`).
- Modify: `cli/main.py` — build `HttpClient(scope=Scope(Scope.for_target(target).hosts | scanner.service_hosts), ...)` for `run` and `verify`, wired with `RecordingHttpBackend`/`ReplayHttpBackend`/`SystemHttpBackend` per `--record`/`--replay` (mirror how the DNS/TLS clients are already selected there).
- Test: `tests/scanners/domscout/test_domscout_scanner.py` (uses `FakeResolver` + a fake `HttpBackend`, no network).

**Interfaces:**
- Consumes: `BaseScanner`, `ScanContext`, `core.dns.DnsClient`/`DnsResponse`/`FakeResolver`, `core.http.HttpClient`, `core.evidence.dns_evidence` + the HTTP pair helper (confirm its name in `core/evidence.py` before use), `core.assetgraph.DiscoveredAsset`, `core.models.{Asset,Finding,CheckRun,ScanResult,Telemetry,RelatedAsset}`, `core.confidence.{ConfidenceEngine,Signal}`, and the four pure modules (`ct`, `rdapp`, `dnssec`, `takeover`).
- Produces: `@register class DomscoutScanner(BaseScanner)` with `name="domscout"`, `version="1.0.0"`, `supported_modes=frozenset({"light"})`, `target_types=frozenset({"domain"})`, `service_hosts=SERVICE_HOSTS`, `requires_authorisation`. `run(target, mode, ctx) -> ScanResult`.

**`run()` order (spec §3):** `validate` → wildcard-detect apex (A, CNAME) → crt.sh seed (via `ctx.http.get(crtsh_url)`; 429/5xx/timeout/`OutOfScopeError`/malformed → enumeration `inconclusive`, other checks proceed) → normalize candidates (`ct.normalize_name`) → resolve each + apex (A/AAAA/CNAME/MX/NS/TXT/SOA) → contribute A/AAAA-resolving in-apex names to `ctx.assets` (canonicalized; §4 discipline: CNAME-to-third-party and MX targets become `RelatedAsset`, not graph assets) → finite checks: `dnssec.dnssec_state(DS, DNSKEY)`, RDAP expiry (`rdapp.parse_rdap` + `expiry_verdict`; `domain-expiring` sets `materialises_at`) → takeover per resolved CNAME (`takeover.match_cname`; DNS-only where `needs_http` is False, else one `ctx.http.get`). `ctx.check_alive()` before every network touch; `ctx.progress(...)`; `telemetry.checks_run` records **every** check with its outcome; findings via `Finding.create(...)` only.

- [ ] **Step 1: Write the failing happy-path test** — `FakeResolver` seeded so apex resolves, one subdomain (`api.<apex>`) resolves A, wildcard probe is NXDOMAIN; a fake `HttpBackend` returns a crt.sh JSON listing `api.<apex>`; assert the scan returns a `dns-records` finding for `api.<apex>`, contributes exactly one `DiscoveredAsset` (`discovered_by="domscout"`), and `telemetry.checks_run` covers every check.

```python
# tests/scanners/domscout/test_domscout_scanner.py (happy path — sketch; fill fixtures)
def test_discovers_resolving_subdomain_and_contributes_asset(fake_ctx):
    result = DomscoutScanner().run(Asset(type="domain", value="x.test"), "light", fake_ctx)
    ids = {f.check_id for f in result.findings}
    assert "dns-records" in ids
    contributed = fake_ctx.assets.all()
    assert [d.asset.value for d in contributed] == ["api.x.test"]
    assert contributed[0].discovered_by == "domscout"
    assert {c.check_id for c in result.telemetry.checks_run} >= {
        "subdomains-ct-log", "dns-records", "dnssec-status", "subdomain-takeover"}
```

- [ ] **Step 2: Run, expect failure.** Implement `run()`/`_Scan` mirroring `scanners/email/scanner.py`'s structure.
- [ ] **Step 3: Add the honesty tests** (each its own step + assertion):
  - wildcard zone: CT-log name that only "resolves" under a wildcard is **not** contributed and not `confirmed`.
  - crt.sh unavailable (fake backend raises/500): `subdomains-ct-log` emits `inconclusive` with `no_verdict_reason`, and DNSSEC/RDAP still run.
  - SERVFAIL on apex A: enumeration `inconclusive`, not "no subdomains".
  - dangling CNAME (target NXDOMAIN + fingerprint): `subdomain-takeover` at `suspected`; a non-dangling CNAME to a live service: silent.
  - a CNAME to a third-party host and an MX target: recorded as `RelatedAsset`, **not** contributed to the graph.
  - every finding has evidence with a control or a non-empty `control_rationale` (assert `f.evidence[0].has_control() or getattr(f.evidence[0], "control_rationale", "")`).
- [ ] **Step 4:** Wire `cli/main.py` HTTP client (service-host scope union) and confirm `scan run domscout --target x.test` constructs without `UnconfiguredClient` errors on the http path.
- [ ] **Step 5:** `uv run mypy && uv run pytest tests/scanners/domscout -q`; commit `domscout: scanner orchestration, discovery, evidence, inconclusive handling`.

---

## Task 8: Corpus wiring — targets, expected, fixtures, two-family gate

**Files:**
- Modify: `cli/corpus.py` — in `_run_case`, construct `http=HttpClient(scope=Scope(Scope.for_target(target).hosts | discover().get(scanner_name).service_hosts), backend=ReplayHttpBackend(fixtures))`; pass `gate.enumeration_check_ids` into `_score`.
- Create: `corpus/targets/domscout.yaml`, `corpus/expected/domscout.yaml`, `corpus/fixtures/domscout/<case>/…`.

**Interfaces:** consumes Task 1's `Gate.enumeration_check_ids`/`finite`, Task 6's `SERVICE_HOSTS`, Task 7's scanner.

- [ ] **Step 1:** Add the HTTP replay client to `_run_case` (a `ReplayHttpBackend` on the case fixtures dir). Verify email/tls still pass (they never call http): `uv run python -m cli.corpus` unchanged.
- [ ] **Step 2:** Author `corpus/targets/domscout.yaml` with `gate: {precision: 0.95, recall: 0.80, inconclusive_max: 0.15, recall_definition: corpus_relative, enumeration_check_ids: [subdomains-ct-log, dns-records], finite: {precision: 0.95, recall: 0.95}}` and cases (all `source: frozen`): `enum-basic` (vulnerable, several planted subdomains — the enumeration recall denominator), `known-good` (a clean apex, `expected: []` — anything reported is an FP), `wildcard-zone` (CT names not confirmed), `servfail` (`expect_inconclusive: true`), `takeover-positive` (dangling CNAME), `takeover-negative` (live CNAME, silent), `dnssec-signed`, `dnssec-insecure`, `expiring` (RDAP within 30 days).
- [ ] **Step 3:** Author `corpus/expected/domscout.yaml` — `check_id`+`location` per case; empty list for `known-good`.
- [ ] **Step 4:** Record fixtures for each case against a controlled/replayable source. For synthetic cases, hand-author the DNS `FakeResolver`-style fixtures via a small `corpus/generators/domscout.py` if recording from live is not appropriate (mirror how `corpus/generators/tls.py` mints ground truth); for real ones, `uv run python -m cli.main run domscout --target <t> --record corpus/fixtures/domscout/<case>`. **Every planted subdomain must be a real fixture answer** — do not fabricate a fixture (the ledger's repeated defect).
- [ ] **Step 5:** `uv run python -m cli.corpus --scanner domscout` → enumeration recall ≥ 0.80, precision ≥ 0.95; finite ≥ 0.95/0.95; inconclusive ≤ 0.15; zero known-good FPs. Then `--update-baseline` and commit baseline.
- [ ] **Step 6:** Commit `domscout: corpus — two-family gate, known-good, wildcard, takeover pos/neg, inconclusive`.

---

## Task 9: Cross-check against free tools + live verification (definition of done)

**Files:**
- Create: `corpus/crosscheck/subfinder.py` (disagreement analysis, mirrors `corpus/crosscheck/testssl.py`'s shape), a `make crosscheck`-style target or a `docs/17-testing-runbook.md` addition.

- [ ] **Step 1:** Guide the operator to install `subfinder` on WSL (one command, ProjectDiscovery release), and confirm `subfinder -version`. **Ask the operator to run it** — do not assume it is installed.
- [ ] **Step 2:** Implement a disagreement report: run domscout + `subfinder` + crt.sh on a domain, print `unique-to-domscout`, `unique-to-each-competitor`, `intersection`. Not gated (external dependency); recorded like the TLS cross-check.
- [ ] **Step 3:** Live-verify against `<operator domain A>`, `<operator domain B>`, `<operator domain C>` (operator-owned) + a DNSSEC-signed reference (`internet.nl`) for the finite checks. Hand-verify every claim; record findings and any disagreement in the ledger (Task 11). Any competitor-unique name is a candidate FN to investigate, not an automatic bug.
- [ ] **Step 4:** Commit `domscout: subfinder disagreement cross-check + live-verification record`.

---

## Task 10: Full-suite green + baseline

- [ ] **Step 1:** `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q && uv run python -m cli.corpus --check-baseline`
Expected: all green; email/tls/example unchanged; domscout PASS with both family lines printed.
- [ ] **Step 2:** Commit any formatting/baseline updates.

---

## Task 11: Documentation reconciliation

**Files:** `SPEC.md`, `docs/03-roadmap.md`, `docs/14-progress-ledger.md`, `docs/02-decisions.md` + `docs/08-changelog.md` (only if an ADR is touched), `docs/how-to-add-a-scanner.md`, `docs/09-ownership-verification.md`.

- [ ] **Step 1:** SPEC A4 — flip to **Shipped**, move dangling-CNAME **subdomain takeover to Light**, state the **two-number recall** with claim counts, list the checks and what is deferred to Standard. Update the status-summary table row and the `make corpus` block.
- [ ] **Step 2:** `docs/03-roadmap.md` Tool 3 row — annotate the gate to name both families (enumeration ≥0.80 corpus-relative / finite ≥0.95 true), reconciling the single "≥0.95/≥0.80" line.
- [ ] **Step 3:** `docs/09-ownership-verification.md` + `docs/how-to-add-a-scanner.md` — record the `service_hosts` mechanism: a passive scanner may declare a fixed allowlist of third-party **read-only service** hosts (the HTTP analogue of scoping the DNS resolver), unioned into the HTTP scope by the CLI, never widening the target scope and never conferring authorisation. If this reads as a change to the scope/authz model, add a short ADR and a `docs/08-changelog.md` entry (ADR-002: a decision change is a migration, not an edit).
- [ ] **Step 4:** `docs/14-progress-ledger.md` — append the Tool 3 entry (Built / Found & fixed / Decided / Deferred), the two-family gate numbers **with claim counts**, the cross-check result, and update the **Next** section. Add any new deferred items to §D.
- [ ] **Step 5:** Commit `docs: reconcile SPEC/roadmap/ledger/authz for DomScout (Tool 3) shipped`.
- [ ] **Step 6:** Offer to open the PR (`tool-3-domscout` → `main`) — only when the operator asks.
