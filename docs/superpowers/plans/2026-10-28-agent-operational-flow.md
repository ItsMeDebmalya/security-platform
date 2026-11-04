# Plan — the host agent's end-to-end operational flow, as one document

**Requested by the operator, 2026-10-28.** A single document in `docs/`, written **for someone who has
not read the ADRs** — his manager should be able to follow it — covering deployment through to
remediation, with one worked example followed end to end.

**Status: PLAN ONLY. Nothing written yet, no code in this task.** This file is the plan he asked for
before the writing.

---

## 1. The problem to solve before writing a word

**CLAUDE.md forbids exactly this document, as normally written**, and that is the first thing to settle
rather than discover in review:

> **3. Do not add a new status or summary document.** `SPEC.md` holds current state; the ledger holds
> history. A third view of the same thing is how this happened before.

and, from the same section: **"Each fact has exactly one home. Everywhere else links to it."** The set
has drifted before **in both directions** — a document restating another's facts and then falling behind
it, and a second document appearing to cover ground the first already owned.

A narrative of the agent's operation inherently touches facts owned by ADR-035 (the decisions),
`SPEC.md` (status and gates), docs/24 (scope), docs/25 (the report) and docs/26 (the build order). Write
it the obvious way and it becomes the fourth view, correct on the day it ships and wrong within a month.

**The resolution, and it is a constraint on every section, not a preamble:**

1. **The document owns exactly one thing: the narrative — the order in which things happen, and why
   each step exists.** No other document owns that today, which is why it is not a duplicate.
2. **It carries no numbers it owns.** No check counts, no gate figures, no precision, no timings
   presented as measured, no status words like WORKING. Every such fact is a link to its home.
3. **Where it must state a fact to be readable, it states it as a link in the same sentence** — "the
   collector reads an allowlist of files ([the allowlist is specified in ADR-035 decision 7](...))" —
   so a reader who wants authority has one hop and an editor who changes the fact has one place.
4. **A "what this document is not" box at the top**, naming `SPEC.md` for status and the ledger for
   history, so a future reader does not mistake it for either.
5. **Every status word is "PLANNED"**, because that is what the agent is. The document describes a
   design, and must not read as a description of something running. **This is the single biggest risk
   in the task**: a fluent operational narrative written for a non-technical reader is indistinguishable
   from a description of a working system unless it says otherwise on every page.

**If the operator would rather not add a file to `docs/`**, the alternative is a section inside docs/24.
Recommendation: **a new file**, because docs/24 is a signed-off scope document with a date and a
sign-off line, and growing a narrative inside it damages what it is. The numbering is free: **`docs/27`**.

---

## 2. Audience, and what that changes

Written for **the operator's manager**: technically literate, has not read the ADRs, will not read
them, and is deciding whether to trust this on fifty servers.

Consequences, each of which changes the writing:

- **Every acronym expanded on first use**, and ADR numbers appear as links with a plain-English clause,
  never as bare citations. "ADR-004" means nothing to this reader; "we never exploit anything we find
  ([ADR-004](...))" does.
- **The question this reader actually has is "what will it do to my servers, and what if it goes
  wrong"**, not "what is the architecture". So **deployment, execution and the honest limits carry the
  weight**, and the architecture section exists only to make them comprehensible.
- **No tables of fields.** A snapshot's shape is described in prose with one short illustrative extract;
  the schema's home is the spec.
- **It must survive being read by a sceptic.** The limits section is not a disclaimer at the end — it is
  the section that earns the rest.

---

## 3. Structure, with what each section owns and where its facts live

Seven sections, in the operator's order, plus the worked example woven through rather than bolted on.

### 3.1 Architecture — what the two halves are
- The collector (runs on the host, collects, judges nothing) and the `host` scanner (runs on our
  platform, judges). What crosses the boundary: **one snapshot file, in one direction**.
- **Why judgement is platform-side**, in the terms this reader cares about: a rule we get wrong today
  can be corrected and re-run against every snapshot already collected, **without going back to the
  fleet**. An agent that decided things would make its mistakes permanent at the moment of collection.
- Facts link to: ADR-035 decisions 2 and 17.
- **Diagram: yes, one.** Two boxes and one arrow, with the arrow labelled "one file, one direction". It
  is the only diagram the document needs and it carries the central point.

### 3.2 Deployment — how it reaches a server and what it leaves
- How the artefact arrives; what the admin does; **what gets installed: nothing**; what is left behind
  afterwards: **nothing**; how it is removed: **delete the file**.
- **The open question stated, not hidden:** packaging is undecided (D95), and on a host whose Python is
  missing or below the floor the admin installs Python. Say so plainly — the reader will ask.
- Facts link to: ADR-035 decisions 3, 5, 14; D95 for the open packaging question.

### 3.3 Execution — what happens from the moment it runs
- In order: the **interpreter check as the first act**; the platform check; the allowlists; what is read
  and what is refused; the receipt being written as it goes.
- **What the host operator would see if they were watching** — this is the section that gets the agent
  accepted, and `--explain-plan` belongs here prominently: it prints the complete allowlist and
  **executes nothing**.
- **Cost in CPU, memory and wall time: NOT stated as a measurement.** Nothing has run. The document says
  what the design bounds are (per-command timeouts, output caps, a fixed command list) and that **the
  measured figures will be filled in from Step 4** with a link to where they will live. **Inventing a
  "typically under five seconds" here would be precisely D94's defect in prose.**
- Facts link to: ADR-035 decisions 7, 14, 15, 16.

### 3.4 The artefact — what a snapshot contains and does not
- What it contains; **what it deliberately does not**: no secret values, key material as fingerprints
  only, redaction at capture rather than display.
- **The `manifest` and the artefact rule in plain words:** everything the report claims is present in
  the file, and anything the collector could not do is recorded **as an error, never as an absence that
  reads as "clean"**. Worth a sentence of the operator's own reasoning: a fleet report that quietly omits
  the oldest, least-patched machines is the worst possible failure mode for this product.
- **The `self_hash`, stated as what it is and is not** — corruption detection, **not** tamper-evidence.
  This reader is exactly the one who would otherwise assume it is a signature.
- **How it travels:** in Alpha, a file the admin transfers and we ingest by command line; after Step 7,
  an API upload.
- Facts link to: ADR-035 decisions 1, 6, 8, 16; docs/26 Steps 4 and 7.

### 3.5 Processing — how a fact becomes a finding
- Ingest; **validation, including that a snapshot is treated as untrusted input** because it may come
  from the compromised host, and what that means concretely (limits, no value used as a path or
  argument, encoding at render).
- **How a CVE verdict is reached:** against the distribution's own fixed-version-per-release data, and
  **why we refuse CVE-range matching** — because a distribution backports, so the upstream "affected
  below 1.2.3" is wrong on a package at 1.2.2-ubuntu4. This is the single most important paragraph for
  a reader judging whether to believe us, and it is a point most scanners get wrong.
- **What makes a finding `inconclusive`**, and that this is a correct outcome rather than a failure.
- **Why package findings stop at `highly_likely` and never reach `confirmed`** — honest ceiling,
  explained in one sentence a non-specialist can hold: confirming it would require asking the package's
  own binary, and asking the host a question built from what the host just told us is the one thing the
  allowlist forbids.
- Facts link to: ADR-035 decisions 9, 10, 13; the accuracy rules in CLAUDE.md; `core/state.py` as the
  only thing that sets state.

### 3.6 Presentation — how it reaches the report
- Where it lands in the report; what the **remediation section** looks like for a real example — the
  exact command for that distribution and that package, **and that we never run it**.
- **Attribution appears here**, because it is a visible part of the report: the vendor data carries an
  attribution-and-link obligation.
- **Re-testing**: how a fix is confirmed by re-running the same check that found it.
- Facts link to: docs/25, ADR-035 decisions 3 and 11, ADR-022 for "close".

### 3.7 The honest limits — its own section, as the operator required
Not a disclaimer. The section that earns the document.
- **What a clean result does and does not mean.** It means: nothing the allowlist looks at, judged
  against the vendor data available, produced a finding. It does **not** mean the host is secure.
- **What this does not detect**, said specifically: anything outside the allowlist; anything the
  vendor's feed does not cover (`inconclusive`, and the reader should know how often that happens once
  we can measure it); anything requiring a running-process view; **a compromised host that lies to the
  collector** — a snapshot is well-formed, not trustworthy.
- **The agent cannot prove it is read-only by its own output.** `--explain-plan` and the receipt are the
  program's account of itself. The source being readable is what currently backs the claim, which is why
  D95's Option B is a real trade and not a packaging detail.
- **Nothing has executed on Python 3.6**, and the fleet's distribution support is not yet fixed.
- **Internal fleet first.** Its first evidence is our own servers under one internal authorisation —
  weaker independence than a customer corpus, and the gate must say so when it is written.

---

## 4. The worked example

**One example, followed end to end, from the command that observed it to the remediation line.** It is
the spine of the document: each section shows the same example advancing, so the reader meets one
concrete thing seven times rather than seven abstractions.

**Chosen example: an outdated package with a known vulnerability on a lab host**, per the operator.
Concretely: an Ubuntu lab box with an `openssl` version below the distribution's fixed version for a
real USN.

**It must be labelled as illustrative, not as a run that happened**, until Step 4 produces a real one —
at which point the illustrative version is **replaced by the real transcript**, which is the better
document and should be written in as a to-do rather than left to chance.

The seven beats:

1. the allowlisted command that read the package database, with its `reason_id`;
2. the raw fact as it appears in the snapshot, with its receipt line;
3. the snapshot arriving and validating;
4. the vendor data lookup — installed version versus fixed-in version for **this release**;
5. the finding, with its state and why it is `highly_likely` and not `confirmed`;
6. the report entry, with the exact `apt install` line and the note that **we do not run it**;
7. the re-test after the admin runs it, and the finding closing.

**Also show one `inconclusive`** in miniature — a package the feed does not cover — because a reader who
only sees the happy path will not believe the limits section.

---

## 5. What I need before writing, and what I can write without it

**Can be written now** (design is settled and merged): sections 3.1, 3.2 (minus packaging), 3.4, 3.5,
3.6's shape, 3.7.

**Blocked, and would be invented if written now:**

- **Timings and resource cost** (3.3) — needs Step 4. Written as design bounds with a named gap, never as
  figures.
- **The real worked-example transcript** — needs a lab host (Step 3) and a collector (Step 4).
- **Packaging and how the admin receives the artefact** (3.2) — needs D95, which needs the fleet probe.
- **The report's exact remediation layout** (3.6) — docs/25 owns it; I will link rather than invent, and
  check what it already specifies before writing that section.

**Recommendation on sequencing: write it now with the gaps named and visible, rather than waiting.**
A document that says "measured cost: to be filled in from Step 4, see here" is useful to the manager
today and honest; a document that waits until everything is known arrives after the decision it was
meant to inform. The named gaps also become a checklist for Step 4.

---

## 6. Risks

| Risk | Why it matters | Mitigation |
|---|---|---|
| **It reads as a description of something that exists** | The reader is deciding whether to trust this on 50 servers. Fluent prose about a PLANNED system is the most likely way this document misleads, and the reader cannot tell | PLANNED on every page, present tense banned for behaviour never observed, and the limits section early enough to be read |
| **It becomes the fourth view and drifts** | Exactly what CLAUDE.md rule 3 forbids, and the set has drifted this way before | Owns the narrative only; no numbers of its own; every fact a link in the sentence that needs it |
| **Invented figures** | D94 in prose. A plausible "under five seconds" would be a claim with nothing behind it | No measurement stated until Step 4 measures it; gaps named in place |
| **The example becomes stale** | A hand-written example diverges from what the collector really emits | Replaced by a real transcript at Step 4, recorded as a to-do, not an intention |
| **Length** | A document the manager does not finish has failed regardless of accuracy | Target 1,200–1,800 words plus the example. The limits section does not get cut to make room |

---

## 7. Deliverable

- **`docs/27-agent-operational-flow.md`**, new file.
- **One linking line added to CLAUDE.md's document list**, in the same change, so the document set
  stays discoverable from one place — the same discipline as ADR-035's `agent/` entry.
- **A ledger row** recording that it exists, what it owns, and the named gaps it carries.
- **No code, no ADR change, no scanner touched**, so no corpus number can move.
- One reviewed PR, CI certified by dispatch per D85.
