# Email live run 1, 2026-10-08 (email v1.1.0, Standard mode)

45 operator-approved domains (`domains.txt`; tiers A, B, C, D, S = screened positives, P = path tests). No operator domains.

- `out/<domain>.json`: the ScanResult, from `scan run email --mode standard --format json --record`.
- `rec/<domain>/`: every DNS answer the scanner received, as recorded. **The fixtures labelled `8.8.8.8` were answered by 1.1.1.1** (ledger D39).
- `disagreement.json`: every lookup the scanner made (1,245 unique name/type pairs), asked again of 1.1.1.1, 8.8.8.8 and 9.9.9.9 one at a time by `disagree.py`. Lookups that disagreed were asked again after 5 s.
- `runlive.py`, `disagree.py`: the drivers, kept so the run can be repeated.

**Status: not hand-verified.** Hand-verification is on hold until D39, the second-resolver defect in `core/dns.py`, is ruled on. Every `confirmed` here rests on a validation that never reached a second resolver.
