# Email live run 2, 2026-10-08 (email v1.2.0, Standard mode, post-D39)

The same 45 operator-approved domains as run 1, scanned on the fixed code: queries go to the resolver they name. 144 `confirmed`, 2 `suspected`, 37 `informational`, 21 `inconclusive`.

- `out/`, `rec/`: ScanResults and recorded DNS. Resolver labels are now accurate.
- `verification.md`: the per-finding hand-verification of all 146 non-informational findings.
- `raw.txt`: raw `dig` output (SPF, DMARC, MX) at three resolvers, for the findings read by hand.
- `checkdmarc.json`: the external cross-check (checkdmarc 6.0.3, Apache-2.0, run as a subprocess with `--skip-tls`, DNS only).
- `v_transport.py`, `v_dkim.py`: the independent verifiers (dig and openssl, not our parsers).
- `rfc/rfc9989.txt`: the current DMARC standard (May 2026), which obsoletes RFC 7489. It is kept because the DMARC verdicts are judged against it.
