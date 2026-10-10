# Canary runs for the secret checks, 2026-10-10

The corpus canaries from the canary policy (ledger, 2026-10-10). Each holds AWS's
documented example key, `AKIAIOSFODNN7EXAMPLE`, which is not a working key. The
operator published both and confirmed them live; we re-checked them before scanning.

## Hand verification (run by us, before and after the scans)

```
$ dig +short TXT sp-lab-7k3q.duckdns.org @1.1.1.1
"sp-canary deploy-key=AKIAIOSFODNN7EXAMPLE"
$ dig +short TXT sp-lab-7k3q.duckdns.org @8.8.8.8
"sp-canary deploy-key=AKIAIOSFODNN7EXAMPLE"

# DuckDNS serves the TXT at every name under the label (a wildcard):
$ dig +short TXT k1._domainkey.sp-lab-7k3q.duckdns.org @1.1.1.1
"sp-canary deploy-key=AKIAIOSFODNN7EXAMPLE"
$ dig +short TXT _dmarc.sp-lab-7k3q.duckdns.org @8.8.8.8
"sp-canary deploy-key=AKIAIOSFODNN7EXAMPLE"
$ dig +short TXT random-18223.sp-lab-7k3q.duckdns.org @1.1.1.1
"sp-canary deploy-key=AKIAIOSFODNN7EXAMPLE"
$ dig +short TXT _dmarc.duckdns.org @1.1.1.1      # empty

$ curl -s -w '%{http_code}' https://itsmedebmalya.github.io/sp-canary/ | grep -c AKIAIOSFODNN7EXAMPLE
1                                    # 200 text/html
$ curl -sI https://itsmedebmalya.github.io/sp-canary/
server: GitHub.com
access-control-allow-origin: *
strict-transport-security: max-age=31556952
                                     # no CSP, X-Frame-Options or X-Content-Type-Options
$ curl -s -o /dev/null -w '%{http_code}' https://itsmedebmalya.github.io/.well-known/security.txt
404
```

## Scans (Light, through the real public resolvers)

| Scanner | Target | Secret finding | Other claims, hand-verified | Recorded as |
|---|---|---|---|---|
| email v1.5.0 | `sp-lab-7k3q.duckdns.org` | `secret-exposed` (suspected), receipt `aws_access_key_id` in `test.answer`, **20 times**: the root TXT plus every wildcard name queried (D52) | `spf-missing`, `dmarc-missing`, `spoofing-possible` confirmed; `dkim-missing` inconclusive (every selector answers with the canary, which is no key) | `corpus/fixtures/email/canary-duckdns` |
| web v1.0.5 | `https://itsmedebmalya.github.io/sp-canary/` | `web-secret-in-response` (suspected), receipt `aws_access_key_id` in `test.response.body`, once; no duplicate `secret-exposed` | `web-clickjacking-unprotected`, `web-xcto-missing` confirmed; CSP, CORS wildcard suspected; security.txt informational | `corpus/fixtures/web/canary-pages` |
| domscout v1.2.0 | `sp-lab-7k3q.duckdns.org` | `secret-exposed` (suspected) once, at `dns:sp-lab-7k3q.duckdns.org/TXT` | `subdomains-ct-log` inconclusive (crt.sh HTTP 502); `domain-expiring` inconclusive (RDAP has no expiry event for a subdomain, D28) | **Not committed.** The recording holds the name's A record, which DuckDNS set to the operator's public IP. Re-record after the operator sets an explicit `ip=` |

No ScanResult held the key: `grep -c AKIAIOSFODNN7EXAMPLE` on each result's JSON printed `0`. The
recorded fixtures do hold it, as they must for replay, the same as `secret-in-txt`.
