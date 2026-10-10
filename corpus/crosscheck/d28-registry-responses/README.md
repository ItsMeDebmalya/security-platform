# D28: domain expiry read from the registries, 2026-10-10

domscout v1.3.0, Light, live through the vendored IANA RDAP bootstrap
(`publication` 2026-09-30T23:00:03Z), straight to each registry. rdap.org is no
longer contacted. Each date below was checked by hand against
`curl -sL https://rdap.org/domain/<d>`, whose `Location` is the same registry URL.

## Apex domains (recorded as corpus cases)

| Domain | Registry RDAP URL the scan used | Expiry (scan's record) | Expiry (`curl -L` rdap.org) | Verdict |
|---|---|---|---|---|
| example.com | `https://rdap.verisign.com/com/v1/domain/example.com` | 2027-08-13T04:00:00Z | 2027-08-13T04:00:00Z | clear |
| iana.org | `https://rdap.publicinterestregistry.org/rdap/domain/iana.org` | 2027-12-08T17:00:53Z | 2027-12-08T17:00:53Z | clear |
| nixi.in | `https://rdap.nixiregistry.in/rdap/domain/nixi.in` | 2026-12-30T16:27:39.000Z | 2026-12-30T16:27:39.000Z | clear |
| nic.in (not recorded: crt.sh 502 on three runs) | `https://rdap.nixiregistry.in/rdap/domain/nic.in` | 2026-12-23T20:45:40.070Z | 2026-12-23T20:45:40.070Z | clear |

```
$ curl -sI https://rdap.org/domain/example.com | grep -i location
location: https://rdap.verisign.com/com/v1/domain/example.com
$ curl -sI https://rdap.org/domain/nixi.in | grep -i location
location: https://rdap.nixiregistry.in/rdap/domain/nixi.in
```

crt.sh answered `502` for nixi.in on five tries (and for nic.in on three), while
other queries succeeded. The nixi.in case is recorded as it happened:
`subdomains-ct-log` is `inconclusive`, and the RDAP read is unaffected.

## A name the registry does not hold (not corpus cases; see D53)

```
$ curl -s -o /dev/null -w '%{http_code}' https://rdap.verisign.com/com/v1/domain/www.example.com
404
$ curl -s -o /dev/null -w '%{http_code}' https://rdap.publicinterestregistry.org/rdap/domain/www.iana.org
400
$ curl -s https://rdap.nixiregistry.in/rdap/domain/www.nixi.in            # 200
  objectClassName domain, ldhName nixi.in, expiration 2026-12-30T16:27:39.000Z
$ curl -s https://rdap.nixiregistry.in/rdap/domain/doesnotexist-zq8x7.nixi.in
  ldhName nixi.in                                                         # the parent's record again
```

NIXI answers any name under a registered domain with that domain's record. The
scan therefore reports a date under the record's own `ldhName`, and only when it
is the target or an ancestor of it.

Live scans of `www.example.com` and `www.nixi.in` behaved as designed for expiry:
`inconclusive` with "no registration for www.example.com (HTTP 404)", and `clear`
from nixi.in's record. **They also showed D53:** `dnssec-status` reported
`www.nixi.in` "not signed" (`confirmed`) and `www.example.com` (`suspected`),
although both zones are signed:

```
$ dig +short DS nixi.in @1.1.1.1         -> 31765 8 2 848EF993...     (signed)
$ dig +short DNSKEY nixi.in @1.1.1.1     -> 2 keys
$ dig +short DS www.nixi.in @1.1.1.1     -> (empty: not a zone cut)
$ dig SOA www.nixi.in @1.1.1.1           -> authority: nixi.in.
$ dig +short DS example.com @1.1.1.1     -> 2371 13 2 C988EC42...     (signed)
```

So these two runs are not corpus cases: their expected set would have to
contain a false claim.

## A TLD missing from the bootstrap

`.io`, `.भारत` (`xn--h2brj9c`) and `.இந்தியா` have no entry in this bootstrap. The
scan sends no RDAP request and reports `inconclusive`: "lists no RDAP server".
This is unit-tested (`tests/scanners/domscout/test_expiry.py`).
