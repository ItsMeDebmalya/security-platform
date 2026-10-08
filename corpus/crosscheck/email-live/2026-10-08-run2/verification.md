# Email live run 2: hand-verification (2026-10-08, email v1.2.0, post-D39)

Every non-informational finding (146), verified outside our code: raw `dig` against 1.1.1.1, 8.8.8.8 and 9.9.9.9, openssl for DKIM key sizes, and checkdmarc 6.0.3 (`--skip-tls`, DNS only) as the external cross-check. **DMARC claims are judged against RFC 9989** (Standards Track, May 2026), which obsoletes RFC 7489.

Tally: FALSE 5, HEDGE 2, TRUE 136, TRUE-MISSTATED 3

| Domain | Check | State | Severity | Verdict | Basis or note |
|---|---|---|---|---|---|
| 1password.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| 1password.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| 1password.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| aajtak.in | `dmarc-invalid` | confirmed | high | **TRUE-MISSTATED** | 'v=DMARC1' with no p and no rua. We cite RFC 7489 §6.6.3 (no DMARC processing); RFC 9989 §4.7 treats an absent p as p=none. Unprotected either way, but the rule we cite is obsolete |
| aajtak.in | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| aajtak.in | `spoofing-possible` | confirmed | high | **TRUE-MISSTATED** | 'v=DMARC1' with no p and no rua. We cite RFC 7489 §6.6.3 (no DMARC processing); RFC 9989 §4.7 treats an absent p as p=none. Unprotected either way, but the rule we cite is obsolete |
| aajtak.in | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| about.com | `dmarc-policy-none` | confirmed | medium | **FALSE** | the record is 'v=dmarc1' (lower case). RFC 7489 §6.3 and RFC 9989 §4.7: the value must match DMARC1 exactly, or the entire record MUST be ignored. Correct finding: the DMARC record is ignored |
| about.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| about.com | `spf-invalid` | confirmed | medium | **TRUE** | raw record read by hand: about.com uses 'ip4 x' (no colon); fanfiction.net has '-allgoogle-site-verification=...' |
| about.com | `spoofing-possible` | confirmed | high | **TRUE-MISSTATED** | the verdict is true (the DMARC record must be ignored) but the stated reason is 'p=none' |
| about.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| airtel.in | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| airtel.in | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| amazon.in | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| amazon.in | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| atlassian.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| atlassian.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| atlassian.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| badssl.com | `dmarc-missing` | confirmed | high | **TRUE** | dig at three resolvers: no _dmarc TXT; RFC 9989 tree walk ends at the same name |
| badssl.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| badssl.com | `spf-missing` | confirmed | medium | **TRUE** | dig at three resolvers: no v=spf1 TXT |
| badssl.com | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| badssl.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| bankrate.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| bankrate.com | `spf-lookup-limit` | confirmed | high | **TRUE** | checkdmarc also finds the limit exceeded (counts differ, see notes) |
| bankrate.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| bebeautiful.in | `dmarc-no-rua` | confirmed | low | **TRUE** | raw record has no rua= |
| bebeautiful.in | `dmarc-policy-none` | confirmed | medium | **TRUE** | raw record p=none |
| bebeautiful.in | `mta-sts-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| bebeautiful.in | `mx-missing` | confirmed | medium | **TRUE** | dig at three resolvers: no MX; severity posture read from DMARC |
| bebeautiful.in | `spf-lookup-limit` | confirmed | high | **TRUE** | checkdmarc also finds the limit exceeded (counts differ, see notes) |
| bebeautiful.in | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| bebeautiful.in | `tls-rpt-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| bookmyshow.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| bookmyshow.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| bookmyshow.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| brookings.edu | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| brookings.edu | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| brookings.edu | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| caltech.edu | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| caltech.edu | `dmarc-policy-none` | confirmed | medium | **TRUE** | raw record p=none |
| caltech.edu | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| caltech.edu | `spf-too-permissive` | confirmed | low | **TRUE** | raw record ends '?all' at three resolvers |
| caltech.edu | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| caltech.edu | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| cloudflare.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| cloudinary.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| cloudinary.com | `dmarc-pct-partial` | confirmed | medium | **FALSE** | pct is removed in RFC 9989 (App. C.5.2, A.6); a receiver following the current standard applies p=quarantine to all failing mail. The '% delivered as if p=none' statement describes obsolete RFC 7489 semantics |
| cloudinary.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| cloudinary.com | `spoofing-possible` | confirmed | high | **FALSE** | the only reason is partial pct, removed in RFC 9989; under the current standard p=quarantine applies to all failing mail |
| cloudinary.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| example.com | `dmarc-no-rua` | confirmed | low | **TRUE** | true but moot: null MX, p=reject |
| example.com | `mta-sts-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| example.com | `tls-rpt-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| fanfiction.net | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| fanfiction.net | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| fanfiction.net | `spf-invalid` | confirmed | medium | **TRUE** | raw record read by hand: about.com uses 'ip4 x' (no colon); fanfiction.net has '-allgoogle-site-verification=...' |
| fanfiction.net | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| flipkart.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| flipkart.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| flipkart.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| gov.uk | `mta-sts-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| gov.uk | `mx-missing` | confirmed | low | **TRUE** | dig at three resolvers: no MX; severity posture read from DMARC |
| gov.uk | `tls-rpt-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| gstatic.com | `dmarc-policy-none` | confirmed | medium | **TRUE** | raw record p=none |
| gstatic.com | `mta-sts-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| gstatic.com | `mx-missing` | confirmed | medium | **TRUE** | dig at three resolvers: no MX; severity posture read from DMARC |
| gstatic.com | `spf-too-permissive` | confirmed | low | **TRUE** | raw record ends '?all' at three resolvers |
| gstatic.com | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| gstatic.com | `tls-rpt-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| hdfcbank.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| hdfcbank.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| iana.org | `dmarc-policy-none` | confirmed | medium | **TRUE** | raw record p=none |
| iana.org | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| iana.org | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| iana.org | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| icicibank.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| icicibank.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| icicibank.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| indiatimes.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| indiatimes.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| indiatimes.com | `spf-multiple-records` | confirmed | medium | **TRUE** | dig at three resolvers: two v=spf1 records |
| indiatimes.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| infosys.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| infosys.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| irctc.co.in | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| irctc.co.in | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| irctc.co.in | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| jpmorganchase.com | `mta-sts-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| jpmorganchase.com | `mx-missing` | confirmed | low | **TRUE** | dig at three resolvers: no MX; severity posture read from DMARC |
| jpmorganchase.com | `tls-rpt-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| kerala.gov.in | `dmarc-invalid` | suspected | high | **HEDGE** | suspected is not a claim; duplicate fo/rua/ruf tags read by hand, and the hedge is appropriate under RFC 9989 |
| kerala.gov.in | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| kerala.gov.in | `spoofing-possible` | suspected | high | **HEDGE** | suspected is not a claim; duplicate fo/rua/ruf tags read by hand, and the hedge is appropriate under RFC 9989 |
| kerala.gov.in | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| makemytrip.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| makemytrip.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| makemytrip.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| microsoft.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| nic.in | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| nic.in | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| nykaa.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| nykaa.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| nykaa.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| oraclecloud.com | `dmarc-pct-partial` | confirmed | medium | **FALSE** | pct is removed in RFC 9989 (App. C.5.2, A.6); a receiver following the current standard applies p=quarantine to all failing mail. The '% delivered as if p=none' statement describes obsolete RFC 7489 semantics |
| oraclecloud.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| oraclecloud.com | `spoofing-possible` | confirmed | high | **FALSE** | the only reason is partial pct, removed in RFC 9989; under the current standard p=quarantine applies to all failing mail |
| oraclecloud.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| paytm.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| paytm.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| paytm.com | `spf-lookup-limit` | confirmed | high | **TRUE** | checkdmarc also finds the limit exceeded (counts differ, see notes) |
| paytm.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| python.org | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| python.org | `dmarc-policy-none` | confirmed | medium | **TRUE** | raw record p=none |
| python.org | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| python.org | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| python.org | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| reliance.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| reliance.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| swiggy.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| swiggy.com | `dmarc-policy-none` | confirmed | medium | **TRUE** | raw record p=none |
| swiggy.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| swiggy.com | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| swiggy.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| tcs.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| tcs.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| tcs.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| vulnweb.com | `dmarc-missing` | confirmed | high | **TRUE** | dig at three resolvers: no _dmarc TXT; RFC 9989 tree walk ends at the same name |
| vulnweb.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| vulnweb.com | `spoofing-possible` | confirmed | high | **TRUE** | DMARC posture read by hand (missing, or p=none); reason matches the record |
| vulnweb.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| warnerbros.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| warnerbros.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| warnerbros.com | `spf-multiple-records` | confirmed | medium | **TRUE** | dig at three resolvers: two v=spf1 records |
| warnerbros.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| wipro.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| wipro.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| zomato.com | `dkim-weak-key` | confirmed | low | **TRUE** | openssl key size of every reported selector at 8.8.8.8 and 9.9.9.9 matches ours; weakest named |
| zomato.com | `mta-sts-missing` | confirmed | low | **TRUE** | dig at 1.1.1.1, 8.8.8.8, 9.9.9.9: NXDOMAIN, or no v=STSv1 TXT |
| zomato.com | `tls-rpt-missing` | confirmed | low | **TRUE** | dig at three resolvers: NXDOMAIN, or no v=TLSRPTv1 TXT |
| zomato.in | `dmarc-no-rua` | confirmed | low | **TRUE** | raw record has no rua= |
| zomato.in | `mta-sts-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
| zomato.in | `mx-missing` | confirmed | low | **TRUE** | dig at three resolvers: no MX; severity posture read from DMARC |
| zomato.in | `spf-missing` | confirmed | medium | **TRUE** | dig at three resolvers: no v=spf1 TXT |
| zomato.in | `tls-rpt-missing` | confirmed | low | **TRUE** | true but moot: the domain accepts no mail |
