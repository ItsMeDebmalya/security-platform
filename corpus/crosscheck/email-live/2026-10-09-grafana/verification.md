# grafana.com — the real positive for `dmarc-test-mode` (2026-10-09)

Operator-approved. One Standard-mode email scan (email v1.4.1, post-D39), recorded; the recording is the corpus case `real-test-mode` (`corpus/fixtures/email/real-test-mode/`). Every non-informational finding was checked by hand with `dig` at 1.1.1.1, 8.8.8.8 and 9.9.9.9, which returned the same answers.

| Finding | State | Verdict | Basis |
|---|---|---|---|
| `dmarc-test-mode` | suspected, medium | **TRUE** | `_dmarc.grafana.com` = `v=DMARC1; p=quarantine; sp=none; adkim=r; aspf=r; t=y; rua=…; ruf=…; fo=1; rf=afrf; ri=86400`. RFC 9989 §4.7 applies quarantine with t=y as none; RFC 7489 ignores `t` |
| `spoofing-possible` | suspected, high | **TRUE (hedge)** | Delivered under RFC 9989 (none); quarantined under RFC 7489 |
| `dkim-weak-key` | confirmed, low | **TRUE** | openssl: k1, s2, mandrill 1024 bits; s1, k2 2048 bits |
| `mta-sts-missing` | confirmed, low | **TRUE** | `_mta-sts.grafana.com` NXDOMAIN at all three; the domain has MX (aspmx.l.google.com and others) |
| `tls-rpt-missing` | confirmed, low | **TRUE** | `_smtp._tls.grafana.com` NXDOMAIN at all three |
| `dmarc-obsolete-tags` | informational | **TRUE** | `rf=afrf`, `ri=86400` are RFC 7489's defaults, as the finding says |

SPF `v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all`: no finding, correctly (`~all` is a declared non-finding).
