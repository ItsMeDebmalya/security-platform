# D31 — what the providers actually return for an unclaimed name

Recorded 2026-10-10 with `curl`, through 1.1.1.1, for random names nobody owns. These recordings are the evidence ADR-027 requires before a fixture may stand in for a provider. Nothing was claimed or created, and each request was a single GET.

| Provider | Request | DNS | Response |
|---|---|---|---|
| S3 (REST) | `https://sp-d31-376b868622fe40f5153cdfb5.s3.amazonaws.com/` | **resolves** (`s3-1-w.amazonaws.com`) | `404`, `Server: AmazonS3`, XML `<Code>NoSuchBucket</Code>` ([body](s3-rest-nosuchbucket.xml)) |
| S3 (website) | `http://sp-d31-376b868622fe40f5153cdfb5.s3-website-us-east-1.amazonaws.com/` | **resolves** | `404`, HTML `Code: NoSuchBucket` ([body](s3-website-nosuchbucket.html)) |
| Heroku | `https://sp-d31-376b868622fe40f5153cdfb5.herokuapp.com/` | **resolves** (`va06.ingress.herokuapp.com`) | `404`, `server: Heroku`, `<title>No such app</title>` ([body](heroku-no-such-app.html)) |

**As a CNAMEd custom domain sees it.** A random host under the operator's DuckDNS test name was sent as the `Host`, with `curl --resolve` to the provider's address. That is what our fetch looks like when a customer's subdomain has a CNAME to the provider.

| Provider | `http://` | `https://` |
|---|---|---|
| S3 REST endpoint | `404`, `NoSuchBucket`, `BucketName` = the custom host | certificate does not cover the custom host |
| S3 website endpoint | `404`, `Code: NoSuchBucket` | connection reset |
| Heroku | `404`, `heroku-router`, `<title>No such app</title>` | certificate does not cover the custom host |
| GitHub Pages (`185.199.108.153`) | `404`, `Server: GitHub.com`, "There isn't a GitHub Pages site here." | certificate does not cover the custom host |

**Conclusions**
1. All three provider names resolve, so the NXDOMAIN fingerprint never matches (D31).
2. The "unclaimed" page is only reachable over **plain HTTP** for a custom domain. domscout fetched `https://`, so **GitHub Pages could never fire live either**. That was not known before this recording.
3. The fingerprints are the bodies above, fetched over `http://`.

Request IDs in the bodies are AWS's per-request identifiers, not secrets.
