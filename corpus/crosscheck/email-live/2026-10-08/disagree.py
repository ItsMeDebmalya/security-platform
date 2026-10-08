"""Re-ask every lookup the email scanner made of three public resolvers, one at a time."""
import json, sys, pathlib, time
from concurrent.futures import ThreadPoolExecutor
import dns.resolver, dns.exception, dns.flags

R = pathlib.Path(sys.argv[1])
NS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
lookups = {}
scan_answers = {}
for f in sorted((R / "rec").rglob("*.json")):
    d = json.loads(f.read_text())
    key = (f.parent.name, d["name"].lower().rstrip("."), d["rrtype"])
    lookups[key] = True
    scan_answers.setdefault(key, []).append(d)

def ask(ns, name, rrtype):
    r = dns.resolver.Resolver(configure=False); r.nameservers = [ns]; r.timeout = r.lifetime = 6
    try:
        a = r.resolve(name, rrtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN: return ("NXDOMAIN", ())
    except dns.resolver.NoNameservers: return ("SERVFAIL", ())
    except dns.exception.Timeout: return ("TIMEOUT", ())
    except dns.exception.DNSException as e: return ("ERROR:" + type(e).__name__, ())
    recs = []
    for it in a.rrset or []:
        if rrtype == "TXT": recs.append("".join(s.decode("utf-8", "replace") for s in it.strings))
        else: recs.append(str(it).lower())
    return ("NOERROR" if recs else "NODATA", tuple(sorted(recs)))

def probe(key):
    dom, name, rrtype = key
    return key, {ns: ask(ns, name, rrtype) for ns in NS}

with ThreadPoolExecutor(16) as ex:
    results = dict(ex.map(probe, lookups))
# second look at anything that disagreed, to separate transient from persistent
dis = [k for k, v in results.items() if len(set(v.values())) > 1]
time.sleep(5)
with ThreadPoolExecutor(16) as ex:
    retry = dict(ex.map(probe, dis))
out = {"|".join(k): {"first": {n: list(map(lambda x: list(x) if isinstance(x, tuple) else x, v[n])) for n in NS},
        "retry": ({n: [retry[k][n][0], list(retry[k][n][1])] for n in NS} if k in retry else None),
        "scan": scan_answers[k]} for k, v in results.items()}
(R / "disagreement.json").write_text(json.dumps(out, indent=1))
print("lookups", len(results), "disagree_first", len(dis),
      "disagree_persistent", sum(1 for k in dis if len(set(retry[k].values())) > 1))
