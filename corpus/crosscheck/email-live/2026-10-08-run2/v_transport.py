import json,sys,subprocess,collections
R=sys.argv[1]; rows=json.load(open(R+"/claims.json"))
def dig(ns,name):
    out=subprocess.run(["dig","+time=4","+tries=2","@"+ns,name,"TXT"],capture_output=True,text=True).stdout
    status=[l for l in out.splitlines() if "status:" in l]
    st=status[0].split("status:")[1].split(",")[0].strip() if status else "NO-REPLY"
    ans=[l for l in out.split(";; ANSWER SECTION:")[1].split("\n\n")[0].splitlines()[1:]] if ";; ANSWER SECTION:" in out else []
    return st,ans
res=collections.Counter(); bad=[]
for d,c,s,sev in rows:
    if c not in ("mta-sts-missing","tls-rpt-missing"): continue
    name=("_mta-sts." if c=="mta-sts-missing" else "_smtp._tls.")+d
    tok="v=stsv1" if c=="mta-sts-missing" else "v=tlsrptv1"
    views={ns:dig(ns,name) for ns in ("1.1.1.1","8.8.8.8","9.9.9.9")}
    ok=all(st in ("NXDOMAIN","NOERROR") and not any(tok in a.lower() for a in ans) for st,ans in views.values())
    res[ok]+=1
    if not ok: bad.append((d,c,views))
    elif any(ans for st,ans in views.values()): bad.append(("NOTE-has-other-records",d,c,views))
print(res); print(json.dumps(bad,indent=0)[:3000])
