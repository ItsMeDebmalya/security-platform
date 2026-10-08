import json,sys,subprocess,base64,re,glob
R=sys.argv[1]
def keybits(ns,name):
    out=subprocess.run(["dig","+short","+time=4","@"+ns,name,"TXT"],capture_output=True,text=True).stdout
    txt="".join(re.findall(r'"([^"]*)"',out))
    m=re.search(r'(?:^|;)\s*p=([A-Za-z0-9+/=]*)',txt.replace(" ",""))
    if not m: return None, txt[:40]
    if not m.group(1): return "revoked",""
    if "k=ed25519" in txt.replace(" ",""): return "ed25519",""
    der=base64.b64decode(m.group(1)+"==="[:(-len(m.group(1)))%4])
    o=subprocess.run(["openssl","pkey","-pubin","-inform","DER","-noout","-text"],input=der,capture_output=True).stdout.decode()
    b=re.search(r"\((\d+) bit\)",o); return (int(b.group(1)) if b else "unparsed"),""
bad=0
for f in sorted(glob.glob(R+"/out/*.json")):
    o=json.load(open(f)); d=o["target"]["value"]
    for x in o["findings"]:
        if x["check_id"]!="dkim-weak-key" or x["state"]!="confirmed": continue
        sels=[k["selector"] for k in x["evidence"][0]["analysis"]["dkim_keys"]]
        ours={k["selector"]:k["key_bits"] for k in x["evidence"][0]["analysis"]["dkim_keys"]}
        theirs={s:keybits("8.8.8.8",f"{s}._domainkey.{d}")[0] for s in sels}
        theirs9={s:keybits("9.9.9.9",f"{s}._domainkey.{d}")[0] for s in sels}
        weak=[s for s,b in theirs.items() if isinstance(b,int) and b<2048]
        named=[s for s in weak if f"{s}._domainkey" in x["description"]]
        agree = all((ours[s]==theirs[s]) or (theirs[s]=="ed25519") or (theirs[s]=="revoked" and ours[s] is None) for s in sels) and theirs==theirs9
        ok = bool(weak) and agree
        bad+= not ok
        print(("OK " if ok else "?? ")+d, "openssl:",theirs, "" if agree else f"ours:{ours} q9:{theirs9}", "| weakest named:", named[:1])
print("not ok:",bad)
