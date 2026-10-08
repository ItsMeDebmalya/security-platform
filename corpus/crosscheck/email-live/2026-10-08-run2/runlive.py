import subprocess, sys, pathlib
from concurrent.futures import ThreadPoolExecutor
R = pathlib.Path(sys.argv[1])
doms = [l.split()[1] for l in (R / "domains.txt").read_text().splitlines() if l.strip()]
def one(d):
    p = subprocess.run(["uv", "run", "scan", "run", "email", "--target", d, "--mode", "standard",
        "--format", "json", "--out", str(R / "out" / f"{d}.json"), "--record", str(R / "rec" / d)],
        cwd="/root/Security-Platform", capture_output=True, text=True)
    (R / "out" / f"{d}.err").write_text(p.stderr)
    return d, p.returncode
with ThreadPoolExecutor(6) as ex:
    for d, rc in ex.map(one, doms):
        print(d, rc)
