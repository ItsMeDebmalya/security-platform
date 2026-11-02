"""D5: modules collect facts and judge nothing."""

import re
from pathlib import Path

MODULES = sorted((Path(__file__).resolve().parents[3] / "agent" / "modules").glob("*.py"))
JUDGEMENT = re.compile(r"insecure|weak|vulnerable", re.IGNORECASE)


def test_modules_exist():
    assert {p.stem for p in MODULES} >= {"os_release", "kernel", "host_identity", "packages", "ssh"}


def test_no_judgement_words():
    hits = [(p.name, m.group(0)) for p in MODULES for m in JUDGEMENT.finditer(p.read_text())]
    assert hits == []
