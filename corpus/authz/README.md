# Authorisation evidence

One file per authorisation record, named `<target>-<verified_at>.txt`.

Each file is the **actual proof** — the DNS answer, the HTTP response, the
signed attestation — that established control of the target. The matching row
in `config/authorised_scope.yaml` cites it by path in `proof.evidence_file`.

**A row asserting verification without its proof is not verification.** These
files are the artefact produced if anyone ever asks by what right we touched a
system, so they are committed, never regenerated, and never edited after the
fact. Retention is 7 years (`docs/11-operations.md`).

The files here today are worked examples on RFC 2606 reserved domains, paired
with `config/authorised_scope.example.yaml`. They authorise nothing: the live
file is `config/authorised_scope.yaml`, and it is empty.
