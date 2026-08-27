# 15 — The IoT & Device Security Scanner

*A distinct tool, not a check family. [ADR-021](02-decisions.md#adr-021--the-iot--device-security-scanner-is-its-own-tool-not-a-check-family).*

---

## What it is

A scanner that takes a **network** rather than a domain, inventories the devices on it, and reports what is exposed, what is unencrypted, what is unauthenticated, and what is running firmware with known vulnerabilities — **without touching a credential, writing to a device, or changing any state.**

The claim it exists to support:

> **The scanner you can safely point at fragile devices, that tells you which vulnerabilities it actually confirmed and says "I do not know" when it cannot tell.**

Two seams make that ownable. Existing tools are either **passive** (a network tap, enterprise money) or **aggressive** (built for servers, knocks devices over) — a deliberately gentle active scanner is an unoccupied position. And **IoT CVE matching is the noisiest output in security**, which is exactly where honest confidence is worth the most.

---

## Split into two tools, deliberately

The exposure half is far simpler than the vulnerability half and has no dependency on port discovery. Shipping them together would delay the useful half behind the hard one.

| | **5a — Device Exposure** | **5b — Device Vulnerability** |
|---|---|---|
| Answers | *What is on this network, and what is wide open?* | *What is on it that has known holes?* |
| Needs | Protocol clients, record/replay | 5a, plus identification and a CVE source |
| Findings | Mostly `confirmed` — direct observation | Mostly `suspected` — inference from an identifier |
| Gate | precision ≥ 0.95, recall corpus-relative | precision ≥ 0.90, recall corpus-relative |

**Why 5b's gate is lower and should be.** It infers from a firmware string rather than observing. Setting an unreachable precision target would push an author to under-report, and the honest instrument is a lower gate plus a mandatory detected/derived split, not a flattering number.

---

## Tool 5a — Device Exposure

### Discovery

Mostly listening rather than probing. Devices announce themselves:

- **mDNS / DNS-SD** — service records with model and version in TXT
- **SSDP / UPnP** (1900/udp) — announcements, plus a device description URL
- **DHCP fingerprints** and **MAC OUI** → vendor
- **Known device ports**, probed directly on an authorised range: 23, 80, 443, 1883, 8883, 5683, 5684, 161, 554, 8080, 9100

Discovery output goes into the **asset graph** ([ADR-019](02-decisions.md#adr-019--scanners-exchange-assets-through-the-run-never-through-each-other)) with provenance, which is what lets 5b consume it without importing 5a.

### Identification

The **UPnP device description XML** is the prize: a device advertises a URL, and it returns manufacturer, model, serial and often firmware version. mDNS TXT records do similar. HTTP headers, page titles and favicon hashes fill gaps.

Output: `vendor · model · firmware`. Everything in 5b depends on this, and **when it cannot be determined, that is a finding in itself** — not silence.

### Encryption checks

Pure observation, unambiguous, and the most common real defect on these networks.

| check_id | Signal | Severity |
|---|---|---|
| `iot-telnet-enabled` | Port 23 answering — plaintext by definition | high |
| `iot-mqtt-plaintext` | Broker on 1883 rather than 8883 | high |
| `iot-coap-no-dtls` | CoAP on 5683 rather than 5684 | medium |
| `iot-admin-http-only` | Admin interface on 80, no redirect to 443 | high |
| `iot-snmp-v1-v2c` | SNMP v1/v2c — community strings cross the wire in clear | medium |

**Lead a first release with these.** They produce `confirmed` findings with clean evidence and no inference.

### Authentication checks

The protocols hand us a control-vs-test pair for free, which is why this can be done without brute force.

| check_id | How |
|---|---|
| `iot-mqtt-anonymous-accepted` | Connect with no credentials. The spec defines both answers: `CONNACK 0` = accepted, `CONNACK 4/5` = rejected. Observing `0` where the protocol provides `5` **is** the test-vs-control pair — the same shape as OpenSSL's `verify_code` in the TLS scanner. |
| `iot-coap-unauthenticated` | `GET /.well-known/core`, the discovery endpoint RFC 7252 defines for exactly this. A response without DTLS means no transport authentication. |
| `iot-admin-no-auth` | Does `GET /` return `200` where `401` is expected? |
| `iot-upnp-control-exposed` | Control endpoints reachable without authentication (detected, never invoked) |
| `iot-default-credential-documented` | This *model* ships with a documented default. **Never tested.** |

### The line, stated so it cannot drift

**Connecting is a handshake. Reading is not.**

We report *that* a broker accepts anonymous connections. We never subscribe to a topic, never read a CoAP resource, never enumerate what a device holds — even though all three would be trivial after a successful connect, and precisely because they would.

**Default credentials are detected, never tried.** A single login attempt is not brute force, but it can trigger account lockout and alerting, and that is how a scanner gets blamed for an outage. `iot-default-credential-documented` reports that a model ships with a known default and asks the operator to verify it was changed. It is an honest hedge, not a claim — and it is a `suspected` finding, permanently.

---

## Tool 5b — Device Vulnerability

### The problem, plainly

Most IoT scanners map banner → CPE → CVE list and print forty criticals. Most are wrong: vendor strings are inconsistent between firmware builds, NVD's CPE coverage for consumer devices is poor, firmware versions are frequently absent from the dictionary, and the same model ships different regional builds.

**Our existing rules are already the right answer**, and this is where they are worth the most.

| Situation | State | Why |
|---|---|---|
| Firmware version unparseable | **`inconclusive`** | Not "no vulnerabilities found". The most important row in this table. |
| Fuzzy vendor+model match, no exact CPE | `suspected`, and the description says the match was fuzzy | We inferred; say so |
| Exact CPE, version in the affected range | `suspected`, confidence ≤ 0.6 | The version-strings-lie rule |
| Version match **plus** behavioural confirmation | `highly_likely` | Two independence classes |

**The documented exception.** The version cap exists because distributions backport patches without bumping versions. IoT vendors rarely do — they ship a new build or nothing — so `firmware_version` is a stronger signal here than for a distro package, and the cap may justifiably be higher. **The corpus must demonstrate that before the cap moves.** It is an exception with a reason, not a loophole.

### Independence classes

| Class | What it observes |
|---|---|
| `service_banner` | What the device claims to be |
| `protocol_behaviour` | What it actually does when spoken to |
| `firmware_version` | The version string — deliberately weak alone |
| `network_exposure` | Where it is reachable from |

A CVE finding resting only on `firmware_version` cannot exceed `suspected`. That is the design working, not a limitation to engineer around.

### End-of-support

`iot-firmware-end-of-support` is a **derived, dated finding** ([ADR-018](02-decisions.md#adr-018--findings-carry-a-date-and-say-whether-they-were-detected-or-derived)) — `materialises_at` set to the vendor's published support end date, confidence inherited from the identification it rests on. A device that stops receiving updates on a known date is exactly the deprecation clock, applied where it is least tracked.

---

## Mitigation and closing the loop

Remediation here is unusually concrete — *disable Telnet*, *move MQTT to 8883 with TLS*, *put this VLAN behind a firewall* — and fix verification is trivially re-runnable: reconnect and observe the `CONNACK 5` you wanted. **Close-the-loop works better here than anywhere else in the product**, because the test that proved the problem is one handshake.

---

## Safety — the part that is not negotiable

Devices break in ways servers do not, and what breaks may be doing something physical. The rules are in [06-guidelines.md](06-guidelines.md) and are stop-the-line:

- device-class rate ceilings are **floors, not defaults** — a slow scan covers fewer devices, it does not go faster
- one connection at a time per device; concurrency is *across* devices
- **never repeat a probe a device did not answer** — a non-response from a constrained device is usually the device struggling, and retrying is how a scan becomes an outage
- **read-only verbs only** — no MQTT PUBLISH, no CoAP PUT/POST/DELETE, no SNMP SET, no UPnP control actions
- authorisation means someone who understands what happens if a device falls over

---

## Corpus

Device emulators and recorded protocol exchanges, using the generic record/replay layer (0b.3) — one recording backend per protocol, not one per scanner.

**Per [ADR-017](02-decisions.md#adr-017--live-verification-is-part-of-a-tools-definition-of-done), none of this is trustworthy until it runs against real devices**, and this is the domain where a synthetic corpus is most likely to mislead: **real devices violate their own specifications constantly**, and an emulator written from an RFC will agree with a scanner written from the same RFC. That is the corpus-encodes-the-author's-assumptions failure in its purest form.

Access to a real device network is a prerequisite for calling this done, not a nice-to-have.

---

## Open before building

- **Where 5a sits.** It needs only protocol clients and record/replay, so it *could* precede the Network Scanner. Placing it earlier trades roadmap tidiness for having the differentiator sooner.
- **CVE data source.** OSV.dev is approved ([ADR-003](02-decisions.md#adr-003--permissive-open-source-or-we-build-it-ourselves)) but its IoT firmware coverage is thin. NVD CPE matching may be needed, with its own licence and rate-limit questions.
- **Protocol library licences.** MQTT, CoAP and mDNS clients must clear ADR-003 and be registered before first use.
- **Authorisation for address ranges** is our hardest case — [09-ownership-verification.md](09-ownership-verification.md) requires signed attestation *and* per-provider policy compliance. A device network is usually private, which may make it simpler; that needs confirming, not assuming.
