# Entrymap: A Fast and Modular Scanner for Tor Entry Guards and HSDirs

> [!IMPORTANT]
> **Safe Research & Testing Scope** — To protect the Tor network and researchers' privacy:
> * **Do Not Probe Live Third-Party Relays**: Validate PoCs and parser edge cases strictly against offline synthetic fixtures (`test/verify_specs.py`), loopback mock listeners (`test/test_active_probes_sandbox.py`), your own authorized Guard, or an isolated local **Chutney** network.
> * **Passive vs. Active OPSEC Boundary**: Passive modules (`residential`, `family_leak`, `ghost_bw`, `cidr_cluster`, `bulletproof`, `hsdir_canary`, `sidecar`) use HTTPS lookups (`onionoo.torproject.org` / `internetdb.shodan.io`) and support `torsocks` / `proxychains`, HTTP `--proxy`, and amnesic `--no-cache` execution. Active wire probes (`probe_guard_wire`, `probe_tls_fingerprint`, `probe_padding`, `probe_timing_jitter`, `probe_flow_control`) initiate direct TCP/TLS connections to target ORPorts and are intended only for your own configured Guard, an isolated measurement host, or local Chutney.

`entrymap` is a fast and modular scanner designed for the Tor research and Network Health community. While `exitmap` focuses on analyzing and detecting malicious behavior at the egress boundary of the Tor network (Exit relays), `entrymap` focuses on the ingress and directory tier: **Entry Guards and Hidden Service Directories (HSDirs)**.

Controlling an Entry Guard or HSDir allows adversaries to mount statistical end-to-end traffic correlation attacks, observe client ingress IP addresses, monitor directory replica availability, and abuse shared consumer physical access plants (e.g. residential FTTP/GPON) without declaring family relationships.

`entrymap` provides a pluggable Python architecture modeled directly after `exitmap` to audit, test, and profile Entry Guards and HSDirs across the consensus.

> **Fixes & Release Updates**: Track ongoing fixes, spec alignments, and active wire improvements in [CHANGELOG.md](CHANGELOG.md).

---

## Features

- **Consensus & Directory Ingestion**: Ingests authoritative Tor consensus telemetry via Onionoo HTTPS (`gzip` + field filtering) and parses local Tor `state` files for Guard auto-discovery.
- **Modular Architecture**: Drop-in modules live in `src/modules/` and can be invoked dynamically via `-m <module>`.
- **Target Filtering**: Scan all relays, only Guards (`--guards-only`), only HSDirs (`--hsdir-only`), or filter by ASN, country, or fingerprint.
- **Specification Grammar Linter**: Automated schema verification hook ensures internal data types conform to `dir-spec`.
- **Zero Local Client Footprint**: Supports passive consensus audits as well as active TCP probes without needing a local Tor daemon.

---

## Directory Layout

```text
entrymap/
├── bin/
│   └── entrymap                   # Main executable CLI entrypoint
├── doc/
│   ├── HACKING.md                 # Developer guide for writing custom analysis modules
│   └── TOR_SPEC_GROUND_TRUTH.md   # Canonical Tor specification & audit registry
├── src/
│   ├── entrymap.py                # Core controller, consensus fetcher & module loader
│   └── modules/                   # Drop-in scanning and analysis modules
│       ├── probe_common.py        # Raw Tor cell parser, Ed25519 CERTS verifier & KDF-TOR
│       ├── probe_guard_wire.py    # Master 4-Phase Active Wire Defense Suite
│       ├── probe_tls_fingerprint.py # TLS 1.3, Link v5, Cert Chain & Clock Skew
│       ├── probe_padding.py       # Proposal 251 & 254 Channel Padding (Fingerprinting Defense)
│       ├── probe_timing_jitter.py # Delay Injection & Watermark Jitter Detector
│       ├── probe_flow_control.py  # Flow-Control Pipelining & SENDME Starvation
│       ├── residential.py         # Identifies Guards on residential/consumer FTTP/DOCSIS pools
│       ├── family_leak.py         # Flags missing MyFamily & verifies CM37 effective_family
│       ├── ghost_bw.py            # Audits BandwidthRate vs. sbws observed throughput
│       ├── cidr_cluster.py        # Audits /24 subnet infrastructure concentration
│       ├── bulletproof.py         # Tracks non-exit ingress hubs in offshore ASNs
│       ├── hsdir_canary.py        # Inspects HSDir ring distribution and uptime stability
│       └── sidecar.py             # Checks for exposed non-Tor services (e.g. Traefik, STUN)
├── test/
│   ├── verify_specs.py            # 1:1 Tor specification conformance testbench
│   └── test_active_probes_sandbox.py # Multi-vector active wire probing sandbox test suite
├── setup.py                       # Standard setuptools configuration
├── requirements.txt               # Dependencies
├── CHANGELOG.md                   # Public engineering updates, fixes & release notes
├── LICENSE                        # BSD-3-Clause License
├── SECURITY.md                    # Vulnerability disclosure policy & safe research scope
└── README.md                      # Project documentation
```

---

## Installation

```bash
git clone https://github.com/Boxfrog1001/entrymap.git
cd entrymap
pip install -r requirements.txt
```

---

## Automated Specification & Wire Sandbox Verification

`entrymap` ships with dual testbenches:

1. **Passive Consensus & Specification Conformance**:
```bash
python3 test/verify_specs.py
```
Validates arithmetic divergence, Consensus Method 37 effective family calculations, `/16` subnet boundaries, and benchmark targets against canonical Tor specifications (`dir-spec`, `path-spec`, `rend-spec-v3`).

2. **Active Multi-Vector Wire Sandbox Testbench**:
```bash
python3 test/test_active_probes_sandbox.py
```
Validates all 4 real-world active wire behaviors against both an authentic running Tor reference guard and targeted loopback adversarial testbeds:
- **Test 0**: Authentic Tor 0.4.9 Reference Guard (`127.0.0.1:5003`, optional when running locally)
- **Test 1**: Adversarial Jitter Trap (Artificial timing delay watermarking)
- **Test 2**: Hostile Fingerprinting Stripper (Proposal 251 / 254 channel padding drop)
- **Test 3**: Flow-Control Stalling & `SENDME` Starvation (Proposal 289)
- **Test 4**: Degraded TLS Front-Door (Expired certificates, Link v3, 7200s clock skew)

---

## Active Wire Probing (What Are Entry Nodes Doing With My Traffic?)

While passive modules audit relay descriptors, `entrymap`'s active wire modules directly inspect the transport layer to answer: **"What are entry nodes doing with my traffic?"** and **"Is my front door secure?"**

### 1. Run the Unified 4-Phase Wire Defense Suite
Audits TLS front-door crypto, website fingerprinting padding defense, timing correlation jitter, and circuit flow control in a single coordinated pass:
```bash
./bin/entrymap -m probe_guard_wire --target 127.0.0.1:5003
```

### 2. Audit TLS Front-Doors, Cipher Suites & Certificate Validity
Validates TLS 1.3 / Link Protocol v5 negotiation, X.509 certificate chains, Ed25519 `CERTS` Type 4/5 MITM binding, and flags directory clock skew:
```bash
./bin/entrymap -m probe_tls_fingerprint --fingerprint <GUARD_FINGERPRINT>
```

### 3. Verify Website Fingerprinting Defenses (Tor Proposals 251 & 254)
Tests whether a Guard honors channel padding negotiation (`CELL_PADDING_NEGOTIATE`, `CELL_PADDING`, `CELL_VPADDING`):
```bash
./bin/entrymap -m probe_padding --target 127.0.0.1:5003
```

### 4. Detect Artificial Delay Injection & Flow Watermarking (Jitter Trap)
Sends nanosecond-precision micro-probe trains to calculate RTT variance, coefficient of variation, and detect timing watermarks:
```bash
./bin/entrymap -m probe_timing_jitter --target 127.0.0.1:5003 --probe-count 10
```

### 5. Audit Circuit Window Pipelining & SENDME Starvation (Tor Proposal 289)
Measures cell pipeline throughput and flags deliberate circuit package window stalling:
```bash
./bin/entrymap -m probe_flow_control --target 127.0.0.1:5003
```

---

## Usage Examples (Passive Consensus Auditing)

### 1. Scan for Guards Operating on Consumer/Residential Broadband
```bash
./bin/entrymap -m residential
```

### 2. Inspect Hidden Service Directory (HSDir) Nodes with Undeclared Families
```bash
./bin/entrymap -m family_leak --hsdir-only
```

### 3. Target a Specific Autonomous System or Relay Fingerprint
```bash
./bin/entrymap -m residential --as AS7922
./bin/entrymap -m sidecar --fingerprint 0123456789ABCDEF0123456789ABCDEF01234567
```

### 4. Audit Your Own Running Tor Client Guards (`--check-my-guards`)
Answer *"Is my front door secure?"* with a single command. `entrymap` parses your local Tor client `state` file (`~/.tor/state`, `/var/lib/tor/state`, or Tor Browser `state`) to auto-discover your persistent Entry Guards, pulls their directory telemetry, and executes deep active or passive audits:
```bash
# Full active wire defense audit on your client's active guards:
./bin/entrymap -m probe_guard_wire --check-my-guards

# Passive consensus topology audit on a specific Tor state file:
./bin/entrymap -m residential --state-file ~/.tor/state
```

### 5. High-Concurrency Scanning & Automated CI Ingestion (`--json`, `--concurrency`)
Integrate `entrymap` directly into Network Health dashboards, Prometheus, Grafana, or cron jobs:
```bash
./bin/entrymap -m sidecar --concurrency 8 --json /var/reports/entrymap_latest.json
```
* **Exit Codes**: Returns `0` on clean/compliant runs, `1` on warnings, and `2` on high risk or active wire verification failures.

---

## OPSEC & Privacy Considerations for Tor Users

If you are auditing the Tor network from a privacy-sensitive environment (e.g. Tails, Whonix, or an anonymous workstation), adhere to these principles:

### 1. Anonymous Execution via `torsocks` or `--proxy`
By default, `entrymap` queries `onionoo.torproject.org` over clearnet HTTPS. To route all directory lookups through the Tor network:
```bash
torsocks ./bin/entrymap -m residential
# Or specify a local HTTP/HTTPS proxy (use torsocks/proxychains for SOCKS5):
./bin/entrymap -m residential --proxy http://127.0.0.1:8118
```

### 2. Amnesic Systems & Zero Disk Footprint (`--no-cache`)
To conform to 7aSecurity Network Health standards, `entrymap` caches consensus records with strict `0600` (`-rw-------`) file permissions for 30 minutes to avoid overloading directory mirrors. On amnesic systems (like Tails) where no disk writes should persist:
```bash
./bin/entrymap -m family_leak --no-cache
```

### 3. Passive vs. Active Threat Model
* **Passive Modules** (`residential`, `family_leak`, `ghost_bw`, `cidr_cluster`, `bulletproof`):
  * **Traffic**: Pure HTTPS requests to `onionoo.torproject.org`.
  * **Exposure**: Never sends packets to relay IP addresses. 100% safe to run through Tor.
* **Active Wire Modules** (`probe_guard_wire`, `probe_tls_fingerprint`, `probe_padding`, `probe_timing_jitter`, `probe_flow_control`):
  * **Traffic**: Direct TCP/TLS connections to the target Guard's ORPort (e.g., port 9001 or 5003).
  * **Exposure**: The target Guard sees the client IP connecting to its ORPort. Standard Tor exit nodes block port 9001 to prevent loop abuse, so active probes cannot be easily routed through multi-hop Tor circuits. Use active wire probing to audit **your own configured Guard**, a local Chutney testbed, or from an isolated measurement node.

### 4. Third-Party Intelligence Disclosures (`sidecar.py`)
The `sidecar` module queries Shodan's free `internetdb.shodan.io` API over HTTPS to detect exposed reverse proxies, STUN, or SSH services. Always run `sidecar` through `torsocks` to prevent leaking your querying IP to third-party databases.

---

## Writing Custom Modules

Writing an `entrymap` module is as simple as defining an `analyze(relay, options)` or `probe(relay, options)` function in a new `.py` file inside `src/modules/`. See `doc/HACKING.md` for full details.

---

## Acknowledgements

Special thanks to **1AEO (`metrics.1aeo.com`)** for detailed community peer review, specification citations, and guidance on Consensus Method 37 microdescriptor attributes, `path-spec` subnet constraints, and `dir-spec` schema grammar.

---

## License & Attribution

`entrymap` is released under the BSD-3-Clause License. Developed by FrogSec for the global Tor research and Network Health community.
