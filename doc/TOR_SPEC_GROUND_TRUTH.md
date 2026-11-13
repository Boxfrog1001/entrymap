# Tor Protocol Ground-Truth Specification & Audit Registry

This registry documents the canonical specifications, mathematical limits, architectural invariants, and security audit standards governing the Tor network directory and consensus subsystems. It serves as the authoritative, peer-reviewed benchmark for all `entrymap` analysis modules, regression testbenches, and heuristic evaluators.

---

### Authoritative Specification Reference Matrix (Sources [1] – [16])

| ID | Domain / Focus | Canonical Specification / Source | Ground-Truth Standard & Architectural Invariant |
| :---: | :--- | :--- | :--- |
| **[1]** | **Relay Benchmark (prsv #1)** | [Onionoo Search 31.58.214.110](https://onionoo.torproject.org/details?search=31.58.214.110) | Live directory telemetry for prsv node on AS20860 (IOMART CLOUD). Serves as regression test fixture for CM37 effective family validation. |
| **[2]** | **Relay Benchmark (prsv #2)** | [Onionoo Search 163.5.89.97](https://onionoo.torproject.org/details?search=163.5.89.97) | Live directory telemetry for prsv node on AS216405 (Metric Systems UK). Benchmarks multi-ASN effective family attribution. |
| **[3]** | **Relay Benchmark (prsv #3)** | [Onionoo Search 57.129.142.30](https://onionoo.torproject.org/details?search=57.129.142.30) | Live directory telemetry for prsv node on AS16276 (OVH SAS). Benchmarks BandwidthRate default evaluation. |
| **[4]** | **Microdescriptor Families** | [dir-spec §Computing Microdescriptors](https://spec.torproject.org/dir-spec/computing-microdescriptors.html#item:family) | Consensus Methods 37 onward intentionally omit legacy `family` lines from microdescriptors to reduce consensus payload size. Auditing tools must evaluate Directory Authority-calculated `effective_family` or raw `@type server-descriptor` to verify mutual family declarations. |
| **[5]** | **Bandwidth Limits** | [tor(1) Manual Page](https://gitlab.torproject.org/tpo/core/tor/-/raw/main/doc/man/tor.1.txt) | `BandwidthRate` & `BandwidthBurst`: Tor's compiled unthrottled default rate is $1\text{ GiB/s}$ ($2^{30} = 1,073,741,824\text{ B/s}$). The signed 32-bit integer ceiling is $2^{31} - 1 = 2,147,483,647\text{ B/s}$. Relays reporting $2^{30}$ operate under default settings, not rate inflation. |
| **[6]** | **Consensus Weights** | [dir-spec §Computing Consensus](https://spec.torproject.org/dir-spec/computing-consensus.html#routerstatuses) | `routerstatuses` / BandwidthAuth: Consensus weight (`w Bandwidth=`) is assigned by Bandwidth Authorities (`sbws`) via dynamic, active measurement voting rounds, rather than self-reported descriptor bandwidths. |
| **[7]** | **Path Diversity Constraints** | [path-spec §Path Selection Constraints](https://spec.torproject.org/path-spec/path-selection-constraints.html) | Section 2.2.1 (`EnforceDistinctSubnets 1`): Standard Tor clients forbid selecting more than one relay from the same IPv4 `/16` subnet in any 3-hop circuit. Consequently, multiple relays in the same `/24` are mathematically excluded from intra-circuit multi-hop collisions. |
| **[8]** | **Vanguards Path Construction** | [vanguards-spec §Path Construction](https://spec.torproject.org/vanguards-spec/path-construction.html) | Vanguards circuits intentionally relax specific subnet and family diversity constraints to protect Layer 2 and Layer 3 guards from discovery attacks. Path-selection audits must account for client purpose (`CIRCUIT_PURPOSE_C_GENERAL` vs HS Vanguards). |
| **[9]** | **Residential Relay Support** | [Tor Community: Technical Considerations](https://community.torproject.org/relay/technical-considerations/) | Official Tor Project guidelines explicitly support and welcome home-hosted non-exit relays as vital contributors to middle-hop capacity. |
| **[10]**| **Relay Roles & Policies** | [Tor Community: Types of Relays](https://community.torproject.org/relay/types-of-relays/) | Non-exit and `reject *:*` relays carry middle-hop traffic and directory requests; an empty family alone establishes only that an operator runs a single instance. |
| **[11]**| **Host Port Telemetry** | [Shodan InternetDB API Reference](https://book.shodan.io/developer-apis/internetdb/) | InternetDB open port scans reflect host service exposure, not co-location or system compromise. Access-network splitters require physical fiber/coax measurements. |
| **[12]**| **v3 Descriptor Encryption** | [rend-spec-v3 §hsdesc-encrypt](https://spec.torproject.org/rend-spec/hsdesc-encrypt.html) | Section 2.5: v3 Hidden Service descriptors are encrypted using blinded keys derived directly from the `.onion` address. HSDir nodes cannot decrypt descriptor contents or harvest onion addresses without prior knowledge of the address. |
| **[13]**| **HSDir Hash-Ring Placement** | [rend-spec-v3 §WHERE-HSDESC](https://spec.torproject.org/rend-spec/deriving-keys.html#WHERE-HSDESC) | Section 2.2.2: Ring placement is derived deterministically from `(relay_identity, time_period, shared_randomness)`. Bandwidth and uptime do not influence hash-ring positioning. |
| **[14]**| **Descriptor Grammar Grammar** | [dir-spec: Text Formats (Archived)](https://gitlab.torproject.org/tpo/core/torspec/-/raw/main/attic/text_formats/dir-spec.txt) | Section 2.1.1: Defines syntactic grammar, token layouts, and field definitions for router descriptors. Validates syntax schema, not heuristic security thresholds. |
| **[15]**| **Client Operation & Downloads** | [dir-spec §Client Operation](https://spec.torproject.org/dir-spec/client-operation.html#dir-spec.txt-5.2) | Section 5.2: Specifies descriptor download schedules and fallback polling logic for clients and directory mirrors. |
| **[16]**| **Network Health Tool Audit** | [Tor Project: Code Audit of Network Health Tools](https://blog.torproject.org/code-audit-network-health-tools/) | Formal 2025 7aSecurity code audit of Tor Network Health tools (`exitmap`, `sbws`, `tagtor`). Defines security hardening standards: input sanitization, directory caching, and rate limiting. |

---

### Implementation Mapping in `entrymap`

1. **`src/modules/family_leak.py` (Sources [1, 2, 3, 4])**:
   * Evaluates `effective_family` (computed by DirAuths) and strips the self-fingerprint hash.
   * Benchmarked against `prsv.ch` fixtures to ensure zero false positives on Consensus Method 37 nodes.
   * Isolates multi-node operators who run $\ge 2$ relays under identical contact strings with zero mutual family declarations.

2. **`src/modules/ghost_bw.py` (Sources [5, 6])**:
   * Explicitly tags $2^{30}\text{ B/s}$ ($1,073,741,824\text{ B/s}$) as `[Tor Default 2^30 B/s]`.
   * Evaluates the divergence between configured descriptor limits and active `sbws` observed throughput to surface measurement-bootstrap lags rather than implying rate inflation.

3. **`src/modules/cidr_cluster.py` (Sources [7, 8])**:
   * Measures physical hosting concentration and autonomous system density across `/24` subnets.
   * Explicitly cites `path-spec §2.2.1` and `vanguards-spec`, clarifying that standard `/16` exclusions prevent circuit-level multi-hop collisions.

4. **`src/modules/residential.py` (Sources [9, 10, 11])**:
   * Replaces binary flags with a weighted composite risk scoring model ($50 - 100$).
   * Requires cumulative triggers: high unmetered residential upstream ($>100\text{ Mbps}$), dual Guard and HSDir flags, and empty family declarations.

5. **`src/modules/hsdir_canary.py` (Sources [12, 13])**:
   * Computes deterministic SHA-256 identity display digests (explicitly decoupled from `rend-spec-v3 §2.2.2` SHA3-256 `WHERE-HSDESC` ring indexes).
   * Focuses on directory ring uptime stability, dual Guard/HSDir roles, and operator contact transparency without asserting plaintext descriptor harvesting.

6. **`src/entrymap.py: run_spec_verification` (Sources [14, 15, 16])**:
   * Reframed as an automated **Schema & Descriptor Grammar Conformance Linter** verifying token syntax against `dir-spec §2.1.1`.
   * Incorporates 7aSecurity Network Health audit hardening standards: strict CLI sanitization, defensive null checking, and directory query caching.

7. **`src/modules/probe_tls_fingerprint.py` (tor-spec §4.2 CERTS Binding)**:
   * Recognizes that outer TLS X.509 certificates serve as ephemeral decoys.
   * Enforces true cryptographic binding by validating that the outer DER certificate's SHA-256 digest matches the certified subject key inside the `CERTS` cell's Type 5 (`ED25519_TLS_LINK`) certificate, detecting active ORPort MITM proxies.

8. **`src/modules/probe_padding.py` & `probe_flow_control.py` (padding-spec §2 & tor-spec §3)**:
   * Differentiates Proposal 251 connection-level link padding (`CELL_PADDING_NEGOTIATE` cmd 12) from Proposal 254 circuit-level adaptive padding.
   * Establishes a baseline circuit to activate C-Tor channel padding timers.
   * Measures channel cell-queue drainage rates and multiplexed circuit setup latency under link load.

---

### 7aSecurity Network Health Hardening Standards (Source [16])

To adhere to the hardening recommendations established in the 2025 7aSecurity Network Health tool audit:
* **Directory Caching**: Local caching of consensus payloads prevents redundant polling against Onionoo infrastructure.
* **Strict Parameter Sanitization**: Hexadecimal regex validation on fingerprints (`^[0-9A-F]{40}$`), strict ASN formatting (`^AS[0-9]+$`), and ISO 3166-1 alpha-2 validation on country codes.
* **Defensive Schema Parsing**: Non-throwing fallbacks for missing or newly introduced consensus descriptor attributes.
