# Changelog & Engineering Updates

All notable fixes, protocol hardening updates, new active wire capabilities, and community peer-review alignments for **entrymap** are documented here to keep the Tor research and Network Health community transparently informed.

---

### ★ Known Minor Code Notes (v0.2.1)
* **Onionoo `User-Agent` String (`src/entrymap.py`)**: `fetch_consensus()` currently sends `User-Agent: entrymap/0.2.0 (Tor Network Health Research)` rather than `0.2.1` (cosmetic only).
* **`--check-my-guards` / `--state-file` Missing-File Exit Code (`src/entrymap.py`)**: When no readable Tor `state` file or active `Guard` entry is found, an error is logged to `stderr`, and `main()` exits `0` rather than a non-zero code (non-breaking fallback).
* **IPv4 Literal Requirement for `--target` (`src/modules/probe_common.py`)**: `perform_tor_handshake()` encodes `NETINFO` `other_address` via IPv4 `socket.inet_aton()` (falling back to `127.0.0.1` when `"."` is absent), so `--target` currently expects an IPv4 literal rather than a dotted hostname or IPv6 address.

---

## [0.2.1] — 2026-11-13 (Chutney MITM Verification & Fail-Closed Hardening)

### Fixed
* **Fail-Closed MITM Scoring (`src/modules/probe_guard_wire.py`)**: Fixed an aggregation edge case discovered during live Chutney + TLS MITM testing where a transparent TLS-terminating proxy forwarding padding, timing, and flow cells cleanly could pull a composite score to `85.0` despite failing Ed25519 `CERTS` verification. Any `ed25519_mitm_verified == False` or `MITM` / `SIG_INVALID` anomaly now caps `composite_score <= 40.0` and forces `HOSTILE_OR_DEFICIENT_GUARD`.
* **Standardized POSIX Exit Codes (`src/entrymap.py`)**: Added `compute_exit_code()` at the end of `main()` so CLI/CI pipelines exit `0` on compliant runs, `1` on warnings/degraded states, and `2` on MITM detections, high-risk findings, or unreachable `--target` endpoints.

### Changed
* **Package & Documentation Hygiene**: Bumped `setup.py` to `0.2.1`, standardized documentation/CLI placeholder examples (`README.md`, `doc/HACKING.md`, `src/entrymap.py`), and added this public `CHANGELOG.md`.

### Verified
* **Offline Chutney Integration (`Tor 0.4.9.11`, `basic-min`)**:
  * Verified authentic Chutney Guard returns `HARDENED_GUARD [Score: 100.0/100]` (`TLSv1.3`, `Link v5`, `CERTS Types [1,2,4,5,7]`, `MITM Verified: True`, exit code `0`).
  * Verified live transparent TLS-terminating MITM proxy wrapping Chutney returns `HOSTILE_OR_DEFICIENT_GUARD [Score: 40.0/100]` with `TLS_CERT_DIGEST_MISMATCH_MITM` and exit code `2` even when inner padding/jitter/flow probes pass transparently.
* **Automated Testbenches**: `test/verify_specs.py` (`5/5` passed, 0 network IO) and `test/test_active_probes_sandbox.py` (`5/5` passed).

---

## [0.2.0] — 2026-11-12 (Spec Ground-Truth Alignment & Active Wire Protocol Suite)

### Added
* **Ed25519 `CERTS` Type 4/5 MITM Verification (`src/modules/probe_common.py`, `src/modules/probe_tls_fingerprint.py`)**: Implemented `cert-spec.txt §2.1` & `tor-spec.txt §4.2` cross-signature validation—verifying Type 4 (`ED25519_SIGNING`) signatures and binding Type 5 (`ED25519_TLS_LINK`) certified keys to the SHA-256 digest of the outer TLS X.509 DER certificate.
* **`CREATE_FAST` KDF-TOR Engine (`src/modules/probe_common.py`, `src/modules/probe_flow_control.py`)**: Implemented KDF-TOR circuit key derivation (`tor-spec.txt §5.1.5 & §5.2.1`), verifying `CREATED_FAST` `KH` proofs and sending AES-128-CTR / SHA-1 encrypted circuit-level `RELAY_DROP` and `RELAY_SENDME` (cmd `5`) cells to measure channel queue drainage.
* **Proposal 251/254 Padding Sequencing (`src/modules/probe_padding.py`)**: Distinguished Proposal 251 (`padding-spec.txt §2` link-layer padding) from Proposal 254 adaptive circuit padding and added initial circuit establishment so C-Tor activates link-padding timers prior to `CELL_PADDING_NEGOTIATE`.
* **TCP vs. Cell RTT Baseline Calibration (`src/modules/probe_timing_jitter.py`)**: Added `cell_to_tcp_ratio` calibration comparing TCP SYN-ACK baseline latency against in-tunnel cell RTT to isolate WAN jitter from relay-side delay injection.
* **Client Discovery, Concurrency & Pipeline Output (`src/entrymap.py`)**: Added `--check-my-guards` and `--state-file` local Tor guard discovery, `--concurrency` worker thread pool (`1–16`), `--json` structured export, and Onionoo `fields=` + `gzip` compression.
* **Canonical Spec Registry (`doc/TOR_SPEC_GROUND_TRUTH.md`)**: Documented 16 authoritative Tor specifications, consensus behaviors, and module mappings.
* **Loopback Active Wire Sandbox (`test/test_active_probes_sandbox.py`)**: Self-contained adversarial server simulating timing jitter watermarks, padding strippers, flow starvation, and degraded TLS/Ed25519 links, plus optional Chutney reference verification.

### Fixed (Community Peer-Review Alignment)
* **Consensus Method 37 `effective_family` Normalization**: Updated `family_leak.py`, `cidr_cluster.py`, `residential.py`, `hsdir_canary.py`, and `bulletproof.py` to evaluate DirAuth-computed `effective_family` and cleanly strip `$` prefixes and self-fingerprints.
* **Tor Default `BandwidthRate` & Consensus Weights (`src/modules/ghost_bw.py`)**: Recognized `2^30 B/s` (`1,073,741,824 B/s`) as Tor's compiled default unthrottled rate (not `2^31 - 1` or inflation) and incorporated authority-measured `sbws` consensus weights.
* **`/16` vs `/24` Subnet Constraints (`src/modules/cidr_cluster.py`)**: Aligned with `path-spec §2.2.1` (`EnforceDistinctSubnets 1`) and `vanguards-spec`, reframing `/24` density as physical hosting concentration rather than intra-circuit Sybil collisions.
* **Residential & `reject *:*` Classification (`src/modules/residential.py`, `src/modules/bulletproof.py`)**: Replaced binary residential flags with weighted multi-factor risk scoring and aligned docs with Tor Project guidance welcoming home-hosted middle relays and `reject *:*` roles.
* **v3 HSDir Encryption & Ring Index (`src/modules/hsdir_canary.py`)**: Updated per `rend-spec-v3 §2.5` blinded encryption and `§2.2.2` (`WHERE-HSDESC`) to confirm HSDirs cannot decrypt unknown `.onion` descriptors and decouple display digests from ring placement.
* **7aSecurity Network Health Hardening (`src/entrymap.py`, `src/modules/sidecar.py`)**: Enforced `0600` cache permissions, strict amnesic `--no-cache` pass-through in `sidecar.py`, regex parameter validation, and `dir-spec §2.1.1` schema/grammar linting.
* **100% Offline Spec Unit Suite (`test/verify_specs.py`)**: Built synthetic RFC 5737 test fixtures validating all 5 passive specification invariants with zero network IO.

---

## [0.1.0] — 2026-11-11 (Initial PoC Release)
* Initial modular scanner controller (`src/entrymap.py`, `bin/entrymap`) modeled after `exitmap`.
* Baseline passive consensus analysis modules (`family_leak`, `ghost_bw`, `cidr_cluster`, `residential`, `hsdir_canary`, `bulletproof`, `sidecar`).
