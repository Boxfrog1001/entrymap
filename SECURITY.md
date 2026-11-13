# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.1   | Yes       |
| < 0.2.1 | No        |

---

## Reporting a Vulnerability

Please **do not** open public GitHub issues for suspected security vulnerabilities, OPSEC/proxy bypass bugs, or active-wire parser flaws.

* **Preferred Channel**: Submit a private report via [GitHub Private Vulnerability Reporting](https://github.com/Boxfrog1001/entrymap/security/advisories/new).
* **Required CWE Assignment**: GitHub Private Vulnerability Reporting on this repository requires assigning a **CWE** on submission (for example: `CWE-20` improper input validation, `CWE-200` / `CWE-319` OPSEC or cleartext exposure, `CWE-295` / `CWE-347` certificate or signature validation flaw, `CWE-400` resource exhaustion).
* **Response Expectations**: We aim to acknowledge reports within **72 hours**, reproduce findings offline, and coordinate a patched release + advisory note in `CHANGELOG.md` once verified.

When submitting a report, please include:
1. Affected module or CLI flag (e.g., `src/entrymap.py`, `probe_common.py`, `probe_guard_wire.py`).
2. Step-by-step reproduction instructions using offline synthetic data, the loopback sandbox (`test/test_active_probes_sandbox.py`), or a local Chutney network.
3. Expected vs. observed behavior (including whether proxy bypass, unintended disk writes, or malformed cell parsing occurred).
4. The most applicable **CWE identifier(s)** and severity assessment.

---

## Safe Research & Testing Scope

To protect the Tor network and researchers' privacy:

* **Do Not Probe Live Third-Party Relays**: Validate all Proof-of-Concept exploits and parser edge cases strictly against offline synthetic fixtures (`test/verify_specs.py`), loopback mock listeners (`test/test_active_probes_sandbox.py`), your own authorized Guard, or an isolated local **Chutney** network.
* **Passive vs. Active OPSEC Boundary**:
  * **Passive modules** (`residential`, `family_leak`, `ghost_bw`, `cidr_cluster`, `bulletproof`, `hsdir_canary`, `sidecar`) use HTTPS lookups (`onionoo.torproject.org` / `internetdb.shodan.io`) and support `torsocks` / `proxychains`, HTTP `--proxy`, and amnesic `--no-cache` execution.
  * **Active wire probes** (`probe_guard_wire`, `probe_tls_fingerprint`, `probe_padding`, `probe_timing_jitter`, `probe_flow_control`) initiate direct TCP/TLS connections to target ORPorts and are intended only for your own configured Guard, an isolated measurement host, or local Chutney.

---

## Security & Hardening Design Notes

* **Zero-Daemon Execution**: `entrymap` does not start a background Tor daemon or open listening sockets.
* **Local Cache Protections**: Local temporary caches use `0700` directories and `0600` file permissions; `--no-cache` disables consensus/sidecar disk caching for amnesic environments (e.g., Tails/Whonix).
* **Input Validation & Fail-Closed Probing**: CLI options (`--fingerprint`, `--as`, `--country`, `--concurrency`) are validated strictly before execution, and `probe_guard_wire` fails closed (`HOSTILE_OR_DEFICIENT_GUARD`, capped at `40.0/100`, exit code `2`) if Ed25519 `CERTS` Type 4/5 verification or TLS link digest binding fails.
* **No Telemetry**: `entrymap` contains no analytics, phone-home beacons, or auto-updaters.
