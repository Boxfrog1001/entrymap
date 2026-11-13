"""
Bandwidth Divergence & Telemetry Analyzer Module for entrymap.

Audits divergence between configured descriptor BandwidthRate (including Tor's
compiled 1 GiB/s unthrottled default of 2^30 B/s) and real-world Observed Bandwidth
measured by Bandwidth Authorities (sbws). Surfaces measurement-bootstrap lags
and capacity distribution across ingress nodes.
"""

def init(options):
    if options.verbose:
        print("[*] Initializing Bandwidth Divergence & Telemetry module...")

def analyze(relay, options):
    flags = relay.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    is_guard = "Guard" in flags
    is_hsdir = "HSDir" in flags

    if not (options.all_relays or is_guard or is_hsdir):
        return None

    bw_rate = relay.get("bandwidth_rate", 0) or 0
    if not isinstance(bw_rate, (int, float)):
        bw_rate = 0
    observed_bw = relay.get("observed_bandwidth", 0) or 0
    if not isinstance(observed_bw, (int, float)):
        observed_bw = 0
    consensus_weight = relay.get("consensus_weight", 0) or 0

    if observed_bw <= 0 or bw_rate <= 0:
        return None

    rate_mbps = round((bw_rate * 8) / 1_000_000, 2)
    obs_mbps = round((observed_bw * 8) / 1_000_000, 2)

    # 1073741824 B/s (2^30) is Tor's compiled default when unthrottled
    is_tor_default = bw_rate == 1_073_741_824

    # Ratio between configured/default rate and measured throughput
    divergence_ratio = round(bw_rate / observed_bw, 2)

    # Surface nodes with substantial divergence (ratio >= 15x and configured rate >= 100 Mbps)
    if (divergence_ratio >= 15.0 and rate_mbps >= 100.0) or (rate_mbps >= 500.0 and obs_mbps <= 10.0):
        or_addresses = relay.get("or_addresses", [])
        return {
            "fingerprint": relay.get("fingerprint"),
            "nickname": relay.get("nickname") or "Unnamed",
            "ip": or_addresses[0] if or_addresses else "unknown",
            "as": relay.get("as") or "Unknown",
            "as_name": relay.get("as_name") or "Unknown AS",
            "configured_rate_mbps": rate_mbps,
            "observed_mbps": obs_mbps,
            "divergence_ratio": divergence_ratio,
            "is_tor_default_rate": is_tor_default,
            "consensus_weight": consensus_weight,
            "flags": flags,
            "contact": (relay.get("contact") or "").strip()
        }

    return None

def finish(results, options):
    print("\n" + "="*70)
    print(" 📊  ENTRYMAP BANDWIDTH DIVERGENCE & TELEMETRY REPORT")
    print("="*70)
    print(f"Total Disparity / Measurement Divergence Relays Identified: {len(results)}\n")

    results.sort(key=lambda x: x["divergence_ratio"], reverse=True)

    for idx, r in enumerate(results[:15], 1):
        default_tag = " [Tor Default 2^30 B/s]" if r["is_tor_default_rate"] else " [Custom torrc Rate]"
        print(f"[{idx}] {r['nickname']} ({r['fingerprint'][:16]}...) - Divergence: {r['divergence_ratio']}x{default_tag}")
        print(f"    OR Address     : {r['ip']}")
        print(f"    Network        : {r['as_name']} ({r['as']})")
        print(f"    Configured Rate: {r['configured_rate_mbps']} Mbps")
        print(f"    Observed Flow  : {r['observed_mbps']} Mbps (sbws measured)")
        print(f"    Consensus Wt   : {r['consensus_weight']}")
        print(f"    Flags          : {', '.join(r['flags'])}")
        print(f"    Contact        : {r['contact'] if r['contact'] else '<None declared>'}")
        print("-" * 70)

    if len(results) > 15:
        print(f"... and {len(results) - 15} additional relays exhibiting bandwidth rate-to-observed divergence.")
