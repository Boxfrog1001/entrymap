"""
probe_guard_wire.py - Master Integrated 4-Phase Wire Defense Probe for entrymap.

Executes the complete active wire audit against Entry Guards in a single coordinated pass:
  1. TLS & Link Protocol Fingerprinting (Front-door crypto, cert validity, clock skew)
  2. Channel Padding Negotiation (Website fingerprinting defense, Proposal 254)
  3. Timing Correlation & Jitter Trap Analysis (Delay watermarking detection)
  4. Flow-Control & SENDME Starvation (Circuit window integrity & starvation)

Computes a comprehensive Composite Guard Wire Score (0 to 100) and authoritative defense verdict.
"""

import sys
from modules import probe_tls_fingerprint
from modules import probe_padding
from modules import probe_timing_jitter
from modules import probe_flow_control
from modules.probe_common import extract_or_endpoint

def init(options):
    if getattr(options, "verbose", False):
        print("[*] Initializing Master 4-Phase Active Wire Defense Suite...")
    probe_tls_fingerprint.init(options)
    probe_padding.init(options)
    probe_timing_jitter.init(options)
    probe_flow_control.init(options)

def analyze(relay, options):
    ip, port = extract_or_endpoint(relay)
    if not ip or not port:
        return None

    if getattr(options, "verbose", False):
        print(f"[*] Executing 4-Phase Wire Audit on {relay.get('nickname', 'node')} ({ip}:{port})...")

    # Phase 1: TLS & Link Protocol Fingerprint
    res_tls = probe_tls_fingerprint.analyze(relay, options)
    if not res_tls:
        return None

    # Phase 2: Channel Padding Negotiation
    res_padding = probe_padding.analyze(relay, options)

    # Phase 3: Timing Watermark & Jitter Trap
    res_jitter = probe_timing_jitter.analyze(relay, options)

    # Phase 4: Flow-Control & SENDME Starvation
    res_flow = probe_flow_control.analyze(relay, options)

    # Compute Composite Wire Defense Score (0 = Compromised/Hostile, 100 = Fully Hardened)
    crypto_score = 100 - res_tls.get("risk_score", 0)
    padding_score = 100 - (res_padding.get("risk_score", 0) if res_padding else 100)
    jitter_score = 100 - (res_jitter.get("risk_score", 0) if res_jitter else 100)
    flow_score = 100 - (res_flow.get("risk_score", 0) if res_flow else 100)

    # Weighted aggregate: 25% each pillar
    composite_score = round(
        0.25 * crypto_score +
        0.25 * padding_score +
        0.25 * jitter_score +
        0.25 * flow_score,
        1
    )

    all_anomalies = []
    all_anomalies.extend(res_tls.get("anomalies", []))
    if res_padding:
        all_anomalies.extend(res_padding.get("anomalies", []))
    if res_jitter:
        all_anomalies.extend(res_jitter.get("anomalies", []))
    if res_flow:
        all_anomalies.extend(res_flow.get("anomalies", []))

    mitm_compromised = (
        res_tls.get("ed25519_mitm_verified") is False
        or any("MITM" in a or "SIG_INVALID" in a for a in all_anomalies)
    )
    if mitm_compromised:
        composite_score = min(composite_score, 40.0)
        verdict = "HOSTILE_OR_DEFICIENT_GUARD"
    elif composite_score >= 85 and not any("WATERMARK" in a or "HOSTILE" in a for a in all_anomalies):
        verdict = "HARDENED_GUARD"
    elif composite_score >= 65:
        verdict = "DEGRADED_GUARD"
    else:
        verdict = "HOSTILE_OR_DEFICIENT_GUARD"

    return {
        "fingerprint": relay.get("fingerprint") or f"IP:{ip}:{port}",
        "nickname": relay.get("nickname") or f"node_{ip}_{port}",
        "ip": ip,
        "port": port,
        "composite_score": composite_score,
        "verdict": verdict,
        "crypto_score": crypto_score,
        "padding_score": padding_score,
        "jitter_score": jitter_score,
        "flow_score": flow_score,
        "tls_summary": res_tls,
        "padding_summary": res_padding,
        "jitter_summary": res_jitter,
        "flow_summary": res_flow,
        "anomalies": all_anomalies
    }

def finish(results, options):
    print("\n" + "="*75)
    print(" 🛡️  ENTRYMAP COMPREHENSIVE 4-PILLAR GUARD WIRE DEFENSE REPORT")
    print("="*75)
    print(f"Total Guards Audited Across All 4 Wire Vectors: {len(results)}\n")

    results.sort(key=lambda x: x["composite_score"], reverse=True)

    for idx, r in enumerate(results[:10], 1):
        icon = "🛡️ " if r["verdict"] == "HARDENED_GUARD" else ("⚠️ " if r["verdict"] == "DEGRADED_GUARD" else "🚨 ")
        print(f"[{idx}] {icon}{r['nickname']} ({r['ip']}:{r['port']}) - Verdict: {r['verdict']} [Score: {r['composite_score']}/100]")
        print(f"    1. TLS / Link Crypto       : {r['crypto_score']}/100 ({r['tls_summary']['tls_version']}, Link v{r['tls_summary']['link_protocol']}, Skew: {r['tls_summary']['clock_skew_seconds']}s)")
        if r['padding_summary']:
            print(f"    2. Channel Padding (Prop254): {r['padding_score']}/100 (Status: {r['padding_summary']['status']})")
        if r['jitter_summary']:
            print(f"    3. Timing / Watermark Guard: {r['jitter_score']}/100 (Mean RTT: {r['jitter_summary']['mean_rtt_ms']}ms, Jitter: {r['jitter_summary']['jitter_ms']}ms)")
        if r['flow_summary']:
            print(f"    4. Flow-Control / SENDME   : {r['flow_score']}/100 (Pipeline: {r['flow_summary']['pipeline_rate_cells_sec']} cells/s, Starvation: {r['flow_summary']['starvation_detected']})")

        if r["anomalies"]:
            print(f"    Detected Wire Anomalies    : {', '.join(r['anomalies'])}")
        print("-" * 75)

    if len(results) > 10:
        print(f"... and {len(results) - 10} additional probed relays.")
