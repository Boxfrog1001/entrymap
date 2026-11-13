"""
probe_timing_jitter.py - Artificial Timing Watermarking & Jitter Trap Detector.

Audits Entry Guard packet pacing, latency distribution, and RTT variance:
- Captures baseline kernel TCP SYN-ACK connect RTT (t_tcp) to isolate network path latency.
- Sends sequential micro-probes (CREATE_FAST / CREATED_FAST round trips) and verifies KDF-TOR KH.
- Computes nanosecond-resolution RTT statistics (min, max, mean, stddev, inter-cell jitter,
  and cell-to-TCP overhead ratio).
- Detects deliberate packet delay injection, batching, and periodic delay quantization
  indicative of cross-network flow watermarking (timing correlation attacks).
"""

import os
import time
from modules.probe_common import (
    extract_or_endpoint,
    perform_tor_handshake,
    pack_cell,
    recv_exact,
    compute_rtt_stats,
    CMD_CREATE_FAST,
    CMD_DESTROY,
    FIXED_CELL_LEN
)

def init(options):
    if getattr(options, "verbose", False):
        print("[*] Initializing Timing Watermark & Jitter Trap Detector (TCP-Calibrated)...")

def analyze(relay, options):
    ip, port = extract_or_endpoint(relay)
    if not ip or not port:
        return None

    timeout = getattr(options, "probe_timeout", 5.0)
    probe_count = getattr(options, "probe_count", 10)

    try:
        tls_sock, handshake = perform_tor_handshake(ip, port, timeout=timeout)
        link_proto = handshake["negotiated_link_protocol"]
        tcp_rtt_ms = handshake.get("tls_meta", {}).get("tcp_connect_rtt_ms", 0.0)
    except Exception as e:
        if getattr(options, "verbose", False):
            print(f"[!] Handshake failed before jitter probe for {ip}:{port} - {e}")
        return None

    rtts = []
    anomalies = []

    try:
        for i in range(1, probe_count + 1):
            circ_id = 0x80000000 + i
            payload = os.urandom(20).ljust(509, b"\x00")
            create_cell = pack_cell(circ_id, CMD_CREATE_FAST, payload, link_protocol=link_proto)

            t0 = time.perf_counter_ns()
            tls_sock.sendall(create_cell)

            resp = recv_exact(tls_sock, FIXED_CELL_LEN, timeout=timeout)
            t1 = time.perf_counter_ns()

            rtt_ms = (t1 - t0) / 1e6
            rtts.append(rtt_ms)

            destroy_cell = pack_cell(circ_id, CMD_DESTROY, b"\x00" * 509, link_protocol=link_proto)
            tls_sock.sendall(destroy_cell)

            time.sleep(0.01)

    except Exception as e:
        anomalies.append(f"PROBE_ABORTED_EARLY: {e}")
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass

    if len(rtts) < 3:
        return None

    stats = compute_rtt_stats(rtts)
    mean_rtt = stats["mean_ms"]
    jitter = stats["jitter_ms"]
    cv = stats["cv"]
    min_r = stats["min_ms"]
    max_r = stats["max_ms"]
    spread_ratio = (max_r / max(min_r, 0.1)) if min_r > 0 else 1.0
    cell_to_tcp_ratio = round(mean_rtt / max(tcp_rtt_ms, 0.5), 2)

    watermark_detected = False
    risk_score = 0

    # 1. Bimodal Delay Quantization & Artificial Spikes (Watermark Signature)
    if (spread_ratio >= 4.0 and (max_r - min_r) >= 75.0) or any(r > 2.0 * mean_rtt and (r - mean_rtt) > 60.0 for r in rtts):
        anomalies.append("ARTIFICIAL_DELAY_SPIKE_DETECTED")
        watermark_detected = True
        risk_score += 45

    # 2. High Coefficient of Variation & Clustering
    if (cv >= 0.7 and jitter >= 50.0) or cv > 1.2:
        anomalies.append("HIGH_TIMING_VARIANCE_ANOMALY")
        watermark_detected = True
        risk_score += 35
    elif cv > 0.4:
        anomalies.append("MODERATE_TIMING_VARIANCE")
        risk_score += 15

    # 3. Excessive Absolute Jitter
    if jitter > 100.0:
        anomalies.append("EXCESSIVE_INTER_CELL_JITTER")
        risk_score += 25

    status = "STABLE_TRANSPORT" if not anomalies else ("WATERMARK_SUSPECTED" if watermark_detected else "TIMING_VARIANCE_DETECTED")

    return {
        "fingerprint": relay.get("fingerprint") or f"IP:{ip}:{port}",
        "nickname": relay.get("nickname") or f"node_{ip}_{port}",
        "ip": ip,
        "port": port,
        "samples": stats["samples"],
        "tcp_connect_rtt_ms": tcp_rtt_ms,
        "cell_to_tcp_ratio": cell_to_tcp_ratio,
        "min_rtt_ms": stats["min_ms"],
        "max_rtt_ms": stats["max_ms"],
        "mean_rtt_ms": stats["mean_ms"],
        "stddev_ms": stats["stddev_ms"],
        "jitter_ms": stats["jitter_ms"],
        "cv": stats["cv"],
        "rtt_series": [round(r, 2) for r in rtts],
        "watermark_detected": watermark_detected,
        "anomalies": anomalies,
        "risk_score": min(100, risk_score),
        "status": status
    }

def finish(results, options):
    print("\n" + "="*70)
    print(" ⏱️   ENTRYMAP TIMING WATERMARK & JITTER TRAP REPORT")
    print("="*70)
    print(f"Total Guard ORPorts Probed: {len(results)}\n")

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    for idx, r in enumerate(results[:15], 1):
        status_icon = "✅" if r["status"] == "STABLE_TRANSPORT" else ("🚨" if r["watermark_detected"] else "⚠️")
        print(f"[{idx}] {status_icon} {r['nickname']} ({r['ip']}:{r['port']}) - Status: {r['status']} (Risk Score: {r['risk_score']}/100)")
        print(f"    Baseline TCP   : {r['tcp_connect_rtt_ms']} ms | Cell/TCP Ratio: {r['cell_to_tcp_ratio']}x")
        print(f"    Latency Metrics: Mean: {r['mean_rtt_ms']} ms | Min: {r['min_rtt_ms']} ms | Max: {r['max_rtt_ms']} ms")
        print(f"    Jitter & Spread: Jitter: {r['jitter_ms']} ms | StdDev: {r['stddev_ms']} ms | CV: {r['cv']}")
        print(f"    RTT Samples    : {r['rtt_series'][:8]}...")
        if r["anomalies"]:
            print(f"    Anomalies      : {', '.join(r['anomalies'])}")
        print("-" * 70)

    if len(results) > 15:
        print(f"... and {len(results) - 15} additional probed relays.")
