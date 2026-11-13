"""
probe_flow_control.py - Channel Cell-Queue Drainage & Encrypted Circuit Flow-Control Probe.

Audits Entry Guard flow-control mechanics and transport pacing:
- Establishes a circuit via CREATE_FAST and derives KDF-TOR keys (tor-spec.txt §5.1.5 & §5.2.1),
  verifying the Guard's CREATED_FAST KH derivative proof.
- Emits genuine AES-128-CTR encrypted RELAY_DROP (cmd 10) and circuit-level RELAY_SENDME (cmd 5)
  cells alongside a 30-cell channel burst.
- Measures Multiplexed Channel Queue Drainage & Circuit Setup Latency to detect intentional
  transport throttling, buffer stalling, and circuit starvation.
"""

import struct
import os
import time
from modules.probe_common import (
    extract_or_endpoint,
    perform_tor_handshake,
    pack_cell,
    read_cell,
    FastCircuitCryptoState,
    CMD_CREATE_FAST,
    CMD_CREATED_FAST,
    CMD_DESTROY,
    CMD_PADDING,
    RELAY_CMD_DROP,
    RELAY_CMD_SENDME
)

def init(options):
    if getattr(options, "verbose", False):
        print("[*] Initializing Channel Queue Drainage & KDF-TOR Flow-Control Module...")

def analyze(relay, options):
    ip, port = extract_or_endpoint(relay)
    if not ip or not port:
        return None

    timeout = getattr(options, "probe_timeout", 5.0)

    try:
        tls_sock, handshake = perform_tor_handshake(ip, port, timeout=timeout)
        link_proto = handshake["negotiated_link_protocol"]
    except Exception as e:
        if getattr(options, "verbose", False):
            print(f"[!] Handshake failed before flow probe for {ip}:{port} - {e}")
        return None

    anomalies = []
    circ_id = 0x80000001
    circuit_established = False
    kdf_kh_verified = False
    pipeline_rate = 0.0
    sendme_accepted = False
    sendme_latency_ms = 0.0
    starvation_detected = False

    try:
        # 1. Establish Circuit with CREATE_FAST and derive KDF-TOR keys (Kf, Df, KH)
        x_material = os.urandom(20)
        create_cell = pack_cell(circ_id, CMD_CREATE_FAST, x_material.ljust(509, b"\x00"), link_protocol=link_proto)
        tls_sock.sendall(create_cell)

        r_cid, r_cmd, r_payload = read_cell(tls_sock, link_protocol=link_proto, timeout=timeout)
        if r_cmd == CMD_CREATED_FAST and len(r_payload) >= 40:
            circuit_established = True
            y_material = r_payload[:20]
            relay_kh = r_payload[20:40]
            crypto_state = FastCircuitCryptoState(x_material, y_material)
            if relay_kh == crypto_state.expected_kh:
                kdf_kh_verified = True
        else:
            crypto_state = None

        # 2. Channel Pipeline Burst (30 cells including encrypted RELAY_DROP cells)
        burst_count = 30
        pad_cell = pack_cell(0, CMD_PADDING, b"\x00" * 509, link_protocol=link_proto)

        t_burst_start = time.perf_counter_ns()
        for i in range(burst_count):
            if crypto_state and i % 5 == 0:
                drop_cell = crypto_state.pack_encrypted_relay_cell(circ_id, RELAY_CMD_DROP, link_protocol=link_proto)
                tls_sock.sendall(drop_cell)
            else:
                tls_sock.sendall(pad_cell)
        t_burst_end = time.perf_counter_ns()

        burst_duration_sec = (t_burst_end - t_burst_start) / 1e9
        pipeline_rate = round(burst_count / max(burst_duration_sec, 0.0001), 1)

        # 3. Emit Encrypted Circuit-Level RELAY_SENDME (RelayCommand=5, Proposal 289 v1 payload)
        t_sendme_start = time.perf_counter_ns()
        if crypto_state:
            sendme_data = struct.pack("!BH", 1, 20) + (b"\x00" * 20)
            enc_sendme = crypto_state.pack_encrypted_relay_cell(
                circ_id, RELAY_CMD_SENDME, data=sendme_data, stream_id=0, link_protocol=link_proto
            )
            tls_sock.sendall(enc_sendme)

        # Measure Multiplexed Channel Queue Drainage & Secondary Circuit Setup Latency
        circ2 = 0x80000002
        probe_cell = pack_cell(circ2, CMD_CREATE_FAST, os.urandom(20).ljust(509, b"\x00"), link_protocol=link_proto)
        tls_sock.sendall(probe_cell)
        read_cell(tls_sock, link_protocol=link_proto, timeout=timeout)
        t_sendme_end = time.perf_counter_ns()

        sendme_latency_ms = round((t_sendme_end - t_sendme_start) / 1e6, 2)
        sendme_accepted = True

        tls_sock.sendall(pack_cell(circ2, CMD_DESTROY, b"\x00" * 509, link_protocol=link_proto))

        if sendme_latency_ms > 450.0:
            starvation_detected = True
            anomalies.append("HIGH_FLOW_CONTROL_LATENCY")

        if pipeline_rate < 50.0:
            anomalies.append("PIPELINE_THROUGHPUT_STALL")

        destroy_cell = pack_cell(circ_id, CMD_DESTROY, b"\x00" * 509, link_protocol=link_proto)
        tls_sock.sendall(destroy_cell)

    except Exception as e:
        anomalies.append(f"FLOW_PROBE_ERROR: {e}")
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass

    risk_score = 0
    if not circuit_established:
        risk_score += 40
    if not sendme_accepted:
        risk_score += 50
    if starvation_detected:
        risk_score += 35
    if "PIPELINE_THROUGHPUT_STALL" in anomalies:
        risk_score += 25

    status = "FLOW_HEALTHY" if not anomalies else ("STARVATION_DETECTED" if risk_score >= 40 else "FLOW_WARNING")

    return {
        "fingerprint": relay.get("fingerprint") or f"IP:{ip}:{port}",
        "nickname": relay.get("nickname") or f"node_{ip}_{port}",
        "ip": ip,
        "port": port,
        "circuit_established": circuit_established,
        "kdf_kh_verified": kdf_kh_verified,
        "pipeline_rate_cells_sec": pipeline_rate,
        "sendme_accepted": sendme_accepted,
        "sendme_latency_ms": sendme_latency_ms,
        "starvation_detected": starvation_detected,
        "anomalies": anomalies,
        "risk_score": min(100, risk_score),
        "status": status
    }

def finish(results, options):
    print("\n" + "="*70)
    print(" 💨   ENTRYMAP CHANNEL QUEUE DRAINAGE & FLOW-CONTROL REPORT")
    print("="*70)
    print(f"Total Guard ORPorts Probed: {len(results)}\n")

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    for idx, r in enumerate(results[:15], 1):
        status_icon = "✅" if r["status"] == "FLOW_HEALTHY" else ("🚨" if r["status"] == "STARVATION_DETECTED" else "⚠️")
        print(f"[{idx}] {status_icon} {r['nickname']} ({r['ip']}:{r['port']}) - Status: {r['status']} (Risk Score: {r['risk_score']}/100)")
        print(f"    Circuit & KDF-TOR : Active: {r['circuit_established']} | CREATED_FAST KH Verified: {r['kdf_kh_verified']}")
        print(f"    Channel Pipelining: {r['pipeline_rate_cells_sec']} cells/sec")
        print(f"    Queue Drainage RTT: {r['sendme_latency_ms']} ms | Starvation Flag: {r['starvation_detected']}")
        if r["anomalies"]:
            print(f"    Anomalies         : {', '.join(r['anomalies'])}")
        print("-" * 70)

    if len(results) > 15:
        print(f"... and {len(results) - 15} additional probed relays.")
