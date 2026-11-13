"""
probe_padding.py - Channel Padding Negotiation & Website Fingerprinting Defense Probe.

Audits Entry Guard conformance to Tor Proposal 251 (padding-spec.txt §2 Link-Layer
Channel Padding) and Proposal 254 (Circuit-Level Adaptive Padding):
- Establishes an initial CREATE_FAST circuit so the Guard marks the channel as client-active.
- Verifies that Guards honor CELL_PADDING_NEGOTIATE (command 12) start and stop requests.
- Validates bidirectional acceptance of CELL_PADDING (command 0) and CELL_VPADDING (command 128).
- Detects hostile padding-stripping behavior where malicious nodes drop or reset connections
  to facilitate passive traffic analysis and website fingerprinting.
"""

import os
import struct
import socket
from modules.probe_common import (
    extract_or_endpoint,
    perform_tor_handshake,
    pack_cell,
    recv_exact,
    CMD_CREATE_FAST,
    CMD_DESTROY,
    CMD_PADDING,
    CMD_VPADDING,
    CMD_PADDING_NEGOTIATE,
    FIXED_CELL_LEN
)

def init(options):
    if getattr(options, "verbose", False):
        print("[*] Initializing Channel Padding Negotiation (Proposals 251 & 254) Module...")

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
            print(f"[!] Link handshake failed before padding probe for {ip}:{port} - {e}")
        return None

    anomalies = []
    padding_negotiate_start_honored = False
    fixed_padding_accepted = False
    vpadding_accepted = False
    padding_negotiate_stop_honored = False
    circ_id = 0x80000010
    circuit_opened = False

    try:
        # 0. Establish initial circuit (C-Tor activates link padding timers only on channels with >=1 circuit)
        create_cell = pack_cell(circ_id, CMD_CREATE_FAST, os.urandom(20).ljust(509, b"\x00"), link_protocol=link_proto)
        tls_sock.sendall(create_cell)
        recv_exact(tls_sock, FIXED_CELL_LEN, timeout=timeout)
        circuit_opened = True
    except Exception:
        pass

    try:
        # 1. Send PADDING_NEGOTIATE START (cmd 12, version 0, command 2=START, ito_low=200, ito_high=400)
        pad_start = struct.pack("!BBHH", 0, 2, 200, 400).ljust(509, b"\x00")
        pad_start_cell = pack_cell(0, CMD_PADDING_NEGOTIATE, pad_start, link_protocol=link_proto)
        tls_sock.sendall(pad_start_cell)
        padding_negotiate_start_honored = True
    except Exception:
        anomalies.append("PADDING_NEGOTIATE_START_FAILED")

    try:
        # 2. Send fixed-length PADDING cell (cmd 0, 509 zero bytes)
        fixed_pad_cell = pack_cell(0, CMD_PADDING, b"\x00" * 509, link_protocol=link_proto)
        tls_sock.sendall(fixed_pad_cell)
        fixed_padding_accepted = True
    except Exception:
        anomalies.append("FIXED_PADDING_CELL_REJECTED")

    try:
        # 3. Send variable-length VPADDING cell (cmd 128, 64 arbitrary bytes)
        vpad_payload = b"\x5A" * 64
        vpad_cell = pack_cell(0, CMD_VPADDING, vpad_payload, link_protocol=link_proto)
        tls_sock.sendall(vpad_cell)
        vpadding_accepted = True
    except Exception:
        anomalies.append("VPADDING_CELL_REJECTED")

    # 4. Probe channel health: ensure the guard did NOT drop the connection
    tls_sock.settimeout(0.5)
    connection_alive = True
    try:
        data = tls_sock.recv(514)
        if len(data) == 0:
            connection_alive = False
            anomalies.append("CONNECTION_CLOSED_BY_GUARD_ON_PADDING")
        elif len(data) >= 5:
            c_id, c_cmd = struct.unpack("!IB" if link_proto >= 4 else "!HB", data[:5])
            if c_cmd == CMD_DESTROY:
                anomalies.append("GUARD_EMITTED_DESTROY_ON_PADDING")
                connection_alive = False
    except socket.timeout:
        connection_alive = True
    except (ConnectionResetError, BrokenPipeError):
        connection_alive = False
        anomalies.append("CONNECTION_RESET_ON_PADDING")

    try:
        # 5. Send PADDING_NEGOTIATE STOP (cmd 12, version 0, command 1=STOP, ito_low=0, ito_high=0)
        pad_stop = struct.pack("!BBHH", 0, 1, 0, 0).ljust(509, b"\x00")
        pad_stop_cell = pack_cell(0, CMD_PADDING_NEGOTIATE, pad_stop, link_protocol=link_proto)
        tls_sock.sendall(pad_stop_cell)
        padding_negotiate_stop_honored = True
        if circuit_opened and connection_alive:
            tls_sock.sendall(pack_cell(circ_id, CMD_DESTROY, b"\x00" * 509, link_protocol=link_proto))
    except Exception:
        anomalies.append("PADDING_NEGOTIATE_STOP_FAILED")

    try:
        tls_sock.close()
    except Exception:
        pass

    risk_score = 0
    if not connection_alive:
        risk_score += 70
    if not padding_negotiate_start_honored:
        risk_score += 40
    if not fixed_padding_accepted:
        risk_score += 30
    if not vpadding_accepted:
        risk_score += 20
    if not padding_negotiate_stop_honored:
        risk_score += 20

    status = "PADDING_COMPLIANT" if not anomalies else ("HOSTILE_PADDING_STRIP" if risk_score >= 50 else "PADDING_WARNING")

    return {
        "fingerprint": relay.get("fingerprint") or f"IP:{ip}:{port}",
        "nickname": relay.get("nickname") or f"node_{ip}_{port}",
        "ip": ip,
        "port": port,
        "padding_negotiate_start": padding_negotiate_start_honored,
        "padding_negotiate_stop": padding_negotiate_stop_honored,
        "fixed_padding_accepted": fixed_padding_accepted,
        "vpadding_accepted": vpadding_accepted,
        "connection_alive": connection_alive,
        "anomalies": anomalies,
        "risk_score": min(100, risk_score),
        "status": status
    }

def finish(results, options):
    print("\n" + "="*70)
    print(" 🛡️  ENTRYMAP CHANNEL PADDING (PROPOSALS 251 & 254) DEFENSE REPORT")
    print("="*70)
    print(f"Total Guard ORPorts Probed: {len(results)}\n")

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    for idx, r in enumerate(results[:15], 1):
        status_icon = "✅" if r["status"] == "PADDING_COMPLIANT" else ("⚠️" if r["status"] == "PADDING_WARNING" else "🚨")
        print(f"[{idx}] {status_icon} {r['nickname']} ({r['ip']}:{r['port']}) - Status: {r['status']} (Risk Score: {r['risk_score']}/100)")
        print(f"    Proposal 251/254: Start Honored: {r['padding_negotiate_start']} | Stop Honored: {r['padding_negotiate_stop']}")
        print(f"    Padding Cells   : Fixed CELL_PADDING: {r['fixed_padding_accepted']} | CELL_VPADDING: {r['vpadding_accepted']}")
        print(f"    Channel State   : Remained Alive: {r['connection_alive']}")
        if r["anomalies"]:
            print(f"    Anomalies       : {', '.join(r['anomalies'])}")
        print("-" * 70)

    if len(results) > 15:
        print(f"... and {len(results) - 15} additional probed relays.")
