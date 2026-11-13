"""
probe_common.py - Shared Tor Wire Protocol & Cryptographic Utilities for entrymap.
Implements cell serialization, TLS negotiation, TCP connect latency calibration,
Ed25519 CERTS cell cross-signature verification (cert-spec.txt §2.1 & tor-spec.txt §4.2),
and CREATE_FAST KDF-TOR circuit key derivation (tor-spec.txt §5.1.5 & §5.2.1).
"""

import ssl
import socket
import struct
import os
import time
import math
import hashlib
from datetime import datetime, timezone

# Tor Link-Layer Cell Commands (tor-spec.txt Section 3)
CMD_PADDING = 0
CMD_CREATE = 1
CMD_CREATED = 2
CMD_RELAY = 3
CMD_DESTROY = 4
CMD_CREATE_FAST = 5
CMD_CREATED_FAST = 6
CMD_VERSIONS = 7
CMD_NETINFO = 8
CMD_RELAY_EARLY = 9
CMD_CREATE2 = 10
CMD_CREATED2 = 11
CMD_PADDING_NEGOTIATE = 12
CMD_VPADDING = 128
CMD_CERTS = 129
CMD_AUTH_CHALLENGE = 130
CMD_AUTHENTICATE = 131

# Encrypted Relay Cell Sub-Commands (tor-spec.txt Section 6.1)
RELAY_CMD_DATA = 2
RELAY_CMD_END = 3
RELAY_CMD_SENDME = 5
RELAY_CMD_EXTEND = 6
RELAY_CMD_DROP = 10
RELAY_CMD_PADDING_NEGOTIATE = 41
RELAY_CMD_PADDING_NEGOTIATED = 42

FIXED_CELL_LEN = 514
FIXED_PAYLOAD_LEN = 509

VARIABLE_COMMANDS = {CMD_VERSIONS, CMD_VPADDING, CMD_CERTS, CMD_AUTH_CHALLENGE, CMD_AUTHENTICATE}

def extract_or_endpoint(relay):
    """
    Extracts IPv4 ORPort endpoint (ip, port) from relay descriptor or search argument.
    """
    if not relay:
        return None, None

    if isinstance(relay, str):
        if ":" in relay:
            parts = relay.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 9001
        return relay, 9001

    addresses = relay.get("or_addresses") or []
    for addr in addresses:
        if addr.startswith("["):
            continue
        if ":" in addr:
            parts = addr.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                continue

    ip = relay.get("ip") or relay.get("address")
    or_port = relay.get("or_port")
    if ip and or_port:
        try:
            return str(ip), int(or_port)
        except ValueError:
            pass

    return None, None

def recv_exact(sock, n, timeout=5.0):
    """
    Reads exactly n bytes from a socket or raises ConnectionResetError.
    """
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)

def open_tls_socket(ip, port, timeout=5.0):
    """
    Initiates TCP connection (recording baseline SYN-ACK RTT in ms) and wraps with
    modern TLS client context. Captures raw DER certificate, SHA-256 digest,
    TLS version, and negotiated cipher suite.
    """
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    t0_tcp = time.perf_counter_ns()
    raw_sock.connect((ip, port))
    t1_tcp = time.perf_counter_ns()
    tcp_connect_rtt_ms = round((t1_tcp - t0_tcp) / 1e6, 3)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0_tls = time.perf_counter_ns()
    tls_sock = ctx.wrap_socket(raw_sock)
    t1_tls = time.perf_counter_ns()
    tls_handshake_ms = round((t1_tls - t0_tls) / 1e6, 3)

    tls_version = tls_sock.version() or "UNKNOWN"
    cipher_info = tls_sock.cipher()
    cipher_name = cipher_info[0] if cipher_info else "UNKNOWN"
    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0

    der_cert = tls_sock.getpeercert(binary_form=True) or b""
    der_sha256 = hashlib.sha256(der_cert).digest() if der_cert else b""

    cert_info = parse_x509_certificate(der_cert)

    metadata = {
        "tls_version": tls_version,
        "cipher_name": cipher_name,
        "cipher_bits": cipher_bits,
        "cert": cert_info,
        "raw_der_len": len(der_cert),
        "tls_cert_sha256": der_sha256,
        "tcp_connect_rtt_ms": tcp_connect_rtt_ms,
        "tls_handshake_ms": tls_handshake_ms
    }

    return tls_sock, metadata

def parse_x509_certificate(der_bytes):
    """
    Parses outer TLS X.509 certificate metadata using cryptography module.
    """
    if not der_bytes:
        return {"valid": False, "error": "No certificate presented"}

    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der_bytes)
        now = datetime.now(timezone.utc)

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_valid_date = (not_before <= now <= not_after)

        return {
            "valid": True,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": hex(cert.serial_number),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "is_date_valid": is_valid_date,
            "sig_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
            "key_size": getattr(cert.public_key(), "key_size", 0)
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def parse_and_verify_ed25519_certs(cert_map, outer_tls_der_sha256):
    """
    Parses and cryptographically verifies Tor Ed25519 certificates from a CERTS cell
    in strict compliance with cert-spec.txt §2.1 and tor-spec.txt §4.2:
      - Type 4 (ED25519_SIGNING): Extracts 32-byte ephemeral Ed25519 signing key
        and verifies signature against the embedded master Ed25519 identity key extension (0x04) if present.
      - Type 5 (ED25519_TLS_LINK): Verifies that CERTIFIED_KEY equals SHA-256(outer_tls_der_cert)
        and verifies the 64-byte Ed25519 signature using Type 4's signing key.
    """
    result = {
        "ed25519_signing_present": 4 in cert_map,
        "ed25519_tls_link_present": 5 in cert_map,
        "tls_link_digest_matches": False,
        "type4_sig_valid": False,
        "type5_sig_valid": False,
        "certs_unexpired": False,
        "mitm_verified": False,
        "ed25519_identity_hex": None
    }

    if 4 not in cert_map or 5 not in cert_map:
        return result

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        def parse_tor_ed_cert(raw):
            if len(raw) < 104:  # 40 byte fixed header + 64 byte sig
                return None
            ver, ctype, exp_hours, ktype = struct.unpack("!BBIB", raw[:7])
            certified_key = raw[7:39]
            n_ext = raw[39]
            idx = 40
            extensions = {}
            for _ in range(n_ext):
                if idx + 4 > len(raw) - 64:
                    return None
                ext_len, ext_type, ext_flags = struct.unpack("!HBB", raw[idx:idx+4])
                idx += 4
                if idx + ext_len > len(raw) - 64:
                    return None
                extensions[ext_type] = raw[idx:idx+ext_len]
                idx += ext_len
            signed_body = raw[:idx]
            signature = raw[idx:idx+64]
            if len(signature) != 64:
                return None
            return {
                "version": ver,
                "cert_type": ctype,
                "exp_hours": exp_hours,
                "key_type": ktype,
                "certified_key": certified_key,
                "extensions": extensions,
                "signed_body": signed_body,
                "signature": signature
            }

        c4 = parse_tor_ed_cert(cert_map[4])
        c5 = parse_tor_ed_cert(cert_map[5])
        if not c4 or not c5:
            return result

        now_hours = int(time.time() // 3600)
        if c4["exp_hours"] > now_hours and c5["exp_hours"] > now_hours:
            result["certs_unexpired"] = True

        # Verify Type 4 signature if SignedWithEd25519Key extension (type 4) is included
        signing_pubkey_bytes = c4["certified_key"]
        if 4 in c4["extensions"] and len(c4["extensions"][4]) == 32:
            id_key_bytes = c4["extensions"][4]
            result["ed25519_identity_hex"] = id_key_bytes.hex().upper()
            id_pub = Ed25519PublicKey.from_public_bytes(id_key_bytes)
            id_pub.verify(c4["signature"], c4["signed_body"])
            result["type4_sig_valid"] = True

        # Verify Type 5 certified key matches outer TLS X.509 certificate SHA-256
        if outer_tls_der_sha256 and c5["certified_key"] == outer_tls_der_sha256:
            result["tls_link_digest_matches"] = True

        # Verify Type 5 signature using Type 4 certified signing key
        signing_pub = Ed25519PublicKey.from_public_bytes(signing_pubkey_bytes)
        signing_pub.verify(c5["signature"], c5["signed_body"])
        result["type5_sig_valid"] = True

        if result["tls_link_digest_matches"] and result["type5_sig_valid"] and result["certs_unexpired"]:
            result["mitm_verified"] = True

    except Exception:
        pass

    return result

def derive_kdf_tor(x_bytes, y_bytes):
    """
    Implements KDF-TOR (tor-spec.txt §5.2.1) over K0 = X | Y (40 bytes).
    Returns dict with:
      - kh (20 bytes): Expected CREATED_FAST derivative proof
      - df (20 bytes): Forward SHA-1 digest seed
      - db (20 bytes): Backward SHA-1 digest seed
      - kf (16 bytes): Forward AES-128-CTR key
      - kb (16 bytes): Backward AES-128-CTR key
    """
    k0 = x_bytes + y_bytes
    stream = b"".join(hashlib.sha1(k0 + bytes([i])).digest() for i in range(5))
    return {
        "kh": stream[0:20],
        "df": stream[20:40],
        "db": stream[40:60],
        "kf": stream[60:76],
        "kb": stream[76:92]
    }

class FastCircuitCryptoState:
    """
    Maintains running SHA-1 forward digest (Df) and AES-128-CTR keystream (Kf)
    for a circuit established via CREATE_FAST / CREATED_FAST (tor-spec.txt §5.1.5 & §6.1).
    Allows entrymap to emit genuine encrypted RELAY cells (e.g. RELAY_DROP, RELAY_SENDME).
    """
    def __init__(self, x_bytes, y_bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        keys = derive_kdf_tor(x_bytes, y_bytes)
        self.expected_kh = keys["kh"]
        self.forward_hash = hashlib.sha1(keys["df"])
        cipher = Cipher(algorithms.AES(keys["kf"]), modes.CTR(b"\x00" * 16))
        self.encryptor = cipher.encryptor()

    def pack_encrypted_relay_cell(self, circ_id, relay_cmd, data=b"", stream_id=0, link_protocol=5):
        data = data[:498]
        header_zero_digest = struct.pack("!BHH4sH", relay_cmd, 0, stream_id, b"\x00\x00\x00\x00", len(data))
        padded_zero = (header_zero_digest + data).ljust(FIXED_PAYLOAD_LEN, b"\x00")

        self.forward_hash.update(padded_zero)
        digest_4 = self.forward_hash.copy().digest()[:4]

        plain_cell_body = (
            struct.pack("!BHH4sH", relay_cmd, 0, stream_id, digest_4, len(data)) + data
        ).ljust(FIXED_PAYLOAD_LEN, b"\x00")

        encrypted_body = self.encryptor.update(plain_cell_body)
        return pack_cell(circ_id, CMD_RELAY, encrypted_body, link_protocol=link_protocol)

def pack_cell(circ_id, cmd, payload=b"", link_protocol=5):
    """
    Packs a Tor link-layer cell according to tor-spec.txt.
    """
    if cmd == CMD_VERSIONS:
        return struct.pack("!HBH", 0, CMD_VERSIONS, len(payload)) + payload

    circ_fmt = "!I" if link_protocol >= 4 else "!H"

    if cmd in VARIABLE_COMMANDS:
        return struct.pack(circ_fmt + "BH", circ_id, cmd, len(payload)) + payload
    else:
        if len(payload) > FIXED_PAYLOAD_LEN:
            payload = payload[:FIXED_PAYLOAD_LEN]
        return struct.pack(circ_fmt + "B", circ_id, cmd) + payload.ljust(FIXED_PAYLOAD_LEN, b"\x00")

def read_cell(sock, link_protocol=5, timeout=5.0):
    """
    Reads a single Tor cell from the socket.
    """
    if link_protocol < 4:
        circ_hdr_len = 2
        circ_fmt = "!H"
    else:
        circ_hdr_len = 4
        circ_fmt = "!I"

    hdr = recv_exact(sock, circ_hdr_len + 1, timeout=timeout)
    circ_id, cmd = struct.unpack(circ_fmt + "B", hdr)

    if cmd in VARIABLE_COMMANDS:
        len_bytes = recv_exact(sock, 2, timeout=timeout)
        length = struct.unpack("!H", len_bytes)[0]
        payload = recv_exact(sock, length, timeout=timeout)
    else:
        payload = recv_exact(sock, FIXED_PAYLOAD_LEN, timeout=timeout)

    return circ_id, cmd, payload

def perform_tor_handshake(ip, port, timeout=5.0, link_versions=(3, 4, 5)):
    """
    Executes full Tor in-protocol Link Handshake with an ORPort:
    1. TCP connect (timed) + TLS 1.3 / 1.2 handshake
    2. Exchanges VERSIONS cells (negotiates link protocol)
    3. Parses CERTS cell and cryptographically verifies Ed25519 Type 4 & Type 5 cross-certs
    4. Reads AUTH_CHALLENGE and NETINFO (computes clock skew)
    5. Sends client NETINFO cell
    """
    tls_sock, tls_meta = open_tls_socket(ip, port, timeout=timeout)

    v_payload = b"".join(struct.pack("!H", v) for v in link_versions)
    versions_cell = struct.pack("!HBH", 0, CMD_VERSIONS, len(v_payload)) + v_payload
    tls_sock.sendall(versions_cell)

    hdr = recv_exact(tls_sock, 5, timeout=timeout)
    circ_id, cmd, vlen = struct.unpack("!HBH", hdr)
    if cmd != CMD_VERSIONS:
        tls_sock.close()
        raise ValueError(f"Expected VERSIONS cell (cmd 7), got cmd {cmd}")

    v_data = recv_exact(tls_sock, vlen, timeout=timeout)
    relay_versions = [struct.unpack("!H", v_data[i*2:i*2+2])[0] for i in range(vlen // 2)]

    common_versions = set(link_versions).intersection(relay_versions)
    if not common_versions:
        tls_sock.close()
        raise ValueError(f"No common link protocol between client {link_versions} and relay {relay_versions}")

    negotiated_link = max(common_versions)

    certs_parsed = []
    cert_map = {}
    auth_challenge_seen = False
    relay_timestamp = None
    clock_skew = None

    start_t = time.time()
    while (time.time() - start_t) < timeout:
        c_id, c_cmd, payload = read_cell(tls_sock, link_protocol=negotiated_link, timeout=timeout)
        if c_cmd == CMD_CERTS:
            if payload:
                num_certs = payload[0]
                idx = 1
                for _ in range(num_certs):
                    if idx + 3 > len(payload):
                        break
                    ctype = payload[idx]
                    clen = struct.unpack("!H", payload[idx+1:idx+3])[0]
                    idx += 3
                    cbody = payload[idx:idx+clen]
                    idx += clen
                    certs_parsed.append(ctype)
                    cert_map[ctype] = cbody
        elif c_cmd == CMD_AUTH_CHALLENGE:
            auth_challenge_seen = True
        elif c_cmd == CMD_NETINFO:
            if len(payload) >= 4:
                relay_timestamp = struct.unpack("!I", payload[:4])[0]
                local_now = int(time.time())
                clock_skew = relay_timestamp - local_now
            break

    ed25519_audit = parse_and_verify_ed25519_certs(cert_map, tls_meta.get("tls_cert_sha256", b""))

    local_ts = int(time.time())
    other_ip_bytes = socket.inet_aton(ip) if "." in ip else b"\x7f\x00\x00\x01"
    netinfo_payload = struct.pack("!IBB4sB", local_ts, 4, 4, other_ip_bytes, 0)
    client_netinfo = pack_cell(0, CMD_NETINFO, netinfo_payload, link_protocol=negotiated_link)
    tls_sock.sendall(client_netinfo)

    handshake_info = {
        "ip": ip,
        "port": port,
        "tls_meta": tls_meta,
        "relay_versions": relay_versions,
        "negotiated_link_protocol": negotiated_link,
        "certs_types": certs_parsed,
        "ed25519_audit": ed25519_audit,
        "auth_challenge_seen": auth_challenge_seen,
        "relay_timestamp": relay_timestamp,
        "clock_skew_seconds": clock_skew
    }

    return tls_sock, handshake_info

def compute_rtt_stats(rtts):
    if not rtts:
        return {
            "samples": 0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "stddev_ms": 0.0,
            "jitter_ms": 0.0,
            "cv": 0.0
        }

    n = len(rtts)
    mean_rtt = sum(rtts) / n
    variance = sum((r - mean_rtt) ** 2 for r in rtts) / n
    stddev = math.sqrt(variance)
    jitter = sum(abs(rtts[i+1] - rtts[i]) for i in range(n - 1)) / (n - 1) if n > 1 else 0.0
    cv = (stddev / mean_rtt) if mean_rtt > 0 else 0.0

    return {
        "samples": n,
        "min_ms": round(min(rtts), 3),
        "max_ms": round(max(rtts), 3),
        "mean_ms": round(mean_rtt, 3),
        "stddev_ms": round(stddev, 3),
        "jitter_ms": round(jitter, 3),
        "cv": round(cv, 4)
    }
