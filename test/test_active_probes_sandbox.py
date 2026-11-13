"""
test_active_probes_sandbox.py - Rigorous Multi-Vector Active Wire Defense Testbench for entrymap.
"""

import sys
import os
import socket
import ssl
import struct
import threading
import time
import datetime
import hashlib
import tempfile
import shutil

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(base_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from modules import (
    probe_tls_fingerprint,
    probe_padding,
    probe_timing_jitter,
    probe_flow_control,
    probe_guard_wire
)
from modules.probe_common import (
    pack_cell,
    recv_exact,
    derive_kdf_tor,
    CMD_VERSIONS,
    CMD_CERTS,
    CMD_NETINFO,
    CMD_CREATE_FAST,
    CMD_CREATED_FAST,
    CMD_PADDING_NEGOTIATE,
    CMD_PADDING,
    CMD_DESTROY,
    FIXED_CELL_LEN
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID

class MockOptions:
    def __init__(self, **kwargs):
        self.target = kwargs.get("target")
        self.probe_timeout = kwargs.get("probe_timeout", 3.0)
        self.probe_count = kwargs.get("probe_count", 6)
        self.verbose = kwargs.get("verbose", False)
        self.all_relays = True
        self.guards_only = False
        self.hsdir_only = False
        self.fingerprint = None
        self.as_num = None
        self.country = None
        self.search = None
        self.no_verify = False

def build_valid_ed25519_certs_payload(der_cert_bytes):
    """
    Constructs cryptographically valid Tor Ed25519 Type 4 (ED25519_SIGNING) and
    Type 5 (ED25519_TLS_LINK) certificates per cert-spec.txt §2.1 bound to der_cert_bytes.
    """
    master_sk = ed25519.Ed25519PrivateKey.generate()
    master_pk = master_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    signing_sk = ed25519.Ed25519PrivateKey.generate()
    signing_pk = signing_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    exp_hours = int(time.time() // 3600) + 720

    # Type 4: version=1, cert_type=4, exp_hours, key_type=1, certified_key=signing_pk, n_ext=1 (ext_type=4: master_pk)
    ext_type4 = struct.pack("!HBB", 32, 4, 0) + master_pk
    c4_body = struct.pack("!BBIB", 1, 4, exp_hours, 1) + signing_pk + b"\x01" + ext_type4
    c4_sig = master_sk.sign(c4_body)
    cert4 = c4_body + c4_sig

    # Type 5: version=1, cert_type=5, exp_hours, key_type=2, certified_key=SHA256(der_cert), n_ext=0
    tls_sha256 = hashlib.sha256(der_cert_bytes).digest()
    c5_body = struct.pack("!BBIB", 1, 5, exp_hours, 2) + tls_sha256 + b"\x00"
    c5_sig = signing_sk.sign(c5_body)
    cert5 = c5_body + c5_sig

    return (
        b"\x02" +
        struct.pack("!BH", 4, len(cert4)) + cert4 +
        struct.pack("!BH", 5, len(cert5)) + cert5
    )

def generate_cert_files(cert_dir=None):
    if cert_dir is None:
        cert_dir = os.path.join(tempfile.gettempdir(), "entrymap_test_certs")
    os.makedirs(cert_dir, mode=0o700, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock.guard.local")])
    now = datetime.datetime.now(datetime.timezone.utc)

    valid_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    exp_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=60))
        .not_valid_after(now - datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )

    v_c_path = os.path.join(cert_dir, "valid_cert.pem")
    v_k_path = os.path.join(cert_dir, "valid_key.pem")
    e_c_path = os.path.join(cert_dir, "expired_cert.pem")
    e_k_path = os.path.join(cert_dir, "expired_key.pem")

    with open(v_c_path, "wb") as f:
        f.write(valid_cert.public_bytes(serialization.Encoding.PEM))
    with open(v_k_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(e_c_path, "wb") as f:
        f.write(exp_cert.public_bytes(serialization.Encoding.PEM))
    with open(e_k_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    valid_der = valid_cert.public_bytes(serialization.Encoding.DER)
    return v_c_path, v_k_path, e_c_path, e_k_path, valid_der

class MockAdversarialServer:
    def __init__(self, mode, port, cert_file, key_file, valid_der=b""):
        self.mode = mode
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.valid_der = valid_der
        self.server_sock = None
        self.running = False
        self.thread = None

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", self.port))
        self.server_sock.listen(5)
        self.running = True

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def stop(self):
        self.running = False
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass

    def _run(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_file, self.key_file)

        while self.running:
            try:
                self.server_sock.settimeout(0.5)
                client_raw, _ = self.server_sock.accept()
                tls_client = ctx.wrap_socket(client_raw, server_side=True)
                t = threading.Thread(target=self._handle_client, args=(tls_client,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, conn):
        try:
            conn.settimeout(4.0)

            hdr = recv_exact(conn, 5)
            cid, cmd, vlen = struct.unpack("!HBH", hdr)
            recv_exact(conn, vlen)

            if self.mode == "degraded_tls":
                v_resp = struct.pack("!HBH", 0, CMD_VERSIONS, 2) + struct.pack("!H", 3)
                conn.sendall(v_resp)

                certs_data = struct.pack("!BBH", 1, 2, 100) + (b"\x11" * 100)
                conn.sendall(struct.pack("!HBH", 0, CMD_CERTS, len(certs_data)) + certs_data)

                skewed_time = int(time.time()) + 7200
                netinfo_payload = struct.pack("!IBB4sB", skewed_time, 4, 4, socket.inet_aton("127.0.0.1"), 0).ljust(509, b"\x00")
                conn.sendall(struct.pack("!HB", 0, CMD_NETINFO) + netinfo_payload)
                return

            v_resp = struct.pack("!HBH", 0, CMD_VERSIONS, 4) + struct.pack("!HH", 4, 5)
            conn.sendall(v_resp)

            certs_payload = build_valid_ed25519_certs_payload(self.valid_der)
            conn.sendall(struct.pack("!IBH", 0, CMD_CERTS, len(certs_payload)) + certs_payload)

            now = int(time.time())
            netinfo_payload = struct.pack("!IBB4sB", now, 4, 4, socket.inet_aton("127.0.0.1"), 0).ljust(509, b"\x00")
            conn.sendall(struct.pack("!IB", 0, CMD_NETINFO) + netinfo_payload)

            recv_exact(conn, 5)
            recv_exact(conn, 509)

            cell_counter = 0
            while self.running:
                try:
                    c_hdr = recv_exact(conn, 5, timeout=1.0)
                    circ_id, c_cmd = struct.unpack("!IB", c_hdr)
                except (socket.timeout, ConnectionResetError):
                    break

                if c_cmd in (CMD_VERSIONS, 128, CMD_CERTS, 130):
                    clen = struct.unpack("!H", recv_exact(conn, 2))[0]
                    cell_body = recv_exact(conn, clen)
                else:
                    cell_body = recv_exact(conn, 509)

                if self.mode == "padding_stripper":
                    if c_cmd == CMD_CREATE_FAST:
                        x_bytes = cell_body[:20]
                        y_bytes = os.urandom(20)
                        kh = derive_kdf_tor(x_bytes, y_bytes)["kh"]
                        conn.sendall(pack_cell(circ_id, CMD_CREATED_FAST, (y_bytes + kh).ljust(509, b"\x00"), link_protocol=5))
                    elif c_cmd in (CMD_PADDING, CMD_PADDING_NEGOTIATE, 128):
                        conn.close()
                        return

                elif self.mode == "timing_watermark":
                    if c_cmd == CMD_CREATE_FAST:
                        cell_counter += 1
                        if cell_counter % 2 == 1:
                            time.sleep(0.18)
                        x_bytes = cell_body[:20]
                        y_bytes = os.urandom(20)
                        kh = derive_kdf_tor(x_bytes, y_bytes)["kh"]
                        resp_cell = pack_cell(circ_id, CMD_CREATED_FAST, (y_bytes + kh).ljust(509, b"\x00"), link_protocol=5)
                        conn.sendall(resp_cell)

                elif self.mode == "flow_starvation":
                    if c_cmd == CMD_CREATE_FAST:
                        time.sleep(0.55)
                        x_bytes = cell_body[:20]
                        y_bytes = os.urandom(20)
                        kh = derive_kdf_tor(x_bytes, y_bytes)["kh"]
                        resp_cell = pack_cell(circ_id, CMD_CREATED_FAST, (y_bytes + kh).ljust(509, b"\x00"), link_protocol=5)
                        conn.sendall(resp_cell)

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

def run_sandbox_tests():
    print("="*75)
    print(" 🧪 ENTRYMAP MULTI-VECTOR ACTIVE WIRE PROBING SANDBOX TESTBENCH")
    print("="*75)

    v_cert, v_key, exp_cert, exp_key, valid_der = generate_cert_files()

    print("\n[TEST 0] Auditing Local Tor/Chutney Reference Guard (127.0.0.1:5003)...")
    s_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_check.settimeout(0.3)
    tor_ref_running = False
    try:
        s_check.connect(("127.0.0.1", 5003))
        s_check.close()
        tor_ref_running = True
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass

    if tor_ref_running:
        opts_real = MockOptions(target="127.0.0.1:5003", probe_count=5)
        relay_real = {
            "nickname": "ChutneyRefGuard",
            "ip": "127.0.0.1",
            "or_port": 5003,
            "or_addresses": ["127.0.0.1:5003"],
            "flags": ["Guard", "Running"]
        }
        r_master = probe_guard_wire.analyze(relay_real, opts_real)
        assert r_master is not None, "Master wire probe failed"
        assert r_master["verdict"] == "HARDENED_GUARD", f"Expected HARDENED_GUARD, got {r_master['verdict']}"
        print(f"  [PASS] Master Defense Suite: Verdict {r_master['verdict']} [Score: {r_master['composite_score']}/100]")
    else:
        print("  [SKIP] No local Tor/Chutney daemon listening on 127.0.0.1:5003 (Optional Reference Test).")
        print("         Proceeding to self-contained simulated loopback test suites [TESTS 1-4]...")

    print("\n[TEST 1] Auditing Adversarial Jitter Trap (Delay Injection Watermarking on 127.0.0.1:15001)...")
    srv_jitter = MockAdversarialServer("timing_watermark", 15001, v_cert, v_key, valid_der)
    srv_jitter.start()
    try:
        opts = MockOptions(target="127.0.0.1:15001", probe_count=6)
        relay_adv1 = {"nickname": "WatermarkNode", "ip": "127.0.0.1", "or_port": 15001, "flags": ["Guard"]}
        res = probe_timing_jitter.analyze(relay_adv1, opts)
        assert res is not None, "Failed to probe watermark node"
        assert res["watermark_detected"] is True, "Failed to detect artificial timing watermarking!"
        assert res["risk_score"] >= 40, f"Expected risk >= 40, got {res['risk_score']}"
        print(f"  [PASS] Jitter Trap Caught! Watermark Detected: {res['watermark_detected']}, Cell/TCP Ratio: {res['cell_to_tcp_ratio']}x")
        print(f"         RTT Series: {res['rtt_series']}, Jitter: {res['jitter_ms']}ms, Risk: {res['risk_score']}/100")
    finally:
        srv_jitter.stop()

    print("\n[TEST 2] Auditing Hostile Padding Stripper (Fingerprinting Defense Stripping on 127.0.0.1:15002)...")
    srv_pad = MockAdversarialServer("padding_stripper", 15002, v_cert, v_key, valid_der)
    srv_pad.start()
    try:
        opts = MockOptions(target="127.0.0.1:15002")
        relay_adv2 = {"nickname": "PaddingStripper", "ip": "127.0.0.1", "or_port": 15002, "flags": ["Guard"]}
        res = probe_padding.analyze(relay_adv2, opts)
        assert res is not None, "Failed to probe padding stripper"
        assert res["connection_alive"] is False, "Expected guard connection to be dropped on padding"
        assert res["status"] in ("HOSTILE_PADDING_STRIP", "PADDING_WARNING")
        assert res["risk_score"] >= 50, f"Expected risk >= 50, got {res['risk_score']}"
        print(f"  [PASS] Padding Stripping Caught! Connection Alive: {res['connection_alive']}, Status: {res['status']}, Risk: {res['risk_score']}/100")
    finally:
        srv_pad.stop()

    print("\n[TEST 3] Auditing Flow-Control Stalling & KDF-TOR Verification (127.0.0.1:15003)...")
    srv_flow = MockAdversarialServer("flow_starvation", 15003, v_cert, v_key, valid_der)
    srv_flow.start()
    try:
        opts = MockOptions(target="127.0.0.1:15003", probe_timeout=4.0)
        relay_adv3 = {"nickname": "StarvationNode", "ip": "127.0.0.1", "or_port": 15003, "flags": ["Guard"]}
        res = probe_flow_control.analyze(relay_adv3, opts)
        assert res is not None, "Failed to probe starvation node"
        assert res["kdf_kh_verified"] is True, "KDF-TOR CREATED_FAST KH verification failed!"
        assert res["starvation_detected"] is True, "Failed to flag flow starvation!"
        assert res["risk_score"] >= 35, f"Expected risk >= 35, got {res['risk_score']}"
        print(f"  [PASS] Flow Starvation & KDF-TOR Verified! KH Valid: {res['kdf_kh_verified']}, Latency: {res['sendme_latency_ms']}ms, Risk: {res['risk_score']}/100")
    finally:
        srv_flow.stop()

    print("\n[TEST 4] Auditing Degraded TLS, Missing Ed25519 CERTS & Clock Skew (127.0.0.1:15004)...")
    srv_deg = MockAdversarialServer("degraded_tls", 15004, exp_cert, exp_key, valid_der)
    srv_deg.start()
    try:
        opts = MockOptions(target="127.0.0.1:15004")
        relay_adv4 = {"nickname": "DegradedRogueNode", "ip": "127.0.0.1", "or_port": 15004, "flags": ["Guard"]}
        res = probe_tls_fingerprint.analyze(relay_adv4, opts)
        assert res is not None, "Failed to probe degraded TLS node"
        assert res["cert_valid"] is False, "Failed to detect expired certificate!"
        assert res["ed25519_mitm_verified"] is False, "Expected Ed25519 MITM check to fail on missing certs"
        assert "EXPIRED_OR_INVALID_CERTIFICATE" in res["anomalies"]
        assert "CONSENSUS_REJECT_CLOCK_SKEW" in res["anomalies"]
        assert "MISSING_ED25519_CERTS" in res["anomalies"]
        assert res["risk_score"] >= 80, f"Expected risk >= 80, got {res['risk_score']}"
        print(f"  [PASS] Degraded TLS/Link Caught! Cert Valid: {res['cert_valid']}, Ed25519 MITM Verified: {res['ed25519_mitm_verified']}, Skew: {res['clock_skew_seconds']}s")
        print(f"         Anomalies: {res['anomalies']}, Risk: {res['risk_score']}/100 (Status: {res['status']})")
    finally:
        srv_deg.stop()

    print("\n" + "="*75)
    print(" ✅ ALL ACTIVE WIRE AUDIT & CRYPTOGRAPHIC KDF/ED25519 SANDBOX TESTS PASSED!")
    print("="*75)

    shutil.rmtree(os.path.dirname(v_cert), ignore_errors=True)

if __name__ == "__main__":
    run_sandbox_tests()
