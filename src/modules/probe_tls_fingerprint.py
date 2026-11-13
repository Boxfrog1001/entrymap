"""
probe_tls_fingerprint.py - TLS & Link Protocol Fingerprinting Module for entrymap.

Audits Entry Guard TLS front-doors and in-protocol cryptographic authentication:
- Validates TLS 1.3 / TLS 1.2 protocol compliance and modern AEAD cipher suites.
- Inspects outer X.509 decoy certificate validity periods.
- Probes Tor Link Protocol v5 / v4 negotiation (tor-spec.txt Section 2 & 3).
- Cryptographically verifies CERTS cell Type 4 (ED25519_SIGNING) and Type 5 (ED25519_TLS_LINK)
  signatures against the SHA-256 digest of the outer TLS certificate (cert-spec.txt §2.1)
  to detect active TLS MITM interception.
- Audits NETINFO clock skew to prevent directory consensus rejection.
"""

from modules.probe_common import (
    extract_or_endpoint,
    perform_tor_handshake
)

def init(options):
    if getattr(options, "verbose", False):
        print("[*] Initializing TLS & Link Protocol Fingerprinting Module (Ed25519 CERTS MITM Verifier)...")

def analyze(relay, options):
    ip, port = extract_or_endpoint(relay)
    if not ip or not port:
        return None

    timeout = getattr(options, "probe_timeout", 5.0)

    try:
        tls_sock, handshake = perform_tor_handshake(ip, port, timeout=timeout)
        tls_sock.close()
    except Exception as e:
        if getattr(options, "verbose", False):
            print(f"[!] TLS/Link Handshake failed for {ip}:{port} - {e}")
        return None

    tls_meta = handshake.get("tls_meta", {})
    cert_info = tls_meta.get("cert", {})
    tls_version = tls_meta.get("tls_version", "UNKNOWN")
    cipher_name = tls_meta.get("cipher_name", "UNKNOWN")
    link_proto = handshake.get("negotiated_link_protocol", 0)
    supported_versions = handshake.get("relay_versions", [])
    clock_skew = handshake.get("clock_skew_seconds", 0) or 0
    cert_valid = cert_info.get("is_date_valid", False)
    cert_types = handshake.get("certs_types", [])
    ed_audit = handshake.get("ed25519_audit", {})

    anomalies = []
    risk_score = 0

    if tls_version == "TLSv1.3":
        pass
    elif tls_version == "TLSv1.2":
        anomalies.append("TLS_1_2_LEGACY")
        risk_score += 15
    else:
        anomalies.append("OBSOLETE_TLS_VERSION")
        risk_score += 50

    if "GCM" in cipher_name or "CHACHA20" in cipher_name:
        pass
    elif "CBC" in cipher_name:
        anomalies.append("CBC_CIPHER_SUITE")
        risk_score += 20
    else:
        anomalies.append("NON_STANDARD_CIPHER")
        risk_score += 30

    if not cert_valid:
        anomalies.append("EXPIRED_OR_INVALID_CERTIFICATE")
        risk_score += 45

    if link_proto >= 5:
        pass
    elif link_proto == 4:
        anomalies.append("LINK_PROTO_V4_ONLY")
        risk_score += 10
    else:
        anomalies.append("OBSOLETE_LINK_PROTOCOL")
        risk_score += 40

    # Ed25519 Cross-Cert & TLS Link Digest Binding Audit (cert-spec.txt §2.1)
    if 4 not in cert_types or 5 not in cert_types:
        anomalies.append("MISSING_ED25519_CERTS")
        risk_score += 25
    else:
        if not ed_audit.get("tls_link_digest_matches", False):
            anomalies.append("TLS_CERT_DIGEST_MISMATCH_MITM")
            risk_score += 60
        if not ed_audit.get("type5_sig_valid", False):
            anomalies.append("INVALID_ED25519_TLS_LINK_SIGNATURE")
            risk_score += 60

    abs_skew = abs(clock_skew)
    if abs_skew > 1800:
        anomalies.append("CONSENSUS_REJECT_CLOCK_SKEW")
        risk_score += 40
    elif abs_skew > 180:
        anomalies.append("MODERATE_CLOCK_SKEW")
        risk_score += 15

    status = "COMPLIANT" if not anomalies else ("HIGH_RISK" if risk_score >= 40 else "WARNING")

    return {
        "fingerprint": relay.get("fingerprint") or f"IP:{ip}:{port}",
        "nickname": relay.get("nickname") or f"node_{ip}_{port}",
        "ip": ip,
        "port": port,
        "tls_version": tls_version,
        "cipher_name": cipher_name,
        "cipher_bits": tls_meta.get("cipher_bits", 0),
        "cert_subject": cert_info.get("subject", "N/A"),
        "cert_issuer": cert_info.get("issuer", "N/A"),
        "cert_valid": cert_valid,
        "cert_not_after": cert_info.get("not_after", "N/A"),
        "link_protocol": link_proto,
        "supported_link_versions": supported_versions,
        "clock_skew_seconds": round(clock_skew, 2),
        "certs_types": cert_types,
        "ed25519_mitm_verified": ed_audit.get("mitm_verified", False),
        "ed25519_identity_hex": ed_audit.get("ed25519_identity_hex"),
        "anomalies": anomalies,
        "risk_score": min(100, risk_score),
        "status": status
    }

def finish(results, options):
    print("\n" + "="*70)
    print(" 🔒  ENTRYMAP TLS & LINK PROTOCOL FINGERPRINT REPORT")
    print("="*70)
    print(f"Total Guard ORPorts Probed: {len(results)}\n")

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    for idx, r in enumerate(results[:15], 1):
        status_icon = "✅" if r["status"] == "COMPLIANT" else ("⚠️" if r["status"] == "WARNING" else "🚨")
        print(f"[{idx}] {status_icon} {r['nickname']} ({r['ip']}:{r['port']}) - Status: {r['status']} (Risk Score: {r['risk_score']}/100)")
        print(f"    TLS Protocol   : {r['tls_version']} ({r['cipher_name']})")
        print(f"    Outer X.509    : Valid Date: {r['cert_valid']} | Expires: {r['cert_not_after']}")
        print(f"    Ed25519 Binding: CERTS Types {r['certs_types']} | MITM Verified: {r['ed25519_mitm_verified']}")
        print(f"    Link Protocol  : v{r['link_protocol']} (Supported: {r['supported_link_versions']})")
        print(f"    Clock Skew     : {r['clock_skew_seconds']}s")
        if r["anomalies"]:
            print(f"    Anomalies      : {', '.join(r['anomalies'])}")
        print("-" * 70)

    if len(results) > 15:
        print(f"... and {len(results) - 15} additional probed relays.")
