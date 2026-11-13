"""
Residential Guard & Access Network Classifier Module for entrymap.

Flags Entry Guards operating within consumer broadband, FTTP/DOCSIS,
and dynamic access network IP ranges where high unmetered upstream load
evaluates ingress capacity concentration on consumer access networks, or where
residential hosting is used to conceal operator identity.
"""

import re

# Known UK and global consumer/residential ISP keywords and ASNs
CONSUMER_ASN_KEYWORDS = [
    "youfibre", "netomnia", "virgin media", "talktalk", "bt-central-plus",
    "sky broadband", "sky uk", "vodafone limited", "kcom", "zen internet",
    "hyperoptic", "community fibre", "plusnet", "gigaclear", "toob",
    "comcast", "charter communications", "at&t", "verizon", "cox communications",
    "deutsche telekom", "orange sa", "free sas", "telefonica", "telecom italia",
    "rogers communications", "bell canada", "telstra"
]

def init(options):
    if options.verbose:
        print("[*] Initializing residential access network classifier module...")

def analyze(relay, options):
    flags = relay.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    as_name = str(relay.get("as_name") or "").lower()
    as_num = str(relay.get("as") or "").upper()
    bandwidth = relay.get("advertised_bandwidth", 0) or 0
    if not isinstance(bandwidth, (int, float)):
        bandwidth = 0
    fp = (relay.get("fingerprint") or "").lstrip("$").upper()
    eff_raw = relay.get("effective_family") or []
    if not isinstance(eff_raw, (list, set, tuple)):
        eff_raw = []
    alleged_raw = relay.get("alleged_family") or []
    if not isinstance(alleged_raw, (list, set, tuple)):
        alleged_raw = []
    effective_siblings = [x.lstrip("$").upper() for x in eff_raw if x.lstrip("$").upper() != fp]
    alleged_siblings = [x.lstrip("$").upper() for x in alleged_raw if x.lstrip("$").upper() != fp]
    has_empty_family = (len(effective_siblings) == 0 and len(alleged_siblings) == 0)
    contact = relay.get("contact") or ""
    or_addresses = relay.get("or_addresses") or []
    if not isinstance(or_addresses, list):
        or_addresses = []

    is_guard = "Guard" in flags
    is_hsdir = "HSDir" in flags

    # Check if ASN matches known consumer ISP signatures
    is_consumer_asn = any(kw in as_name for kw in CONSUMER_ASN_KEYWORDS)

    # Specific threshold checks:
    # 1. Operating on consumer ISP with Guard/HSDir
    # 2. Bandwidth >= 50 Mbps (~6,250,000 B/s)
    # 3. Undeclared family
    if is_consumer_asn and (is_guard or is_hsdir):
        bw_mbps = round((bandwidth * 8) / 1_000_000, 2)

        risk_score = 50
        reasons = [f"Consumer ISP match: {relay.get('as_name')} ({as_num})"]

        if bw_mbps >= 100:
            risk_score += 25
            reasons.append(f"High residential upstream throughput: {bw_mbps} Mbps")
        elif bw_mbps >= 50:
            risk_score += 15
            reasons.append(f"Moderate residential upstream throughput: {bw_mbps} Mbps")

        if has_empty_family:
            risk_score += 15
            reasons.append("Empty / undeclared family (MyFamily == None)")

        if is_guard and is_hsdir:
            risk_score += 10
            reasons.append("Simultaneously holds Guard and HSDir flags")

        return {
            "fingerprint": relay.get("fingerprint"),
            "nickname": relay.get("nickname"),
            "ip": or_addresses[0] if or_addresses else "unknown",
            "as": as_num,
            "as_name": relay.get("as_name"),
            "bandwidth_mbps": bw_mbps,
            "flags": flags,
            "risk_score": min(risk_score, 100),
            "reasons": reasons,
            "contact": contact
        }

    return None

def finish(results, options):
    print("\n" + "="*70)
    print(" 🛡️  ENTRYMAP RESIDENTIAL ACCESS NETWORK AUDIT REPORT")
    print("="*70)
    print(f"Total High-Risk Consumer Relays Identified: {len(results)}\n")

    # Sort by risk score descending
    sorted_res = sorted(results, key=lambda x: x["risk_score"], reverse=True)

    for idx, r in enumerate(sorted_res, 1):
        print(f"[{idx}] {r['nickname']} ({r['fingerprint']}) - Risk Score: {r['risk_score']}/100")
        print(f"    OR Address : {r['ip']}")
        print(f"    Network    : {r['as_name']} ({r['as']})")
        print(f"    Bandwidth  : {r['bandwidth_mbps']} Mbps")
        print(f"    Flags      : {', '.join(r['flags'])}")
        print(f"    Contact    : {r['contact'] if r['contact'] else '<None declared>'}")
        print("    Findings   :")
        for reason in r["reasons"]:
            print(f"      • {reason}")
        print("-" * 70)
