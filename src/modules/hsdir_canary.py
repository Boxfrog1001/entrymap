"""
HSDir Canary & Descriptor Ring Audit Module for entrymap.

Audits Hidden Service Directory (HSDir) relays across the Tor network.
Models HSDir uptime/role properties and flags elevated-risk directory
configurations (empty family declarations, dual Guard/HSDir role overlap,
missing operator contact), focusing on ring stability and operator
transparency per rend-spec-v3.
"""

import hashlib
import time

def init(options):
    if options.verbose:
        print("[*] Initializing HSDir Canary & Directory Ring audit module...")

def analyze(relay, options):
    flags = relay.get("flags") or []
    if not isinstance(flags, list) or "HSDir" not in flags:
        return None

    fingerprint = str(relay.get("fingerprint") or "")
    nickname = str(relay.get("nickname") or "Unnamed")
    contact = str(relay.get("contact") or "").strip()
    as_name = str(relay.get("as_name") or "Unknown AS")
    as_num = str(relay.get("as") or "Unknown")
    or_addresses = relay.get("or_addresses") or []
    if not isinstance(or_addresses, list):
        or_addresses = []
    observed_bw = relay.get("observed_bandwidth", 0) or 0
    if not isinstance(observed_bw, (int, float)):
        observed_bw = 0
    advertised_bw = relay.get("advertised_bandwidth", 0) or 0
    if not isinstance(advertised_bw, (int, float)):
        advertised_bw = 0
    platform = str(relay.get("platform") or "Unknown")

    fp = fingerprint.lstrip("$").upper()
    eff_raw = relay.get("effective_family") or []
    if not isinstance(eff_raw, (list, set, tuple)):
        eff_raw = []
    alleged_raw = relay.get("alleged_family") or []
    if not isinstance(alleged_raw, (list, set, tuple)):
        alleged_raw = []
    effective_siblings = [x.lstrip("$").upper() for x in eff_raw if x.lstrip("$").upper() != fp]
    alleged_siblings = [x.lstrip("$").upper() for x in alleged_raw if x.lstrip("$").upper() != fp]
    has_empty_family = (len(effective_siblings) == 0 and len(alleged_siblings) == 0)
    has_no_contact = (len(contact) == 0)

    # Risk scoring for HSDir candidate vetting
    risk_score = 0
    risk_factors = []

    # 1. Undeclared family on a directory node
    if has_empty_family:
        risk_score += 30
        risk_factors.append("Undeclared family (Neither alleged nor effective siblings)")

    # 2. Stripped or anonymous operator contact
    if has_no_contact:
        risk_score += 20
        risk_factors.append("No operator contact info provided")

    # 3. Running alongside Guard flag (Dual-role Ingress/Directory)
    if "Guard" in flags:
        risk_score += 20
        risk_factors.append("Dual-role: Holds both Guard and HSDir flags (Correlation Vector)")

    # 4. Outdated or unusual platform
    if "Windows" in platform:
        risk_score += 15
        risk_factors.append(f"Non-standard HSDir OS: {platform}")

    # Note: Full v3 HSDir index position per rend-spec-v3 §2.2.2 requires
    # SHA3-256("node-idx" | ed25519_id | shared_rand_val | period_num | period_len).
    # Here we calculate a deterministic display digest of the relay identity.
    display_digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    return {
        "fingerprint": fingerprint,
        "nickname": nickname,
        "ip": or_addresses[0] if or_addresses else "unknown",
        "as": as_num,
        "as_name": as_name,
        "platform": platform,
        "flags": flags,
        "contact": contact if contact else "<None>",
        "risk_score": min(risk_score, 100),
        "risk_factors": risk_factors,
        "display_digest_prefix": display_digest[:16],
        "bw_mbps": round((advertised_bw * 8) / 1_000_000, 2)
    }

def finish(results, options):
    print("\n" + "="*70)
    print(" 🧅  ENTRYMAP HSDIR DIRECTORY STABILITY & ROLE AUDIT")
    print("="*70)
    print(f"Total HSDir Relays Analyzed: {len(results)}\n")

    # Filter for nodes with elevated risk scores (>= 50)
    elevated_risk = [r for r in results if r["risk_score"] >= 50]
    elevated_risk.sort(key=lambda x: x["risk_score"], reverse=True)

    print(f"🚨 Elevated-Risk HSDir Nodes Identified: {len(elevated_risk)}")
    print("   (Criteria: Empty families, dual Guard/HSDir roles, anonymous operators)\n")

    for idx, r in enumerate(elevated_risk[:15], 1):  # Display top 15
        print(f"[{idx}] {r['nickname']} ({r['fingerprint']}) - Risk: {r['risk_score']}/100")
        print(f"    OR Address  : {r['ip']}")
        print(f"    Network     : {r['as_name']} ({r['as']})")
        print(f"    Platform    : {r['platform']}")
        print(f"    Bandwidth   : {r['bw_mbps']} Mbps")
        print(f"    Node Digest : 0x{r['display_digest_prefix']}... (Deterministic Fingerprint Digest)")
        print(f"    Contact     : {r['contact']}")
        print("    Risk Indicators:")
        for factor in r["risk_factors"]:
            print(f"      • {factor}")
        print("-" * 70)

    if len(elevated_risk) > 15:
        print(f"... and {len(elevated_risk) - 15} additional elevated-risk HSDir nodes in consensus.")
