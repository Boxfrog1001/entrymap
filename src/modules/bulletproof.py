"""
Bulletproof & High-Risk Offshore ASN Ingress Module for entrymap.

Flags Entry Guards and HSDirs operating within Autonomous Systems historically
associated with bulletproof hosting, non-cooperative jurisdictions, or high-risk
offshore infrastructure, especially where operators enforce strict 'reject *:*'
exit policies to operate purely as covert traffic ingress hubs.
"""

# Curated list of ASNs historically associated with bulletproof / offshore hosting
BULLETPROOF_ASNS = {
    "AS200019": "Alexhost SRL (Moldova/Bulgaria)",
    "AS44477": "Stark Industries Solutions / PQ Hosting (Seychelles/Moldova)",
    "AS210644": "Baxet Group Inc.",
    "AS62005": "BlueVPS / Servers Australia Pty",
    "AS206264": "Amarutu Technology Ltd (Offshore)",
    "AS58224": "Iran Telecommunication Company (ITC)",
    "AS48031": "G-Core Labs S.A. (High-risk routing ranges)",
    "AS202425": "IP Volume inc (Seychelles)",
    "AS208437": "MivoCloud SRL",
    "AS51852": "Private Layer INC (Panama/Switzerland)",
    "AS60068": "Datacamp Limited / CDN77",
    "AS43350": "NForce Entertainment B.V.",
}

def init(options):
    if options.verbose:
        print("[*] Initializing Bulletproof & High-Risk Offshore ASN module...")

def analyze(relay, options):
    flags = relay.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    is_guard = "Guard" in flags
    is_hsdir = "HSDir" in flags

    if not (options.all_relays or is_guard or is_hsdir):
        return None

    as_num = str(relay.get("as") or "").upper()
    as_name = str(relay.get("as_name") or "Unknown AS")
    exit_policy = relay.get("exit_policy") or []
    if not isinstance(exit_policy, list):
        exit_policy = []
    exit_summary = relay.get("exit_policy_summary") or {}
    if not isinstance(exit_summary, dict):
        exit_summary = {}
    bandwidth = relay.get("advertised_bandwidth", 0) or 0
    if not isinstance(bandwidth, (int, float)):
        bandwidth = 0

    # Check if ASN is in high-risk / bulletproof registry or matches keyword patterns
    is_flagged_asn = as_num in BULLETPROOF_ASNS
    asn_desc = BULLETPROOF_ASNS.get(as_num, as_name)

    # Check if node has strict middle/guard policy (rejects all egress)
    rejects_all_egress = False
    if "reject" in exit_summary and exit_summary["reject"] == ["1-65535"]:
        rejects_all_egress = True
    elif exit_policy == ["reject *:*"]:
        rejects_all_egress = True

    if is_flagged_asn and (is_guard or is_hsdir):
        or_addresses = relay.get("or_addresses", [])
        bw_mbps = round((bandwidth * 8) / 1_000_000, 2)
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

        risk_score = 60
        reasons = [f"Operating in targeted/bulletproof network: {asn_desc} ({as_num})"]

        if rejects_all_egress:
            risk_score += 20
            reasons.append("Non-exit relay role ('reject *:*') operating in flagged ASN")

        if has_empty_family:
            risk_score += 10
            reasons.append("Empty / undeclared family (Neither alleged nor effective siblings)")

        if is_guard and is_hsdir:
            risk_score += 10
            reasons.append("Holds dual Guard and HSDir flags simultaneously")

        return {
            "fingerprint": relay.get("fingerprint"),
            "nickname": relay.get("nickname") or "Unnamed",
            "ip": or_addresses[0] if or_addresses else "unknown",
            "as": as_num,
            "as_name": asn_desc,
            "bw_mbps": bw_mbps,
            "flags": flags,
            "risk_score": min(risk_score, 100),
            "reasons": reasons,
            "contact": (relay.get("contact") or "").strip()
        }

    return None

def finish(results, options):
    print("\n" + "="*70)
    print(" 🏴‍☠️  ENTRYMAP BULLETPROOF & OFFSHORE INGRESS REPORT")
    print("="*70)
    print(f"Total High-Risk Offshore Ingress Relays Identified: {len(results)}\n")

    results.sort(key=lambda x: x["risk_score"], reverse=True)

    for idx, r in enumerate(results[:15], 1):
        print(f"[{idx}] {r['nickname']} ({r['fingerprint'][:16]}...) - Risk: {r['risk_score']}/100")
        print(f"    OR Address  : {r['ip']}")
        print(f"    Network     : {r['as_name']} ({r['as']})")
        print(f"    Bandwidth   : {r['bw_mbps']} Mbps")
        print(f"    Flags       : {', '.join(r['flags'])}")
        print(f"    Contact     : {r['contact'] if r['contact'] else '<None declared>'}")
        print("    Findings    :")
        for reason in r["reasons"]:
            print(f"      • {reason}")
        print("-" * 70)

    if len(results) > 15:
        print(f"... and {len(results) - 15} additional relays in bulletproof/offshore networks.")
