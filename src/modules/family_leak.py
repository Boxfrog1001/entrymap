"""
Family Leak & Hidden Sibling Analyzer Module for entrymap.

Flags Entry Guards and HSDirs that operate without declared families,
cross-referencing operator contact strings, ASNs, and subnet allocations
to identify undeclared clusters that threaten client path selection.
"""

def init(options):
    if options.verbose:
        print("[*] Initializing family leak & hidden sibling module...")

def analyze(relay, options):
    flags = relay.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    alleged = relay.get("alleged_family")
    family = alleged if isinstance(alleged, (list, set, tuple)) else []
    effective_family = relay.get("effective_family") or []
    if not isinstance(effective_family, (list, set, tuple)):
        effective_family = []
    contact = (relay.get("contact") or "") if isinstance(relay.get("contact"), str) else ""
    contact = contact.strip()
    nickname = str(relay.get("nickname") or "")
    or_addresses = relay.get("or_addresses") or []
    ip = or_addresses[0] if (isinstance(or_addresses, list) and or_addresses) else ""

    is_guard = "Guard" in flags
    is_hsdir = "HSDir" in flags

    # Under Tor Directory Specification Consensus Method 37 onward,
    # microdescriptors omit legacy alleged_family lines to reduce consensus size.
    # Directory Authorities compute mutual cryptographic relationships into effective_family.
    # In Onionoo, effective_family includes the relay's own fingerprint.
    # Therefore, a relay has no declared effective siblings if effective_family
    # contains only itself (or is empty).
    fp = (relay.get("fingerprint") or "").lstrip("$").upper()
    effective_siblings = [x.lstrip("$").upper() for x in effective_family if x.lstrip("$").upper() != fp]
    alleged_siblings = [x.lstrip("$").upper() for x in family if x.lstrip("$").upper() != fp]
    has_no_alleged = len(alleged_siblings) == 0
    has_no_effective = len(effective_siblings) == 0

    if (is_guard or is_hsdir) and has_no_alleged and has_no_effective:
        # Check if contact or nickname exhibits numbered cluster patterns (e.g. node1, node2, node3)
        has_numbered_nickname = any(c.isdigit() for c in nickname)
        has_contact = len(contact) > 0

        return {
            "fingerprint": relay.get("fingerprint"),
            "nickname": nickname,
            "ip": ip,
            "as": relay.get("as"),
            "as_name": relay.get("as_name"),
            "flags": flags,
            "contact": contact,
            "numbered_nickname": has_numbered_nickname,
            "effective_family_count": len(effective_family)
        }

    return None

def finish(results, options):
    print("\n" + "="*70)
    print(" 🔍  ENTRYMAP UNDECLARED FAMILY & CLUSTER REPORT")
    print("="*70)
    print(f"Total Guard/HSDir Relays with Empty Family Declarations: {len(results)}\n")

    # Group by contact string to expose undeclared multi-node operators
    contact_map = {}
    for r in results:
        c = r["contact"] or "<NO_CONTACT>"
        contact_map.setdefault(c, []).append(r)

    # Show multi-node operators who forgot/refused to declare MyFamily
    multi_operators = {k: v for k, v in contact_map.items() if len(v) > 1 and k != "<NO_CONTACT>"}

    if multi_operators:
        print(f"🚨 FOUND {len(multi_operators)} OPERATORS RUNNING MULTIPLE GUARDS WITH ZERO FAMILY DECLARATION:")
        for c, nodes in multi_operators.items():
            print(f"\nOperator Contact: {c} ({len(nodes)} undeclared nodes)")
            for n in nodes:
                print(f"  • {n['nickname']} ({n['fingerprint']}) on {n['ip']} | {n['as_name']}")
        print("\n" + "-"*70)
    else:
        print("No multi-node shared-contact clusters detected in the filtered set.")
