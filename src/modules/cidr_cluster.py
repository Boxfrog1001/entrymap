"""
Subnet & CIDR Infrastructure Concentration Analyzer for entrymap.

Audits ingress relay concentration across IPv4 /24 subnets and hosting providers.
NOTE: Per path-spec.txt §2.2.1, standard Tor clients enforce 'EnforceDistinctSubnets 1'
which forbids selecting two relays from the same /16 IPv4 subnet in any single circuit.
Therefore, /24 colocation does NOT cause intra-circuit multi-hop collisions.
Instead, this module measures ingress tier centralization (identifying hosting
providers or ASNs where significant Guard/HSDir bandwidth is clustered).
"""

import ipaddress
from collections import defaultdict

def init(options):
    if options.verbose:
        print("[*] Initializing Subnet & CIDR Infrastructure Concentration module...")

def analyze(relay, options):
    flags = relay.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    is_guard = "Guard" in flags
    is_hsdir = "HSDir" in flags

    # Filter for ingress/directory tier unless user specified --all-relays
    if not (options.all_relays or is_guard or is_hsdir):
        return None

    or_addresses = relay.get("or_addresses") or []
    if not isinstance(or_addresses, list) or not or_addresses:
        return None

    primary_addr = or_addresses[0]
    if not isinstance(primary_addr, str):
        return None
    raw_ip = primary_addr.split(":")[0] if ":" in primary_addr else primary_addr

    try:
        ip_obj = ipaddress.ip_address(raw_ip)
    except (ValueError, TypeError):
        return None

    # Calculate /24 and /16 network blocks for IPv4
    if ip_obj.version == 4:
        network_24 = str(ipaddress.ip_network(f"{raw_ip}/24", strict=False))
        network_16 = str(ipaddress.ip_network(f"{raw_ip}/16", strict=False))
    else:
        # IPv6: /48 and /64 blocks
        network_24 = str(ipaddress.ip_network(f"{raw_ip}/64", strict=False))
        network_16 = str(ipaddress.ip_network(f"{raw_ip}/48", strict=False))

    fp = (relay.get("fingerprint") or "").lstrip("$").upper()
    alleged = relay.get("alleged_family")
    family = {str(x).lstrip("$").upper() for x in alleged} if isinstance(alleged, list) else set()
    eff = relay.get("effective_family")
    effective_family = {str(x).lstrip("$").upper() for x in eff} if isinstance(eff, list) else set()
    declared_family = family.union(effective_family)

    bandwidth = relay.get("advertised_bandwidth", 0)
    consensus_weight = relay.get("consensus_weight_fraction", 0.0)

    return {
        "fingerprint": fp,
        "nickname": relay.get("nickname") or "Unnamed",
        "ip": raw_ip,
        "network_24": network_24,
        "network_16": network_16,
        "as": relay.get("as") or "Unknown",
        "as_name": relay.get("as_name") or "Unknown AS",
        "flags": flags,
        "contact": (relay.get("contact") or "").strip(),
        "declared_family": declared_family,
        "bandwidth_mbps": round((bandwidth * 8) / 1_000_000, 2),
        "consensus_weight": consensus_weight
    }

def finish(results, options):
    print("\n" + "="*70)
    print(" 🌐  ENTRYMAP CIDR SUBNET HOSTING DENSITY REPORT")
    print("="*70)
    print(f"Total Target Ingress Relays Ingested: {len(results)}\n")

    # Group relays by /24 subnet
    subnet_map = defaultdict(list)
    for r in results:
        subnet_map[r["network_24"]].append(r)

    # Filter for subnets hosting >= 2 relays
    dense_subnets = {k: v for k, v in subnet_map.items() if len(v) >= 2}

    print(f"🚨 Found {len(dense_subnets)} dense /24 CIDR subnets hosting multiple ingress relays.\n")

    # Audit mutual family declarations within each dense subnet
    high_density_clusters = []

    for subnet, nodes in dense_subnets.items():
        total_bw = sum(n["bandwidth_mbps"] for n in nodes)
        as_name = nodes[0]["as_name"]
        as_num = nodes[0]["as"]

        # Check if all nodes in this subnet declare each other
        fingerprints_in_subnet = {n["fingerprint"] for n in nodes}
        has_undeclared = False

        for n in nodes:
            # If any sibling fingerprint in this subnet is missing from declared_family
            undeclared_siblings = fingerprints_in_subnet - n["declared_family"] - {n["fingerprint"]}
            if undeclared_siblings:
                has_undeclared = True
                break

        if has_undeclared:
            high_density_clusters.append({
                "subnet": subnet,
                "as": as_num,
                "as_name": as_name,
                "node_count": len(nodes),
                "total_bandwidth": round(total_bw, 2),
                "nodes": nodes
            })

    # Sort clusters by node count descending
    high_density_clusters.sort(key=lambda x: (x["node_count"], x["total_bandwidth"]), reverse=True)

    print(f"📊  IDENTIFIED {len(high_density_clusters)} DENSE /24 INGRESS CLUSTERS (Infrastructure Concentration):")
    print("    (Note: path-spec §2.2.1 prevents single-circuit collisions across the encompassing /16;")
    print("     this metric measures physical hosting provider and network centralization)\n")

    for idx, c in enumerate(high_density_clusters[:15], 1):
        print(f"[{idx}] Subnet: {c['subnet']} ({c['as_name']} - {c['as']})")
        print(f"    Nodes in /24     : {c['node_count']} relays")
        print(f"    Total Bandwidth  : {c['total_bandwidth']} Mbps")
        print("    Cluster Members  :")
        for n in c["nodes"][:8]:  # Display top 8 per subnet
            contact_str = f" | Contact: {n['contact']}" if n['contact'] else " | <No Contact>"
            print(f"      • {n['nickname']} ({n['fingerprint'][:16]}...) on {n['ip']} [{n['bandwidth_mbps']} Mbps]{contact_str}")
        if len(c["nodes"]) > 8:
            print(f"      ... and {len(c['nodes']) - 8} more relays in this subnet")
        print("-" * 70)

    if len(high_density_clusters) > 15:
        print(f"... and {len(high_density_clusters) - 15} additional undeclared /24 clusters across consensus.")
