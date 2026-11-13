"""
Passive Sidecar & Vulnerability Exposure Analyzer Module for entrymap.

Queries public host intelligence (InternetDB / Shodan cache) over HTTPS to
identify non-Tor sidecar ports (e.g. Traefik, STUN, Minecraft, RDP, CWMP)
and CVE vulnerabilities co-located on Entry Guard and HSDir IP addresses
without sending raw probe packets directly from the scanner.
"""

import urllib.request
import json

# Service signatures mapped to standard ports
KNOWN_SIDECARS = {
    80: "HTTP Web Server",
    443: "HTTPS / Reverse Proxy (Traefik, Nginx, Caddy)",
    22: "SSH Administration",
    25565: "Minecraft Server (Java Protocol)",
    19132: "Minecraft / RakNet (Bedrock UDP)",
    3478: "STUN / TURN NAT Traversal",
    21115: "RustDesk Remote Access (NAT Type Test)",
    21116: "RustDesk Remote Access (ID Registration)",
    21117: "RustDesk Remote Access (Relay)",
    7547: "CWMP / TR-069 Management",
    37547: "CWMP / TR-069 Management (Alt)",
    3389: "Microsoft Remote Desktop (RDP)",
    8080: "HTTP Alternate / Proxy",
    8443: "HTTPS Alternate",
}

import os
import tempfile
import hashlib
import time

def init(options):
    if getattr(options, "verbose", False):
        print("[*] Initializing passive sidecar & vulnerability analysis module...")
    # OPSEC Disclosure for privacy-conscious Tor users
    print("[*] OPSEC Note: The sidecar module queries InternetDB over HTTPS. Use 'torsocks ./bin/entrymap -m sidecar' for anonymous lookups.")

def query_passive_intel(ip, timeout=5, no_cache=False):
    """
    Queries Shodan's free InternetDB API for open ports, hostnames, and CVEs.
    Caches responses locally with strict 0600 permissions to avoid redundant queries
    unless --no-cache is explicitly specified for ephemeral OPSEC.
    """
    cache_dir = os.path.join(tempfile.gettempdir(), "entrymap_sidecar_cache")
    cache_file = os.path.join(cache_dir, f"intel_{hashlib.sha256(ip.encode()).hexdigest()[:16]}.json")

    if not no_cache:
        os.makedirs(cache_dir, mode=0o700, exist_ok=True)
        if os.path.exists(cache_file):
            try:
                if (time.time() - os.path.getmtime(cache_file)) < 86400: # 24h TTL
                    with open(cache_file, "r", encoding="utf-8") as f:
                        return json.load(f)
            except Exception:
                pass

    url = f"https://internetdb.shodan.io/{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "entrymap-research/0.1.0 (Tor Network Health)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8"))
                if not no_cache:
                    try:
                        fd = os.open(cache_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with open(fd, "wb") as f:
                            f.write(raw_bytes)
                    except Exception:
                        pass
                return data
    except Exception:
        # Host not indexed in InternetDB or blocked
        return None
    return None

def analyze(relay, options):
    or_addresses = relay.get("or_addresses") or []
    if not isinstance(or_addresses, list) or not or_addresses:
        return None

    # Parse target IPv4
    primary_addr = str(or_addresses[0])
    ip = primary_addr.split(":")[0] if ":" in primary_addr else primary_addr
    try:
        tor_port = int(primary_addr.split(":")[-1]) if ":" in primary_addr else 9001
    except (ValueError, TypeError):
        tor_port = 9001

    # Query third-party passive intelligence
    intel = query_passive_intel(ip, no_cache=getattr(options, "no_cache", False))
    if not intel:
        return None

    open_ports = intel.get("ports", [])
    cves = intel.get("cves", [])
    hostnames = intel.get("hostnames", [])
    tags = intel.get("tags", [])

    # Filter out the Tor OR-port itself to identify strictly non-Tor sidecars
    sidecar_ports = [p for p in open_ports if p != tor_port]

    if sidecar_ports or cves:
        identified_services = []
        for p in sidecar_ports:
            desc = KNOWN_SIDECARS.get(p, "Unclassified Service")
            identified_services.append((p, desc))

        return {
            "fingerprint": relay.get("fingerprint"),
            "nickname": relay.get("nickname"),
            "ip": ip,
            "or_port": tor_port,
            "as": relay.get("as"),
            "as_name": relay.get("as_name"),
            "flags": relay.get("flags", []),
            "contact": relay.get("contact"),
            "sidecar_services": sorted(identified_services, key=lambda x: x[0]),
            "cves": cves,
            "hostnames": hostnames,
            "tags": tags,
        }

    return None

def finish(results, options):
    print("\n" + "="*70)
    print(" 🚪  ENTRYMAP PASSIVE SIDECAR & EXPOSURE REPORT")
    print("="*70)
    print(f"Total Guards with Indexed Non-Tor Sidecars / CVEs: {len(results)}\n")

    for idx, r in enumerate(results, 1):
        print(f"[{idx}] {r['nickname']} ({r['fingerprint']})")
        print(f"    Host IP       : {r['ip']} (Tor ORPort: {r['or_port']})")
        print(f"    Network       : {r['as_name']} ({r['as']})")
        print(f"    Flags         : {', '.join(r['flags'])}")
        print(f"    Contact       : {r['contact'] if r['contact'] else '<None declared>'}")

        if r["hostnames"]:
            print(f"    Hostnames     : {', '.join(r['hostnames'])}")
        if r["tags"]:
            print(f"    Tags          : {', '.join(r['tags'])}")

        print("    Co-located Non-Tor Services:")
        for port, service in r["sidecar_services"]:
            print(f"      • Port {port}/TCP: {service}")

        if r["cves"]:
            print(f"    🚨 Known CVEs ({len(r['cves'])}):")
            for cve in r["cves"][:5]:  # Show top 5
                print(f"      • {cve}")
            if len(r["cves"]) > 5:
                print(f"      ... and {len(r['cves']) - 5} more")

        print("-" * 70)
