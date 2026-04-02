from __future__ import annotations
#!/usr/bin/env python3
"""
mass_resolver.py — Async mass DNS resolver for sudomy v2
Resolves thousands of subdomains concurrently, deduplicates,
and outputs: subdomain -> IP mappings.

Usage:
  python3 mass_resolver.py -i subdomains.txt -o resolved.txt [-r resolvers.txt] [-t 200] [-v]

Dependencies: pip install aiodns --break-system-packages
"""

import argparse
import asyncio
import sys
import os
import random
import time
from collections import defaultdict

try:
    import aiodns
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

# ── Fallback: use subprocess dig if aiodns not available ──────────────────────

DEFAULT_RESOLVERS = [
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "8.8.8.8", "8.8.4.4",           # Google
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",        # Verisign
    "77.88.8.8", "77.88.8.1",        # Yandex
    "185.228.168.9", "185.228.169.9",# CleanBrowsing
    "176.103.130.130", "176.103.130.131", # AdGuard
]

WILDCARD_CHECK_LABEL = "sudomy-wildcard-check-nonexistent-12345"


async def check_wildcard(domain: str, resolver) -> set:
    """Return the wildcard IPs for domain (empty set = no wildcard)."""
    test = f"{WILDCARD_CHECK_LABEL}.{domain}"
    try:
        result = await resolver.gethostbyname(test, socket.AF_INET)
        return set(result.addresses)
    except Exception:
        return set()


async def resolve_one(subdomain: str, resolver, wildcard_ips: set, semaphore, results: dict, stats: dict):
    async with semaphore:
        try:
            result = await resolver.gethostbyname(subdomain, 2)  # AF_INET = 2
            ips = set(result.addresses)
            if wildcard_ips and ips.issubset(wildcard_ips):
                stats["wildcard"] += 1
                return
            results[subdomain] = sorted(ips)
            stats["resolved"] += 1
        except aiodns.error.DNSError:
            stats["nxdomain"] += 1
        except asyncio.TimeoutError:
            stats["timeout"] += 1
        except Exception:
            stats["error"] += 1


async def run_async(subdomains, resolvers, concurrency, domain, verbose):
    import socket  # needed inside async context for AF_INET constant

    loop = asyncio.get_event_loop()
    nameservers = resolvers if resolvers else DEFAULT_RESOLVERS

    resolver = aiodns.DNSResolver(
        loop=loop,
        nameservers=nameservers,
        timeout=5,
        tries=2,
    )

    print(f"[*] Checking for wildcard DNS on {domain}...")
    # Manually call since check_wildcard needs socket
    wildcard_ips: set = set()
    test = f"{WILDCARD_CHECK_LABEL}.{domain}"
    try:
        result = await resolver.gethostbyname(test, socket.AF_INET)
        wildcard_ips = set(result.addresses)
        print(f"[!] Wildcard DNS detected on {domain} -> {wildcard_ips} (these IPs will be filtered)")
    except Exception:
        print(f"[✓] No wildcard DNS detected on {domain}")

    semaphore = asyncio.Semaphore(concurrency)
    results = {}
    stats = defaultdict(int)
    stats["total"] = len(subdomains)

    print(f"[*] Resolving {len(subdomains):,} subdomains with concurrency={concurrency}...")
    start = time.time()

    tasks = [
        resolve_one(sub, resolver, wildcard_ips, semaphore, results, stats)
        for sub in subdomains
    ]

    # Progress reporting every 500 completions
    done = 0
    for coro in asyncio.as_completed(tasks):
        await coro
        done += 1
        if verbose and done % 500 == 0:
            pct = done / len(subdomains) * 100
            elapsed = time.time() - start
            rate = done / elapsed if elapsed > 0 else 0
            print(f"    [{done:>6}/{len(subdomains)}] {pct:5.1f}%  {rate:6.0f}/s  "
                  f"resolved={stats['resolved']}  nx={stats['nxdomain']}  "
                  f"timeout={stats['timeout']}", file=sys.stderr)

    elapsed = time.time() - start
    return results, stats, elapsed


def run_fallback_dig(subdomains, domain, verbose):
    """Fallback to subprocess-based resolution when aiodns isn't available."""
    import subprocess
    results = {}
    total = len(subdomains)
    for i, sub in enumerate(subdomains, 1):
        try:
            out = subprocess.check_output(
                ["dig", "+short", "+time=3", "+tries=2", sub],
                stderr=subprocess.DEVNULL, timeout=6
            ).decode().strip()
            ips = [line.strip() for line in out.splitlines()
                   if line.strip() and not line.strip().endswith(".")]
            if ips:
                results[sub] = ips
        except Exception:
            pass
        if verbose and i % 100 == 0:
            print(f"    [{i}/{total}] resolved so far: {len(results)}", file=sys.stderr)
    return results


def load_resolvers(path):
    if not path or not os.path.isfile(path):
        return DEFAULT_RESOLVERS
    with open(path) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return lines if lines else DEFAULT_RESOLVERS


def main():
    parser = argparse.ArgumentParser(description="sudomy async mass DNS resolver")
    parser.add_argument("-i", "--input",   required=True,  help="Input file (one subdomain per line)")
    parser.add_argument("-o", "--output",  required=True,  help="Output file (subdomain TAB IP,IP,...)")
    parser.add_argument("-r", "--resolvers", default=None, help="File with custom DNS resolvers (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrency level (default: 200)")
    parser.add_argument("-d", "--domain",  default="",     help="Root domain (for wildcard check)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress")
    parser.add_argument("--ip-only",       action="store_true", help="Output only resolved IPs (one per line)")
    parser.add_argument("--live-only",     action="store_true", help="Output only subdomains that resolved")
    args = parser.parse_args()

    # Load subdomains
    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        subdomains = sorted(set(
            line.strip().lower() for line in f
            if line.strip() and not line.startswith("#")
        ))

    if not subdomains:
        print("[!] No subdomains to resolve.", file=sys.stderr)
        sys.exit(1)

    resolvers = load_resolvers(args.resolvers)
    random.shuffle(resolvers)  # distribute load

    print(f"[*] Loaded {len(subdomains):,} unique subdomains | {len(resolvers)} resolvers")

    if HAS_AIODNS:
        import socket
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results, stats, elapsed = loop.run_until_complete(
                run_async(subdomains, resolvers, args.threads, args.domain, args.verbose)
            )
        finally:
            loop.close()
    else:
        print("[~] aiodns not found — falling back to sequential dig (install aiodns for 50x speed)", file=sys.stderr)
        results = run_fallback_dig(subdomains, args.domain, args.verbose)
        stats = {"resolved": len(results), "total": len(subdomains)}
        elapsed = 0

    # Write output
    with open(args.output, "w") as f:
        for sub in sorted(results):
            ips = results[sub]
            if args.ip_only:
                for ip in ips:
                    f.write(ip + "\n")
            elif args.live_only:
                f.write(sub + "\n")
            else:
                f.write(f"{sub}\t{','.join(ips)}\n")

    rate = stats.get("resolved", 0) / elapsed if elapsed > 0 else 0
    print(f"\n[✓] Done in {elapsed:.1f}s @ {rate:.0f}/s")
    print(f"    Total:    {stats.get('total', 0):>7,}")
    print(f"    Resolved: {stats.get('resolved', 0):>7,}")
    print(f"    NXDOMAIN: {stats.get('nxdomain', 0):>7,}")
    print(f"    Timeout:  {stats.get('timeout', 0):>7,}")
    print(f"    Wildcard: {stats.get('wildcard', 0):>7,}")
    print(f"    Output:   {args.output}")


if __name__ == "__main__":
    main()
