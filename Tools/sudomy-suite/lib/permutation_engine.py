from __future__ import annotations
#!/usr/bin/env python3
"""
permutation_engine.py — Smart subdomain permutation generator for sudomy v2

Given a list of known subdomains, generates likely new ones using:
  1. Word-based mutations (dev, staging, api, admin prefixes/suffixes)
  2. Number sequences (api1, api2 ... api10)
  3. Environment combos (dev-api, staging-app, etc.)
  4. Discovered-word recombination

Usage:
  python3 permutation_engine.py -i known_subs.txt -d example.com -o permutations.txt [-w extra_words.txt]

Output: one subdomain per line, ready for mass_resolver.py
"""

import argparse
import itertools
import os
import re
import sys
from collections import Counter

# ── Built-in permutation word lists ──────────────────────────────────────────

PREFIXES = [
    "dev", "development", "stage", "staging", "stg", "uat", "qa", "test", "testing",
    "prod", "production", "live", "demo", "beta", "alpha", "sandbox", "preview",
    "api", "api2", "api3", "apiv2", "apiv3", "v1", "v2", "v3",
    "admin", "administrator", "manage", "management", "portal", "dashboard", "panel",
    "app", "apps", "web", "www", "www2", "www3", "static", "assets", "media", "cdn",
    "img", "images", "video", "videos", "files", "uploads", "downloads",
    "mail", "email", "smtp", "imap", "pop", "pop3", "webmail", "mx", "mx1", "mx2",
    "vpn", "remote", "ssh", "ftp", "sftp", "rdp",
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "proxy", "gateway", "router", "lb", "loadbalancer", "waf", "firewall",
    "internal", "intranet", "corp", "corporate", "private",
    "auth", "login", "sso", "oauth", "id", "identity",
    "git", "gitlab", "github", "bitbucket", "svn", "repo", "registry",
    "ci", "cd", "jenkins", "build", "deploy", "devops",
    "monitor", "monitoring", "metrics", "logs", "logging", "grafana", "kibana",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "backup", "bak", "archive",
    "shop", "store", "cart", "checkout", "payment", "pay",
    "help", "support", "helpdesk", "service", "services",
    "blog", "news", "forum", "community", "kb", "docs", "wiki", "doc",
    "mobile", "m", "ios", "android",
    "search", "suggest", "autocomplete",
    "analytics", "tracking", "pixel",
    "cr", "cr2", "new", "old", "legacy", "classic",
    "global", "us", "eu", "ap", "us-east", "us-west", "eu-west",
]

SUFFIXES = [
    "-dev", "-stg", "-staging", "-prod", "-test", "-qa", "-uat",
    "-api", "-app", "-web", "-admin",
    "-internal", "-corp", "-private",
    "-backup", "-bak", "-old", "-new", "-v2",
    "1", "2", "3", "01", "02", "03",
]

JOINER_CHARS = ["-", ".", ""]


def extract_words_from_subdomains(subdomains: list, domain: str) -> list:
    """Pull meaningful words from discovered subdomain labels."""
    words = Counter()
    tld_parts = set(domain.split("."))

    for sub in subdomains:
        # Strip the root domain
        prefix = sub.rstrip("." + domain)
        # Split on dots and hyphens
        labels = re.split(r"[.\-_]", prefix)
        for label in labels:
            label = label.lower().strip()
            if label and label not in tld_parts and len(label) > 1 and not label.isdigit():
                words[label] += 1

    # Return words seen at least once, sorted by frequency
    return [w for w, _ in words.most_common(200)]


def generate_permutations(known_subdomains: list, domain: str,
                          extra_words: list[str] = None) -> set[str]:
    results = set()
    discovered_words = extract_words_from_subdomains(known_subdomains, domain)

    # Combine built-in prefixes with discovered words
    all_words = list(dict.fromkeys(PREFIXES + discovered_words + (extra_words or [])))

    print(f"[*] Permutation words: {len(all_words):,} (built-in + {len(discovered_words)} discovered)")

    # 1. Simple word → subdomain
    for word in all_words:
        results.add(f"{word}.{domain}")

    # 2. Word + numeric suffix
    for word in all_words[:60]:   # top words only for number sequences
        for n in range(1, 11):
            results.add(f"{word}{n}.{domain}")
        for n in ["01", "02", "03", "04", "05"]:
            results.add(f"{word}{n}.{domain}")

    # 3. Suffix mutations on discovered labels
    for word in discovered_words[:100]:
        for suffix in SUFFIXES:
            results.add(f"{word}{suffix}.{domain}")

    # 4. Pair combos: top words × top words (env × service patterns)
    env_words = ["dev", "stg", "staging", "prod", "test", "uat", "qa", "beta"]
    service_words = discovered_words[:40] + ["api", "app", "web", "admin", "portal", "auth"]
    for env in env_words:
        for svc in service_words:
            if env != svc:
                for j in ["-", "."]:
                    results.add(f"{env}{j}{svc}.{domain}")
                    results.add(f"{svc}{j}{env}.{domain}")

    # 5. Regional prefixes
    regions = ["us", "eu", "ap", "sg", "uk", "ca", "au", "jp",
               "us-east", "us-west", "eu-west", "eu-central", "ap-southeast"]
    for region in regions:
        for svc in service_words[:30]:
            results.add(f"{region}-{svc}.{domain}")
            results.add(f"{svc}-{region}.{domain}")

    # 6. Mutate existing subdomains with env/version swaps
    for sub in known_subdomains[:200]:
        prefix = sub.replace(f".{domain}", "")
        for suf in ["-v2", "-v3", "-new", "-old", "-bak", "2", "3"]:
            results.add(f"{prefix}{suf}.{domain}")
        for env in ["dev", "stg", "prod", "test"]:
            if env not in prefix:
                results.add(f"{env}-{prefix}.{domain}")

    # Remove root domain and known subdomains from output
    known_set = set(known_subdomains)
    results.discard(domain)
    results -= known_set

    # Final validation: only valid hostnames
    valid_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    results = {r for r in results if valid_pattern.match(r)}

    return results


def main():
    parser = argparse.ArgumentParser(description="sudomy smart permutation generator")
    parser.add_argument("-i", "--input",   required=True,  help="Known subdomains (one per line)")
    parser.add_argument("-d", "--domain",  required=True,  help="Root domain (e.g. example.com)")
    parser.add_argument("-o", "--output",  required=True,  help="Output file for permutations")
    parser.add_argument("-w", "--words",   default=None,   help="Extra wordlist file to include")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        known = [l.strip().lower() for l in f if l.strip()]

    extra_words = []
    if args.words and os.path.isfile(args.words):
        with open(args.words) as f:
            extra_words = [l.strip().lower() for l in f if l.strip()]
        print(f"[*] Loaded {len(extra_words):,} extra words from {args.words}")

    print(f"[*] Generating permutations for {args.domain} from {len(known):,} known subdomains...")
    perms = generate_permutations(known, args.domain, extra_words)

    with open(args.output, "w") as f:
        for sub in sorted(perms):
            f.write(sub + "\n")

    print(f"[✓] Generated {len(perms):,} permutation candidates → {args.output}")


if __name__ == "__main__":
    main()
