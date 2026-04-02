from __future__ import annotations
#!/usr/bin/env python3
"""
takeover_scanner.py — Subdomain takeover detection for sudomy v2

Checks subdomains for CNAME chains pointing to unclaimed third-party services.
Fingerprint database is maintained inline and easy to extend.

Usage:
  python3 takeover_scanner.py -i subdomains.txt -o results.txt [-t 100] [-v]

Exit codes: 0 = success, 1 = error
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# ── Fingerprint Database ─────────────────────────────────────────────────────
# Each entry: service name, CNAME pattern(s), HTTP response fingerprint(s),
# and whether NXDOMAIN alone is sufficient to flag.

@dataclass
class Fingerprint:
    service:      str
    cname:        list[str]     = field(default_factory=list)  # substrings to match in CNAME
    response:     list[str]     = field(default_factory=list)  # substrings in HTTP body/headers
    nxdomain:     bool          = False                         # flag on NXDOMAIN + matching CNAME
    status_codes: list[int]     = field(default_factory=list)  # expected HTTP status codes
    confidence:   str           = "HIGH"                        # HIGH / MEDIUM / LOW


FINGERPRINTS = [
    Fingerprint("AWS S3",
        cname=["s3.amazonaws.com", "s3-website", ".s3."],
        response=["NoSuchBucket", "The specified bucket does not exist"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("AWS CloudFront",
        cname=["cloudfront.net"],
        response=["The request could not be satisfied", "ERROR: The request could not be satisfied"],
        confidence="HIGH"),
    Fingerprint("AWS Elastic Beanstalk",
        cname=["elasticbeanstalk.com"],
        response=["404 Not Found"], nxdomain=True, confidence="HIGH"),
    Fingerprint("GitHub Pages",
        cname=["github.io", "github.map.fastly.net"],
        response=["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Heroku",
        cname=["herokudns.com", "herokussl.com", ".herokuapp.com"],
        response=["No such app", "herokucdn.com/error-pages/no-such-app"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Zendesk",
        cname=["zendesk.com"],
        response=["Help Center Closed", "Oops, this help center no longer exists"],
        confidence="HIGH"),
    Fingerprint("Shopify",
        cname=["myshopify.com", "shopify.com"],
        response=["Sorry, this shop is currently unavailable", "Only one step away!"],
        confidence="HIGH"),
    Fingerprint("Tumblr",
        cname=["tumblr.com"],
        response=["Whatever you were looking for doesn't currently exist at this address"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Squarespace",
        cname=["squarespace.com", "squarespace.net"],
        response=["No Such Account", "page not claimed"],
        confidence="MEDIUM"),
    Fingerprint("Fastly",
        cname=["fastly.net"],
        response=["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
        confidence="HIGH"),
    Fingerprint("Ghost",
        cname=["ghost.io"],
        response=["The thing you were looking for is no longer here"],
        confidence="HIGH"),
    Fingerprint("Pantheon",
        cname=["pantheonsite.io"],
        response=["The gods are wise", "404 error unknown site!"],
        confidence="HIGH"),
    Fingerprint("Readme.io",
        cname=["readme.io", "readmessl.com"],
        response=["Project doesnt exist... yet!"],
        confidence="HIGH"),
    Fingerprint("StatusPage (Atlassian)",
        cname=["statuspage.io", "atlassian.com"],
        response=["Better Status Communication", "You are being redirected"],
        confidence="MEDIUM"),
    Fingerprint("Surge.sh",
        cname=["surge.sh"],
        response=["project not found", "surge.sh"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Bitbucket",
        cname=["bitbucket.io"],
        response=["Repository not found"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Unbounce",
        cname=["unbouncepages.com", "unbounce.com"],
        response=["The requested URL was not found on this server"],
        confidence="MEDIUM"),
    Fingerprint("UserVoice",
        cname=["uservoice.com"],
        response=["This UserVoice subdomain is currently available!"],
        confidence="HIGH"),
    Fingerprint("Wordpress.com",
        cname=["wordpress.com"],
        response=["Do you want to register"],
        confidence="HIGH"),
    Fingerprint("Strikingly",
        cname=["strikingly.com"],
        response=["But if you're looking to build your own website"],
        confidence="HIGH"),
    Fingerprint("Webflow",
        cname=["proxy.webflow.com", "webflow.io"],
        response=["The page you are looking for doesn't exist or has been moved"],
        confidence="HIGH"),
    Fingerprint("Intercom",
        cname=["custom.intercom.help", "intercom.io"],
        response=["This page is reserved for artistic dogs"],
        confidence="HIGH"),
    Fingerprint("HelpScout",
        cname=["helpscoutdocs.com"],
        response=["No settings were found for this company"],
        confidence="HIGH"),
    Fingerprint("Cargo",
        cname=["cargocollective.com"],
        response=["404 Not Found"],
        confidence="LOW"),
    Fingerprint("Azure",
        cname=["azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
               "trafficmanager.net", "azureedge.net", "azure-api.net",
               "azurehdinsight.net", "azuredatalakestore.net"],
        response=["404 Web Site not found", "Microsoft Azure App Service"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Kinsta",
        cname=["kinsta.cloud"],
        response=["No Site For Domain"],
        confidence="HIGH"),
    Fingerprint("Fly.io",
        cname=[".fly.dev", ".edgeapp.net"],
        response=["404 Not Found", "Fly.io"],
        nxdomain=True, confidence="MEDIUM"),
    Fingerprint("Render",
        cname=[".onrender.com"],
        response=["Service Not Found"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Netlify",
        cname=[".netlify.app", ".netlify.com"],
        response=["Not Found - Request ID"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Vercel",
        cname=[".vercel.app", "cname.vercel-dns.com"],
        response=["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Wix",
        cname=["wixdns.net", "parastorage.com"],
        response=["Error ConnectYourDomain"],
        confidence="MEDIUM"),
    Fingerprint("Freshdesk",
        cname=["freshdesk.com"],
        response=["Oops...This page doesn't exist"],
        confidence="HIGH"),
    Fingerprint("Feedpress",
        cname=["redirect.feedpress.me"],
        response=["The feed has not been found"],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("HubSpot",
        cname=["hubspot.com", "hs-sites.com"],
        response=["Domain not configured", "does not exist in our system"],
        confidence="HIGH"),
    Fingerprint("Pingdom",
        cname=["stats.pingdom.com"],
        response=["This public report page has not been activated"],
        confidence="HIGH"),
    Fingerprint("Tave",
        cname=["clientaccess.tave.com"],
        response=["<h1>Error 404"],
        confidence="MEDIUM"),
    Fingerprint("Airee",
        cname=["cdn.airee.ru"],
        response=["Ошибка 402"],
        confidence="MEDIUM"),
    Fingerprint("Launchrock",
        cname=["launchrock.com"],
        response=["It looks like you may have taken a wrong turn somewhere"],
        confidence="HIGH"),
    Fingerprint("Tilda",
        cname=["tilda.ws"],
        response=["Please renew your subscription"],
        confidence="HIGH"),
    Fingerprint("Ngrok",
        cname=[".ngrok.io"],
        response=["ngrok.io not found", "Tunnel "],
        nxdomain=True, confidence="HIGH"),
    Fingerprint("Short.io",
        cname=["short.io", "cname.short.io"],
        response=["Link Not Found"],
        confidence="HIGH"),
    Fingerprint("Campaign Monitor",
        cname=["createsend.com"],
        response=["Double check the URL"],
        confidence="HIGH"),
    Fingerprint("Mailchimp",
        cname=["mcsv.net", "list-manage.com"],
        response=["Oops, that page's gone"],
        confidence="HIGH"),
]


# ── DNS helpers ───────────────────────────────────────────────────────────────

def get_cname_chain(hostname: str, depth: int = 10):
    """Return (cname_chain, is_nxdomain) via dig."""
    chain = []
    current = hostname
    nxdomain = False

    for _ in range(depth):
        try:
            out = subprocess.check_output(
                ["dig", "+short", "+time=5", "+tries=2", current, "CNAME"],
                stderr=subprocess.DEVNULL, timeout=8
            ).decode().strip()
        except Exception:
            break

        if not out:
            # Check if NXDOMAIN
            try:
                status_out = subprocess.check_output(
                    ["dig", "+short", "+time=5", current],
                    stderr=subprocess.DEVNULL, timeout=8
                ).decode().strip()
                if not status_out:
                    # Do NXDOMAIN check
                    nx_out = subprocess.check_output(
                        ["dig", "+noall", "+comments", "+time=5", current],
                        stderr=subprocess.DEVNULL, timeout=8
                    ).decode()
                    if "NXDOMAIN" in nx_out or "SERVFAIL" in nx_out:
                        nxdomain = True
            except Exception:
                pass
            break

        cname_target = out.splitlines()[-1].rstrip(".").strip()
        if cname_target:
            chain.append(cname_target)
            current = cname_target
        else:
            break

    return chain, nxdomain


async def fetch_http_response(url: str, timeout: int = 10) -> tuple[int, str]:
    """Return (status_code, body_snippet) via curl."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sk", "--max-time", str(timeout),
            "-o", "-", "-w", "\n__STATUS__:%{http_code}",
            "-L", "--max-redirs", "3",
            "-A", "Mozilla/5.0 (compatible; Sudomy/2.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        text = stdout.decode("utf-8", errors="replace")
        if "__STATUS__:" in text:
            body, status_part = text.rsplit("__STATUS__:", 1)
            try:
                code = int(status_part.strip())
            except ValueError:
                code = 0
            return code, body[:4000]
        return 0, text[:4000]
    except Exception:
        return 0, ""


def match_fingerprint(cname_chain: list, body: str,
                      status_code: int, nxdomain: bool) :
    cname_str = " ".join(cname_chain).lower()
    body_lower = body.lower()

    for fp in FINGERPRINTS:
        # Check CNAME match first
        cname_matched = any(c.lower() in cname_str for c in fp.cname)
        if not cname_matched:
            continue

        # NXDOMAIN is sufficient for some services
        if fp.nxdomain and nxdomain:
            return fp

        # Check HTTP response fingerprints
        for sig in fp.response:
            if sig.lower() in body_lower:
                return fp

        # Check status code hints
        if fp.status_codes and status_code in fp.status_codes and cname_matched:
            return fp

    return None


# ── Async scanner ─────────────────────────────────────────────────────────────

async def check_subdomain(subdomain: str, semaphore: asyncio.Semaphore,
                           results: list, stats: dict, verbose: bool):
    async with semaphore:
        cname_chain, nxdomain = await asyncio.to_thread(get_cname_chain, subdomain)

        if not cname_chain and not nxdomain:
            stats["no_cname"] += 1
            return

        # Try both HTTP and HTTPS
        body, status = "", 0
        for scheme in ["https", "http"]:
            status, body = await fetch_http_response(f"{scheme}://{subdomain}")
            if body:
                break

        fp = match_fingerprint(cname_chain, body, status, nxdomain)

        if fp:
            result = {
                "subdomain": subdomain,
                "service": fp.service,
                "confidence": fp.confidence,
                "cname": cname_chain,
                "nxdomain": nxdomain,
                "status_code": status,
            }
            results.append(result)
            stats["vulnerable"] += 1
            verdict = f"  [{'HIGH' if fp.confidence == 'HIGH' else fp.confidence}]"
            color_start = "\033[1;31m" if fp.confidence == "HIGH" else "\033[1;33m"
            color_end = "\033[0m"
            print(f"{color_start}[VULNERABLE]{color_end} {subdomain} -> {fp.service}{verdict}")
            if cname_chain:
                print(f"           CNAME: {' -> '.join(cname_chain)}")
        else:
            stats["safe"] += 1
            if verbose and cname_chain:
                print(f"  [OK] {subdomain} -> {' -> '.join(cname_chain)}")

        stats["checked"] += 1


async def run_scanner(subdomains: list[str], concurrency: int, verbose: bool) -> list[dict]:
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    stats = {"checked": 0, "vulnerable": 0, "safe": 0, "no_cname": 0}

    total = len(subdomains)
    print(f"[*] Scanning {total:,} subdomains for takeover with concurrency={concurrency}...\n")
    start = time.time()

    tasks = [
        check_subdomain(sub, semaphore, results, stats, verbose)
        for sub in subdomains
    ]

    done = 0
    for coro in asyncio.as_completed(tasks):
        await coro
        done += 1
        if done % 100 == 0 or done == total:
            elapsed = time.time() - start
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  Progress: [{done}/{total}] {rate:.0f}/s | "
                  f"Vulnerable: {stats['vulnerable']}", end="\r", file=sys.stderr)

    elapsed = time.time() - start
    print(f"\n\n[✓] Scan completed in {elapsed:.1f}s")
    print(f"    Checked:     {stats['checked']:>6,}")
    print(f"    Vulnerable:  {stats['vulnerable']:>6,}")
    print(f"    No CNAME:    {stats['no_cname']:>6,}")
    return results


def main():
    parser = argparse.ArgumentParser(description="sudomy takeover scanner")
    parser.add_argument("-i", "--input",   required=True, help="Subdomain list (one per line)")
    parser.add_argument("-o", "--output",  required=True, help="Output file (TXT + JSON)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrency (default: 50)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    with open(args.input) as f:
        subdomains = [l.strip().lower() for l in f if l.strip()]

    print(f"[*] Loaded {len(subdomains):,} subdomains | Fingerprints: {len(FINGERPRINTS)}")
    print(f"[*] Output: {args.output}\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(run_scanner(subdomains, args.threads, args.verbose))
    loop.close()

    # Write text output
    with open(args.output, "w") as f:
        if not results:
            f.write("No vulnerable subdomains found.\n")
        else:
            f.write(f"# Subdomain Takeover Results — {len(results)} vulnerable\n\n")
            for r in sorted(results, key=lambda x: x["confidence"], reverse=True):
                f.write(f"[{r['confidence']}] {r['subdomain']} => {r['service']}\n")
                if r["cname"]:
                    f.write(f"  CNAME: {' -> '.join(r['cname'])}\n")
                if r["nxdomain"]:
                    f.write(f"  NXDOMAIN: True\n")
                f.write(f"  HTTP Status: {r['status_code']}\n\n")

    # Write JSON output
    json_out = args.output.replace(".txt", ".json")
    with open(json_out, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[✓] Results → {args.output}")
    print(f"[✓] JSON    → {json_out}")
    if results:
        high = sum(1 for r in results if r["confidence"] == "HIGH")
        print(f"\n[!] {high} HIGH confidence vulnerabilities found!")


if __name__ == "__main__":
    main()
