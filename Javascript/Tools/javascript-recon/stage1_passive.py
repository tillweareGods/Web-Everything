import json
import os
import time
import requests
from urllib.parse import urlencode, quote_plus
from colorama import Fore, Style, init

init(autoreset=True)


def log(msg, color=Fore.WHITE):
    print(f"{color}[Stage 1]{Style.RESET_ALL} {msg}")


# ─────────────────────────────────────────────
# Google Dorking
# ─────────────────────────────────────────────
def google_dork(domain, pause, skip):
    if skip:
        log("Skipping Google dorking (--skip-google)", Fore.YELLOW)
        return []

    log(f"Starting Google dorking for {domain}", Fore.CYAN)

    dorks = [
        f"site:{domain} ext:js",
        f"site:{domain} \"_next/static\"",
        f"site:{domain} filetype:js",
        f"site:{domain} \"static/chunks\"",
        f"site:{domain} \"webpack\"",
    ]

    urls = []

    try:
        from googlesearch import search
    except ImportError:
        log("googlesearch-python not installed. Run: pip3 install googlesearch-python --break-system-packages", Fore.RED)
        return []

    for dork in dorks:
        log(f"Dorking: {dork}", Fore.WHITE)
        try:
            results = list(search(dork, num_results=20, sleep_interval=pause))
            for url in results:
                if domain in url:
                    urls.append(url)
                    log(f"  Found: {url}", Fore.GREEN)
            time.sleep(pause)
        except Exception as e:
            log(f"  Google dork error: {e}", Fore.RED)
            time.sleep(pause * 2)

    log(f"Google dorking complete — {len(urls)} URLs found", Fore.CYAN)
    return list(set(urls))


# ─────────────────────────────────────────────
# Wayback Machine CDX API
# ─────────────────────────────────────────────
def wayback_crawl(domain, max_results, skip):
    if skip:
        log("Skipping Wayback Machine (--skip-wayback)", Fore.YELLOW)
        return []

    log(f"Querying Wayback Machine CDX API for {domain}", Fore.CYAN)

    urls = []

    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "filter": "statuscode:200",
        "limit": max_results,
        "matchType": "domain"
    }

    try:
        response = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params=params,
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            # First row is header
            for row in data[1:]:
                url = row[0]
                urls.append(url)
            log(f"Wayback Machine returned {len(urls)} URLs", Fore.GREEN)
        else:
            log(f"Wayback Machine returned status {response.status_code}", Fore.RED)
    except Exception as e:
        log(f"Wayback Machine error: {e}", Fore.RED)

    return list(set(urls))


# ─────────────────────────────────────────────
# CommonCrawl Index API
# ─────────────────────────────────────────────
def commoncrawl_crawl(domain, max_results, skip):
    if skip:
        log("Skipping CommonCrawl (--skip-wayback)", Fore.YELLOW)
        return []

    log(f"Querying CommonCrawl index for {domain}", Fore.CYAN)

    urls = []

    try:
        # Get latest index
        index_response = requests.get(
            "https://index.commoncrawl.org/collinfo.json",
            timeout=15
        )
        if index_response.status_code != 200:
            log("Could not fetch CommonCrawl index list", Fore.RED)
            return []

        indexes = index_response.json()
        latest_index = indexes[0]["cdx-api"]

        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "url",
            "limit": max_results,
            "filter": "status:200"
        }

        response = requests.get(latest_index, params=params, timeout=30)
        if response.status_code == 200:
            for line in response.text.strip().split("\n"):
                if line:
                    try:
                        entry = json.loads(line)
                        if "url" in entry:
                            urls.append(entry["url"])
                    except json.JSONDecodeError:
                        pass
            log(f"CommonCrawl returned {len(urls)} URLs", Fore.GREEN)
        else:
            log(f"CommonCrawl returned status {response.status_code}", Fore.RED)

    except Exception as e:
        log(f"CommonCrawl error: {e}", Fore.RED)

    return list(set(urls))


# ─────────────────────────────────────────────
# HAR File Parser
# ─────────────────────────────────────────────
def parse_har(har_path, domain):
    if not har_path:
        log("No HAR file provided, skipping", Fore.YELLOW)
        return []

    if not os.path.exists(har_path):
        log(f"HAR file not found: {har_path}", Fore.RED)
        return []

    log(f"Parsing HAR file: {har_path}", Fore.CYAN)

    urls = []

    try:
        with open(har_path, "r", encoding="utf-8") as f:
            har_data = json.load(f)

        entries = har_data.get("log", {}).get("entries", [])
        for entry in entries:
            url = entry.get("request", {}).get("url", "")
            if domain in url:
                urls.append(url)

        log(f"HAR file yielded {len(urls)} URLs from {len(entries)} total entries", Fore.GREEN)

    except json.JSONDecodeError as e:
        log(f"HAR file parse error: {e}", Fore.RED)
    except Exception as e:
        log(f"HAR file error: {e}", Fore.RED)

    return list(set(urls))


# ─────────────────────────────────────────────
# Main Stage 1 Runner
# ─────────────────────────────────────────────
def run(args):
    log("="*50, Fore.CYAN)
    log("STAGE 1 — Passive JS Discovery", Fore.CYAN)
    log("="*50, Fore.CYAN)

    all_urls = []

    # Google dorking
    google_urls = google_dork(
        args.domain,
        args.google_pause,
        args.skip_google
    )
    all_urls.extend(google_urls)

    # Wayback Machine
    wayback_urls = wayback_crawl(
        args.domain,
        args.max_wayback,
        args.skip_wayback
    )
    all_urls.extend(wayback_urls)

    # CommonCrawl
    cc_urls = commoncrawl_crawl(
        args.domain,
        args.max_wayback,
        args.skip_wayback
    )
    all_urls.extend(cc_urls)

    # HAR file
    har_urls = parse_har(args.har, args.domain)
    all_urls.extend(har_urls)

    # Deduplicate
    all_urls = list(set(all_urls))

    # Save output
    output = {
        "target": args.target,
        "domain": args.domain,
        "total_urls": len(all_urls),
        "sources": {
            "google": len(google_urls),
            "wayback": len(wayback_urls),
            "commoncrawl": len(cc_urls),
            "har": len(har_urls)
        },
        "urls": all_urls
    }

    output_path = os.path.join(args.output, "stage1_passive.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    log(f"Stage 1 complete — {len(all_urls)} total unique URLs", Fore.GREEN)
    log(f"Output saved to {output_path}", Fore.GREEN)

    return output
