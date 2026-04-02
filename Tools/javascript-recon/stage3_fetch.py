import json
import os
import time
import hashlib
import shutil
import subprocess
from urllib.parse import urlparse
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


def log(msg, color=Fore.WHITE):
    print(f"{color}[Stage 3]{Style.RESET_ALL} {msg}")


# ─────────────────────────────────────────────
# Shared Utilities
# ─────────────────────────────────────────────

def url_to_filename(url):
    """Convert URL to a safe filename."""
    parsed = urlparse(url)
    path = parsed.path.replace("/", "_").strip("_")
    if not path:
        path = "index"
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    if not path.endswith(".js") and not path.endswith(".json") and not path.endswith(".map"):
        path += ".js"
    return f"{path}_{url_hash}"


def save_content(content, url, output_dir):
    """Save content to disk and return filename and size."""
    filename = url_to_filename(url)
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)
    return filename, len(content)


# ─────────────────────────────────────────────
# Method 1 — curl-impersonate
# Bypasses JA3/TLS fingerprinting by using
# a real Chrome TLS stack at the socket level.
# Most effective against Akamai Bot Manager.
# ─────────────────────────────────────────────

# curl-impersonate binary names to try in order
CURL_IMPERSONATE_BINS = [
    "curl_chrome116",
    "curl_chrome124",
    "curl_chrome120",
    "curl_chrome110",
    "curl_chrome107",
    "curl_chrome104",
    "curl_chrome101",
    "curl_chrome100",
    "curl_chrome99",
    "curl-impersonate-chrome",
    "curl-impersonate",
]


def find_curl_impersonate():
    """Find the first available curl-impersonate binary."""
    for binary in CURL_IMPERSONATE_BINS:
        if shutil.which(binary):
            return binary
    return None


def fetch_with_curl_impersonate(urls, args, category="js"):
    """
    Fetch URLs using curl-impersonate which spoofs Chrome's TLS fingerprint
    at the socket level. Bypasses JA3-based bot detection that blocks
    Playwright's Chromium and standard curl/wget.
    """
    binary = find_curl_impersonate()
    if not binary:
        log("curl-impersonate not found — skipping to Playwright fallback", Fore.YELLOW)
        log("  Install: https://github.com/lwthiker/curl-impersonate", Fore.YELLOW)
        return [], urls  # return empty results and all urls as failed

    log(f"Using curl-impersonate ({binary}) for TLS fingerprint bypass", Fore.CYAN)

    output_dir = os.path.join(args.output, "stage3_js")
    results = []
    failed_urls = []

    for url in tqdm(urls, desc=f"curl-impersonate [{category}]", unit="file"):
        result = {
            "url": url,
            "category": category,
            "method": "curl-impersonate",
            "status": None,
            "size": 0,
            "filename": None,
            "error": None
        }

        try:
            cmd = [
                binary,
                "--silent",
                "--show-error",
                "--location",                          # follow redirects
                "--max-redirs", "5",
                "--connect-timeout", str(args.timeout),
                "--max-time", str(args.timeout * 2),
                "--compressed",                        # handle gzip/brotli
                "--write-out", "\n%{http_code}",       # append status code
                "-H", "Accept: */*",
                "-H", "Accept-Language: en-US,en;q=0.9",
                "-H", "Cache-Control: no-cache",
                "-H", "Pragma: no-cache",
                url
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=args.timeout * 3
            )

            output = proc.stdout
            if not output:
                result["error"] = "Empty output from curl-impersonate"
                failed_urls.append(url)
                log(f"  ✗ {url} — Empty output", Fore.YELLOW)
                results.append(result)
                time.sleep(args.rate_limit)
                continue

            # Last line is the HTTP status code
            lines = output.rstrip().split("\n")
            try:
                status_code = int(lines[-1].strip())
                content = "\n".join(lines[:-1])
            except ValueError:
                status_code = 0
                content = output

            result["status"] = status_code

            if status_code == 200 and content.strip():
                filename, size = save_content(content, url, output_dir)
                result["filename"] = filename
                result["size"] = size
                log(f"  ✓ {url} → {filename} ({size:,} bytes)", Fore.GREEN)

            elif status_code == 403:
                result["error"] = "HTTP 403 — Still blocked (WAF challenge page)"
                failed_urls.append(url)
                log(f"  ✗ {url} — 403 (WAF still blocking, will retry with Playwright)", Fore.YELLOW)

            elif status_code == 0:
                result["error"] = f"curl-impersonate error: {proc.stderr[:100]}"
                failed_urls.append(url)
                log(f"  ✗ {url} — curl error: {proc.stderr[:80]}", Fore.RED)

            else:
                result["error"] = f"HTTP {status_code}"
                failed_urls.append(url)
                log(f"  ✗ {url} — HTTP {status_code}", Fore.YELLOW)

        except subprocess.TimeoutExpired:
            result["error"] = "Timeout"
            failed_urls.append(url)
            log(f"  ✗ {url} — Timeout", Fore.RED)
        except Exception as e:
            result["error"] = str(e)
            failed_urls.append(url)
            log(f"  ✗ {url} — {e}", Fore.RED)

        results.append(result)
        time.sleep(args.rate_limit)

    successful = len([r for r in results if r["status"] == 200])
    log(f"curl-impersonate: {successful}/{len(urls)} successful, {len(failed_urls)} to retry", Fore.CYAN)

    return results, failed_urls


# ─────────────────────────────────────────────
# Method 2 — Playwright (fallback)
# Used for URLs that curl-impersonate failed on.
# Less effective against JA3 detection but handles
# JavaScript challenges and cookie flows.
# ─────────────────────────────────────────────

def fetch_with_playwright(urls, args, category="js"):
    """
    Fallback fetcher using Playwright headless Chrome.
    Used when curl-impersonate is unavailable or returns 403.
    Handles JS challenges but has a distinct TLS fingerprint.
    """
    if not urls:
        return []

    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    results = []
    output_dir = os.path.join(args.output, "stage3_js")
    timeout_ms = args.timeout * 1000

    log(f"Playwright fallback for {len(urls)} {category} files", Fore.CYAN)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=args.headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-web-security",
                "--disable-features=IsolateOrigins,site-per-process",
            ]
        )

        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            extra_http_headers={
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        )

        # Remove webdriver property to reduce bot detection signals
        context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        """)

        page = context.new_page()

        for url in tqdm(urls, desc=f"Playwright [{category}]", unit="file"):
            result = {
                "url": url,
                "category": category,
                "method": "playwright",
                "status": None,
                "size": 0,
                "filename": None,
                "error": None
            }

            try:
                response = page.goto(url, timeout=timeout_ms, wait_until="networkidle")

                if response:
                    result["status"] = response.status

                    if response.status == 200:
                        try:
                            content = response.text()
                        except Exception:
                            content = page.inner_text("body") or page.content()

                        if content and content.strip():
                            filename, size = save_content(content, url, output_dir)
                            result["filename"] = filename
                            result["size"] = size
                            log(f"  ✓ {url} → {filename} ({size:,} bytes)", Fore.GREEN)
                        else:
                            result["error"] = "Empty response"
                            log(f"  ✗ {url} — Empty response", Fore.YELLOW)
                    else:
                        result["error"] = f"HTTP {response.status}"
                        log(f"  ✗ {url} — HTTP {response.status}", Fore.YELLOW)
                else:
                    result["error"] = "No response"
                    log(f"  ✗ {url} — No response", Fore.RED)

            except PlaywrightTimeout:
                result["error"] = "Timeout"
                log(f"  ✗ {url} — Timeout after {args.timeout}s", Fore.RED)
            except Exception as e:
                result["error"] = str(e)
                log(f"  ✗ {url} — {e}", Fore.RED)

            results.append(result)
            time.sleep(args.rate_limit)

        context.close()
        browser.close()

    return results


# ─────────────────────────────────────────────
# Stage 3 Runner
# ─────────────────────────────────────────────

def fetch_urls(urls, args, category):
    """
    Fetch a list of URLs using the two-tier approach:
    1. curl-impersonate (real Chrome TLS fingerprint)
    2. Playwright fallback for anything curl-impersonate fails on
    """
    if not urls:
        return []

    # Tier 1 — curl-impersonate
    curl_results, failed_urls = fetch_with_curl_impersonate(urls, args, category)

    # Tier 2 — Playwright fallback for failed URLs
    playwright_results = []
    if failed_urls:
        log(f"Retrying {len(failed_urls)} failed URLs with Playwright", Fore.YELLOW)
        playwright_results = fetch_with_playwright(failed_urls, args, category)

    return curl_results + playwright_results


def run(args):
    log("="*50, Fore.CYAN)
    log("STAGE 3 — JS Fetching (curl-impersonate + Playwright)", Fore.CYAN)
    log("="*50, Fore.CYAN)

    # Check for curl-impersonate
    binary = find_curl_impersonate()
    if binary:
        log(f"curl-impersonate found: {binary}", Fore.GREEN)
    else:
        log("curl-impersonate NOT found — will use Playwright only", Fore.YELLOW)
        log("For better WAF bypass, install curl-impersonate:", Fore.YELLOW)
        log("  https://github.com/lwthiker/curl-impersonate", Fore.YELLOW)
        log("  Or on Kali: apt install curl-impersonate (if available)", Fore.YELLOW)

    # Load stage 2 output
    input_path = os.path.join(args.output, "stage2_urls.json")
    if not os.path.exists(input_path):
        log(f"Stage 2 output not found: {input_path}", Fore.RED)
        log("Run Stage 2 first", Fore.RED)
        return None

    with open(input_path, "r") as f:
        stage2_data = json.load(f)

    js_urls = stage2_data.get("js", [])
    sourcemap_urls = stage2_data.get("sourcemap", [])
    nextjs_urls = stage2_data.get("nextjs", [])

    total = len(js_urls) + len(sourcemap_urls) + len(nextjs_urls)

    if total == 0:
        log("No URLs to fetch from Stage 2", Fore.YELLOW)
        return None

    log(f"Total files to fetch: {total}", Fore.WHITE)
    log(f"  JS files:     {len(js_urls)}", Fore.WHITE)
    log(f"  Source maps:  {len(sourcemap_urls)}", Fore.WHITE)
    log(f"  Next.js data: {len(nextjs_urls)}", Fore.WHITE)

    all_results = []

    if js_urls:
        all_results.extend(fetch_urls(js_urls, args, "js"))

    if sourcemap_urls:
        all_results.extend(fetch_urls(sourcemap_urls, args, "sourcemap"))

    if nextjs_urls:
        all_results.extend(fetch_urls(nextjs_urls, args, "nextjs"))

    # Stats
    successful = [r for r in all_results if r.get("status") == 200]
    failed = [r for r in all_results if r.get("status") != 200]
    curl_success = [r for r in successful if r.get("method") == "curl-impersonate"]
    playwright_success = [r for r in successful if r.get("method") == "playwright"]

    log(f"\nFetch complete:", Fore.CYAN)
    log(f"  Total successful:          {len(successful)}", Fore.GREEN)
    log(f"  via curl-impersonate:      {len(curl_success)}", Fore.GREEN)
    log(f"  via Playwright fallback:   {len(playwright_success)}", Fore.GREEN)
    log(f"  Failed:                    {len(failed)}", Fore.RED)
    log(f"  Total size:                {sum(r.get('size', 0) for r in successful):,} bytes", Fore.WHITE)

    if failed:
        log(f"\nFailed URLs:", Fore.YELLOW)
        for r in failed:
            log(f"  {r['url']} — {r.get('error', 'unknown')}", Fore.YELLOW)

    # Save fetch log
    output = {
        "target": args.target,
        "total_fetched": len(all_results),
        "successful": len(successful),
        "failed": len(failed),
        "method_stats": {
            "curl_impersonate": len(curl_success),
            "playwright": len(playwright_success)
        },
        "results": all_results
    }

    output_path = os.path.join(args.output, "stage3_fetch_log.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    log(f"Output saved to {output_path}", Fore.GREEN)
    log(f"JS files saved to {os.path.join(args.output, 'stage3_js/')}", Fore.GREEN)

    return output