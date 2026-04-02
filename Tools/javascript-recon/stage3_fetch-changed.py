import json
import os
import time
import hashlib
from urllib.parse import urlparse
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


def log(msg, color=Fore.WHITE):
    print(f"{color}[Stage 3]{Style.RESET_ALL} {msg}")


def url_to_filename(url):
    """Convert URL to a safe filename."""
    parsed = urlparse(url)
    path = parsed.path.replace("/", "_").strip("_")
    if not path:
        path = "index"
    # Add hash suffix to avoid collisions
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    # Ensure .js extension
    if not path.endswith(".js") and not path.endswith(".json") and not path.endswith(".map"):
        path += ".js"
    return f"{path}_{url_hash}"


def fetch_with_playwright(urls, args, category="js"):
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    results = []
    output_dir = os.path.join(args.output, "stage3_js")
    timeout_ms = args.timeout * 1000

    log(f"Fetching {len(urls)} {category} files with Playwright", Fore.CYAN)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=args.headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
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

        page = context.new_page()

        for url in tqdm(urls, desc=f"Fetching {category}", unit="file"):
            result = {
                "url": url,
                "category": category,
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
                        content = page.content()

                        # For JS files get raw content not HTML
                        try:
                            content = response.text()
                        except Exception:
                            content = page.inner_text("body") or page.content()

                        if content:
                            filename = url_to_filename(url)
                            filepath = os.path.join(output_dir, filename)

                            with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                                f.write(content)

                            result["size"] = len(content)
                            result["filename"] = filename
                            log(f"  ✓ {url} → {filename} ({len(content):,} bytes)", Fore.GREEN)
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

            # Rate limiting
            time.sleep(args.rate_limit)

        context.close()
        browser.close()

    return results


def run(args):
    log("="*50, Fore.CYAN)
    log("STAGE 3 — Playwright JS Fetching", Fore.CYAN)
    log("="*50, Fore.CYAN)

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

    all_results = []

    # Fetch JS files
    if js_urls:
        js_results = fetch_with_playwright(js_urls, args, category="js")
        all_results.extend(js_results)

    # Fetch source maps
    if sourcemap_urls:
        map_results = fetch_with_playwright(sourcemap_urls, args, category="sourcemap")
        all_results.extend(map_results)

    # Fetch Next.js data files
    if nextjs_urls:
        nextjs_results = fetch_with_playwright(nextjs_urls, args, category="nextjs")
        all_results.extend(nextjs_results)

    # Stats
    successful = [r for r in all_results if r["status"] == 200]
    failed = [r for r in all_results if r["status"] != 200]

    log(f"\nFetch complete:", Fore.CYAN)
    log(f"  Successful: {len(successful)}", Fore.GREEN)
    log(f"  Failed:     {len(failed)}", Fore.RED)
    log(f"  Total size: {sum(r['size'] for r in successful):,} bytes", Fore.WHITE)

    # Save fetch log
    output = {
        "target": args.target,
        "total_fetched": len(all_results),
        "successful": len(successful),
        "failed": len(failed),
        "results": all_results
    }

    output_path = os.path.join(args.output, "stage3_fetch_log.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    log(f"Output saved to {output_path}", Fore.GREEN)
    log(f"JS files saved to {os.path.join(args.output, 'stage3_js/')}", Fore.GREEN)

    return output
