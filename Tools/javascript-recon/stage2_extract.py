import json
import os
import re
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)


def log(msg, color=Fore.WHITE):
    print(f"{color}[Stage 2]{Style.RESET_ALL} {msg}")


# JS file patterns worth fetching
JS_PATTERNS = [
    r"/_next/static/chunks/.*\.js$",
    r"/_next/static/chunks/pages/.*\.js$",
    r"/_next/static/chunks/app/.*\.js$",
    r"/static/js/.*\.js$",
    r"/assets/.*\.js$",
    r"/js/.*\.js$",
    r"\.chunk\.js$",
    r"webpack.*\.js$",
    r"main.*\.js$",
    r"vendor.*\.js$",
    r"runtime.*\.js$",
]

# Source map patterns
MAP_PATTERNS = [
    r"\.js\.map$",
]

# Next.js data patterns
NEXTJS_PATTERNS = [
    r"/_next/data/.*\.json$",
    r"/_next/BUILD_ID$",
    r"/_next/static/.*\.(js|json|css)$",
]

# Patterns to skip — not useful for analysis
SKIP_PATTERNS = [
    r"\.png$", r"\.jpg$", r"\.jpeg$", r"\.gif$",
    r"\.svg$", r"\.ico$", r"\.woff$", r"\.woff2$",
    r"\.ttf$", r"\.eot$", r"\.css$", r"\.pdf$",
    r"\.mp4$", r"\.webm$", r"\.mp3$",
]


def categorize_url(url):
    path = urlparse(url).path.lower()

    for pattern in SKIP_PATTERNS:
        if re.search(pattern, path):
            return None

    for pattern in MAP_PATTERNS:
        if re.search(pattern, path):
            return "sourcemap"

    for pattern in NEXTJS_PATTERNS:
        if re.search(pattern, path):
            return "nextjs"

    for pattern in JS_PATTERNS:
        if re.search(pattern, path):
            return "js"

    # Generic JS fallback
    if path.endswith(".js"):
        return "js"

    return None


def normalize_url(url, target):
    url = url.strip()

    # Skip data URIs and blobs
    if url.startswith("data:") or url.startswith("blob:"):
        return None

    # If relative, make absolute
    if url.startswith("//"):
        url = "https:" + url
    elif url.startswith("/"):
        parsed_target = urlparse(target)
        url = f"{parsed_target.scheme}://{parsed_target.netloc}{url}"

    # Validate
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None

    return url


def run(args):
    log("="*50, Fore.CYAN)
    log("STAGE 2 — URL Extraction and Deduplication", Fore.CYAN)
    log("="*50, Fore.CYAN)

    # Load stage 1 output
    input_path = os.path.join(args.output, "stage1_passive.json")
    if not os.path.exists(input_path):
        log(f"Stage 1 output not found: {input_path}", Fore.RED)
        log("Run Stage 1 first", Fore.RED)
        return None

    with open(input_path, "r") as f:
        stage1_data = json.load(f)

    raw_urls = stage1_data.get("urls", [])
    log(f"Processing {len(raw_urls)} URLs from Stage 1", Fore.WHITE)

    # Categorize and normalize
    categorized = {
        "js": [],
        "sourcemap": [],
        "nextjs": [],
        "skipped": 0
    }

    seen = set()

    for url in raw_urls:
        normalized = normalize_url(url, args.target)
        if not normalized:
            categorized["skipped"] += 1
            continue

        if normalized in seen:
            continue
        seen.add(normalized)

        category = categorize_url(normalized)
        if category is None:
            categorized["skipped"] += 1
            continue

        categorized[category].append(normalized)

    # Sort by category
    total_actionable = (
        len(categorized["js"]) +
        len(categorized["sourcemap"]) +
        len(categorized["nextjs"])
    )

    log(f"JS files:      {len(categorized['js'])}", Fore.GREEN)
    log(f"Source maps:   {len(categorized['sourcemap'])}", Fore.GREEN)
    log(f"Next.js data:  {len(categorized['nextjs'])}", Fore.GREEN)
    log(f"Skipped:       {categorized['skipped']}", Fore.YELLOW)
    log(f"Total to fetch: {total_actionable}", Fore.CYAN)

    # Print discovered JS files
    if categorized["js"]:
        log("\nJS files to fetch:", Fore.CYAN)
        for url in categorized["js"]:
            log(f"  {url}", Fore.WHITE)

    if categorized["sourcemap"]:
        log("\nSource maps to fetch:", Fore.CYAN)
        for url in categorized["sourcemap"]:
            log(f"  {url}", Fore.YELLOW)

    # Save output
    output = {
        "target": args.target,
        "domain": args.domain,
        "total_actionable": total_actionable,
        "counts": {
            "js": len(categorized["js"]),
            "sourcemap": len(categorized["sourcemap"]),
            "nextjs": len(categorized["nextjs"]),
            "skipped": categorized["skipped"]
        },
        "js": categorized["js"],
        "sourcemap": categorized["sourcemap"],
        "nextjs": categorized["nextjs"]
    }

    output_path = os.path.join(args.output, "stage2_urls.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    log(f"\nStage 2 complete — {total_actionable} URLs ready for fetching", Fore.GREEN)
    log(f"Output saved to {output_path}", Fore.GREEN)

    return output
