import json
import os
import re
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


def log(msg, color=Fore.WHITE):
    print(f"{color}[Stage 4]{Style.RESET_ALL} {msg}")


# ─────────────────────────────────────────────
# Regex Patterns
# ─────────────────────────────────────────────

PATTERNS = {

    "api_endpoints": [
        (r'"(/api/[a-zA-Z0-9/_\-\.]+)"', "Double-quoted API path"),
        (r"'(/api/[a-zA-Z0-9/_\-\.]+)'", "Single-quoted API path"),
        (r'`(/api/[a-zA-Z0-9/_\-\.]+)`', "Template literal API path"),
        (r'fetch\(["\`]([^"\'`]+)["\`\)]', "fetch() call URL"),
        (r'axios\.[a-z]+\(["\`]([^"\'`]+)["\`\)]', "axios call URL"),
    ],

    "graphql": [
        (r'gql`([^`]+)`', "GraphQL gql template literal"),
        (r'"query"\s*:\s*"(query\s+\w+[^"]+)"', "Inline GraphQL query string"),
        (r'query\s+(\w+)\s*[\({]', "GraphQL query definition"),
        (r'mutation\s+(\w+)\s*[\({]', "GraphQL mutation definition"),
        (r'fragment\s+(\w+)\s+on\s+(\w+)', "GraphQL fragment definition"),
        (r'/graphql["\s\)]', "GraphQL endpoint reference"),
        (r'__typename', "GraphQL __typename usage"),
    ],

    "secrets": [
        (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', "API Key"),
        (r'(?i)(secret[_\-]?key|secretkey)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', "Secret Key"),
        (r'(?i)(access[_\-]?token|accesstoken)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', "Access Token"),
        (r'(?i)(auth[_\-]?token|authtoken)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', "Auth Token"),
        (r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})', "Bearer Token"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Hardcoded Password"),
        (r'(?i)(private[_\-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', "Private Key"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
        (r'sk-[a-zA-Z0-9]{32,}', "OpenAI API Key"),
        (r'(?i)aws[_\-]?access[_\-]?key[_\-]?id\s*[=:]\s*["\']?([A-Z0-9]{20})', "AWS Access Key"),
    ],

    "internal_urls": [
        (r'https?://[a-zA-Z0-9\-\.]+\.internal[^\s"\'`]*', "Internal .internal URL"),
        (r'https?://[a-zA-Z0-9\-\.]+\.local[^\s"\'`]*', "Internal .local URL"),
        (r'https?://localhost[^\s"\'`]*', "Localhost URL"),
        (r'https?://127\.0\.0\.[0-9]+[^\s"\'`]*', "Loopback URL"),
        (r'https?://10\.[0-9]+\.[0-9]+\.[0-9]+[^\s"\'`]*', "Private 10.x.x.x URL"),
        (r'https?://192\.168\.[0-9]+\.[0-9]+[^\s"\'`]*', "Private 192.168.x.x URL"),
        (r'https?://172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+[^\s"\'`]*', "Private 172.x.x.x URL"),
        (r'[a-zA-Z0-9\-]+\.svc\.cluster\.local', "Kubernetes internal service"),
        (r'[a-zA-Z0-9\-]+\.applications\.svc', "Kubernetes applications namespace service"),
    ],

    "env_vars": [
        (r'process\.env\.([A-Z_][A-Z0-9_]*)', "process.env variable"),
        (r'NEXT_PUBLIC_([A-Z_][A-Z0-9_]*)', "Next.js public env var"),
    ],

    "nextjs_specific": [
        (r'/_next/data/([a-zA-Z0-9_\-]+)/([^\s"\'`]+)', "Next.js data endpoint"),
        (r'/_next/static/chunks/([^\s"\'`]+)', "Next.js chunk reference"),
        (r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]+)"', "Next.js Build ID"),
        (r'/_next/BUILD_ID', "Next.js BUILD_ID reference"),
    ],

    "interesting_params": [
        (r'(?i)(admin|internal|debug|test|dev)["\s/\.]', "Admin/debug reference"),
        (r'(?i)role\s*[=:]\s*["\']?(admin|superuser|staff|employee|root)', "Role value"),
        (r'(?i)isAdmin\s*[=:]\s*(true|1)', "isAdmin flag"),
        (r'(?i)isStaff\s*[=:]\s*(true|1)', "isStaff flag"),
        (r'(?i)override[_\-]?price', "Override price reference"),
        (r'(?i)b2b[_\-]?(usage|price|channel)', "B2B reference"),
    ],

    "source_maps": [
        (r'//# sourceMappingURL=([^\s]+)', "Source map reference"),
    ]
}


def analyze_file(filepath, url):
    findings = {
        "url": url,
        "filepath": filepath,
        "size": os.path.getsize(filepath),
        "results": {}
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        findings["error"] = str(e)
        return findings

    for category, patterns in PATTERNS.items():
        matches = []
        for pattern, description in patterns:
            try:
                found = re.findall(pattern, content)
                for match in found:
                    if isinstance(match, tuple):
                        match_str = " | ".join(match)
                    else:
                        match_str = match

                    # Deduplicate within category
                    entry = {
                        "pattern": description,
                        "match": match_str.strip()
                    }
                    if entry not in matches:
                        matches.append(entry)
            except re.error:
                pass

        if matches:
            findings["results"][category] = matches

    return findings


def run(args):
    log("="*50, Fore.CYAN)
    log("STAGE 4 — JS File Analysis", Fore.CYAN)
    log("="*50, Fore.CYAN)

    # Load stage 3 fetch log
    fetch_log_path = os.path.join(args.output, "stage3_fetch_log.json")
    if not os.path.exists(fetch_log_path):
        log(f"Stage 3 fetch log not found: {fetch_log_path}", Fore.RED)
        log("Run Stage 3 first", Fore.RED)
        return None

    with open(fetch_log_path, "r") as f:
        fetch_data = json.load(f)

    successful = [r for r in fetch_data.get("results", []) if r.get("status") == 200 and r.get("filename")]

    if not successful:
        log("No successfully fetched files to analyze", Fore.YELLOW)
        return None

    log(f"Analyzing {len(successful)} files", Fore.WHITE)

    js_dir = os.path.join(args.output, "stage3_js")
    all_findings = []

    # Summary accumulators
    summary = {
        "api_endpoints": set(),
        "graphql": set(),
        "secrets": [],
        "internal_urls": set(),
        "env_vars": set(),
        "nextjs_specific": set(),
        "interesting_params": set(),
        "source_maps": set()
    }

    for result in tqdm(successful, desc="Analyzing", unit="file"):
        filepath = os.path.join(js_dir, result["filename"])
        if not os.path.exists(filepath):
            continue

        findings = analyze_file(filepath, result["url"])
        all_findings.append(findings)

        # Accumulate into summary
        for category, matches in findings.get("results", {}).items():
            for match in matches:
                match_str = match["match"]
                if category == "secrets":
                    summary["secrets"].append({
                        "file": result["url"],
                        "type": match["pattern"],
                        "value": match_str
                    })
                elif category in summary:
                    summary[category].add(match_str)

        # Log interesting findings immediately
        if findings.get("results"):
            categories_found = list(findings["results"].keys())
            log(f"  {result['url']}", Fore.WHITE)
            for cat in categories_found:
                count = len(findings["results"][cat])
                color = Fore.RED if cat == "secrets" else Fore.GREEN
                log(f"    → {cat}: {count} matches", color)

    # Convert sets to sorted lists
    for key in summary:
        if isinstance(summary[key], set):
            summary[key] = sorted(list(summary[key]))

    # Print summary
    log("\nAnalysis Summary:", Fore.CYAN)
    log(f"  API Endpoints:      {len(summary['api_endpoints'])}", Fore.GREEN)
    log(f"  GraphQL references: {len(summary['graphql'])}", Fore.GREEN)
    log(f"  Secrets found:      {len(summary['secrets'])}", Fore.RED if summary['secrets'] else Fore.WHITE)
    log(f"  Internal URLs:      {len(summary['internal_urls'])}", Fore.YELLOW)
    log(f"  Env Variables:      {len(summary['env_vars'])}", Fore.WHITE)
    log(f"  Next.js specific:   {len(summary['nextjs_specific'])}", Fore.WHITE)
    log(f"  Interesting params: {len(summary['interesting_params'])}", Fore.YELLOW)
    log(f"  Source maps:        {len(summary['source_maps'])}", Fore.YELLOW)

    if summary["secrets"]:
        log("\n[!] SECRETS FOUND — Review immediately:", Fore.RED)
        for secret in summary["secrets"]:
            log(f"  [{secret['type']}] in {secret['file']}", Fore.RED)
            log(f"    Value: {secret['value'][:80]}...", Fore.RED)

    # Save output
    output = {
        "target": args.target,
        "files_analyzed": len(all_findings),
        "summary": summary,
        "per_file": all_findings
    }

    output_path = os.path.join(args.output, "stage4_findings.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    log(f"\nStage 4 complete", Fore.GREEN)
    log(f"Output saved to {output_path}", Fore.GREEN)

    return output
