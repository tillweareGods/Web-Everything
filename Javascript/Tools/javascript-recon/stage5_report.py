import json
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


def log(msg, color=Fore.WHITE):
    print(f"{color}[Stage 5]{Style.RESET_ALL} {msg}")


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def section(title, level=2):
    prefix = "#" * level
    return f"\n{prefix} {title}\n"


def code_block(content, lang=""):
    return f"```{lang}\n{content}\n```\n"


def run(args):
    log("="*50, Fore.CYAN)
    log("STAGE 5 — Final Report Generation", Fore.CYAN)
    log("="*50, Fore.CYAN)

    # Load all stage outputs
    stage1 = load_json(os.path.join(args.output, "stage1_passive.json"))
    stage2 = load_json(os.path.join(args.output, "stage2_urls.json"))
    stage3 = load_json(os.path.join(args.output, "stage3_fetch_log.json"))
    stage4 = load_json(os.path.join(args.output, "stage4_findings.json"))

    report_lines = []

    # ─── Header ───
    report_lines.append("# JS Recon Pipeline — Final Report\n")
    report_lines.append(f"**Target:** `{args.target}`  ")
    report_lines.append(f"**Domain:** `{args.domain}`  ")
    report_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    report_lines.append("\n---\n")

    # ─── Executive Summary ───
    report_lines.append(section("Executive Summary"))

    if stage4 and stage4.get("summary"):
        summary = stage4["summary"]
        report_lines.append("| Category | Count |")
        report_lines.append("|---|---|")
        report_lines.append(f"| JS Files Discovered | {stage2['counts']['js'] if stage2 else 'N/A'} |")
        report_lines.append(f"| Source Maps Found | {stage2['counts']['sourcemap'] if stage2 else 'N/A'} |")
        report_lines.append(f"| Files Successfully Fetched | {stage3['successful'] if stage3 else 'N/A'} |")
        report_lines.append(f"| API Endpoints Extracted | {len(summary.get('api_endpoints', []))} |")
        report_lines.append(f"| GraphQL References | {len(summary.get('graphql', []))} |")
        report_lines.append(f"| Secrets Found | {len(summary.get('secrets', []))} |")
        report_lines.append(f"| Internal URLs | {len(summary.get('internal_urls', []))} |")
        report_lines.append(f"| Environment Variables | {len(summary.get('env_vars', []))} |")
        report_lines.append(f"| Interesting Parameters | {len(summary.get('interesting_params', []))} |")
        report_lines.append(f"| Source Map References | {len(summary.get('source_maps', []))} |")
    else:
        report_lines.append("Stage 4 analysis data not available.\n")

    report_lines.append("\n---\n")

    # ─── Stage 1 — Discovery ───
    report_lines.append(section("Stage 1 — Passive Discovery"))
    if stage1:
        report_lines.append(f"Total unique URLs discovered: **{stage1['total_urls']}**\n")
        report_lines.append("| Source | Count |")
        report_lines.append("|---|---|")
        for source, count in stage1.get("sources", {}).items():
            report_lines.append(f"| {source.title()} | {count} |")
    else:
        report_lines.append("Stage 1 data not available.\n")

    # ─── Stage 2 — URL Categorization ───
    report_lines.append(section("Stage 2 — URL Categorization"))
    if stage2:
        report_lines.append(f"Total actionable URLs: **{stage2['total_actionable']}**\n")

        if stage2.get("js"):
            report_lines.append(section("JavaScript Files", 3))
            for url in stage2["js"]:
                report_lines.append(f"- `{url}`")

        if stage2.get("sourcemap"):
            report_lines.append(section("Source Maps", 3))
            for url in stage2["sourcemap"]:
                report_lines.append(f"- `{url}`")

        if stage2.get("nextjs"):
            report_lines.append(section("Next.js Data Files", 3))
            for url in stage2["nextjs"]:
                report_lines.append(f"- `{url}`")
    else:
        report_lines.append("Stage 2 data not available.\n")

    # ─── Stage 3 — Fetch Results ───
    report_lines.append(section("Stage 3 — Fetch Results"))
    if stage3:
        report_lines.append(f"- Successful fetches: **{stage3['successful']}**")
        report_lines.append(f"- Failed fetches: **{stage3['failed']}**")
        report_lines.append(f"- Total files: **{stage3['total_fetched']}**\n")

        failed = [r for r in stage3.get("results", []) if r.get("status") != 200]
        if failed:
            report_lines.append(section("Failed Fetches", 3))
            for r in failed:
                report_lines.append(f"- `{r['url']}` — {r.get('error', 'Unknown error')}")
    else:
        report_lines.append("Stage 3 data not available.\n")

    # ─── Stage 4 — Findings ───
    report_lines.append(section("Stage 4 — Analysis Findings"))

    if stage4 and stage4.get("summary"):
        summary = stage4["summary"]

        # Secrets — highest priority
        if summary.get("secrets"):
            report_lines.append(section("⚠ Secrets Found", 3))
            report_lines.append("> **These require immediate review**\n")
            for secret in summary["secrets"]:
                report_lines.append(f"**Type:** {secret['type']}  ")
                report_lines.append(f"**File:** `{secret['file']}`  ")
                report_lines.append(f"**Value:** `{secret['value']}`  \n")

        # API Endpoints
        if summary.get("api_endpoints"):
            report_lines.append(section("API Endpoints", 3))
            for endpoint in sorted(summary["api_endpoints"]):
                report_lines.append(f"- `{endpoint}`")

        # GraphQL
        if summary.get("graphql"):
            report_lines.append(section("GraphQL References", 3))
            for ref in sorted(summary["graphql"]):
                report_lines.append(f"- `{ref}`")

        # Internal URLs
        if summary.get("internal_urls"):
            report_lines.append(section("Internal URLs", 3))
            report_lines.append("> Internal URLs may reveal infrastructure topology\n")
            for url in sorted(summary["internal_urls"]):
                report_lines.append(f"- `{url}`")

        # Environment Variables
        if summary.get("env_vars"):
            report_lines.append(section("Environment Variables", 3))
            for var in sorted(summary["env_vars"]):
                report_lines.append(f"- `{var}`")

        # Next.js Specific
        if summary.get("nextjs_specific"):
            report_lines.append(section("Next.js Specific", 3))
            for item in sorted(summary["nextjs_specific"]):
                report_lines.append(f"- `{item}`")

        # Interesting Parameters
        if summary.get("interesting_params"):
            report_lines.append(section("Interesting Parameters", 3))
            for param in sorted(summary["interesting_params"]):
                report_lines.append(f"- `{param}`")

        # Source Maps
        if summary.get("source_maps"):
            report_lines.append(section("Source Map References", 3))
            report_lines.append("> Source maps may expose original unminified source code\n")
            for ref in sorted(summary["source_maps"]):
                report_lines.append(f"- `{ref}`")

        # Per-file breakdown
        report_lines.append(section("Per-File Breakdown", 3))
        for file_findings in stage4.get("per_file", []):
            if not file_findings.get("results"):
                continue
            report_lines.append(f"\n**File:** `{file_findings['url']}`  ")
            report_lines.append(f"**Size:** {file_findings['size']:,} bytes  \n")
            for category, matches in file_findings["results"].items():
                report_lines.append(f"*{category}* ({len(matches)} matches):\n")
                for match in matches[:20]:  # Cap at 20 per category per file
                    report_lines.append(f"- `{match['match']}` — {match['pattern']}")
                if len(matches) > 20:
                    report_lines.append(f"- *...and {len(matches)-20} more*")
    else:
        report_lines.append("Stage 4 data not available.\n")

    # ─── Footer ───
    report_lines.append("\n---\n")
    report_lines.append("*Generated by JS Recon Pipeline*\n")

    # Write report
    report_content = "\n".join(report_lines)
    output_path = os.path.join(args.output, "final_report.md")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    log(f"Final report saved to {output_path}", Fore.GREEN)

    # Print quick wins
    if stage4 and stage4.get("summary"):
        summary = stage4["summary"]
        log("\nQuick Wins to Investigate:", Fore.CYAN)
        if summary.get("secrets"):
            log(f"  [CRITICAL] {len(summary['secrets'])} potential secrets found", Fore.RED)
        if summary.get("source_maps"):
            log(f"  [HIGH] {len(summary['source_maps'])} source map references — check if accessible", Fore.YELLOW)
        if summary.get("internal_urls"):
            log(f"  [MEDIUM] {len(summary['internal_urls'])} internal URLs found", Fore.YELLOW)
        if summary.get("api_endpoints"):
            log(f"  [INFO] {len(summary['api_endpoints'])} API endpoints to test", Fore.GREEN)

    return output_path
