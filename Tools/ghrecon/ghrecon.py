#!/usr/bin/env python3
"""
ghrecon.py — GitHub Repository Security Analysis Tool
======================================================
Analyzes a GitHub repository (or local clone) across 7 security dimensions:
  1. Secrets & sensitive data (regex + entropy + base64)
  2. Git history (full commit tree, deleted secrets)
  3. CI/CD pipeline security (injection, unsafe triggers)
  4. Dependency vulnerabilities (OSV.dev)
  5. Misconfigurations (gitignore, debug flags, Docker)
  6. GitHub metadata recon (API: emails, branches, issues)
  7. Hidden files & documentation leaks

Usage:
  python3 ghrecon.py https://github.com/owner/repo
  python3 ghrecon.py /path/to/local/repo --no-clone
  python3 ghrecon.py https://github.com/org/repo --token ghp_xxx --all
  python3 ghrecon.py https://github.com/org/repo --skip-history --skip-deps

Output:
  reports/<repo_name>/<repo_name>_report.html  (interactive)
  reports/<repo_name>/<repo_name>_report.json
  reports/<repo_name>/<repo_name>_summary.md
"""

from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── Colour helpers ────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"
    AMBER   = "\033[38;5;214m"

def _c(text, color): return f"{color}{text}{C.RESET}"
def crit(t): return _c(t, C.RED + C.BOLD)
def high(t): return _c(t, C.ORANGE)
def med(t):  return _c(t, C.YELLOW)
def low(t):  return _c(t, C.BLUE)
def ok(t):   return _c(t, C.GREEN)
def info(t): return _c(t, C.CYAN)
def dim(t):  return _c(t, C.DIM)
def bold(t): return _c(t, C.BOLD)
def amber(t):return _c(t, C.AMBER)


BANNER = f"""
{C.AMBER}╔══════════════════════════════════════════════════════════╗
║  {C.BOLD}ghrecon{C.RESET}{C.AMBER} — github repository security analyzer  v2.0  ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
{C.DIM}  For authorized security testing only.{C.RESET}
"""

SEV_COLORS = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.BLUE,
}

def print_sev(severity: str, text: str):
    color = SEV_COLORS.get(severity.upper(), C.RESET)
    print(f"  {color}[{severity[:4]}]{C.RESET} {text}")


# ── Cloner ────────────────────────────────────────────────────────────────────

def clone_repo(url: str, dest: str, verbose: bool = False) -> bool:
    """Clone with --depth=0 (full history) for comprehensive scanning."""
    print(f"\n{info('▸')} Cloning {bold(url)}...")
    try:
        cmd = ["git", "clone", "--quiet", url, dest]
        result = subprocess.run(cmd, capture_output=not verbose, timeout=300)
        if result.returncode != 0:
            # Retry without quiet for error message
            result2 = subprocess.run(
                ["git", "clone", url, dest],
                capture_output=True, timeout=300, text=True
            )
            if result2.returncode != 0:
                print(f"  {crit('Error:')} {result2.stderr[:300]}")
                return False
        print(f"  {ok('✓')} Cloned successfully")
        return True
    except subprocess.TimeoutExpired:
        print(f"  {crit('Error:')} Clone timed out (5 min)")
        return False
    except FileNotFoundError:
        print(f"  {crit('Error:')} git not found — install git first")
        return False


# ── Module runner ─────────────────────────────────────────────────────────────

def run_module(name: str, fn, *args, **kwargs):
    """Run a module with timing and error isolation."""
    icon_map = {
        "secrets":      "🔑",
        "git_history":  "📜",
        "cicd":         "⚙️ ",
        "dependencies": "📦",
        "misconfig":    "🔧",
        "metadata":     "👤",
    }
    icon = icon_map.get(name, "▸")
    print(f"\n{amber(icon)} {bold(name.replace('_', ' ').title())}...", end=" ", flush=True)
    start = time.time()
    try:
        result = fn(*args, **kwargs)
        elapsed = time.time() - start
        count = len(result) if result else 0
        print(f"{ok(f'✓ {count} findings')} {dim(f'({elapsed:.1f}s)')}")
        return result or []
    except Exception as e:
        elapsed = time.time() - start
        print(f"{crit(f'✗ error: {str(e)[:80]}')} {dim(f'({elapsed:.1f}s)')}")
        if kwargs.get("verbose"):
            import traceback
            traceback.print_exc()
        return []


# ── Per-module summary printer ────────────────────────────────────────────────

def print_module_summary(name: str, findings: list):
    if not findings:
        return

    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        inner = f.finding if hasattr(f, "finding") else f
        sev   = getattr(inner, "severity", "LOW").upper()
        if sev not in sev_counts:
            sev = "LOW"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    parts = []
    if sev_counts["CRITICAL"]: parts.append(crit(f"{sev_counts['CRITICAL']} critical"))
    if sev_counts["HIGH"]:     parts.append(high(f"{sev_counts['HIGH']} high"))
    if sev_counts["MEDIUM"]:   parts.append(med(f"{sev_counts['MEDIUM']} medium"))
    if sev_counts["LOW"]:      parts.append(low(f"{sev_counts['LOW']} low"))

    if parts:
        print(f"    └─ {' | '.join(parts)}")

    # Show top 3 critical/high
    def _sev_rank(f):
        sev = getattr(f.finding if hasattr(f, "finding") else f, "severity", "LOW").upper()
        return SEV_ORDER.index(sev) if sev in SEV_ORDER else len(SEV_ORDER)

    top = sorted(findings, key=_sev_rank)[:3]
    for f in top:
        inner = f.finding if hasattr(f, "finding") else f
        sev   = getattr(inner, "severity", "LOW")
        title = (getattr(inner, "title", None) or
                 getattr(inner, "pattern_name", None) or "Finding")
        fpath = getattr(inner, "file_path", "")
        if sev in ("CRITICAL", "HIGH"):
            color = crit if sev == "CRITICAL" else high
            print(f"      {color(f'[{sev[:4]}]')} {title[:70]}")
            if fpath:
                print(f"             {dim(fpath[:60])}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ghrecon — GitHub security analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ghrecon.py https://github.com/org/repo
  python3 ghrecon.py https://github.com/org/repo --token ghp_xxx
  python3 ghrecon.py /path/to/local/repo --no-clone
  python3 ghrecon.py https://github.com/org/repo --skip-history --output /tmp/reports
  python3 ghrecon.py https://github.com/org/repo --format json --quiet
        """,
    )
    parser.add_argument("target",              help="GitHub URL or local repo path")
    parser.add_argument("--token",    "-t",    help="GitHub personal access token (increases API limits)")
    parser.add_argument("--output",   "-o",    default="reports", help="Output directory (default: reports/)")
    parser.add_argument("--no-clone",          action="store_true", help="Target is a local path, skip cloning")
    parser.add_argument("--format",            choices=["all", "html", "json", "md"], default="all")
    parser.add_argument("--quiet",    "-q",    action="store_true", help="Suppress progress output")
    parser.add_argument("--verbose",  "-v",    action="store_true", help="Verbose module output")
    parser.add_argument("--max-commits",       type=int, default=500, help="Max commits to scan in history (default: 500)")
    parser.add_argument("--skip-history",      action="store_true")
    parser.add_argument("--skip-deps",         action="store_true", help="Skip OSV.dev dependency check")
    parser.add_argument("--skip-recon",        action="store_true", help="Skip GitHub API metadata recon")
    parser.add_argument("--skip-cicd",         action="store_true")
    parser.add_argument("--only-secrets",      action="store_true", help="Run only secrets scanner (fast mode)")
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    # ── Resolve repo path ─────────────────────────────────────────────────────
    repo_path  = None
    temp_dir   = None
    github_url = args.target

    if args.no_clone:
        repo_path = Path(args.target).resolve()
        if not repo_path.is_dir():
            print(f"{crit('Error:')} Path does not exist: {repo_path}")
            sys.exit(1)
        repo_name = repo_path.name
        github_url = ""
    else:
        if not args.target.startswith("http"):
            # Might be a local path
            local = Path(args.target)
            if local.is_dir():
                repo_path = local.resolve()
                repo_name = repo_path.name
                github_url = ""
            else:
                print(f"{crit('Error:')} Not a valid URL or path: {args.target}")
                sys.exit(1)
        else:
            temp_dir  = tempfile.mkdtemp(prefix="ghrecon_")
            repo_path = Path(temp_dir) / "repo"
            # Derive repo name from URL
            repo_name = args.target.rstrip("/").rstrip(".git").split("/")[-1]
            if not clone_repo(args.target, str(repo_path), verbose=args.verbose):
                shutil.rmtree(temp_dir, ignore_errors=True)
                sys.exit(1)

    if not args.quiet:
        print(f"\n{info('▸')} Target:    {bold(str(repo_path))}")
        print(f"{info('▸')} Repo name: {bold(repo_name)}")
        print(f"{info('▸')} Output:    {bold(args.output)}/")
        print(f"\n{'─'*58}")

    start_time = time.time()
    results = {}

    # ── 1. Secrets Scanner ────────────────────────────────────────────────────
    from modules.secrets_scanner import SecretsScanner
    scanner = SecretsScanner(str(repo_path), verbose=args.verbose)
    results["secrets"] = run_module("secrets", scanner.scan)
    if not args.quiet:
        print_module_summary("secrets", results["secrets"])

    if args.only_secrets:
        _finalize(results, repo_name, github_url, args, start_time, repo_path)
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return

    # ── 2. Git History ────────────────────────────────────────────────────────
    if not args.skip_history:
        from modules.git_history import GitHistoryAnalyzer
        git_analyzer = GitHistoryAnalyzer(str(repo_path), verbose=args.verbose,
                                          max_commits=args.max_commits)
        results["git_history"] = run_module("git_history", git_analyzer.scan)
        if not args.quiet:
            print_module_summary("git_history", results["git_history"])
    else:
        results["git_history"] = []

    # ── 3. CI/CD Inspector ────────────────────────────────────────────────────
    if not args.skip_cicd:
        from modules.cicd_inspector import CICDInspector
        cicd = CICDInspector(str(repo_path), verbose=args.verbose)
        results["cicd"] = run_module("cicd", cicd.scan)
        if not args.quiet:
            print_module_summary("cicd", results["cicd"])
    else:
        results["cicd"] = []

    # ── 4. Dependency Analyzer ────────────────────────────────────────────────
    from modules.dependency_analyzer import DependencyAnalyzer
    dep_analyzer = DependencyAnalyzer(
        str(repo_path), verbose=args.verbose,
        skip_osv=args.skip_deps
    )
    results["dependencies"] = run_module("dependencies", dep_analyzer.scan)
    if not args.quiet:
        print_module_summary("dependencies", results["dependencies"])

    # ── 5. Misconfig Scanner ──────────────────────────────────────────────────
    from modules.misconfig_scanner import MisconfigScanner
    misconfig = MisconfigScanner(str(repo_path), verbose=args.verbose)
    results["misconfig"] = run_module("misconfig", misconfig.scan)
    if not args.quiet:
        print_module_summary("misconfig", results["misconfig"])

    # ── 6. Metadata Recon ─────────────────────────────────────────────────────
    metadata_summary = {}
    if not args.skip_recon and github_url:
        from modules.metadata_recon import MetadataRecon
        recon = MetadataRecon(github_url, token=args.token, verbose=args.verbose)
        results["metadata"] = run_module("metadata", recon.scan)
        metadata_summary = recon.summary()
        if not args.quiet:
            print_module_summary("metadata", results["metadata"])
            if metadata_summary.get("all_emails"):
                print(f"    └─ Emails found: " +
                      ", ".join(e["email"] for e in metadata_summary["all_emails"][:5]))
    else:
        results["metadata"] = []

    # ── Finalize ──────────────────────────────────────────────────────────────
    _finalize(results, repo_name, github_url, args, start_time, repo_path,
              metadata_summary=metadata_summary)

    # Cleanup temp clone
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _finalize(results: dict, repo_name: str, github_url: str,
              args, start_time: float, repo_path,
              metadata_summary: dict = None):
    from modules.risk_scorer import compute_risk
    from modules.report_generator import ReportGenerator

    total_time = time.time() - start_time

    # ── Risk scoring ──────────────────────────────────────────────────────────
    risk = compute_risk(results)

    # ── Print final summary ───────────────────────────────────────────────────
    if not args.quiet:
        print(f"\n{'═'*58}")
        print(f"  {bold('RISK SCORE')}  {_risk_display(risk)}")
        print(f"{'─'*58}")

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for findings in results.values():
            for f in findings:
                inner = f.finding if hasattr(f, "finding") else f
                sev   = getattr(inner, "severity", "LOW").upper()
                if sev not in counts:
                    sev = "LOW"
                counts[sev] = counts.get(sev, 0) + 1
        total = sum(counts.values())

        print(f"  Total findings: {bold(str(total))}")
        print(f"  {crit(str(counts['CRITICAL']) + ' critical')}  "
              f"{high(str(counts['HIGH']) + ' high')}  "
              f"{med(str(counts['MEDIUM']) + ' medium')}  "
              f"{low(str(counts['LOW']) + ' low')}")
        print(f"\n  {bold('Top risks:')}")
        for r in risk.top_risks[:5]:
            print(f"    • {r}")
        print(f"\n  Scan completed in {bold(f'{total_time:.1f}s')}")

    # ── Generate reports ──────────────────────────────────────────────────────
    output_dir = Path(args.output) / re.sub(r"[^a-zA-Z0-9_\-]", "_", repo_name)
    reporter = ReportGenerator(
        repo_name=github_url or repo_name,
        output_dir=str(output_dir),
    )
    paths = reporter.generate(results, risk, total_time, metadata_summary)

    if not args.quiet:
        print(f"\n{'─'*58}")
        print(f"  {bold('Reports saved:')}")
        for fmt, path in paths.items():
            print(f"    {ok('✓')} {fmt:<8} {dim(path)}")
        print()

    # Open HTML report automatically if available
    if "html" in paths and not args.quiet:
        try:
            import webbrowser
            webbrowser.open(f"file://{Path(paths['html']).resolve()}")
        except Exception:
            pass

import re


def _risk_display(risk) -> str:
    score = risk.total
    grade = risk.grade
    level = risk.level
    if score >= 80:
        color = C.RED + C.BOLD
    elif score >= 60:
        color = C.ORANGE + C.BOLD
    elif score >= 40:
        color = C.YELLOW
    elif score >= 20:
        color = C.BLUE
    else:
        color = C.GREEN
    bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
    return f"{color}{score:.0f}/100  Grade {grade}  {level}{C.RESET}\n  {color}{bar}{C.RESET}"


if __name__ == "__main__":
    main()
