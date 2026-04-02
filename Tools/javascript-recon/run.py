#!/usr/bin/env python3
"""
JS Recon Pipeline
WAF-aware JavaScript discovery and analysis tool

Usage:
  python3 run.py --target https://example.com
  python3 run.py --target https://example.com --har /path/to/export.har
  python3 run.py --target https://example.com --stages 1,2,3,4,5
  python3 run.py --target https://example.com --skip-google --skip-wayback
"""

import sys
import os
from colorama import Fore, Style, init

init(autoreset=True)

from config import parse_args, print_config


def banner():
    print(f"""
{Fore.CYAN}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
 JS Recon Pipeline — WAF-aware JS Discovery
{Style.RESET_ALL}""")


def run_stage(stage_num, args):
    print(f"\n{Fore.CYAN}{'─'*60}")
    print(f"  Running Stage {stage_num}")
    print(f"{'─'*60}{Style.RESET_ALL}\n")

    if stage_num == 1:
        import stage1_passive
        return stage1_passive.run(args)

    elif stage_num == 2:
        import stage2_extract
        return stage2_extract.run(args)

    elif stage_num == 3:
        import stage3_fetch
        return stage3_fetch.run(args)

    elif stage_num == 4:
        import stage4_analyze
        return stage4_analyze.run(args)

    elif stage_num == 5:
        import stage5_report
        return stage5_report.run(args)

    else:
        print(f"{Fore.RED}Unknown stage: {stage_num}{Style.RESET_ALL}")
        return None


def main():
    banner()
    args = parse_args()
    print_config(args)

    results = {}
    failed_stages = []

    for stage_num in args.stages:
        try:
            result = run_stage(stage_num, args)
            results[stage_num] = result

            if result is None and stage_num < 5:
                print(f"\n{Fore.YELLOW}[WARNING] Stage {stage_num} returned no output.")
                print(f"          Subsequent stages may fail or produce empty results.{Style.RESET_ALL}\n")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Interrupted by user at Stage {stage_num}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Partial results saved to {args.output}/{Style.RESET_ALL}")
            sys.exit(0)

        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Stage {stage_num} failed: {e}{Style.RESET_ALL}")
            failed_stages.append(stage_num)
            import traceback
            traceback.print_exc()
            continue

    # Final summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  PIPELINE COMPLETE")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Stages run:{Style.RESET_ALL}    {args.stages}")
    print(f"  {Fore.GREEN}Output dir:{Style.RESET_ALL}    {args.output}/")

    if failed_stages:
        print(f"  {Fore.RED}Failed stages: {failed_stages}{Style.RESET_ALL}")

    if 5 in args.stages:
        report_path = os.path.join(args.output, "final_report.md")
        if os.path.exists(report_path):
            print(f"  {Fore.GREEN}Final report:{Style.RESET_ALL}  {report_path}")

    print(f"\n{Fore.CYAN}Output files:{Style.RESET_ALL}")
    output_files = {
        1: "stage1_passive.json     — Raw discovered URLs",
        2: "stage2_urls.json        — Categorized JS URLs",
        3: "stage3_fetch_log.json   — Fetch results log",
        3.1: "stage3_js/              — Downloaded JS files",
        4: "stage4_findings.json    — Analysis findings",
        5: "final_report.md         — Combined report"
    }

    for stage, description in output_files.items():
        path = os.path.join(args.output, description.split("—")[0].strip())
        exists = os.path.exists(path)
        icon = Fore.GREEN + "✓" if exists else Fore.RED + "✗"
        print(f"  {icon}{Style.RESET_ALL}  {description}")

    print()


if __name__ == "__main__":
    main()
