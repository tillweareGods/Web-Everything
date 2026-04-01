import argparse
import os
import sys
from urllib.parse import urlparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="JS Recon Pipeline — WAF-aware JS discovery and analysis",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 run.py --target https://example.com
  python3 run.py --target https://example.com --har /path/to/export.har
  python3 run.py --target https://example.com --rate-limit 3 --max-wayback 1000
  python3 run.py --target https://example.com --stages 1,2,3
  python3 run.py --target https://example.com --output /tmp/recon_output
        """
    )

    # Required
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g. https://example.com)"
    )

    # Optional with defaults
    parser.add_argument(
        "--output",
        default="output",
        help="Output directory (default: ./output)"
    )
    parser.add_argument(
        "--har",
        default=None,
        help="Path to HAR file exported from browser DevTools (optional)"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=2.0,
        help="Seconds to wait between Playwright requests (default: 2.0)"
    )
    parser.add_argument(
        "--max-wayback",
        type=int,
        default=500,
        help="Max results to fetch from Wayback Machine CDX API (default: 500)"
    )
    parser.add_argument(
        "--google-pause",
        type=float,
        default=10.0,
        help="Seconds to pause between Google dork queries (default: 10.0)"
    )
    parser.add_argument(
        "--stages",
        default="1,2,3,4,5",
        help="Comma-separated list of stages to run (default: 1,2,3,4,5)"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help="Run Playwright in headless mode (default: True)"
    )
    parser.add_argument(
        "--no-headless",
        action="store_false",
        dest="headless",
        help="Run Playwright with visible browser window"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Playwright page load timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--skip-google",
        action="store_true",
        default=False,
        help="Skip Google dorking (useful if rate limited)"
    )
    parser.add_argument(
        "--skip-wayback",
        action="store_true",
        default=False,
        help="Skip Wayback Machine and CommonCrawl"
    )

    args = parser.parse_args()

    # Validate target URL
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        print(f"[ERROR] Invalid target URL: {args.target}")
        print("        Must include scheme, e.g. https://example.com")
        sys.exit(1)

    # Parse stages
    try:
        args.stages = [int(s.strip()) for s in args.stages.split(",")]
    except ValueError:
        print(f"[ERROR] Invalid stages: {args.stages}")
        print("        Must be comma-separated integers, e.g. 1,2,3")
        sys.exit(1)

    # Derive domain from target
    args.domain = parsed.netloc

    # Create output directory structure
    os.makedirs(args.output, exist_ok=True)
    os.makedirs(os.path.join(args.output, "stage3_js"), exist_ok=True)

    return args


def print_config(args):
    from colorama import Fore, Style, init
    init(autoreset=True)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  JS RECON PIPELINE")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Target:{Style.RESET_ALL}        {args.target}")
    print(f"  {Fore.GREEN}Domain:{Style.RESET_ALL}        {args.domain}")
    print(f"  {Fore.GREEN}Output:{Style.RESET_ALL}        {args.output}")
    print(f"  {Fore.GREEN}HAR File:{Style.RESET_ALL}      {args.har or 'None'}")
    print(f"  {Fore.GREEN}Rate Limit:{Style.RESET_ALL}    {args.rate_limit}s")
    print(f"  {Fore.GREEN}Max Wayback:{Style.RESET_ALL}   {args.max_wayback}")
    print(f"  {Fore.GREEN}Google Pause:{Style.RESET_ALL}  {args.google_pause}s")
    print(f"  {Fore.GREEN}Stages:{Style.RESET_ALL}        {args.stages}")
    print(f"  {Fore.GREEN}Headless:{Style.RESET_ALL}      {args.headless}")
    print(f"  {Fore.GREEN}Timeout:{Style.RESET_ALL}       {args.timeout}s")
    print(f"  {Fore.GREEN}Skip Google:{Style.RESET_ALL}   {args.skip_google}")
    print(f"  {Fore.GREEN}Skip Wayback:{Style.RESET_ALL}  {args.skip_wayback}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
