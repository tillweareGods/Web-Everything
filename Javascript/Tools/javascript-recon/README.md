# JS Recon Pipeline

WAF-aware JavaScript discovery and analysis pipeline for bug bounty reconnaissance.

## Setup debian Linux

```bash
# Create a virtual env with a Python 3.13.9(or use an existing one if you have one setup), I have Not tested on any older versions
# Install dependencies
pip3 install -r requirements.txt

# Install Playwright browsers
playwright install chromium
# Download and extract curl-impersonate 
wget https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz
tar -xzf curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz
# move the extracted files to the  /usr/local/bin
sudo mv curl_chrome116 curl_chrome99 curl_chrome100 curl_chrome101 curl_chrome104 curl_chrome107 curl_chrome110 curl-impersonate-chrome curl-impersonate-ff /usr/local/bin/
# Download other dependacies
sudo apt install libnss3 nss-plugin-pem ca-certificates
# Check if install successfull
/usr/local/bin/curl_chrome116 --version
 
```

## Usage

```bash
# Basic run — all stages
python3 run.py --target https://example.com

# With HAR file from browser
python3 run.py --target https://example.com --har ~/Downloads/export.har

# Skip Google (if rate limited) and Wayback
python3 run.py --target https://example.com --skip-google --skip-wayback

# Run specific stages only
python3 run.py --target https://example.com --stages 1,2

# Custom rate limit and output directory
python3 run.py --target https://example.com --rate-limit 3 --output /tmp/myrecon

# Visible browser window (not headless)
python3 run.py --target https://example.com --no-headless
# Skip google and common crawl and save to file, while taking har file from a path 
python3 run.py --target https://example.com/path --har /media/Social/example.com --skip-google --skip-wayback --output ~/Targets/example-test
```

## All Options

| Flag             | Default    | Description                         |
| ---------------- | ---------- | ----------------------------------- |
| `--target`       | Required   | Target URL                          |
| `--output`       | `./output` | Output directory                    |
| `--har`          | None       | Path to HAR file                    |
| `--rate-limit`   | 2.0        | Seconds between Playwright requests |
| `--max-wayback`  | 500        | Max Wayback Machine results         |
| `--google-pause` | 10.0       | Seconds between Google queries      |
| `--stages`       | 1,2,3,4,5  | Stages to run                       |
| `--headless`     | True       | Headless browser                    |
| `--no-headless`  | —          | Visible browser window              |
| `--timeout`      | 30         | Page load timeout (seconds)         |
| `--skip-google`  | False      | Skip Google dorking                 |
| `--skip-wayback` | False      | Skip Wayback + CommonCrawl          |

## Stages

| Stage | Description                                                                        | Output                                |
| ----- | -----------------------------------------------------------------------------------| ------------------------------------- |
| 1     | Passive discovery — Google, Wayback, CommonCrawl, HAR                              | `stage1_passive.json`                 |
| 2     | URL categorization and deduplication                                               | `stage2_urls.json`                    |
| 3     | Curl-impersonate Fetchs then falls back on Playwright JS fetching if error occurs  | `stage3_js/`, `stage3_fetch_log.json` |
| 4     | JS analysis — endpoints, secrets, GraphQL                                          | `stage4_findings.json`                |
| 5     | Final report generation                                                            | `final_report.md`                     |

## How to Export a HAR File

1. Open Chrome DevTools (F12)
2. Go to Network tab
3. Browse the entire target application
4. Right click any request → Save all as HAR with content
5. Pass the path with `--har /path/to/export.har`

## Tips for WAF Targets

- Always provide a HAR file — it's the most reliable source
- Use `--skip-google` if Google is rate limiting you
- Increase `--rate-limit` to 3-5 seconds for aggressive WAFs
- Use `--no-headless` to solve Playwright challenges manually
- Run stages individually to debug issues: `--stages 1` then `--stages 2` etc.
