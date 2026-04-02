# Sudomy v2.0 — Subdomain Enumeration & Analysis

A modernized, accurate subdomain discovery toolkit. Built on the original [Sudomy by @screetsec](https://github.com/screetsec/sudomy), with extensive fixes, new sources, and new active tools.

---

## What Changed in v2.0

### Dead Sources Removed / Replaced

| Old Source     | Status         | Replacement     |
|----------------|----------------|-----------------|
| BufferOver     | Offline 2022   | Chaos (PD)      |
| ThreatCrowd    | Shut down 2022 | LeakIX          |
| Riddler        | Shut down 2021 | LeakIX          |
| Spyse          | API retired    | SecurityTrails  |

### API Versions Updated

| Source      | Before  | After   |
|-------------|---------|---------|
| VirusTotal  | v2 API  | v3 API with pagination |
| Censys      | v1 API  | v2 API with correct auth |

### New Sources Added

| Source  | Auth  | Notes |
|---------|-------|-------|
| **Chaos** (ProjectDiscovery) | API key | Massive passive DNS dataset |
| **LeakIX** | Optional key | Replaces Riddler + ThreatCrowd |
| **Netlas** | API key | Modern internet scanner |

### New Active Tools (Python 3, zero external Go deps)

| Tool | Description |
|------|-------------|
| `lib/mass_resolver.py` | Async DNS mass resolver — 200+ concurrent, wildcard detection |
| `lib/takeover_scanner.py` | Takeover scanner with 40+ service fingerprints, async CNAME crawl |
| `lib/permutation_engine.py` | Smart permutation generator — recombines discovered labels |

### Other Fixes

- **`source slack.conf` crash** — was unconditionally sourced even when missing. Now Slack is opt-in via `SLACK_WEBHOOK_URL` in `sudomy.conf`
- **Parallel engine isolation** — each source now runs in its own subshell; one failure doesn't crash others
- **Proper curl flags** — `--max-time`, `--retry`, `-A` user-agent on all requests
- **Wildcard DNS detection** — mass resolver probes a random nonexistent name first; wildcard IPs are filtered from results
- **Consistent output validation** — every engine now validates output against `^[a-zA-Z0-9._-]+\.domain\.tld$`

---

## Installation

```bash
git clone https://github.com/yourfork/sudomy
cd sudomy
chmod +x install.sh sudomy
./install.sh
```

**Minimum requirements:** `bash`, `curl`, `jq`, `dig`, `python3`  
**Recommended:** `go` (for httpx, dnsx, httprobe, gobuster, gowitness)

---

## Quick Start

```bash
# Basic passive scan
./sudomy -d example.com

# Full scan with all free sources
./sudomy -d example.com --httpx --dnsx -rS

# Full scan including takeover check + screenshots
./sudomy -d example.com --all --httpx --dnsx -rS -tO -sS

# Targeted sources only
./sudomy -d example.com -s CrtSH,AlienVault,Webarchive,CommonCrawl

# Permutation-based discovery (finds dev-api, staging-app, etc.)
./sudomy -d example.com -pE -rS

# DNS bruteforce
./sudomy -d example.com -b

# Save output to custom directory
./sudomy -d example.com --all -o /path/to/results
```

---

## API Keys

Edit `sudomy.api` to add keys. All keys are optional — sources without keys are skipped gracefully.

| Source | Where to get key |
|--------|-----------------|
| Shodan | https://developer.shodan.io |
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| Censys | https://search.censys.io/register |
| SecurityTrails | https://securitytrails.com/app/api |
| BinaryEdge | https://app.binaryedge.io |
| Chaos | https://chaos.projectdiscovery.io |
| Netlas | https://app.netlas.io |
| DNSDB | https://www.farsightsecurity.com/dnsdb-api |
| RiskIQ | https://community.riskiq.com (email:key format) |
| Facebook | https://developers.facebook.com |

---

## Output Structure

```
output/
└── MM-DD-YYYY/
    └── example.com/
        ├── subdomain.txt              # All unique discovered subdomains
        ├── Subdomain_Resolver.txt     # Live subdomains (resolved DNS)
        ├── ip_resolver.txt            # Unique IPs
        ├── massdns_resolved.txt       # subdomain → IP mapping
        ├── httprobe_subdomain.txt     # Live HTTP/HTTPS endpoints
        ├── httpx_status_title.txt     # Status codes + titles + tech
        ├── dnsx_subdomain.txt         # DNS record data
        ├── httpstatus_code.txt        # HTTP status per URL
        ├── Live_hosts_pingsweep.txt   # Ping sweep results
        ├── nmap_top_ports.txt         # Nmap scan
        ├── permutations.txt           # Generated permutations
        ├── permutation_resolved.txt   # Resolved permutations
        ├── takeover/
        │   ├── TakeOver.txt           # Takeover results (human)
        │   └── TakeOver.json          # Takeover results (machine)
        └── screenshots/               # gowitness screenshots
```

---

## Supported Sources (25 total)

### Free (no key needed)
`CrtSH` · `HackerTarget` · `AlienVault` · `RapidDNS` · `Webarchive` · `CommonCrawl` · `URLScan` · `Certspotter` · `ThreatMiner` · `DNSdumpster` · `LeakIX`

### Require API key
`Shodan` · `VirusTotal` · `Censys` · `BinaryEdge` · `SecurityTrails` · `DNSDB` · `RiskIQ` · `Chaos` · `Netlas` · `FBCert`

### Deprecated stubs (graceful no-op)
`BufferOver` · `ThreatCrowd` · `Riddler` · `Spyse`
