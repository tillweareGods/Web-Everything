# ghrecon — GitHub Repository Security Analyzer

A comprehensive, exploit-minded security scanner for GitHub repositories.
Analyzes source code, git history, CI/CD pipelines, dependencies, and metadata
to surface real attack paths — not just compliance checkboxes.

```
[Input: GitHub URL / Local Path]
        ↓
[Repo Cloner]
        ↓
[Analysis Engine] ─── parallel execution ────────────────────
    ├── 🔑 Secrets Scanner      49 patterns + entropy + base64
    ├── 📜 Git History          Full tree incl. deleted secrets
    ├── ⚙️  CI/CD Inspector      Injection, unsafe triggers, pinning
    ├── 📦 Dependency Analyzer  OSV.dev CVEs + confusion attacks
    ├── 🔧 Misconfig Scanner    gitignore, debug, Docker, docs
    └── 👤 Metadata Recon       GitHub API: emails, branches, issues
        ↓
[Risk Scorer (0-100) + Report Generator]
    ├── report.html    (interactive, dark terminal UI)
    ├── report.json    (machine-readable, CI integration)
    └── summary.md     (human summary)
```

## Quick Start

```bash
# Clone this tool
git clone https://github.com/yourfork/ghrecon
cd ghrecon

# No installation needed — pure stdlib + optional PyYAML
pip install PyYAML  # optional, for YAML CI configs

# Scan a public repo
python3 ghrecon.py https://github.com/org/repo

# With GitHub token (higher API limits, email enumeration)
python3 ghrecon.py https://github.com/org/repo --token ghp_xxx

# Scan local clone
python3 ghrecon.py /path/to/repo --no-clone

# Fast scan (secrets only, no network calls)
python3 ghrecon.py https://github.com/org/repo --only-secrets --skip-recon

# Full scan with verbose output
python3 ghrecon.py https://github.com/org/repo --verbose --max-commits 1000
```

## Modules

### 🔑 Secrets Scanner
- **49 compiled regex patterns** covering AWS, GCP, Azure, GitHub, Stripe, Slack, OpenAI, Anthropic, MongoDB, PostgreSQL, JWT, private keys, and more
- **Shannon entropy analysis** catches high-entropy strings missed by regex
- **Base64 decode + re-scan** finds encoded credentials
- **False positive filtering** ignores placeholders, example values, git SHAs

### 📜 Git History Analyzer *(most tools miss this)*
- Scans **every commit diff** across all branches, not just HEAD
- Flags secrets as **still_present** (active risk) vs **historic** (rotation needed)
- Collects contributor emails and branch naming patterns
- Recommends `git-filter-repo` for purging from history

### ⚙️ CI/CD Inspector
| Finding Type | Severity | Example |
|---|---|---|
| `pull_request_target` + checkout | CRITICAL | PR injection → exfiltrate GITHUB_TOKEN |
| Expression injection in `run:` | CRITICAL | `${{ github.event.issue.body }}` in shell |
| Secret echoed to log | HIGH | `echo $SECRET_KEY` |
| Unpinned third-party action | MEDIUM | `uses: org/action@v2` instead of SHA |
| Self-hosted runner + public PR | HIGH | Lateral movement risk |
| `write-all` permissions | HIGH | Full repo write access on compromise |

### 📦 Dependency Analyzer
- Queries **OSV.dev batch API** for CVEs across npm, PyPI, Go, Cargo, Maven
- Detects **dependency confusion** candidates (internal-looking package names)
- Flags **unpinned version ranges** (wildcard `*`, `^`, `~`)

### 🔧 Misconfig Scanner
- `.gitignore` gaps: sensitive files committed but not excluded
- Debug flags (`DEBUG=true`, `InsecureSkipVerify: true`)
- Hardcoded internal endpoints and RFC1918 IPs
- Backup/temp files (`.bak`, `.swp`, `.DS_Store`)
- Dockerfile misconfigs (root user, `:latest`, `COPY .`)
- Documentation leaks (internal URLs, admin panel endpoints)

### 👤 Metadata Recon (GitHub API)
- Contributor email enumeration (personal vs corporate)
- Branch name analysis (naming conventions, suspicious names)
- Issue/PR scanning for sensitive keywords
- Fork and archive risk assessment

## Risk Score

| Score | Grade | Level |
|-------|-------|-------|
| 80-100 | F | CRITICAL |
| 60-79  | D | HIGH |
| 40-59  | C | MEDIUM |
| 20-39  | B | LOW |
| 0-19   | A | MINIMAL |

Weighted by module importance:
- Secrets: 35% · History: 20% · CI/CD: 15% · Deps: 10% · Misconfig: 10% · Metadata: 5%

## Output

```
reports/
└── repo-name/
    ├── repo-name_report.html    ← Interactive findings, collapsible cards
    ├── repo-name_report.json    ← Full structured data for automation
    └── repo-name_summary.md     ← Human-readable markdown summary
```

## Requirements

- Python 3.8+
- `git` (for cloning and history analysis)
- `PyYAML` (optional, improves CI/CD parsing)
- No other dependencies — uses stdlib `urllib`, `re`, `subprocess`

## Legal

For authorized security testing only. Always obtain explicit written permission
before scanning repositories you do not own.
