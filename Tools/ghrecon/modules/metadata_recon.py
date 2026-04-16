"""
modules/metadata_recon.py — GitHub API Metadata Recon

Enumerates via GitHub REST API v3:
  - Contributors + email addresses
  - Commit patterns (commit times, activity windows)
  - Branch name analysis (naming conventions)
  - Fork/star patterns
  - Issue/PR body scanning for sensitive data
  - Past collaborator enumeration
"""

from __future__ import annotations
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Contributor:
    login:       str
    name:        str = ""
    email:       str = ""
    commits:     int = 0
    company:     str = ""
    location:    str = ""
    blog:        str = ""
    is_personal_email: bool = False

@dataclass
class RepoMetadata:
    owner:           str
    name:            str
    full_name:       str
    description:     str
    is_private:      bool
    is_fork:         bool
    default_branch:  str
    stars:           int
    forks:           int
    open_issues:     int
    language:        str
    topics:          list[str]
    created_at:      str
    pushed_at:       str
    has_wiki:        bool
    has_pages:       bool
    archived:        bool
    license:         str
    contributors:    list[Contributor] = field(default_factory=list)
    branches:        list[str] = field(default_factory=list)
    tags:            list[str] = field(default_factory=list)
    interesting_issues: list[dict] = field(default_factory=list)


@dataclass
class ReconFinding:
    finding_type: str
    severity:     str
    title:        str
    description:  str
    data:         dict = field(default_factory=dict)
    exploit_path: str = ""

    def to_dict(self) -> dict:
        return {
            "type":        self.finding_type,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "data":        self.data,
            "exploit":     self.exploit_path,
        }


GITHUB_API = "https://api.github.com"

# Common public email providers — personal emails
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "me.com", "protonmail.com", "proton.me", "tutanota.com",
    "fastmail.com", "pm.me", "zoho.com", "yandex.com", "mail.com",
}


def _gh_get(path: str, token: Optional[str] = None, timeout: int = 15) -> Optional[dict | list]:
    url = f"{GITHUB_API}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ghrecon/2.0 security-scanner",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"_rate_limited": True}
        if e.code == 404:
            return None
        return None
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None


def _gh_paginate(path: str, token: Optional[str] = None, max_pages: int = 5) -> list:
    all_items = []
    sep = "&" if "?" in path else "?"
    for page in range(1, max_pages + 1):
        result = _gh_get(f"{path}{sep}per_page=100&page={page}", token)
        if not result or not isinstance(result, list):
            break
        all_items.extend(result)
        if len(result) < 100:
            break
    return all_items


class MetadataRecon:
    def __init__(self, github_url: str, token: Optional[str] = None, verbose: bool = False):
        self.github_url = github_url
        self.token      = token
        self.verbose    = verbose
        self.metadata:  Optional[RepoMetadata] = None
        self.findings:  list[ReconFinding] = []

        # Parse owner/repo from URL
        self.owner, self.repo = self._parse_github_url(github_url)

    def _parse_github_url(self, url: str) -> tuple[str, str]:
        patterns = [
            r"github\.com[/:]([^/]+)/([^/.]+)",
        ]
        for pat in patterns:
            m = re.search(pat, url.rstrip("/").rstrip(".git"))
            if m:
                return m.group(1), m.group(2)
        return "", ""

    # ── Repository metadata ───────────────────────────────────────────────────

    def _fetch_repo_info(self) -> Optional[RepoMetadata]:
        if not self.owner or not self.repo:
            return None
        data = _gh_get(f"/repos/{self.owner}/{self.repo}", self.token)
        if not data or not isinstance(data, dict):
            return None
        if data.get("_rate_limited"):
            if self.verbose:
                print("  [recon] GitHub API rate limited — metadata collection limited")
            return None

        return RepoMetadata(
            owner=data.get("owner", {}).get("login", ""),
            name=data.get("name", ""),
            full_name=data.get("full_name", ""),
            description=data.get("description") or "",
            is_private=data.get("private", False),
            is_fork=data.get("fork", False),
            default_branch=data.get("default_branch", "main"),
            stars=data.get("stargazers_count", 0),
            forks=data.get("forks_count", 0),
            open_issues=data.get("open_issues_count", 0),
            language=data.get("language") or "",
            topics=data.get("topics", []),
            created_at=data.get("created_at", ""),
            pushed_at=data.get("pushed_at", ""),
            has_wiki=data.get("has_wiki", False),
            has_pages=data.get("has_pages", False),
            archived=data.get("archived", False),
            license=(data.get("license") or {}).get("spdx_id", "") or "",
        )

    # ── Contributor enumeration ───────────────────────────────────────────────

    def _fetch_contributors(self) -> list[Contributor]:
        raw = _gh_paginate(f"/repos/{self.owner}/{self.repo}/contributors", self.token)
        contributors = []
        for c in raw[:50]:  # cap at 50
            login = c.get("login", "")
            contrib = Contributor(login=login, commits=c.get("contributions", 0))

            # Get user profile for email
            user_data = _gh_get(f"/users/{login}", self.token)
            if user_data and isinstance(user_data, dict):
                contrib.name     = user_data.get("name") or ""
                contrib.email    = user_data.get("email") or ""
                contrib.company  = user_data.get("company") or ""
                contrib.location = user_data.get("location") or ""
                contrib.blog     = user_data.get("blog") or ""
                if contrib.email:
                    domain = contrib.email.split("@")[-1].lower()
                    contrib.is_personal_email = domain in PERSONAL_EMAIL_DOMAINS

            contributors.append(contrib)
        return contributors

    # ── Branch analysis ───────────────────────────────────────────────────────

    def _fetch_branches(self) -> list[str]:
        raw = _gh_paginate(f"/repos/{self.owner}/{self.repo}/branches", self.token)
        return [b.get("name", "") for b in raw if b.get("name")]

    # ── Issue / PR scanning ───────────────────────────────────────────────────

    def _fetch_interesting_issues(self) -> list[dict]:
        """Scan issue titles/bodies for sensitive keywords."""
        raw = _gh_paginate(f"/repos/{self.owner}/{self.repo}/issues?state=all", self.token, max_pages=3)
        interesting = []
        sensitive_pattern = re.compile(
            r"(?i)(password|secret|token|api.?key|credential|bypass|exploit|vulnerability|"
            r"rce|sqli|xss|ssrf|backdoor|internal|staging|prod\s+secret)",
            re.IGNORECASE,
        )
        for issue in raw:
            title = issue.get("title", "")
            body  = (issue.get("body") or "")[:500]
            if sensitive_pattern.search(title) or sensitive_pattern.search(body):
                interesting.append({
                    "number": issue.get("number", 0),
                    "title":  title,
                    "url":    issue.get("html_url", ""),
                    "state":  issue.get("state", ""),
                    "snippet": sensitive_pattern.search(title + " " + body).group(0) if sensitive_pattern.search(title + " " + body) else "",
                })
        return interesting[:20]

    # ── Analysis & findings generation ───────────────────────────────────────

    def _analyze(self):
        if not self.metadata:
            return

        m = self.metadata

        # 1. Personal email addresses exposed
        personal_emails = [
            c for c in m.contributors if c.email and c.is_personal_email
        ]
        corporate_emails = [
            c for c in m.contributors if c.email and not c.is_personal_email
        ]
        all_emails = [c for c in m.contributors if c.email]

        if personal_emails:
            self.findings.append(ReconFinding(
                finding_type="PERSONAL_EMAIL",
                severity="MEDIUM",
                title=f"Personal email addresses exposed for {len(personal_emails)} contributor(s)",
                description=(
                    "Developer personal email addresses are visible via the GitHub API. "
                    "These can be used for targeted phishing, credential stuffing, or OSINT."
                ),
                data={
                    "emails": [
                        {"login": c.login, "email": c.email, "commits": c.commits}
                        for c in personal_emails
                    ]
                },
                exploit_path="Email → spearphishing → account takeover → code push / secret access",
            ))

        if corporate_emails:
            domains = list({c.email.split("@")[1] for c in corporate_emails if "@" in c.email})
            self.findings.append(ReconFinding(
                finding_type="CORPORATE_DOMAIN",
                severity="LOW",
                title=f"Corporate email domain(s) identified: {', '.join(domains[:5])}",
                description=(
                    "Corporate/organizational email domains identified from contributor profiles. "
                    "Reveals the organization's internal domain naming conventions."
                ),
                data={"domains": domains, "contributors": len(corporate_emails)},
                exploit_path="Domain → LinkedIn OSINT → targeted phishing campaign",
            ))

        # 2. Sensitive branch names
        sensitive_branch_patterns = re.compile(
            r"(?i)(secret|password|cred|token|api.?key|hotfix|hack|exploit|"
            r"temp|test-prod|prod-debug|backdoor|admin)",
        )
        suspicious_branches = [b for b in m.branches if sensitive_branch_patterns.search(b)]
        if suspicious_branches:
            self.findings.append(ReconFinding(
                finding_type="BRANCH_NAMES",
                severity="MEDIUM",
                title=f"Suspicious branch names: {', '.join(suspicious_branches[:5])}",
                description=(
                    "Branch names suggest sensitive content or security-relevant work. "
                    "These branches may contain credentials, debug code, or security bypasses."
                ),
                data={"branches": suspicious_branches},
                exploit_path="Checkout suspicious branch → access non-mainline code → find old secrets/backdoors",
            ))

        # 3. Naming convention leakage
        internal_branch_patterns = re.compile(
            r"(?i)(internal|corp|private|staging|uat|qa|prod|"
            r"dev-\w+-feature|release/)"
        )
        internal_branches = [b for b in m.branches if internal_branch_patterns.search(b)][:10]
        if internal_branches:
            self.findings.append(ReconFinding(
                finding_type="NAMING_CONVENTIONS",
                severity="LOW",
                title="Internal naming conventions revealed by branch names",
                description=(
                    "Branch naming patterns reveal internal development workflows, "
                    "environment names, and organizational structure."
                ),
                data={"branches": internal_branches},
                exploit_path="Naming convention → guess internal hostnames/services → targeted recon",
            ))

        # 4. Interesting issues
        if m.interesting_issues:
            self.findings.append(ReconFinding(
                finding_type="SENSITIVE_ISSUES",
                severity="MEDIUM",
                title=f"{len(m.interesting_issues)} issue(s) contain sensitive keywords",
                description=(
                    "Open or closed issues contain keywords suggesting security-relevant content: "
                    "credentials, vulnerabilities, internal configurations."
                ),
                data={"issues": m.interesting_issues[:10]},
                exploit_path="Read issue history → find exposed configs/tokens → extract useful info",
            ))

        # 5. Archived repo risk
        if m.archived:
            self.findings.append(ReconFinding(
                finding_type="ARCHIVED_REPO",
                severity="LOW",
                title="Repository is archived — may contain unrotated credentials",
                description=(
                    "Archived repos are often forgotten but remain publicly accessible. "
                    "They frequently contain credentials or configurations that were "
                    "never rotated because the project was 'completed'."
                ),
                data={},
                exploit_path="Read archived code → find old production credentials → check if still active",
            ))

        # 6. Forked repo from sensitive source
        if m.is_fork:
            self.findings.append(ReconFinding(
                finding_type="FORK_RISK",
                severity="LOW",
                title="Repository is a fork — changes may expose original org's secrets",
                description=(
                    "Fork repos sometimes accidentally expose secrets from the upstream organization "
                    "if the developer copies configuration files with real credentials."
                ),
                data={},
                exploit_path="Compare fork diff against upstream → find added secrets",
            ))

    # ── Main scan entry ───────────────────────────────────────────────────────

    def scan(self) -> list[ReconFinding]:
        self.findings = []
        if not self.owner or not self.repo:
            if self.verbose:
                print("  [recon] Could not parse GitHub owner/repo from URL — skipping API recon")
            return []

        if self.verbose:
            print(f"  [recon] Fetching metadata for {self.owner}/{self.repo}...")

        self.metadata = self._fetch_repo_info()
        if not self.metadata:
            if self.verbose:
                print("  [recon] Could not fetch repo metadata (private or API limit)")
            return []

        if self.verbose:
            print(f"  [recon] Fetching contributors...")
        self.metadata.contributors = self._fetch_contributors()

        if self.verbose:
            print(f"  [recon] Fetching branches...")
        self.metadata.branches = self._fetch_branches()

        if self.verbose:
            print(f"  [recon] Scanning issues...")
        self.metadata.interesting_issues = self._fetch_interesting_issues()

        self._analyze()

        if self.verbose:
            print(f"  [recon] {len(self.metadata.contributors)} contributors, "
                  f"{len(self.metadata.branches)} branches, "
                  f"{len(self.findings)} findings")

        return self.findings

    def summary(self) -> dict:
        if not self.metadata:
            return {"available": False}
        contributors_with_email = [c for c in self.metadata.contributors if c.email]
        return {
            "available":    True,
            "full_name":    self.metadata.full_name,
            "stars":        self.metadata.stars,
            "forks":        self.metadata.forks,
            "contributors": len(self.metadata.contributors),
            "emails":       len(contributors_with_email),
            "branches":     len(self.metadata.branches),
            "language":     self.metadata.language,
            "findings":     len(self.findings),
            "all_emails":   [
                {"login": c.login, "email": c.email}
                for c in contributors_with_email
            ],
        }
