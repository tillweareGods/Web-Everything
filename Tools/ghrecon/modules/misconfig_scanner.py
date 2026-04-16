"""
modules/misconfig_scanner.py — Misconfiguration, Hidden Files, and Docs Leak Scanner

Combines:
  - .gitignore analysis (what SHOULD be ignored but isn't)
  - Debug flag detection
  - Hardcoded internal endpoints & IPs
  - Hidden/backup file detection
  - Documentation leak analysis (READMEs, wikis, comments)
"""

from __future__ import annotations
import re
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MisconfigFinding:
    file_path:    str
    line_number:  int
    finding_type: str   # "GITIGNORE" / "DEBUG" / "ENDPOINT" / "HIDDEN_FILE" / "DOCS_LEAK" / "DOCKER"
    severity:     str
    title:        str
    description:  str
    code_snippet: str = ""
    exploit_path: str = ""
    remediation:  str = ""

    def to_dict(self) -> dict:
        return {
            "file":        self.file_path,
            "line":        self.line_number,
            "type":        self.finding_type,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "snippet":     self.code_snippet,
            "exploit":     self.exploit_path,
            "remediation": self.remediation,
        }


# ── Patterns ──────────────────────────────────────────────────────────────────

# Files that should always be in .gitignore for a healthy repo
SHOULD_BE_IGNORED = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
    ".aws/credentials", "config/secrets*", "secrets.*",
    "id_rsa", "id_dsa", "*.local",
    "terraform.tfvars", "*.tfvars",
    ".npmrc",
]

# Internal URL / endpoint patterns
INTERNAL_ENDPOINT_PATTERN = re.compile(
    r"(?i)(https?://)?"
    r"("
    r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}"   # RFC1918
    r"|localhost"
    r"|127\.0\.0\.1"
    r"|[a-z0-9\-]+\.internal"
    r"|[a-z0-9\-]+\.corp(?:\.|$)"
    r"|[a-z0-9\-]+\.local(?:\.|$)"
    r"|[a-z0-9\-]+\.intranet(?:\.|$)"
    r")"
    r"(?::\d{1,5})?"
    r"(?:/[^\s\"'<>]*)?",
    re.MULTILINE,
)

# Debug / development flags
DEBUG_PATTERNS = [
    re.compile(r'(?i)DEBUG\s*[=:]\s*(true|1|yes|on)', re.MULTILINE),
    re.compile(r'(?i)APP_ENV\s*[=:]\s*["\']?(development|dev)["\']?', re.MULTILINE),
    re.compile(r'(?i)FLASK_DEBUG\s*[=:]\s*1', re.MULTILINE),
    re.compile(r'(?i)NODE_ENV\s*[=:]\s*["\']?development["\']?', re.MULTILINE),
    re.compile(r'(?i)RAILS_ENV\s*[=:]\s*["\']?development["\']?', re.MULTILINE),
    re.compile(r'(?i)(allow_all_origins|cors.*\*)', re.MULTILINE),
    re.compile(r'(?i)verify_ssl?\s*[=:]\s*(false|0|no)', re.MULTILINE),
    re.compile(r'(?i)InsecureSkipVerify\s*:\s*true', re.MULTILINE),
]

# Backup / forgotten file extensions
BACKUP_EXTENSIONS = {
    ".bak", ".backup", ".old", ".orig", ".copy", ".swp", ".swo",
    ".tmp", ".temp", "~", ".save", ".1", ".2",
    ".DS_Store", ".Thumbs.db",
}

# Files that are almost never safe to commit
ALWAYS_SENSITIVE_FILES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".htpasswd", ".netrc",
    "wp-config.php", "configuration.php",
    "settings.local.php",
    "database.yml",
    "secrets.yml", "master.key",  # Rails
    "credentials.json",  # GCP
}

# Interesting strings in documentation
DOCS_LEAK_PATTERNS = [
    (re.compile(r"https?://[a-zA-Z0-9\-\.]+\.(internal|corp|intranet|local)[^\s\"']*", re.I),
     "Internal URL in documentation", "MEDIUM",
     "Internal service URL visible in public docs — may allow SSRF or reveal internal architecture."),
    (re.compile(r"/api/v\d+/[a-zA-Z0-9/\-_?=&%]+", re.MULTILINE),
     "Undocumented API endpoint", "LOW",
     "API endpoint pattern discovered in documentation or comments."),
    (re.compile(r"(?i)(swagger|openapi|graphql|grpc)\s+(endpoint|url|at|available)[^:\n]*:\s*https?://[^\s\"']+", re.MULTILINE),
     "API interface URL exposed", "MEDIUM",
     "Explicit API interface URL found — may expose internal services or staging environments."),
    (re.compile(r"(?i)(admin|dashboard|monitoring|metrics|prometheus|grafana|kibana|elasticsearch|jenkins)\s+(is at|available at|running at|lives at|hosted at|url|endpoint)[^:\n]*:\s*https?://[^\s\"']+", re.MULTILINE),
     "Admin panel URL in documentation", "HIGH",
     "Admin/monitoring tool URL found in documentation — direct attack surface."),
    (re.compile(r"(?i)(aws[_-]account|account[_-]id|account[_-]number)\s*[=:]\s*[\"']?[0-9]{10,12}[\"']?", re.MULTILINE),
     "AWS Account ID in documentation", "MEDIUM",
     "AWS Account ID exposed — used in ARN enumeration and IAM attacks."),
    (re.compile(r"(?i)ssh\s+(into|to|at)\s+([a-zA-Z0-9@\.\-]+)", re.MULTILINE),
     "SSH target host in documentation", "LOW",
     "SSH connection hint found — reveals server hostname/IP."),
]

# Docker misconfigurations
DOCKER_PATTERNS = [
    (re.compile(r"USER\s+root", re.MULTILINE),
     "Container runs as root", "HIGH",
     "Dockerfile sets USER root or doesn't specify a non-root user. If the container is compromised, the attacker has root privileges.",
     "Add `USER nonroot` or create and use a dedicated low-privilege user."),
    (re.compile(r"--privileged", re.MULTILINE),
     "Privileged container", "CRITICAL",
     "Container running with --privileged flag has full access to the host system.",
     "Remove --privileged and grant only specific capabilities needed."),
    (re.compile(r"COPY\s+\.\s+", re.MULTILINE),
     "Broad COPY . in Dockerfile", "MEDIUM",
     "`COPY . .` may copy sensitive files (.env, keys) into the image if .dockerignore is incomplete.",
     "Use specific COPY paths and maintain a thorough .dockerignore file."),
    (re.compile(r"(?i)ADD\s+https?://", re.MULTILINE),
     "Remote file fetched in Dockerfile ADD", "MEDIUM",
     "`ADD` with a URL fetches at build time without hash verification.",
     "Use `RUN curl -L <url> | sha256sum` to verify downloaded content, or copy files locally."),
    (re.compile(r"(?i)FROM\s+[a-zA-Z0-9\-_/]+:latest", re.MULTILINE),
     "Unpinned :latest Docker base image", "LOW",
     "Using :latest tag means base image changes are not reproducible and may introduce vulnerabilities.",
     "Pin base images to specific SHA256 digests."),
]


class MisconfigScanner:
    def __init__(self, repo_path: str, verbose: bool = False):
        self.repo_path = Path(repo_path)
        self.verbose   = verbose
        self.findings:  list[MisconfigFinding] = []

    # ── .gitignore analysis ───────────────────────────────────────────────────

    def _check_gitignore(self):
        gitignore_path = self.repo_path / ".gitignore"
        if not gitignore_path.exists():
            self.findings.append(MisconfigFinding(
                file_path=".gitignore",
                line_number=0,
                finding_type="GITIGNORE",
                severity="MEDIUM",
                title="No .gitignore file found",
                description=(
                    "The repository has no .gitignore file. Sensitive files (.env, keys, credentials) "
                    "may be accidentally committed in the future."
                ),
                remediation="Create a .gitignore using github.com/github/gitignore as a reference.",
            ))
            return

        gitignore_content = gitignore_path.read_text(encoding="utf-8", errors="replace")
        gitignore_patterns = set(l.strip() for l in gitignore_content.splitlines()
                                  if l.strip() and not l.startswith("#"))

        # Check if sensitive files exist in repo but NOT in .gitignore
        for fpath in self.repo_path.rglob("*"):
            if not fpath.is_file():
                continue
            rel = str(fpath.relative_to(self.repo_path))
            fname = fpath.name.lower()

            if fname in ALWAYS_SENSITIVE_FILES:
                is_gitignored = any(
                    pattern.lstrip("/") in rel or fname.endswith(pattern.lstrip("*"))
                    for pattern in gitignore_patterns
                )
                if not is_gitignored:
                    self.findings.append(MisconfigFinding(
                        file_path=rel,
                        line_number=0,
                        finding_type="GITIGNORE",
                        severity="CRITICAL",
                        title=f"Sensitive file `{fname}` committed and not in .gitignore",
                        description=(
                            f"`{rel}` is a highly sensitive file that is committed to the repository "
                            "and is not excluded by .gitignore. It should never be version-controlled."
                        ),
                        exploit_path=f"Clone repo → read {fname} → extract credentials",
                        remediation=(
                            f"1. Add `{fname}` to .gitignore\n"
                            f"2. Remove from history: `git rm --cached {rel}`\n"
                            "3. Rotate any secrets contained in the file immediately"
                        ),
                    ))

    # ── Debug flag detection ──────────────────────────────────────────────────

    def _check_debug(self):
        config_extensions = {".env", ".conf", ".cfg", ".ini", ".yaml", ".yml",
                              ".json", ".toml", ".properties", ".py", ".rb", ".php", ".js"}
        for fpath in self.repo_path.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in config_extensions and fpath.name not in {".env"}:
                continue
            rel = str(fpath.relative_to(self.repo_path))
            if any(p in rel for p in ("node_modules", "vendor", ".git")):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except OSError:
                continue

            for pattern in DEBUG_PATTERNS:
                for m in pattern.finditer(content):
                    lineno = content[:m.start()].count("\n") + 1
                    line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                    self.findings.append(MisconfigFinding(
                        file_path=rel,
                        line_number=lineno,
                        finding_type="DEBUG",
                        severity="MEDIUM",
                        title=f"Debug/development flag enabled: {line_text[:60]}",
                        description=(
                            "Debug mode or development settings detected in a committed config file. "
                            "These flags enable verbose error messages, disable security checks, "
                            "and may expose stack traces containing sensitive data."
                        ),
                        code_snippet=line_text,
                        exploit_path="Trigger application error → read stack trace → leak internals → targeted attack",
                        remediation="Use environment-specific config, never commit debug=true in production configs.",
                    ))

    # ── Internal endpoint detection ───────────────────────────────────────────

    def _check_endpoints(self):
        text_extensions = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php",
                           ".yaml", ".yml", ".json", ".env", ".conf", ".md", ".txt"}
        seen: set[str] = set()

        for fpath in self.repo_path.rglob("*"):
            if not fpath.is_file() or fpath.suffix.lower() not in text_extensions:
                continue
            rel = str(fpath.relative_to(self.repo_path))
            if any(p in rel for p in ("node_modules", "vendor", ".git")):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except OSError:
                continue

            for m in INTERNAL_ENDPOINT_PATTERN.finditer(content):
                endpoint = m.group(0).strip()
                dedup = f"{rel}:{endpoint[:30]}"
                if dedup in seen:
                    continue
                seen.add(dedup)

                lineno = content[:m.start()].count("\n") + 1
                line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                self.findings.append(MisconfigFinding(
                    file_path=rel,
                    line_number=lineno,
                    finding_type="ENDPOINT",
                    severity="MEDIUM",
                    title=f"Internal endpoint hardcoded: {endpoint[:60]}",
                    description=(
                        f"Internal network endpoint `{endpoint[:80]}` found hardcoded in source. "
                        "This reveals internal network topology and may be exploitable via SSRF."
                    ),
                    code_snippet=line_text,
                    exploit_path="SSRF via exposed endpoint → pivot to internal network → access metadata/services",
                    remediation="Move internal endpoints to environment variables or service discovery configuration.",
                ))

    # ── Hidden/backup file detection ──────────────────────────────────────────

    def _check_hidden_files(self):
        for fpath in self.repo_path.rglob("*"):
            if not fpath.is_file():
                continue
            rel = str(fpath.relative_to(self.repo_path))
            fname = fpath.name

            # Backup/temp extensions
            _, ext = os.path.splitext(fname)
            if ext.lower() in BACKUP_EXTENSIONS or fname.endswith("~"):
                self.findings.append(MisconfigFinding(
                    file_path=rel,
                    line_number=0,
                    finding_type="HIDDEN_FILE",
                    severity="LOW",
                    title=f"Backup/temporary file committed: {fname}",
                    description=(
                        f"A backup or temporary file `{fname}` is tracked by git. "
                        "These often contain old configurations, credentials, or source code "
                        "from previous versions."
                    ),
                    exploit_path="Download backup file → read previous config version → find old credentials",
                    remediation=f"Add `{ext}` pattern to .gitignore and remove with `git rm --cached {rel}`",
                ))

            # Vim swap files
            if fname.endswith(".swp") or fname.endswith(".swo"):
                self.findings.append(MisconfigFinding(
                    file_path=rel,
                    line_number=0,
                    finding_type="HIDDEN_FILE",
                    severity="MEDIUM",
                    title=f"Vim swap file committed: {fname}",
                    description=(
                        "Vim swap files contain the full content of the file being edited, "
                        "including unsaved changes. May contain credentials or source code."
                    ),
                    exploit_path="Read swap file → recover full file content including unsaved secret changes",
                    remediation="Add `*.swp *.swo` to .gitignore globally (`git config --global core.excludesFile ~/.gitignore_global`)",
                ))

    # ── Documentation leak analysis ───────────────────────────────────────────

    def _check_docs(self):
        doc_files = []
        for fpath in self.repo_path.rglob("*"):
            if not fpath.is_file():
                continue
            fname = fpath.name.lower()
            if any(fname.endswith(ext) for ext in (".md", ".rst", ".txt", ".adoc", ".wiki")):
                doc_files.append(fpath)
            elif fname in ("readme", "readme.md", "contributing.md", "docs"):
                doc_files.append(fpath)

        for fpath in doc_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except OSError:
                continue
            rel = str(fpath.relative_to(self.repo_path))

            for pattern, title, severity, description in DOCS_LEAK_PATTERNS:
                for m in pattern.finditer(content):
                    lineno = content[:m.start()].count("\n") + 1
                    line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                    self.findings.append(MisconfigFinding(
                        file_path=rel,
                        line_number=lineno,
                        finding_type="DOCS_LEAK",
                        severity=severity,
                        title=title,
                        description=description + f"\n  Found: {m.group(0)[:120]}",
                        code_snippet=line_text,
                        exploit_path="Enumerate documentation → discover attack surface → targeted exploitation",
                        remediation="Review all public-facing documentation for sensitive URLs, endpoints, and identifiers.",
                    ))

    # ── Dockerfile misconfig ──────────────────────────────────────────────────

    def _check_docker(self):
        for fpath in self.repo_path.rglob("Dockerfile*"):
            if not fpath.is_file():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except OSError:
                continue
            rel = str(fpath.relative_to(self.repo_path))

            for pattern, title, severity, description, remediation in DOCKER_PATTERNS:
                for m in pattern.finditer(content):
                    lineno = content[:m.start()].count("\n") + 1
                    line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                    self.findings.append(MisconfigFinding(
                        file_path=rel,
                        line_number=lineno,
                        finding_type="DOCKER",
                        severity=severity,
                        title=title,
                        description=description,
                        code_snippet=line_text,
                        exploit_path="Exploit container misconfiguration → container escape → host access",
                        remediation=remediation,
                    ))

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan(self) -> list[MisconfigFinding]:
        self.findings = []
        self._check_gitignore()
        self._check_debug()
        self._check_endpoints()
        self._check_hidden_files()
        self._check_docs()
        self._check_docker()

        if self.verbose:
            print(f"  [misconfig] Found {len(self.findings)} findings")
        return self.findings

    def summary(self) -> dict:
        return {
            "total":    len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in self.findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in self.findings if f.severity == "LOW"),
            "types":    list({f.finding_type for f in self.findings}),
        }
