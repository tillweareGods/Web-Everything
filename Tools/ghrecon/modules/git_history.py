"""
modules/git_history.py — Full commit history secret scanner

Scans EVERY commit diff, not just HEAD. Catches:
  - Deleted secrets still in history
  - Reverted commits that exposed credentials
  - Branch-specific secrets
  - Merge conflicts that leaked info

Key insight: git log -p dumps ALL diffs; secrets removed in a later
commit are still 100% visible and usable by an attacker.
"""

from __future__ import annotations
import subprocess
import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from modules.secrets_scanner import SecretsScanner, SecretFinding


@dataclass
class CommitInfo:
    hash:        str
    short_hash:  str
    author:      str
    email:       str
    date:        str
    message:     str
    findings:    list[SecretFinding] = field(default_factory=list)


@dataclass
class HistoryFinding:
    finding:     SecretFinding
    commit:      CommitInfo
    status:      str   # "added" | "removed" | "still_present"
    risk_note:   str = ""

    def to_dict(self) -> dict:
        return {
            **self.finding.to_dict(),
            "commit_short":  self.commit.short_hash,
            "commit_message": self.commit.message[:80],
            "commit_author":  self.commit.author,
            "commit_date":    self.commit.date,
            "commit_email":   self.commit.email,
            "diff_status":    self.status,
            "risk_note":      self.risk_note,
        }


class GitHistoryAnalyzer:
    def __init__(self, repo_path: str, verbose: bool = False, max_commits: int = 500):
        self.repo_path = Path(repo_path)
        self.verbose   = verbose
        self.max_commits = max_commits
        self._scanner  = SecretsScanner(str(repo_path), verbose=False)
        self.findings:  list[HistoryFinding] = []
        self.commits:   list[CommitInfo] = []
        self.emails:    set[str] = set()
        self.branch_names: set[str] = []
        self.tag_names: list[str] = []

    # ── Git helpers ───────────────────────────────────────────────────────────

    def _git(self, *args, timeout: int = 60) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repo_path)] + list(args),
                capture_output=True, text=True,
                timeout=timeout, errors="replace",
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def _is_git_repo(self) -> bool:
        return (self.repo_path / ".git").exists() or \
               self._git("rev-parse", "--git-dir").strip() != ""

    # ── Metadata collection ───────────────────────────────────────────────────

    def collect_metadata(self):
        """Gather branches, tags, authors, emails."""
        # Branches
        branch_out = self._git("branch", "-a", "--format=%(refname:short)")
        self.branch_names = [b.strip() for b in branch_out.splitlines() if b.strip()]

        # Tags
        tag_out = self._git("tag", "-l")
        self.tag_names = [t.strip() for t in tag_out.splitlines() if t.strip()]

        # All emails from git log
        email_out = self._git("log", "--format=%ae", "--all")
        self.emails = {e.strip().lower() for e in email_out.splitlines() if "@" in e}

        if self.verbose:
            print(f"  [history] {len(self.branch_names)} branches, "
                  f"{len(self.tag_names)} tags, {len(self.emails)} unique emails")

    # ── Commit parsing ────────────────────────────────────────────────────────

    def _parse_log(self, log_output: str) -> list[CommitInfo]:
        """Parse git log --format output into CommitInfo objects."""
        # Separator we use between commits
        SEP = "<<<COMMIT_SEP>>>"
        commits = []
        blocks = log_output.split(SEP)
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            lines = block.splitlines()
            if len(lines) < 4:
                continue
            try:
                commits.append(CommitInfo(
                    hash=lines[0].strip(),
                    short_hash=lines[0].strip()[:8],
                    author=lines[1].strip(),
                    email=lines[2].strip(),
                    date=lines[3].strip(),
                    message=lines[4].strip() if len(lines) > 4 else "",
                ))
            except IndexError:
                continue
        return commits

    # ── History scan ──────────────────────────────────────────────────────────

    def scan(self) -> list[HistoryFinding]:
        if not self._is_git_repo():
            if self.verbose:
                print("  [history] Not a git repository — skipping")
            return []

        self.collect_metadata()

        # Get all commit hashes (across all branches)
        log_out = self._git(
            "log", "--all",
            f"--max-count={self.max_commits}",
            "--format=<<<COMMIT_SEP>>>%n%H%n%an%n%ae%n%ai%n%s",
        )
        self.commits = self._parse_log(log_out)

        if self.verbose:
            print(f"  [history] Scanning {len(self.commits)} commits...")

        seen_secrets: set[str] = set()
        # Track which secrets are still in current HEAD
        head_findings = self._scanner.scan()
        head_secrets = {
            (f.pattern_name, f.matched_text[:20])
            for f in head_findings
        }

        for i, commit in enumerate(self.commits):
            # Get the diff for this commit
            diff_out = self._git(
                "diff-tree", "--no-commit-id", "-p", "-r",
                "--text",   # force text output
                commit.hash,
                timeout=30,
            )
            if not diff_out:
                continue

            # Only scan added lines (lines starting with +)
            added_lines: list[tuple[int, str]] = []
            removed_lines: list[tuple[int, str]] = []
            current_file = ""
            line_num = 0

            for line in diff_out.splitlines():
                if line.startswith("diff --git"):
                    # Extract filename
                    m = re.search(r'b/(.+)$', line)
                    current_file = m.group(1) if m else "unknown"
                    line_num = 0
                elif line.startswith("@@"):
                    # Parse hunk header for line numbers
                    m = re.search(r'\+(\d+)', line)
                    if m:
                        line_num = int(m.group(1))
                elif line.startswith("+") and not line.startswith("+++"):
                    added_lines.append((line_num, current_file, line[1:]))
                    line_num += 1
                elif line.startswith("-") and not line.startswith("---"):
                    removed_lines.append((line_num, current_file, line[1:]))
                else:
                    if not line.startswith("-"):
                        line_num += 1

            # Scan added lines for secrets
            added_text = "\n".join(l[2] for l in added_lines)
            if not added_text.strip():
                continue

            raw_findings = self._scanner.scan_text(
                added_text,
                source_label=f"git:{commit.short_hash}",
                commit_hash=commit.hash,
                commit_date=commit.date,
            )

            for finding in raw_findings:
                dedup_key = f"{finding.pattern_name}:{finding.matched_text[:20]}"
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)

                # Determine if this secret is still present in HEAD
                still_present = (finding.pattern_name, finding.matched_text[:20]) in head_secrets

                if still_present:
                    status = "still_present"
                    risk_note = "Secret is STILL in current HEAD — immediate action required"
                else:
                    status = "removed"
                    risk_note = ("Secret was deleted/changed but remains in git history. "
                                 "Consider BFG Repo Cleaner or git-filter-repo to purge.")

                # Boost severity for removed-but-historic secrets
                if finding.severity in ("CRITICAL", "HIGH"):
                    effective_severity = finding.severity
                else:
                    effective_severity = "MEDIUM"

                finding.severity = effective_severity

                self.findings.append(HistoryFinding(
                    finding=finding,
                    commit=commit,
                    status=status,
                    risk_note=risk_note,
                ))

                if self.verbose:
                    flag = "🔴" if status == "still_present" else "🟡"
                    print(f"    {flag} [{commit.short_hash}] {finding.pattern_name} "
                          f"in {commit.date[:10]}: {commit.message[:50]}")

        if self.verbose:
            still = sum(1 for f in self.findings if f.status == "still_present")
            historic = sum(1 for f in self.findings if f.status == "removed")
            print(f"  [history] Done: {still} still-present, {historic} historic secrets")

        return self.findings

    def summary(self) -> dict:
        still   = [f for f in self.findings if f.status == "still_present"]
        removed = [f for f in self.findings if f.status == "removed"]
        return {
            "total":         len(self.findings),
            "still_present": len(still),
            "historic":      len(removed),
            "commits_scanned": len(self.commits),
            "unique_emails": len(self.emails),
            "branches":      len(self.branch_names),
            "emails":        sorted(self.emails),
        }
