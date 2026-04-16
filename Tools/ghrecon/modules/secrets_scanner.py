"""
modules/secrets_scanner.py — Secrets & sensitive data scanner

Combines:
  1. Regex pattern matching (80+ patterns)
  2. Shannon entropy analysis
  3. Base64 decode + re-scan
  4. Context-aware false positive filtering
  5. High-value file prioritization
"""

from __future__ import annotations
import base64
import binascii
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from patterns.secrets import (
    COMPILED_PATTERNS, BASE64_PATTERN, PLACEHOLDER_PATTERNS,
    BOOST_KEYWORDS, HIGH_VALUE_FILES, ENTROPY_THRESHOLDS,
    MIN_SECRET_LENGTH, MAX_SECRET_LENGTH,
)

# ── Binary file detection ─────────────────────────────────────────────────────

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z",
    ".exe", ".bin", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class",
    ".mp3", ".mp4", ".avi", ".mov",
    ".woff", ".woff2", ".ttf", ".eot",
    ".lock",  # lockfiles: very noisy, low value
}

MAX_FILE_SIZE_MB = 5


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    file_path:   str
    line_number: int
    pattern_name: str
    severity:    str
    matched_text: str
    line_content: str
    commit_hash:  str = ""       # set by git history scanner
    commit_date:  str = ""
    confidence:  str = "HIGH"   # HIGH / MEDIUM / LOW
    method:      str = "regex"  # regex / entropy / base64
    context_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "pattern": self.pattern_name,
            "severity": self.severity,
            "matched": self.masked_secret(),
            "line": self.line_content.strip(),
            "confidence": self.confidence,
            "method": self.method,
            "commit": self.commit_hash,
            "commit_date": self.commit_date,
        }

    def masked_secret(self) -> str:
        """Show first 6 and last 4 chars for identification without full exposure."""
        t = self.matched_text.strip()
        if len(t) <= 12:
            return t[:3] + "***"
        return t[:6] + "..." + t[-4:]


# ── Entropy calculation ───────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def _charset_name(token: str) -> str:
    hex_chars   = set("0123456789abcdefABCDEF")
    b64_chars   = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    alnum_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    char_set = set(token)
    if char_set <= hex_chars:
        return "hex"
    if char_set <= b64_chars:
        return "base64"
    if char_set <= alnum_chars:
        return "alnum"
    return "unknown"


def is_high_entropy(token: str) -> tuple[bool, float]:
    if len(token) < MIN_SECRET_LENGTH or len(token) > MAX_SECRET_LENGTH:
        return False, 0.0
    charset = _charset_name(token)
    threshold = ENTROPY_THRESHOLDS.get(charset, 4.0)
    ent = shannon_entropy(token)
    return ent >= threshold, ent


# ── False positive filtering ──────────────────────────────────────────────────

_COMMON_FP = re.compile(
    r"(?i)(lorem|ipsum|example\.com|localhost|127\.0\.0\.1|"
    r"github\.com/[a-z]+/[a-z]+|https?://docs\.|https?://www\.)"
)

def is_false_positive(match_text: str, line: str) -> bool:
    if PLACEHOLDER_PATTERNS.search(match_text):
        return True
    if _COMMON_FP.search(match_text):
        return True
    # URL path segments that look like tokens but aren't
    if re.match(r"^[a-f0-9]{40}$", match_text) and "sha" in line.lower():
        return True
    return False


# ── Main scanner class ────────────────────────────────────────────────────────

class SecretsScanner:
    def __init__(self, repo_path: str, verbose: bool = False):
        self.repo_path = Path(repo_path)
        self.verbose = verbose
        self.findings: list[SecretFinding] = []
        self._scanned_files = 0
        self._skipped_files = 0

    # ── File iterator ─────────────────────────────────────────────────────────

    def _iter_files(self) -> Generator[Path, None, None]:
        for root, dirs, files in os.walk(self.repo_path):
            # Skip .git object store (handled separately by history scanner)
            dirs[:] = [d for d in dirs
                       if d not in {".git", "node_modules", "__pycache__",
                                    "vendor", ".gradle", "dist", "build",
                                    ".venv", "venv", "env"}]
            for fname in files:
                fpath = Path(root) / fname
                yield fpath

    def _should_skip(self, fpath: Path) -> bool:
        if fpath.suffix.lower() in BINARY_EXTENSIONS:
            return True
        try:
            if fpath.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                return True
        except OSError:
            return True
        return False

    def _is_high_value(self, fpath: Path) -> bool:
        name = fpath.name.lower()
        return any(
            name == hv or (hv.startswith("*") and name.endswith(hv[1:]))
            for hv in HIGH_VALUE_FILES
        )

    # ── Line-level scanning ───────────────────────────────────────────────────

    def _scan_content(self, content: str, file_path: str,
                      commit_hash: str = "", commit_date: str = "") -> list[SecretFinding]:
        results: list[SecretFinding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            if len(line) > 2000:  # skip minified / very long lines
                continue

            # 1. Regex pattern matching
            for pat in COMPILED_PATTERNS:
                for m in pat["regex"].finditer(line):
                    matched = m.group(0)
                    if is_false_positive(matched, line):
                        continue

                    # Confidence boost for high-value files / boosting keywords
                    confidence = "HIGH" if pat["severity"] in ("CRITICAL", "HIGH") else "MEDIUM"
                    if any(kw in line.lower() for kw in BOOST_KEYWORDS):
                        confidence = "HIGH"

                    ctx_start = max(0, lineno - 3)
                    ctx_end   = min(len(lines), lineno + 2)
                    context   = lines[ctx_start:ctx_end]

                    results.append(SecretFinding(
                        file_path=file_path,
                        line_number=lineno,
                        pattern_name=pat["name"],
                        severity=pat["severity"],
                        matched_text=matched,
                        line_content=line,
                        commit_hash=commit_hash,
                        commit_date=commit_date,
                        confidence=confidence,
                        method="regex",
                        context_lines=context,
                    ))

            # 2. Entropy-based detection on string literals
            for token_match in re.finditer(r"""['"]([A-Za-z0-9+/=\-_\.]{20,512})['"]""", line):
                token = token_match.group(1)
                if PLACEHOLDER_PATTERNS.search(token):
                    continue
                high_ent, ent_score = is_high_entropy(token)
                if high_ent:
                    # Check if already caught by regex
                    already_found = any(
                        f.line_number == lineno and f.method == "regex"
                        and token in f.matched_text
                        for f in results
                    )
                    if not already_found:
                        results.append(SecretFinding(
                            file_path=file_path,
                            line_number=lineno,
                            pattern_name=f"High-Entropy String (entropy={ent_score:.2f})",
                            severity="MEDIUM",
                            matched_text=token,
                            line_content=line,
                            commit_hash=commit_hash,
                            commit_date=commit_date,
                            confidence="MEDIUM",
                            method="entropy",
                            context_lines=[],
                        ))

            # 3. Base64-encoded secrets: decode and re-scan
            for b64_match in BASE64_PATTERN.finditer(line):
                raw = b64_match.group(0)
                try:
                    decoded = base64.b64decode(raw + "==").decode("utf-8", errors="replace")
                    if len(decoded) > 10 and decoded.isprintable():
                        sub_results = self._scan_content(
                            decoded,
                            file_path=f"{file_path}[base64@{lineno}]",
                            commit_hash=commit_hash,
                            commit_date=commit_date,
                        )
                        for sr in sub_results:
                            sr.method = "base64"
                            sr.severity = max(
                                ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(sr.severity),
                                ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index("MEDIUM")
                            )
                            sr.severity = ["LOW", "MEDIUM", "HIGH", "CRITICAL"][sr.severity]
                            results.append(sr)
                except (binascii.Error, UnicodeDecodeError):
                    pass

        return results

    # ── File-level scan ───────────────────────────────────────────────────────

    def scan_file(self, fpath: Path) -> list[SecretFinding]:
        if self._should_skip(fpath):
            self._skipped_files += 1
            return []
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        rel_path = str(fpath.relative_to(self.repo_path))
        self._scanned_files += 1
        return self._scan_content(content, rel_path)

    # ── Directory scan ────────────────────────────────────────────────────────

    def scan(self) -> list[SecretFinding]:
        self.findings = []
        seen: set[tuple] = set()

        for fpath in self._iter_files():
            file_findings = self.scan_file(fpath)
            for f in file_findings:
                dedup_key = (f.file_path, f.line_number, f.pattern_name, f.matched_text[:20])
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    self.findings.append(f)

        if self.verbose:
            print(f"  [secrets] Scanned {self._scanned_files} files, "
                  f"skipped {self._skipped_files}, "
                  f"found {len(self.findings)} findings")
        return self.findings

    def scan_text(self, text: str, source_label: str,
                  commit_hash: str = "", commit_date: str = "") -> list[SecretFinding]:
        """Scan arbitrary text (used by git history scanner)."""
        return self._scan_content(text, source_label, commit_hash, commit_date)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    def summary(self) -> dict:
        return {
            "total":    len(self.findings),
            "critical": self.critical_count,
            "high":     self.high_count,
            "medium":   sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in self.findings if f.severity == "LOW"),
        }
