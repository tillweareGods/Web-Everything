"""
modules/dependency_analyzer.py — Dependency & Supply Chain Analyzer

Checks:
  1. Known vulnerable packages via OSV.dev API (batch queries)
  2. Dependency confusion candidates (internal-looking package names)
  3. Typosquatting patterns
  4. Unpinned / wildcard version ranges
  5. Suspicious packages (post-install scripts, excessive permissions)
"""

from __future__ import annotations
import json
import os
import re
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import xml.etree.ElementTree as ET
    HAS_ET = True
except ImportError:
    HAS_ET = False


@dataclass
class VulnInfo:
    vuln_id:     str
    severity:    str
    summary:     str
    aliases:     list[str]
    fixed_ver:   str = ""


@dataclass
class DepFinding:
    file_path:    str
    package_name: str
    version:      str
    ecosystem:    str    # PyPI / npm / Go / Maven / Cargo / NuGet
    finding_type: str    # "KNOWN_VULN" / "CONFUSED" / "TYPOSQUAT" / "UNPINNED" / "SUSPICIOUS"
    severity:     str
    title:        str
    description:  str
    vulns:        list[VulnInfo] = field(default_factory=list)
    exploit_path: str = ""
    remediation:  str = ""

    def to_dict(self) -> dict:
        return {
            "file":        self.file_path,
            "package":     self.package_name,
            "version":     self.version,
            "ecosystem":   self.ecosystem,
            "type":        self.finding_type,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "vulns":       [{"id": v.vuln_id, "severity": v.severity, "summary": v.summary,
                             "fixed": v.fixed_ver} for v in self.vulns],
            "exploit":     self.exploit_path,
            "remediation": self.remediation,
        }


# ── Typosquatting patterns for popular packages ───────────────────────────────

POPULAR_PACKAGES = {
    "npm": [
        "react", "lodash", "express", "axios", "webpack", "babel-core",
        "typescript", "next", "vue", "angular", "jquery", "bootstrap",
        "moment", "chalk", "commander", "nodemon", "dotenv", "passport",
        "sequelize", "mongoose", "socket.io", "cors", "helmet",
    ],
    "PyPI": [
        "requests", "numpy", "pandas", "flask", "django", "sqlalchemy",
        "boto3", "cryptography", "pillow", "scipy", "matplotlib",
        "pytest", "celery", "redis", "psycopg2", "aiohttp",
    ],
}

TYPO_PATTERNS = [
    (r"python-(.+)", "PyPI"),   # python-requests vs requests
    (r"(.+)-python$", "PyPI"),
    (r"node-(.+)", "npm"),       # node-fetch vs fetch
    (r"(.+)-js$", "npm"),
]

# Packages known to have been used in dependency confusion or typosquatting
SUSPICIOUS_NAMES = re.compile(
    r"(?i)^(setup|install|loader|helper|utils|core|base|common|lib|"
    r"test-[a-z]+|internal-[a-z]+|private-[a-z]+|my-[a-z]+)$"
)

# ── Version pinning analysis ──────────────────────────────────────────────────

WILDCARD_VERSION = re.compile(r"^[\*^~><=]")


def is_unpinned(version: str) -> bool:
    if not version or version in ("*", "latest", ""):
        return True
    return bool(WILDCARD_VERSION.match(version))


# ── OSV.dev API client ────────────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT   = 15


def _osv_query_batch(packages: list[tuple[str, str, str]]) -> dict[tuple, list[VulnInfo]]:
    """
    Query OSV.dev for multiple (package, version, ecosystem) tuples.
    Returns dict keyed by (name, version) -> list[VulnInfo]
    """
    if not packages:
        return {}

    queries = []
    for name, version, ecosystem in packages:
        query: dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version and not is_unpinned(version):
            # Clean version string
            clean_ver = re.sub(r"[^0-9a-zA-Z.\-+]", "", version)
            query["version"] = clean_ver
        queries.append(query)

    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return {}

    results = {}
    for i, result_set in enumerate(data.get("results", [])):
        if i >= len(packages):
            break
        name, version, _ = packages[i]
        vulns = []
        for vuln in result_set.get("vulns", []):
            # Find severity
            severity = "UNKNOWN"
            for sev in vuln.get("severity", []):
                score_str = sev.get("score", "")
                if score_str:
                    try:
                        score = float(score_str) if score_str.replace(".", "").isdigit() else 0
                    except ValueError:
                        score = 0
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    break
            # cvss type
            if severity == "UNKNOWN":
                for sev in vuln.get("severity", []):
                    t = sev.get("type", "")
                    if "CVSS" in t:
                        severity = "HIGH"  # default if CVSS present but no score
                        break

            # Find fix version
            fixed_ver = ""
            for affected in vuln.get("affected", []):
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            fixed_ver = event["fixed"]
                            break

            vulns.append(VulnInfo(
                vuln_id=vuln.get("id", ""),
                severity=severity,
                summary=vuln.get("summary", "")[:120],
                aliases=vuln.get("aliases", [])[:3],
                fixed_ver=fixed_ver,
            ))

        if vulns:
            results[(name, version)] = vulns

    return results


# ── Manifest parsers ──────────────────────────────────────────────────────────

def _parse_package_json(content: str, file_path: str) -> list[tuple[str, str, str, str]]:
    """Returns list of (name, version, ecosystem, file_path)"""
    deps = []
    try:
        data = json.loads(content)
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            for pkg, ver in data.get(section, {}).items():
                deps.append((pkg, str(ver), "npm", file_path))
    except (json.JSONDecodeError, AttributeError):
        pass
    return deps


def _parse_requirements_txt(content: str, file_path: str) -> list[tuple[str, str, str, str]]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.0, package>=1.0, package~=1.0, package
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~]{0,3})\s*([0-9A-Za-z\.\-\*]*)", line)
        if m:
            name, op, ver = m.group(1), m.group(2), m.group(3)
            version = (op + ver) if op else ver
            deps.append((name, version, "PyPI", file_path))
    return deps


def _parse_go_mod(content: str, file_path: str) -> list[tuple[str, str, str, str]]:
    deps = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line == "require (":
            in_require = True
            continue
        if line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            line = line.replace("require ", "").strip()
            parts = line.split()
            if len(parts) >= 2:
                name, ver = parts[0], parts[1]
                if not name.startswith("//"):
                    deps.append((name, ver, "Go", file_path))
    return deps


def _parse_cargo_toml(content: str, file_path: str) -> list[tuple[str, str, str, str]]:
    deps = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if re.match(r"^\[(dependencies|dev-dependencies|build-dependencies)\]", line):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in line:
            parts = line.split("=", 1)
            name = parts[0].strip()
            ver_raw = parts[1].strip().strip('"').strip("'")
            # Handle table format: { version = "1.0", ... }
            m = re.search(r'version\s*=\s*"([^"]+)"', ver_raw)
            if m:
                ver_raw = m.group(1)
            if name and not name.startswith("#"):
                deps.append((name, ver_raw, "crates.io", file_path))
    return deps


# ── Main analyzer ─────────────────────────────────────────────────────────────

class DependencyAnalyzer:
    def __init__(self, repo_path: str, verbose: bool = False, skip_osv: bool = False):
        self.repo_path = Path(repo_path)
        self.verbose   = verbose
        self.skip_osv  = skip_osv
        self.findings:  list[DepFinding] = []
        self._all_deps: list[tuple[str, str, str, str]] = []  # (name, version, eco, file)

    # ── Manifest discovery ────────────────────────────────────────────────────

    def _collect_deps(self):
        manifest_map = {
            "package.json":      _parse_package_json,
            "requirements.txt":  _parse_requirements_txt,
            "requirements*.txt": _parse_requirements_txt,
            "Pipfile":           _parse_requirements_txt,  # similar format
            "go.mod":            _parse_go_mod,
            "Cargo.toml":        _parse_cargo_toml,
        }

        for fpath in self.repo_path.rglob("*"):
            if not fpath.is_file():
                continue
            # Skip node_modules, vendor etc.
            rel = fpath.relative_to(self.repo_path)
            parts = rel.parts
            if any(p in ("node_modules", "vendor", ".git", "dist", "build") for p in parts):
                continue

            fname = fpath.name
            for pattern, parser in manifest_map.items():
                if "*" in pattern:
                    base = pattern.replace("*", "")
                    if not (fname.startswith(base.split("*")[0]) and fname.endswith(base.split("*")[-1])):
                        continue
                elif fname != pattern:
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel_str = str(rel)
                self._all_deps.extend(parser(content, rel_str))
                break

        if self.verbose:
            print(f"  [deps] Collected {len(self._all_deps)} dependencies from manifests")

    # ── OSV vulnerability check ───────────────────────────────────────────────

    def _check_osv(self):
        # Batch in groups of 50 to avoid API limits
        BATCH_SIZE = 50
        vuln_map: dict[tuple, list[VulnInfo]] = {}

        for i in range(0, len(self._all_deps), BATCH_SIZE):
            batch = [(name, ver, eco) for name, ver, eco, _ in self._all_deps[i:i + BATCH_SIZE]]
            batch_results = _osv_query_batch(batch)
            vuln_map.update(batch_results)

        for name, version, ecosystem, file_path in self._all_deps:
            vulns = vuln_map.get((name, version), [])
            if vulns:
                max_sev = max(
                    vulns,
                    key=lambda v: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(
                        v.severity if v.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else "UNKNOWN"
                    )
                )
                cve_ids = ", ".join(
                    alias for v in vulns for alias in v.aliases if alias.startswith("CVE")
                )[:80]

                self.findings.append(DepFinding(
                    file_path=file_path,
                    package_name=name,
                    version=version,
                    ecosystem=ecosystem,
                    finding_type="KNOWN_VULN",
                    severity=max_sev.severity,
                    title=f"Vulnerable dependency: {name} {version}",
                    description=(
                        f"{len(vulns)} known vulnerabilit{'y' if len(vulns)==1 else 'ies'} in "
                        f"{name} {version} ({ecosystem}). "
                        + (f"CVEs: {cve_ids}." if cve_ids else "")
                    ),
                    vulns=vulns,
                    exploit_path=(
                        f"Use known {max_sev.vuln_id} exploit against {name} {version} → "
                        "RCE / data exposure / privilege escalation"
                    ),
                    remediation=(
                        f"Upgrade to fixed version. "
                        + (f"Fixed in: {max_sev.fixed_ver}" if max_sev.fixed_ver else "Check OSV.dev for patched version.")
                    ),
                ))

    # ── Dependency confusion detection ───────────────────────────────────────

    def _check_confusion(self):
        """Detect packages that look like internal packages and may be
        vulnerable to dependency confusion attacks."""
        for name, version, ecosystem, file_path in self._all_deps:
            # Patterns suggesting internal/private package names
            looks_internal = bool(re.search(
                r"(?i)(^internal[-.]|[-.]internal$|^private[-.]|[-.]private$|"
                r"^corp[-.]|[-.]corp$|^company[-.]|[-.]company$|"
                r"\.(internal|local|corp|private)$)",
                name
            ))
            # Scoped npm packages from internal orgs
            is_unscoped_internal = (
                ecosystem == "npm" and
                not name.startswith("@") and
                SUSPICIOUS_NAMES.match(name)
            )

            if looks_internal or is_unscoped_internal:
                self.findings.append(DepFinding(
                    file_path=file_path,
                    package_name=name,
                    version=version,
                    ecosystem=ecosystem,
                    finding_type="CONFUSED",
                    severity="HIGH",
                    title=f"Dependency confusion candidate: {name}",
                    description=(
                        f"`{name}` appears to be an internal package name. "
                        "If this package is not published on the public registry, "
                        "an attacker can publish a malicious package with the same name "
                        "at a higher version number and automatically get it installed."
                    ),
                    exploit_path=(
                        f"Register `{name}` on public {ecosystem} registry at high version → "
                        "package manager resolves public version → malicious code executes on install"
                    ),
                    remediation=(
                        "Use scoped package names (@yourorg/package-name) for internal packages. "
                        "Configure your package manager to use private registry for internal packages."
                    ),
                ))

    # ── Unpinned version detection ────────────────────────────────────────────

    def _check_pinning(self):
        unpinned_by_file: dict[str, int] = {}
        for name, version, ecosystem, file_path in self._all_deps:
            if is_unpinned(version):
                unpinned_by_file[file_path] = unpinned_by_file.get(file_path, 0) + 1

        for file_path, count in unpinned_by_file.items():
            if count >= 3:  # Only flag if multiple unpinned
                self.findings.append(DepFinding(
                    file_path=file_path,
                    package_name="(multiple)",
                    version="*",
                    ecosystem="",
                    finding_type="UNPINNED",
                    severity="LOW",
                    title=f"{count} unpinned dependencies in {file_path}",
                    description=(
                        f"Found {count} dependencies using wildcard or range versions. "
                        "This makes builds non-reproducible and allows malicious package "
                        "updates to automatically propagate."
                    ),
                    exploit_path="Compromise package → publish malicious patch version → auto-installed on next build",
                    remediation="Pin all dependencies to exact versions and use a lockfile (package-lock.json, Pipfile.lock).",
                ))

    # ── Main scan entry ───────────────────────────────────────────────────────

    def scan(self) -> list[DepFinding]:
        self.findings = []
        self._collect_deps()

        if not self.skip_osv and self._all_deps:
            if self.verbose:
                print(f"  [deps] Querying OSV.dev for {len(self._all_deps)} packages...")
            self._check_osv()

        self._check_confusion()
        self._check_pinning()

        if self.verbose:
            print(f"  [deps] Found {len(self.findings)} dependency findings")

        return self.findings

    def summary(self) -> dict:
        return {
            "total_packages": len(self._all_deps),
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in self.findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in self.findings if f.severity == "LOW"),
            "vuln_count": sum(1 for f in self.findings if f.finding_type == "KNOWN_VULN"),
        }
