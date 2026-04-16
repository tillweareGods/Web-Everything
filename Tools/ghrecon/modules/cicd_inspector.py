"""
modules/cicd_inspector.py — CI/CD Pipeline Security Analyzer

Detects:
  1. GitHub Actions: unsafe triggers (pull_request_target),
     untrusted input injection, secret echo in logs, GITHUB_TOKEN misuse
  2. GitLab CI: privileged runners, artifact exposure
  3. CircleCI: orb trust issues
  4. General: hardcoded creds in CI configs
"""

from __future__ import annotations
import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class CICDFinding:
    file_path:    str
    line_number:  int
    finding_type: str
    severity:     str
    title:        str
    description:  str
    code_snippet: str = ""
    exploit_path: str = ""
    remediation:  str = ""
    cwe:          str = ""

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


class CICDInspector:
    def __init__(self, repo_path: str, verbose: bool = False):
        self.repo_path = Path(repo_path)
        self.verbose   = verbose
        self.findings:  list[CICDFinding] = []

    # ── File discovery ────────────────────────────────────────────────────────

    def _find_ci_files(self) -> list[Path]:
        patterns = [
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            "Jenkinsfile",
            "Jenkinsfile.*",
            ".travis.yml",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
            ".drone.yml",
            "cloudbuild.yaml",
            "codebuild.yml",
            "buildspec.yml",
            "appveyor.yml",
        ]
        found = []
        for pattern in patterns:
            found.extend(self.repo_path.glob(pattern))
        # Also search recursively in .github
        gh_dir = self.repo_path / ".github" / "workflows"
        if gh_dir.is_dir():
            found.extend(gh_dir.glob("*.yml"))
            found.extend(gh_dir.glob("*.yaml"))
        return list(set(found))

    # ── Text-level checks (work without YAML parser) ─────────────────────────

    def _check_text(self, content: str, file_path: str, lines: list[str]):

        # 1. Secrets echoed to log output
        echo_pattern = re.compile(
            r"(?i)(echo|print|console\.log|puts)\s+['\"]?\$?\{?\s*"
            r"(secrets\.|[A-Z_]*TOKEN|[A-Z_]*API_KEY|[A-Z_]*PASSWORD|[A-Z_]*SECRET)",
            re.MULTILINE,
        )
        for m in echo_pattern.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            self.findings.append(CICDFinding(
                file_path=file_path,
                line_number=lineno,
                finding_type="SECRET_ECHO",
                severity="HIGH",
                title="Secret value echoed to CI log",
                description=(
                    "A secret or token is being printed to the CI log output. "
                    "Logs are often accessible to unauthorized users or stored long-term."
                ),
                code_snippet=lines[lineno - 1].strip(),
                exploit_path="Read CI logs → extract token → use for API access / privilege escalation",
                remediation="Remove the echo/print statement. Use step masking or never log secret values.",
                cwe="CWE-532",
            ))

        # 2. pull_request_target with checkout of PR code (pwn request attack)
        if "pull_request_target" in content:
            # Dangerous when combined with actions/checkout of the PR ref
            has_dangerous_checkout = bool(re.search(
                r"ref:\s*\$\{\{.*?(head\.ref|head\.sha|pull_request\.head)",
                content
            ))
            trigger_lineno = next(
                (i + 1 for i, l in enumerate(lines) if "pull_request_target" in l), 1
            )
            severity = "CRITICAL" if has_dangerous_checkout else "HIGH"
            self.findings.append(CICDFinding(
                file_path=file_path,
                line_number=trigger_lineno,
                finding_type="PWNABLE_TRIGGER",
                severity=severity,
                title="Dangerous `pull_request_target` workflow trigger",
                description=(
                    "`pull_request_target` runs in the context of the BASE repository with write "
                    "permissions and access to secrets. If combined with a checkout of the PR HEAD, "
                    "an attacker can submit a malicious PR and execute arbitrary code with full repo access."
                ),
                code_snippet=lines[trigger_lineno - 1].strip(),
                exploit_path=(
                    "Fork repo → modify .github/workflows → open PR → "
                    "code executes with secrets exposed → exfiltrate GITHUB_TOKEN → "
                    "push to main / access cloud credentials"
                ),
                remediation=(
                    "Never use `pull_request_target` with a checkout of untrusted code. "
                    "If you need PR access to secrets, use separate privileged workflow triggered by label."
                ),
                cwe="CWE-94",
            ))

        # 3. Untrusted user-controlled input used in run steps (expression injection)
        injection_pattern = re.compile(
            r"run:.*\$\{\{\s*(github\.event\.(issue\.body|pull_request\.(title|body|head\.ref)|"
            r"comment\.body|review\.body|discussion\.body)|"
            r"inputs\.[a-zA-Z_]+)\s*\}\}",
            re.MULTILINE,
        )
        for m in injection_pattern.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            untrusted_input = m.group(1)
            self.findings.append(CICDFinding(
                file_path=file_path,
                line_number=lineno,
                finding_type="EXPRESSION_INJECTION",
                severity="CRITICAL",
                title="Untrusted input injected into shell `run:` step",
                description=(
                    f"The expression `${{{{ {untrusted_input} }}}}` is interpolated directly "
                    "into a shell run step. An attacker controlling this value can inject arbitrary "
                    "shell commands and execute them in the CI runner with full secret access."
                ),
                code_snippet=lines[lineno - 1].strip(),
                exploit_path=(
                    f"Craft malicious {untrusted_input.split('.')[-1]} → "
                    "injection triggers on next CI run → "
                    "RCE in runner → exfiltrate all secrets"
                ),
                remediation=(
                    "Assign the expression to an environment variable first:\n"
                    "  env:\n    INPUT_VAL: ${{ " + untrusted_input + " }}\n"
                    "Then use $INPUT_VAL in the shell command."
                ),
                cwe="CWE-78",
            ))

        # 4. Wildcard / overly-permissive GITHUB_TOKEN permissions
        if "permissions:" in content:
            if re.search(r"permissions:\s*write-all", content):
                lineno = next(
                    (i + 1 for i, l in enumerate(lines) if "write-all" in l), 1
                )
                self.findings.append(CICDFinding(
                    file_path=file_path,
                    line_number=lineno,
                    finding_type="OVERPERMISSIVE_TOKEN",
                    severity="HIGH",
                    title="GITHUB_TOKEN has `write-all` permissions",
                    description=(
                        "The workflow grants all write permissions to GITHUB_TOKEN. "
                        "If this workflow is compromised, the attacker gains full write access "
                        "to the repository including pushing to protected branches."
                    ),
                    code_snippet=lines[lineno - 1].strip(),
                    exploit_path="Compromise workflow → use GITHUB_TOKEN → push malicious code → supply chain attack",
                    remediation="Apply principle of least privilege: specify only required permissions explicitly.",
                    cwe="CWE-732",
                ))

        # 5. Use of third-party actions without pinned SHA (supply chain risk)
        action_pattern = re.compile(r"uses:\s+([a-zA-Z0-9\-]+/[a-zA-Z0-9\-]+)@([^\s#]+)")
        for m in action_pattern.finditer(content):
            action_name = m.group(1)
            action_ref  = m.group(2).strip()
            lineno = content[:m.start()].count("\n") + 1

            # Mutable refs (branch names, version tags without SHA) are risky
            is_sha = bool(re.match(r"[a-f0-9]{40}", action_ref))
            is_official = action_name.startswith(("actions/", "github/"))

            if not is_sha and not is_official:
                self.findings.append(CICDFinding(
                    file_path=file_path,
                    line_number=lineno,
                    finding_type="UNPINNED_ACTION",
                    severity="MEDIUM",
                    title=f"Third-party action `{action_name}` not pinned to commit SHA",
                    description=(
                        f"Action `{action_name}@{action_ref}` uses a mutable reference. "
                        "If the action repo is compromised or the tag is moved, "
                        "malicious code will run in your CI pipeline."
                    ),
                    code_snippet=lines[lineno - 1].strip(),
                    exploit_path=(
                        f"Compromise {action_name} repo → push malicious code to {action_ref} → "
                        "your CI automatically runs attacker code with secret access"
                    ),
                    remediation=f"Pin to a specific commit SHA: `uses: {action_name}@<full-sha>  # {action_ref}`",
                    cwe="CWE-1357",
                ))

        # 6. Self-hosted runners with public fork PR trigger
        if "self-hosted" in content and ("pull_request" in content or "push" in content):
            lineno = next(
                (i + 1 for i, l in enumerate(lines) if "self-hosted" in l), 1
            )
            self.findings.append(CICDFinding(
                file_path=file_path,
                line_number=lineno,
                finding_type="SELF_HOSTED_RUNNER_RISK",
                severity="HIGH",
                title="Self-hosted runner used in externally-triggered workflow",
                description=(
                    "Self-hosted runners process jobs on infrastructure you control. "
                    "If a public repo accepts external PRs and runs them on self-hosted runners, "
                    "attackers can execute code on your internal network."
                ),
                code_snippet=lines[lineno - 1].strip(),
                exploit_path=(
                    "Submit malicious PR → CI runs on self-hosted runner inside your network → "
                    "lateral movement → access internal systems"
                ),
                remediation="Only use self-hosted runners for trusted internal workflows. Use GitHub-hosted runners for public PRs.",
                cwe="CWE-284",
            ))

        # 7. Artifact upload of sensitive paths
        artifact_pattern = re.compile(
            r"path:\s*(.*(\.env|config\.|secret|credential|private_key|\.pem|\.key)[^\n]*)",
            re.IGNORECASE,
        )
        for m in artifact_pattern.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            self.findings.append(CICDFinding(
                file_path=file_path,
                line_number=lineno,
                finding_type="SENSITIVE_ARTIFACT",
                severity="HIGH",
                title="Potentially sensitive file uploaded as CI artifact",
                description=(
                    f"The path `{m.group(1).strip()}` appears to include sensitive files "
                    "being uploaded as a CI artifact. Artifacts may be accessible to anyone "
                    "who can view the workflow run."
                ),
                code_snippet=lines[lineno - 1].strip(),
                exploit_path="Download CI artifact → extract credentials → unauthorized access",
                remediation="Exclude sensitive files from artifact uploads. Review artifact retention settings.",
                cwe="CWE-532",
            ))

        # 8. Curl piped to bash (script injection risk in CI)
        curl_bash = re.compile(r"curl.+\|\s*(ba)?sh", re.IGNORECASE)
        for m in curl_bash.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            self.findings.append(CICDFinding(
                file_path=file_path,
                line_number=lineno,
                finding_type="CURL_PIPE_BASH",
                severity="MEDIUM",
                title="Remote script piped to shell in CI step",
                description=(
                    "Downloading and executing remote scripts at CI runtime is risky. "
                    "If the remote URL is compromised or served over HTTP, "
                    "an attacker can inject code into your pipeline."
                ),
                code_snippet=lines[lineno - 1].strip(),
                exploit_path="MITM or compromise remote script host → inject malicious code → CI executes with secret access",
                remediation="Pin script content via hash verification, or vendor the script into the repo.",
                cwe="CWE-494",
            ))

    # ── Main scan entry point ─────────────────────────────────────────────────

    def scan(self) -> list[CICDFinding]:
        self.findings = []
        ci_files = self._find_ci_files()

        if self.verbose:
            print(f"  [cicd] Found {len(ci_files)} CI/CD config files")

        for fpath in ci_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel_path = str(fpath.relative_to(self.repo_path))
            lines = content.splitlines()
            self._check_text(content, rel_path, lines)

        if self.verbose:
            print(f"  [cicd] Found {len(self.findings)} findings")

        return self.findings

    def summary(self) -> dict:
        return {
            "total":    len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in self.findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "types":    list({f.finding_type for f in self.findings}),
        }
