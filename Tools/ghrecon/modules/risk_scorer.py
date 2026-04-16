"""
modules/risk_scorer.py — Composite risk scoring engine

Weights findings across all modules into a single risk score (0-100)
with a letter grade (A-F) and per-category breakdown.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── Severity weights ──────────────────────────────────────────────────────────
SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1}

# ── Module weights in final score (sum to 1.0) ────────────────────────────────
MODULE_WEIGHTS = {
    "secrets":      0.35,
    "git_history":  0.20,
    "cicd":         0.15,
    "dependencies": 0.10,
    "misconfig":    0.10,
    "metadata":     0.05,
    "other":        0.05,
}


@dataclass
class ModuleScore:
    module:   str
    score:    float      # 0-100
    weight:   float
    findings: int
    critical: int
    high:     int

@dataclass
class RiskScore:
    total:          float          # 0-100 (higher = worse)
    grade:          str            # A-F
    level:          str            # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    module_scores:  list[ModuleScore] = field(default_factory=list)
    top_risks:      list[str] = field(default_factory=list)


def _grade(score: float) -> tuple[str, str]:
    if score >= 80: return "F", "CRITICAL"
    if score >= 60: return "D", "HIGH"
    if score >= 40: return "C", "MEDIUM"
    if score >= 20: return "B", "LOW"
    return "A", "MINIMAL"


def _module_score(findings: list, max_score: float = 100.0) -> float:
    """Convert a list of findings (with .severity) to a 0-100 score."""
    raw = sum(SEV_WEIGHT.get(getattr(f, "severity", "LOW"), 1) for f in findings)
    # Clamp to max_score using diminishing returns
    return min(raw, max_score)


def compute_risk(results: dict) -> RiskScore:
    """
    results = {
        "secrets":      list of SecretFinding,
        "git_history":  list of HistoryFinding,
        "cicd":         list of CICDFinding,
        "dependencies": list of DepFinding,
        "misconfig":    list of MisconfigFinding,
        "metadata":     list of ReconFinding,
    }
    """
    module_scores: list[ModuleScore] = []
    weighted_sum = 0.0

    for module, findings in results.items():
        weight = MODULE_WEIGHTS.get(module, 0.05)

        # Normalize findings list (history findings have nested finding)
        flat = []
        for f in findings:
            if hasattr(f, "finding"):          # HistoryFinding
                flat.append(f.finding)
            else:
                flat.append(f)

        critical = sum(1 for f in flat if getattr(f, "severity", "") == "CRITICAL")
        high     = sum(1 for f in flat if getattr(f, "severity", "") == "HIGH")

        score = _module_score(flat)
        weighted_sum += score * weight

        module_scores.append(ModuleScore(
            module=module,
            score=round(score, 1),
            weight=weight,
            findings=len(findings),
            critical=critical,
            high=high,
        ))

    total = min(round(weighted_sum, 1), 100.0)
    grade, level = _grade(total)

    # Top risks (most impactful findings across all modules)
    top_risks = []
    all_findings = []
    for module, findings in results.items():
        for f in findings:
            inner = f.finding if hasattr(f, "finding") else f
            sev   = getattr(inner, "severity", "LOW")
            title = (
                getattr(inner, "title", None) or
                getattr(inner, "pattern_name", None) or
                getattr(inner, "finding_type", "Finding")
            )
            fname = getattr(inner, "file_path", "")
            all_findings.append((SEV_WEIGHT.get(sev, 1), sev, title, fname))

    all_findings.sort(key=lambda x: -x[0])
    seen_titles: set[str] = set()
    for _, sev, title, fname in all_findings[:15]:
        key = title[:60]
        if key not in seen_titles:
            seen_titles.add(key)
            top_risks.append(f"[{sev}] {title}" + (f" ({fname})" if fname else ""))

    return RiskScore(
        total=total,
        grade=grade,
        level=level,
        module_scores=sorted(module_scores, key=lambda x: -x.score),
        top_risks=top_risks[:10],
    )
