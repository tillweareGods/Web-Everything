"""
modules/report_generator.py — HTML + JSON + Markdown report generator

Design: Dark terminal aesthetic — monospace, amber/red accent on near-black.
Each module gets a collapsible section. Risk score is the hero element.
"""

from __future__ import annotations
import json
import os
import re
from datetime import datetime
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ghrecon — {repo_name}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=IBM+Plex+Sans:wght@300;400;600&display=swap');

  :root {{
    --bg:       #0a0c0f;
    --surface:  #111418;
    --border:   #1e2530;
    --border2:  #2a3340;
    --text:     #c8d0dc;
    --muted:    #5a6578;
    --amber:    #e8a020;
    --amber2:   #f0c040;
    --red:      #e84040;
    --red-dim:  #501818;
    --orange:   #e06020;
    --yellow:   #d0b020;
    --green:    #40c080;
    --blue:     #4080d0;
    --mono:     'JetBrains Mono', 'Fira Code', monospace;
    --sans:     'IBM Plex Sans', system-ui, sans-serif;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* Scanline overlay */
  body::before {{
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px
    );
    pointer-events: none; z-index: 9999;
  }}

  /* ── Header ───────────────────────────────── */
  .header {{
    border-bottom: 1px solid var(--border);
    padding: 32px 48px;
    background: linear-gradient(180deg, #0d1018 0%, var(--bg) 100%);
    position: relative;
    overflow: hidden;
  }}
  .header::after {{
    content: '';
    position: absolute; right: -60px; top: -60px;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(232,160,32,0.06) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-top {{
    display: flex; align-items: flex-start;
    justify-content: space-between; flex-wrap: wrap; gap: 24px;
  }}
  .logo {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--amber);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 12px;
    opacity: 0.7;
  }}
  .repo-name {{
    font-family: var(--mono);
    font-size: 26px;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.02em;
  }}
  .repo-meta {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-top: 8px;
    display: flex; gap: 24px; flex-wrap: wrap;
  }}
  .repo-meta span {{ display: flex; gap: 6px; }}

  /* ── Risk Score Hero ──────────────────────── */
  .score-card {{
    text-align: right;
  }}
  .score-ring {{
    display: inline-flex;
    flex-direction: column; align-items: center;
  }}
  .score-label {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .score-value {{
    font-family: var(--mono);
    font-size: 68px;
    font-weight: 700;
    line-height: 1;
    color: var(--score-color, var(--red));
  }}
  .score-grade {{
    font-family: var(--mono);
    font-size: 14px;
    padding: 3px 12px;
    border: 1px solid currentColor;
    color: var(--score-color, var(--red));
    margin-top: 8px;
    letter-spacing: 0.1em;
  }}
  .score-level {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
    letter-spacing: 0.1em;
  }}

  /* ── Stats Row ────────────────────────────── */
  .stats-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1px;
    background: var(--border);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }}
  .stat-cell {{
    background: var(--surface);
    padding: 20px 24px;
    text-align: center;
  }}
  .stat-num {{
    font-family: var(--mono);
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 6px;
  }}
  .stat-lbl {{
    font-size: 11px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
  }}
  .num-critical {{ color: var(--red); }}
  .num-high     {{ color: var(--orange); }}
  .num-medium   {{ color: var(--yellow); }}
  .num-low      {{ color: var(--blue); }}
  .num-neutral  {{ color: var(--text); }}

  /* ── Layout ───────────────────────────────── */
  .content {{ display: flex; gap: 0; min-height: calc(100vh - 200px); }}

  .sidebar {{
    width: 220px;
    flex-shrink: 0;
    border-right: 1px solid var(--border);
    padding: 24px 0;
    position: sticky; top: 0; height: 100vh;
    overflow-y: auto;
  }}
  .sidebar-title {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--muted);
    padding: 0 20px 12px;
  }}
  .nav-item {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 20px;
    cursor: pointer;
    border-left: 2px solid transparent;
    transition: all 0.15s;
    text-decoration: none;
    color: var(--text);
    font-size: 13px;
  }}
  .nav-item:hover {{ background: var(--surface); border-left-color: var(--amber); }}
  .nav-item.active {{ border-left-color: var(--amber); color: var(--amber2); }}
  .nav-badge {{
    margin-left: auto;
    font-family: var(--mono);
    font-size: 11px;
    background: var(--border2);
    padding: 1px 7px;
    border-radius: 2px;
  }}
  .nav-badge.crit {{ background: var(--red-dim); color: var(--red); }}

  .main {{ flex: 1; padding: 32px 40px; max-width: 1000px; }}

  /* ── Section ──────────────────────────────── */
  .section {{
    margin-bottom: 40px;
    scroll-margin-top: 20px;
  }}
  .section-header {{
    display: flex; align-items: center; gap: 16px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 20px;
    cursor: pointer; user-select: none;
  }}
  .section-icon {{
    font-size: 18px;
    width: 36px; height: 36px;
    display: flex; align-items: center; justify-content: center;
    border: 1px solid var(--border2);
    background: var(--surface);
    font-family: var(--mono);
  }}
  .section-title {{
    font-family: var(--mono);
    font-size: 15px;
    font-weight: 600;
    color: #fff;
    flex: 1;
  }}
  .section-count {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
  }}
  .collapse-btn {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    transition: transform 0.2s;
  }}
  .section-body {{ animation: fadeIn 0.2s ease; }}
  @keyframes fadeIn {{ from {{ opacity:0; transform:translateY(-4px) }} to {{ opacity:1; transform:none }} }}

  /* ── Finding Card ─────────────────────────── */
  .finding {{
    border: 1px solid var(--border);
    margin-bottom: 12px;
    background: var(--surface);
    transition: border-color 0.15s;
  }}
  .finding:hover {{ border-color: var(--border2); }}
  .finding.critical {{ border-left: 3px solid var(--red); }}
  .finding.high     {{ border-left: 3px solid var(--orange); }}
  .finding.medium   {{ border-left: 3px solid var(--yellow); }}
  .finding.low      {{ border-left: 3px solid var(--blue); }}

  .finding-header {{
    display: flex; align-items: flex-start; gap: 12px;
    padding: 14px 16px;
    cursor: pointer;
  }}
  .sev-badge {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.1em;
    padding: 3px 8px;
    flex-shrink: 0;
    margin-top: 2px;
  }}
  .sev-badge.CRITICAL {{ background: var(--red-dim); color: var(--red); border: 1px solid var(--red); }}
  .sev-badge.HIGH     {{ background: #301408; color: var(--orange); border: 1px solid var(--orange); }}
  .sev-badge.MEDIUM   {{ background: #282010; color: var(--yellow); border: 1px solid var(--yellow); }}
  .sev-badge.LOW      {{ background: #101828; color: var(--blue); border: 1px solid var(--blue); }}

  .finding-title {{ font-size: 14px; font-weight: 600; color: #e0e8f0; flex: 1; }}
  .finding-file  {{
    font-family: var(--mono);
    font-size: 11px; color: var(--muted);
    white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis; max-width: 300px;
    margin-top: 4px;
  }}
  .finding-body {{
    padding: 0 16px 16px 16px;
    border-top: 1px solid var(--border);
    display: none;
  }}
  .finding-body.open {{ display: block; }}

  .detail-row {{
    margin-top: 12px;
  }}
  .detail-label {{
    font-family: var(--mono);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: var(--amber);
    margin-bottom: 5px;
  }}
  .detail-text {{
    font-size: 13px; color: var(--text); line-height: 1.5;
  }}
  .code-snippet {{
    font-family: var(--mono);
    font-size: 12px;
    background: #060809;
    border: 1px solid var(--border);
    padding: 10px 14px;
    white-space: pre-wrap;
    word-break: break-all;
    color: #a8d080;
    margin-top: 5px;
    max-height: 120px;
    overflow-y: auto;
  }}
  .exploit-box {{
    background: rgba(232,64,64,0.05);
    border: 1px solid rgba(232,64,64,0.2);
    padding: 10px 14px;
    font-size: 12px;
    font-family: var(--mono);
    color: #e08080;
    margin-top: 5px;
    line-height: 1.5;
  }}
  .remediation-box {{
    background: rgba(64,192,128,0.05);
    border: 1px solid rgba(64,192,128,0.2);
    padding: 10px 14px;
    font-size: 12px;
    color: #80c0a0;
    margin-top: 5px;
    line-height: 1.5;
  }}

  /* ── Top Risks ────────────────────────────── */
  .top-risks {{
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 20px 24px;
    margin-bottom: 32px;
  }}
  .top-risks-title {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--amber);
    margin-bottom: 16px;
  }}
  .risk-item {{
    display: flex; gap: 12px; align-items: flex-start;
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }}
  .risk-item:last-child {{ border-bottom: none; }}
  .risk-idx {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    min-width: 20px;
    margin-top: 2px;
  }}

  /* ── Module Score Bar ─────────────────────── */
  .module-bars {{ margin-bottom: 32px; }}
  .bar-row {{
    display: flex; align-items: center; gap: 16px;
    margin-bottom: 10px;
  }}
  .bar-name {{
    font-family: var(--mono);
    font-size: 12px;
    width: 130px;
    flex-shrink: 0;
    color: var(--muted);
  }}
  .bar-track {{
    flex: 1; height: 6px;
    background: var(--border2); position: relative;
  }}
  .bar-fill {{
    height: 100%; position: absolute; left: 0; top: 0;
    background: var(--amber);
    transition: width 0.5s ease;
  }}
  .bar-fill.critical {{ background: var(--red); }}
  .bar-fill.high     {{ background: var(--orange); }}
  .bar-fill.medium   {{ background: var(--yellow); }}
  .bar-fill.low      {{ background: var(--blue); }}
  .bar-count {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    min-width: 30px;
    text-align: right;
  }}

  /* ── Email / Metadata table ───────────────── */
  .data-table {{
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 12px;
    margin-top: 8px;
  }}
  .data-table th {{
    text-align: left;
    padding: 8px 12px;
    background: var(--border);
    color: var(--amber);
    font-weight: 400;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-size: 10px;
  }}
  .data-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    color: var(--text);
  }}
  .data-table tr:last-child td {{ border-bottom: none; }}

  /* ── Footer ───────────────────────────────── */
  .footer {{
    border-top: 1px solid var(--border);
    padding: 20px 48px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    display: flex; justify-content: space-between;
  }}

  /* ── Responsive ───────────────────────────── */
  @media (max-width: 768px) {{
    .header {{ padding: 20px; }}
    .sidebar {{ display: none; }}
    .main {{ padding: 20px; }}
    .stats-row {{ grid-template-columns: repeat(2, 1fr); }}
  }}

  /* ── Scrollbar ────────────────────────────── */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}
</style>
</head>
<body>

<!-- HEADER -->
<header class="header">
  <div class="header-top">
    <div>
      <div class="logo">⬛ ghrecon // security analysis report</div>
      <div class="repo-name">{repo_name}</div>
      <div class="repo-meta">
        <span>📅 {scan_date}</span>
        <span>🔍 {total_findings} findings</span>
        <span>⏱ {scan_duration}s</span>
        <span>🌿 {commits_scanned} commits scanned</span>
      </div>
    </div>
    <div class="score-card">
      <div class="score-ring">
        <div class="score-label">risk score</div>
        <div class="score-value" style="color:{score_color}">{risk_score}</div>
        <div class="score-grade" style="color:{score_color}">Grade {grade}</div>
        <div class="score-level">{risk_level}</div>
      </div>
    </div>
  </div>
</header>

<!-- STATS ROW -->
<div class="stats-row">
  <div class="stat-cell">
    <div class="stat-num num-critical">{count_critical}</div>
    <div class="stat-lbl">Critical</div>
  </div>
  <div class="stat-cell">
    <div class="stat-num num-high">{count_high}</div>
    <div class="stat-lbl">High</div>
  </div>
  <div class="stat-cell">
    <div class="stat-num num-medium">{count_medium}</div>
    <div class="stat-lbl">Medium</div>
  </div>
  <div class="stat-cell">
    <div class="stat-num num-low">{count_low}</div>
    <div class="stat-lbl">Low</div>
  </div>
  <div class="stat-cell">
    <div class="stat-num num-neutral">{secrets_count}</div>
    <div class="stat-lbl">Secrets Found</div>
  </div>
  <div class="stat-cell">
    <div class="stat-num num-neutral">{history_count}</div>
    <div class="stat-lbl">Historic Leaks</div>
  </div>
  <div class="stat-cell">
    <div class="stat-num num-neutral">{vuln_deps}</div>
    <div class="stat-lbl">Vuln Deps</div>
  </div>
</div>

<!-- CONTENT -->
<div class="content">

  <!-- SIDEBAR -->
  <nav class="sidebar">
    <div class="sidebar-title">modules</div>
    {nav_items}
  </nav>

  <!-- MAIN -->
  <main class="main">

    <!-- Top Risks -->
    {top_risks_html}

    <!-- Module Score Bars -->
    <div class="module-bars">
      <div class="top-risks-title" style="margin-bottom:16px">▸ risk by module</div>
      {module_bars_html}
    </div>

    <!-- Finding Sections -->
    {sections_html}

  </main>
</div>

<footer class="footer">
  <span>ghrecon v2.0 — for authorized security testing only</span>
  <span>{repo_name} // {scan_date}</span>
</footer>

<script>
  // Accordion for finding cards
  document.querySelectorAll('.finding-header').forEach(h => {{
    h.addEventListener('click', () => {{
      const body = h.nextElementSibling;
      if (body) body.classList.toggle('open');
    }});
  }});
  // Section collapse
  document.querySelectorAll('.section-header').forEach(h => {{
    h.addEventListener('click', () => {{
      const body = h.nextElementSibling;
      const btn  = h.querySelector('.collapse-btn');
      if (body) {{
        const hidden = body.style.display === 'none';
        body.style.display = hidden ? '' : 'none';
        if (btn) btn.textContent = hidden ? '▲' : '▼';
      }}
    }});
  }});
  // Sidebar active tracking
  const sections = document.querySelectorAll('.section');
  const navItems = document.querySelectorAll('.nav-item');
  const obs = new IntersectionObserver(entries => {{
    entries.forEach(e => {{
      if (e.isIntersecting) {{
        navItems.forEach(n => n.classList.remove('active'));
        const active = document.querySelector(`.nav-item[href="#${{e.target.id}}"]`);
        if (active) active.classList.add('active');
      }}
    }});
  }}, {{ threshold: 0.3 }});
  sections.forEach(s => obs.observe(s));
</script>
</body>
</html>"""


def _sev_color(severity: str) -> str:
    return {"CRITICAL": "#e84040", "HIGH": "#e06020",
            "MEDIUM": "#d0b020", "LOW": "#4080d0"}.get(severity, "#5a6578")


def _score_color(score: float) -> str:
    if score >= 80: return "#e84040"
    if score >= 60: return "#e06020"
    if score >= 40: return "#d0b020"
    if score >= 20: return "#4080d0"
    return "#40c080"


def _escape(text: str) -> str:
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _finding_card(title: str, severity: str, file_path: str,
                  description: str = "", snippet: str = "",
                  exploit: str = "", remediation: str = "",
                  extra_rows: list[tuple[str, str]] = None) -> str:
    sev_cls = severity.upper()
    html = f"""
    <div class="finding {sev_cls.lower()}">
      <div class="finding-header">
        <span class="sev-badge {sev_cls}">{sev_cls}</span>
        <div>
          <div class="finding-title">{_escape(title)}</div>
          <div class="finding-file">{_escape(file_path)}</div>
        </div>
      </div>
      <div class="finding-body">"""

    if description:
        html += f"""
        <div class="detail-row">
          <div class="detail-label">description</div>
          <div class="detail-text">{_escape(description)}</div>
        </div>"""

    if snippet:
        html += f"""
        <div class="detail-row">
          <div class="detail-label">code snippet</div>
          <div class="code-snippet">{_escape(snippet[:400])}</div>
        </div>"""

    if exploit:
        html += f"""
        <div class="detail-row">
          <div class="detail-label">⚡ exploit path</div>
          <div class="exploit-box">{_escape(exploit)}</div>
        </div>"""

    if remediation:
        html += f"""
        <div class="detail-row">
          <div class="detail-label">✓ remediation</div>
          <div class="remediation-box">{_escape(remediation)}</div>
        </div>"""

    for label, value in (extra_rows or []):
        html += f"""
        <div class="detail-row">
          <div class="detail-label">{_escape(label)}</div>
          <div class="detail-text">{_escape(value)}</div>
        </div>"""

    html += "</div></div>"
    return html


def _section(section_id: str, icon: str, title: str, findings_html: str, count: int) -> str:
    badge_cls = "crit" if count > 0 else ""
    return f"""
    <div class="section" id="{section_id}">
      <div class="section-header">
        <div class="section-icon">{icon}</div>
        <div class="section-title">{title}</div>
        <div class="section-count">{count} findings</div>
        <div class="collapse-btn">▲</div>
      </div>
      <div class="section-body">
        {findings_html if findings_html else '<p style="color:var(--muted);font-size:13px;padding:12px 0">No findings in this category.</p>'}
      </div>
    </div>"""


class ReportGenerator:
    def __init__(self, repo_name: str, output_dir: str):
        self.repo_name  = repo_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: dict, risk_score, scan_duration: float,
                 metadata_summary: dict = None) -> dict[str, str]:
        """
        results keys: secrets, git_history, cicd, dependencies, misconfig, metadata
        """
        paths = {}

        # ── JSON export ───────────────────────────────────────────────────────
        json_data = self._build_json(results, risk_score, scan_duration, metadata_summary)
        json_path = self.output_dir / f"{self._safe_name()}_report.json"
        json_path.write_text(json.dumps(json_data, indent=2, default=str))
        paths["json"] = str(json_path)

        # ── HTML report ───────────────────────────────────────────────────────
        html_path = self.output_dir / f"{self._safe_name()}_report.html"
        html_path.write_text(self._build_html(results, risk_score, scan_duration, metadata_summary))
        paths["html"] = str(html_path)

        # ── Markdown summary ──────────────────────────────────────────────────
        md_path = self.output_dir / f"{self._safe_name()}_summary.md"
        md_path.write_text(self._build_markdown(results, risk_score, scan_duration))
        paths["markdown"] = str(md_path)

        return paths

    def _safe_name(self) -> str:
        # Extract just repo name from GitHub URLs like https://github.com/owner/repo
        name = self.repo_name
        if "/" in name:
            name = name.rstrip("/").split("/")[-1]
        return re.sub(r"[^a-zA-Z0-9_\-]", "_", name)[:60]

    def _count_severity(self, results: dict) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for module, findings in results.items():
            for f in findings:
                inner = f.finding if hasattr(f, "finding") else f
                sev = getattr(inner, "severity", "LOW").upper()
                counts[sev] = counts.get(sev, 0) + 1
        return counts

    # ── HTML builder ──────────────────────────────────────────────────────────

    def _build_html(self, results: dict, risk_score, scan_duration: float,
                    metadata_summary: dict = None) -> str:
        counts = self._count_severity(results)
        total  = sum(counts.values())
        sc     = _score_color(risk_score.total)

        commits_scanned = 0
        if hasattr(risk_score, 'module_scores'):
            pass
        history_summary = {}
        if results.get("git_history"):
            commits_scanned = getattr(results["git_history"][0], "commit", None)
            # Try to get from first history finding
            try:
                from modules.git_history import HistoryFinding
                history_findings = [f for f in results["git_history"] if isinstance(f, HistoryFinding)]
                commits_scanned = "unknown"
            except ImportError:
                commits_scanned = "unknown"

        # ── NAV items ─────────────────────────────────────────────────────────
        module_meta = [
            ("secrets",      "🔑", "Secrets",       results.get("secrets", [])),
            ("history",      "📜", "Git History",   results.get("git_history", [])),
            ("cicd",         "⚙️",  "CI/CD",         results.get("cicd", [])),
            ("dependencies", "📦", "Dependencies",  results.get("dependencies", [])),
            ("misconfig",    "🔧", "Misconfig",     results.get("misconfig", [])),
            ("metadata",     "👤", "Metadata",      results.get("metadata", [])),
        ]
        nav_items = ""
        for mid, icon, name, findings in module_meta:
            cnt  = len(findings)
            has_crit = any(
                getattr(f.finding if hasattr(f, "finding") else f, "severity", "") == "CRITICAL"
                for f in findings
            )
            badge_cls = "crit" if has_crit else ""
            nav_items += f"""<a class="nav-item" href="#{mid}">{icon} {name}<span class="nav-badge {badge_cls}">{cnt}</span></a>"""

        # ── Top risks ─────────────────────────────────────────────────────────
        top_risks_html = '<div class="top-risks"><div class="top-risks-title">▸ top risks</div>'
        for i, risk in enumerate(risk_score.top_risks[:10], 1):
            sev_m = re.match(r"\[(\w+)\]", risk)
            sev   = sev_m.group(1) if sev_m else "LOW"
            top_risks_html += f"""
            <div class="risk-item">
              <span class="risk-idx">0{i}</span>
              <span class="sev-badge {sev}" style="margin-top:0">{sev}</span>
              <span>{_escape(risk[len(sev)+3:].strip())}</span>
            </div>"""
        top_risks_html += "</div>"

        # ── Module bars ───────────────────────────────────────────────────────
        module_bars = ""
        for ms in risk_score.module_scores:
            bar_pct = min(ms.score, 100)
            bar_cls = ("critical" if ms.score >= 80 else
                       "high"     if ms.score >= 50 else
                       "medium"   if ms.score >= 25 else "low")
            module_bars += f"""
            <div class="bar-row">
              <div class="bar-name">{ms.module}</div>
              <div class="bar-track"><div class="bar-fill {bar_cls}" style="width:{bar_pct}%"></div></div>
              <div class="bar-count">{ms.findings}</div>
            </div>"""

        # ── Build each section ────────────────────────────────────────────────
        sections_html = ""

        # Secrets section
        secrets_html = ""
        for f in sorted(results.get("secrets", []),
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(
                            getattr(x,"severity","LOW") if getattr(x,"severity","LOW") in
                            ["CRITICAL","HIGH","MEDIUM","LOW"] else "LOW")):
            secrets_html += _finding_card(
                title=f.pattern_name,
                severity=f.severity,
                file_path=f"{f.file_path}:{f.line_number}",
                description=f"Secret matched by: {f.method} | Confidence: {f.confidence}",
                snippet=f.line_content,
                exploit="Extracted credential → direct API/service access → privilege escalation",
                remediation="Rotate the secret immediately. Remove from git history using BFG Repo Cleaner.",
                extra_rows=[("match (masked)", f.masked_secret())] if hasattr(f, "masked_secret") else [],
            )
        sections_html += _section("secrets", "🔑", "Secrets & Sensitive Data", secrets_html, len(results.get("secrets", [])))

        # Git history section
        history_html = ""
        for hf in results.get("git_history", []):
            f = hf.finding
            status_icon = "🔴 STILL PRESENT" if hf.status == "still_present" else "🟡 HISTORIC"
            history_html += _finding_card(
                title=f"{f.pattern_name} [{status_icon}]",
                severity=f.severity,
                file_path=f"commit:{hf.commit.short_hash} ({hf.commit.date[:10]})",
                description=hf.risk_note,
                snippet=f.line_content,
                exploit=f"git show {hf.commit.hash} → extract credential → test if still active",
                remediation="Run: git filter-repo --invert-paths --path <file> to purge from history.",
                extra_rows=[
                    ("commit message", hf.commit.message[:80]),
                    ("author", f"{hf.commit.author} <{hf.commit.email}>"),
                ],
            )
        sections_html += _section("history", "📜", "Git History Analysis", history_html, len(results.get("git_history", [])))

        # CI/CD section
        cicd_html = ""
        for f in sorted(results.get("cicd", []),
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity)):
            cicd_html += _finding_card(
                title=f.title, severity=f.severity,
                file_path=f"{f.file_path}:{f.line_number}",
                description=f.description, snippet=f.code_snippet,
                exploit=f.exploit_path, remediation=f.remediation,
                extra_rows=[("type", f.finding_type), ("cwe", f.cwe)] if f.cwe else [("type", f.finding_type)],
            )
        sections_html += _section("cicd", "⚙️", "CI/CD Pipeline", cicd_html, len(results.get("cicd", [])))

        # Dependencies section
        dep_html = ""
        for f in sorted(results.get("dependencies", []),
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW"] else "LOW")):
            vuln_details = ""
            if f.vulns:
                vuln_details = " | ".join(f"{v.vuln_id} ({v.severity})" for v in f.vulns[:5])
            dep_html += _finding_card(
                title=f.title, severity=f.severity,
                file_path=f"{f.file_path}",
                description=f.description,
                exploit=f.exploit_path, remediation=f.remediation,
                extra_rows=[
                    ("package", f"{f.package_name} @ {f.version} ({f.ecosystem})"),
                    ("vulnerabilities", vuln_details),
                ] if vuln_details else [("package", f"{f.package_name} @ {f.version} ({f.ecosystem})")],
            )
        sections_html += _section("dependencies", "📦", "Dependencies & Supply Chain", dep_html, len(results.get("dependencies", [])))

        # Misconfig section
        mis_html = ""
        for f in sorted(results.get("misconfig", []),
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW"] else "LOW")):
            mis_html += _finding_card(
                title=f.title, severity=f.severity,
                file_path=f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path,
                description=f.description, snippet=f.code_snippet,
                exploit=f.exploit_path, remediation=f.remediation,
                extra_rows=[("type", f.finding_type)],
            )
        sections_html += _section("misconfig", "🔧", "Misconfiguration", mis_html, len(results.get("misconfig", [])))

        # Metadata / Recon section
        meta_html = ""
        for f in results.get("metadata", []):
            data_str = ""
            if isinstance(f.data, dict):
                if "emails" in f.data:
                    rows = "".join(
                        f"<tr><td>{_escape(e.get('login',''))}</td><td>{_escape(e.get('email',''))}</td>"
                        f"<td>{e.get('commits',0)}</td></tr>"
                        for e in f.data["emails"][:10]
                    )
                    data_str = f"<table class='data-table'><tr><th>login</th><th>email</th><th>commits</th></tr>{rows}</table>"
                elif "branches" in f.data:
                    data_str = " • ".join(_escape(b) for b in f.data["branches"][:10])
                elif "issues" in f.data:
                    rows = "".join(
                        f"<tr><td>#{_escape(str(i.get('number','')))}</td>"
                        f"<td><a href='{_escape(i.get('url',''))}' style='color:var(--amber)'>{_escape(i.get('title',''))}</a></td></tr>"
                        for i in f.data["issues"][:8]
                    )
                    data_str = f"<table class='data-table'><tr><th>#</th><th>title</th></tr>{rows}</table>"

            meta_html += f"""
            <div class="finding {f.severity.lower()}">
              <div class="finding-header">
                <span class="sev-badge {f.severity}">{f.severity}</span>
                <div>
                  <div class="finding-title">{_escape(f.title)}</div>
                  <div class="finding-file">{_escape(f.finding_type)}</div>
                </div>
              </div>
              <div class="finding-body">
                <div class="detail-row"><div class="detail-label">description</div>
                  <div class="detail-text">{_escape(f.description)}</div></div>
                {f'<div class="detail-row"><div class="detail-label">data</div><div class="detail-text">{data_str}</div></div>' if data_str else ''}
                {f'<div class="detail-row"><div class="detail-label">⚡ exploit path</div><div class="exploit-box">{_escape(f.exploit_path)}</div></div>' if f.exploit_path else ''}
              </div>
            </div>"""
        sections_html += _section("metadata", "👤", "Metadata & Recon", meta_html, len(results.get("metadata", [])))

        # ── Fill template ─────────────────────────────────────────────────────
        return HTML_TEMPLATE.format(
            repo_name=_escape(self.repo_name),
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
            scan_duration=f"{scan_duration:.1f}",
            total_findings=total,
            commits_scanned=commits_scanned,
            risk_score=f"{risk_score.total:.0f}",
            grade=risk_score.grade,
            risk_level=risk_score.level,
            score_color=sc,
            count_critical=counts["CRITICAL"],
            count_high=counts["HIGH"],
            count_medium=counts["MEDIUM"],
            count_low=counts["LOW"],
            secrets_count=len(results.get("secrets", [])),
            history_count=len(results.get("git_history", [])),
            vuln_deps=sum(1 for f in results.get("dependencies", []) if f.finding_type == "KNOWN_VULN"),
            nav_items=nav_items,
            top_risks_html=top_risks_html,
            module_bars_html=module_bars,
            sections_html=sections_html,
        )

    # ── JSON export ───────────────────────────────────────────────────────────

    def _build_json(self, results: dict, risk_score, scan_duration: float,
                    metadata_summary: dict = None) -> dict:
        def flatten(findings):
            out = []
            for f in findings:
                try:
                    inner = f.finding if hasattr(f, "finding") else f
                    d = inner.to_dict() if hasattr(inner, "to_dict") else {}
                    if hasattr(f, "status"):
                        d["diff_status"] = f.status
                        d["risk_note"]   = f.risk_note
                    out.append(d)
                except Exception:
                    pass
            return out

        counts = self._count_severity(results)
        return {
            "meta": {
                "repo":     self.repo_name,
                "scanned":  datetime.now().isoformat(),
                "duration": round(scan_duration, 2),
            },
            "risk": {
                "score":   risk_score.total,
                "grade":   risk_score.grade,
                "level":   risk_score.level,
                "top_risks": risk_score.top_risks,
            },
            "counts": counts,
            "metadata": metadata_summary or {},
            "findings": {
                "secrets":      flatten(results.get("secrets", [])),
                "git_history":  flatten(results.get("git_history", [])),
                "cicd":         flatten(results.get("cicd", [])),
                "dependencies": flatten(results.get("dependencies", [])),
                "misconfig":    flatten(results.get("misconfig", [])),
                "metadata":     flatten(results.get("metadata", [])),
            },
        }

    # ── Markdown summary ──────────────────────────────────────────────────────

    def _build_markdown(self, results: dict, risk_score, scan_duration: float) -> str:
        counts = self._count_severity(results)
        total  = sum(counts.values())

        lines = [
            f"# ghrecon Security Report: {self.repo_name}",
            f"",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Risk Score:** {risk_score.total:.0f}/100 — Grade {risk_score.grade} ({risk_score.level})  ",
            f"**Duration:** {scan_duration:.1f}s",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {counts['CRITICAL']} |",
            f"| 🟠 High     | {counts['HIGH']} |",
            f"| 🟡 Medium   | {counts['MEDIUM']} |",
            f"| 🔵 Low      | {counts['LOW']} |",
            f"| **Total**   | **{total}** |",
            f"",
            f"## Top Risks",
            f"",
        ]
        for i, risk in enumerate(risk_score.top_risks[:10], 1):
            lines.append(f"{i}. {risk}")

        for module_name, label in [
            ("secrets", "Secrets"),
            ("git_history", "Git History"),
            ("cicd", "CI/CD"),
            ("dependencies", "Dependencies"),
            ("misconfig", "Misconfig"),
        ]:
            findings = results.get(module_name, [])
            if not findings:
                continue
            lines += [f"", f"## {label} ({len(findings)} findings)", f""]
            for f in findings[:20]:
                inner = f.finding if hasattr(f, "finding") else f
                sev   = getattr(inner, "severity", "?")
                title = getattr(inner, "title", None) or getattr(inner, "pattern_name", "Finding")
                fpath = getattr(inner, "file_path", "")
                lines.append(f"- **[{sev}]** {title}  \n  `{fpath}`")

        lines += ["", "---", "_Generated by ghrecon — for authorized security testing only_"]
        return "\n".join(lines)
