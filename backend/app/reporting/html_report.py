"""
HTML Report Generator — Phase 13
==================================
Generates standalone self-contained HTML audit reports from scan results.
Uses inline CSS and JavaScript — no external CDN dependencies.
Sanitizes all code snippets to prevent XSS.
Redacts secrets before rendering.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime
from typing import Optional

from ..models.schemas import ScanResult, Finding
from ..analyzer.ast_visitor import redact_secrets

logger = logging.getLogger(__name__)


def _escape(text: str) -> str:
    """HTML-escape text to prevent XSS."""
    return html.escape(str(text), quote=True)


def _severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#f59e0b",
        "LOW": "#22c55e",
    }
    return colors.get(severity, "#64748b")


def _confidence_color(confidence: str) -> str:
    colors = {
        "HIGH": "#22c55e",
        "MEDIUM": "#f59e0b",
        "LOW": "#94a3b8",
    }
    return colors.get(confidence, "#64748b")


def generate_html_report(scan_result: ScanResult) -> str:
    """
    Generate a complete standalone HTML report from a ScanResult.

    Args:
        scan_result: The completed scan result.

    Returns:
        HTML string (self-contained, no external dependencies).
    """
    stats = scan_result.summary_stats
    project = scan_result.project
    findings = scan_result.findings

    # ── Header Section ────────────────────────────────────────────────────
    html_parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Confused Deputy Report — {_escape(project.project_name)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a; color: #e2e8f0; line-height: 1.6; font-size: 14px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
  h1 {{ font-size: 24px; font-weight: 700; color: #f8fafc; margin-bottom: 4px; }}
  h2 {{ font-size: 18px; font-weight: 600; color: #cbd5e1; margin: 24px 0 12px; }}
  h3 {{ font-size: 14px; font-weight: 600; color: #94a3b8; margin-bottom: 8px; }}
  .subtitle {{ color: #64748b; font-size: 13px; margin-bottom: 32px; }}
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 9999px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;
  }}
  .card {{
    background: #1e293b; border: 1px solid #334155; border-radius: 8px;
    padding: 20px; margin-bottom: 16px;
  }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .stat-card {{
    background: #1e293b; border: 1px solid #334155; border-radius: 8px;
    padding: 16px; text-align: center;
  }}
  .stat-number {{ font-size: 32px; font-weight: 700; }}
  .stat-label {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
  .finding {{
    border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 12px;
    border-left: 4px solid #334155;
  }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
  .finding-title {{ font-size: 15px; font-weight: 600; color: #f8fafc; }}
  .finding-meta {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
  .badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
  pre, code {{
    font-family: 'Courier New', Courier, monospace; font-size: 12px;
    background: #0f172a; border: 1px solid #334155; border-radius: 4px;
    padding: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
    color: #94a3b8;
  }}
  .obs-list {{ list-style: none; padding: 0; }}
  .obs-list li {{ padding: 4px 0 4px 16px; position: relative; color: #cbd5e1; }}
  .obs-list li::before {{ content: '▸'; position: absolute; left: 0; color: #3b82f6; }}
  .remediation {{
    background: #0f2744; border: 1px solid #1d4ed8; border-radius: 6px;
    padding: 12px; margin-top: 12px; color: #93c5fd; font-size: 13px;
  }}
  .limitations {{
    background: #1f1b08; border: 1px solid #78350f; border-radius: 6px;
    padding: 10px; margin-top: 8px; color: #fbbf24; font-size: 12px;
  }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
  th {{ background: #1e293b; color: #94a3b8; font-size: 11px; text-transform: uppercase;
        padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; color: #cbd5e1; }}
  tr:hover td {{ background: #1e293b22; }}
  .header-bar {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid #334155; padding: 16px 24px;
    display: flex; align-items: center; gap: 12px; margin-bottom: 24px;
    border-radius: 8px;
  }}
  .logo {{ font-size: 20px; }}
  .section-divider {{ border: none; border-top: 1px solid #334155; margin: 24px 0; }}
  .watermark {{
    font-size: 11px; color: #334155; text-align: center;
    margin-top: 40px; padding-top: 16px; border-top: 1px solid #334155;
  }}
  @media (max-width: 768px) {{
    .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
  }}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header-bar">
  <span class="logo">🔍</span>
  <div>
    <h1>Confused Deputy API Detector</h1>
    <div class="subtitle">Microservices Authorization Flow Security Report</div>
  </div>
</div>

<!-- Project Info -->
<div class="card">
  <h3>Scan Information</h3>
  <table>
    <tr><td><strong>Project</strong></td><td>{_escape(project.project_name)}</td>
        <td><strong>Scan ID</strong></td><td><code>{_escape(scan_result.scan_id)}</code></td></tr>
    <tr><td><strong>Analysis Time</strong></td><td>{_escape(str(scan_result.scan_duration_seconds or 0))}s</td>
        <td><strong>Engine Version</strong></td><td>{_escape(project.analysis_version)}</td></tr>
    <tr><td><strong>Generated</strong></td><td>{_escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'))}</td>
        <td><strong>Status</strong></td><td>{_escape(project.scan_status)}</td></tr>
  </table>
  <div style="font-size:12px;color:#64748b;margin-top:8px;">
    ⚠️ This report presents <strong>potential</strong> confused deputy risks based on static analysis.
    Findings require manual security review to confirm exploitability.
    Static analysis cannot evaluate runtime authorization policies, service mesh controls, or dynamic URL patterns.
  </div>
</div>

<!-- Summary Stats -->
<h2>Summary Statistics</h2>
<div class="stat-grid">
  <div class="stat-card">
    <div class="stat-number" style="color:#ef4444;">{stats.get('critical', 0) + stats.get('high', 0)}</div>
    <div class="stat-label">High/Critical Findings</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#3b82f6;">{stats.get('total_services', 0)}</div>
    <div class="stat-label">Services Discovered</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#8b5cf6;">{stats.get('total_endpoints', 0)}</div>
    <div class="stat-label">API Endpoints</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#f59e0b;">{stats.get('total_findings', 0)}</div>
    <div class="stat-label">Total Findings</div>
  </div>
</div>

<!-- Services Table -->
<h2>Discovered Services</h2>
<table>
  <thead>
    <tr>
      <th>Service ID</th><th>Name</th><th>Path</th>
      <th>Privilege Level</th><th>Confidence</th><th>Entry Points</th>
    </tr>
  </thead>
  <tbody>
"""]

    for svc in scan_result.services:
        html_parts.append(f"""    <tr>
      <td><code>{_escape(svc.service_id)}</code></td>
      <td>{_escape(svc.name)}</td>
      <td><code>{_escape(svc.path)}</code></td>
      <td><span class="badge" style="background:{_get_privilege_bg(svc.privilege_level)};color:#fff;">{_escape(svc.privilege_level)}</span></td>
      <td>{_escape(svc.confidence)}</td>
      <td><code>{_escape(', '.join(svc.entry_points[:2]))}</code></td>
    </tr>
""")

    html_parts.append("""  </tbody>
</table>

<hr class="section-divider">

<!-- Findings -->
<h2>Security Findings</h2>
""")

    if not findings:
        html_parts.append("""<div class="card" style="text-align:center;color:#22c55e;">
  <div style="font-size:32px;margin-bottom:8px;">✅</div>
  <div style="font-size:16px;font-weight:600;">No Confused Deputy Findings Detected</div>
  <div style="font-size:13px;color:#64748b;margin-top:4px;">
    Static analysis did not identify potential confused deputy authorization risks
    in the analyzed microservices. Manual security review is still recommended.
  </div>
</div>
""")
    else:
        for finding in findings:
            border_color = _severity_color(finding.severity)
            html_parts.append(f"""
<div class="finding" style="border-left-color:{border_color};">
  <div class="finding-header">
    <div>
      <div class="finding-title">{_escape(finding.title)}</div>
      <div class="finding-meta">
        {_escape(finding.finding_id)} · {_escape(finding.source_service_id)} → {_escape(finding.destination_service_id)}
        · File: {_escape(finding.source_file)} Line {finding.line_number}
      </div>
    </div>
    <div class="badges">
      <span class="badge" style="background:{_severity_color(finding.severity)}22;color:{_severity_color(finding.severity)};border:1px solid {_severity_color(finding.severity)}44;">
        {_escape(finding.severity)}
      </span>
      <span class="badge" style="background:{_confidence_color(finding.confidence)}22;color:{_confidence_color(finding.confidence)};border:1px solid {_confidence_color(finding.confidence)}44;">
        CONF: {_escape(finding.confidence)}
      </span>
      <span class="badge" style="background:#1e40af22;color:#60a5fa;border:1px solid #1e40af44;">
        {_escape(finding.rule_id)}
      </span>
    </div>
  </div>

  <h3>Authorization Observations</h3>
  <ul class="obs-list">
""")
            for obs in finding.authorization_observations:
                html_parts.append(f"    <li>{_escape(obs)}</li>\n")

            html_parts.append("""  </ul>

  <h3 style="margin-top:12px;">Privilege Observations</h3>
  <ul class="obs-list">
""")
            for obs in finding.privilege_observations:
                html_parts.append(f"    <li>{_escape(obs)}</li>\n")

            html_parts.append(f"""  </ul>

  <h3 style="margin-top:12px;">Code Evidence</h3>
  <pre>{_escape(redact_secrets(finding.evidence_snippet))}</pre>

  <div class="limitations">
    ⚠️ <strong>Static Analysis Limitations:</strong> {_escape(finding.limitations)}
  </div>

  <div class="remediation">
    🔧 <strong>Recommended Remediation:</strong><br>
    <pre style="background:transparent;border:none;color:#93c5fd;padding:8px 0 0 0;">{_escape(finding.remediation)}</pre>
  </div>
</div>
""")

    # ── Endpoints Table ────────────────────────────────────────────────────
    html_parts.append("""
<hr class="section-divider">
<h2>API Endpoint Inventory</h2>
<table>
  <thead>
    <tr>
      <th>Service</th><th>Method</th><th>Route</th><th>Handler</th>
      <th>Auth</th><th>Sensitive</th><th>File:Line</th>
    </tr>
  </thead>
  <tbody>
""")
    for ep in scan_result.endpoints:
        auth_icon = "✅" if ep.authentication else "❌"
        sens_icon = "⚠️" if ep.is_sensitive else "—"
        html_parts.append(f"""    <tr>
      <td><code>{_escape(ep.service_id)}</code></td>
      <td><span class="badge" style="background:#1e3a5f;color:#60a5fa;">{_escape(ep.method)}</span></td>
      <td><code>{_escape(ep.route)}</code></td>
      <td><code>{_escape(ep.handler)}</code></td>
      <td style="text-align:center;">{auth_icon}</td>
      <td style="text-align:center;">{sens_icon}</td>
      <td><code>{_escape(ep.file)}:{ep.line_start}</code></td>
    </tr>
""")

    html_parts.append("""  </tbody>
</table>

<div class="watermark">
  Generated by Confused Deputy API Detector v1.0.0 · Static Analysis Report ·
  This report presents potential risks based on static evidence and requires human security review.
</div>
</div>
</body>
</html>""")

    return "".join(html_parts)


def _get_privilege_bg(privilege: str) -> str:
    colors = {
        "PUBLIC": "#16a34a", "USER": "#2563eb",
        "SERVICE": "#7c3aed", "ADMIN": "#dc2626",
        "ELEVATED": "#7c3aed", "UNKNOWN": "#475569",
    }
    return colors.get(privilege, "#475569")
