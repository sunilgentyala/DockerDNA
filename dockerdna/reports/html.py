"""Interactive HTML report generator."""

from __future__ import annotations

import html as html_lib
from typing import Any


_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
}

_STATUS_COLORS = {
    "PASS":        "#16a34a",
    "FAIL":        "#dc2626",
    "NOT_CHECKED": "#6b7280",
}


def _esc(text: Any) -> str:
    return html_lib.escape(str(text) if text is not None else "")


def _badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.75rem;font-weight:bold;">'
        f'{_esc(severity)}</span>'
    )


def _status_badge(status: str) -> str:
    color = _STATUS_COLORS.get(status, "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.75rem;font-weight:bold;">'
        f'{_esc(status)}</span>'
    )


def _finding_rows(findings: list[Any], cols: list[tuple[str, str]]) -> str:
    if not findings:
        return '<tr><td colspan="100" style="text-align:center;color:#6b7280;">No findings</td></tr>'
    rows = []
    for f in findings:
        cells = []
        for attr, kind in cols:
            val = getattr(f, attr, "")
            if kind == "badge":
                cells.append(f"<td>{_badge(str(val))}</td>")
            elif kind == "code":
                cells.append(f'<td><code>{_esc(val)}</code></td>')
            else:
                cells.append(f"<td>{_esc(val)}</td>")
        rows.append(f"<tr>{''.join(cells)}</tr>")
    return "\n".join(rows)


def generate_html(report: dict) -> str:
    summary = report.get("summary", {})
    risk     = summary.get("risk_score", 0)
    comp     = summary.get("compliance_score", 0)
    total    = summary.get("total_findings", 0)
    by_sev   = summary.get("by_severity", {})

    risk_color = (
        "#dc2626" if risk >= 70 else
        "#ea580c" if risk >= 40 else
        "#d97706" if risk >= 20 else
        "#16a34a"
    )

    meta = report.get("metadata", {})

    # ------------------------------------------------------------------ #
    # Findings tables
    # ------------------------------------------------------------------ #

    def _table(title: str, findings: list[dict], columns: list[tuple[str, str, str]]) -> str:
        headers = "".join(f"<th>{h}</th>" for h, _, _ in columns)
        rows_html = ""
        if not findings:
            rows_html = f'<tr><td colspan="{len(columns)}" style="text-align:center;color:#6b7280;">No findings</td></tr>'
        else:
            for f in findings:
                cells = []
                for _, key, kind in columns:
                    val = f.get(key, "")
                    if kind == "badge":
                        cells.append(f"<td>{_badge(str(val))}</td>")
                    elif kind == "code":
                        cells.append(f'<td><code style="font-size:0.8rem;">{_esc(val)}</code></td>')
                    else:
                        cells.append(f"<td>{_esc(val)}</td>")
                rows_html += f"<tr>{''.join(cells)}</tr>\n"

        return f"""
        <h3>{_esc(title)}</h3>
        <div style="overflow-x:auto;">
        <table>
          <thead><tr>{headers}</tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
        </div>"""

    df_findings  = report.get("findings", {}).get("dockerfile", [])
    cf_findings  = report.get("findings", {}).get("compose", [])
    sec_findings = report.get("findings", {}).get("secrets", [])
    sc_findings  = report.get("findings", {}).get("supply_chain", [])

    df_table = _table("Dockerfile Findings", df_findings, [
        ("Severity",    "severity",    "badge"),
        ("Line",        "line",        "text"),
        ("CIS ID",      "cis_id",      "code"),
        ("Title",       "title",       "text"),
        ("Detail",      "detail",      "text"),
        ("Stage",       "stage",       "text"),
    ])

    cf_table = _table("docker-compose.yml Findings", cf_findings, [
        ("Severity",  "severity", "badge"),
        ("Service",   "service",  "text"),
        ("CIS ID",    "cis_id",   "code"),
        ("Title",     "title",    "text"),
        ("Detail",    "detail",   "text"),
    ])

    sec_table = _table("Secrets Detected", sec_findings, [
        ("Severity",    "severity",         "badge"),
        ("File",        "file",             "text"),
        ("Line",        "line",             "text"),
        ("CIS ID",      "cis_id",           "code"),
        ("Type",        "type",             "text"),
        ("Method",      "detection",        "text"),
        ("Value",       "matched_value",    "code"),
    ])

    sc_table = _table("Supply Chain Analysis", sc_findings, [
        ("Severity",     "severity",    "badge"),
        ("Image",        "image",       "code"),
        ("Stage",        "stage",       "text"),
        ("Risk Score",   "risk_score",  "text"),
        ("Factors",      "factors",     "text"),
    ])

    # Compliance table
    compliance = report.get("compliance", {})
    c_summary  = compliance.get("summary", {})
    c_controls = compliance.get("controls", [])
    c_rows = ""
    for ctrl in c_controls:
        c_rows += (
            f"<tr>"
            f"<td><code>{_esc(ctrl.get('id',''))}</code></td>"
            f"<td>{_esc(ctrl.get('title',''))}</td>"
            f"<td>{_status_badge(ctrl.get('status',''))}</td>"
            f"<td>{_badge(ctrl.get('severity',''))}</td>"
            f"<td>{_esc(ctrl.get('findings_count',''))}</td>"
            f"</tr>\n"
        )
    comp_table = f"""
    <h3>CIS Docker Benchmark v1.6 Compliance</h3>
    <p>Controls passed: {c_summary.get('passed',0)} /
       {c_summary.get('total_controls',0)} &nbsp;|&nbsp;
       Score: <strong>{c_summary.get('compliance_score',0):.1f}%</strong></p>
    <div style="overflow-x:auto;">
    <table>
      <thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Findings</th></tr></thead>
      <tbody>{c_rows}</tbody>
    </table>
    </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DockerDNA Security Report</title>
  <style>
    body {{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f9fafb;color:#111827;}}
    .header {{background:#1e293b;color:#f8fafc;padding:24px 40px;}}
    .header h1 {{margin:0;font-size:1.8rem;}}
    .header p  {{margin:4px 0 0;opacity:.7;}}
    .container {{max-width:1200px;margin:0 auto;padding:24px 40px;}}
    .cards {{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:32px;}}
    .card {{background:#fff;border-radius:8px;padding:20px 28px;box-shadow:0 1px 3px rgba(0,0,0,.1);min-width:160px;}}
    .card .value {{font-size:2.2rem;font-weight:700;}}
    .card .label {{font-size:.85rem;color:#6b7280;margin-top:4px;}}
    table {{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;
            box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:32px;}}
    th {{background:#1e293b;color:#f8fafc;padding:10px 14px;text-align:left;font-size:.85rem;}}
    td {{padding:9px 14px;border-bottom:1px solid #e5e7eb;font-size:.9rem;vertical-align:top;}}
    tr:hover td {{background:#f9fafb;}}
    h3 {{margin:32px 0 12px;color:#1e293b;}}
    code {{background:#f1f5f9;padding:2px 6px;border-radius:3px;font-size:.85rem;}}
  </style>
</head>
<body>
  <div class="header">
    <h1>&#x1F9EC; DockerDNA Security Report</h1>
    <p>Generated: {_esc(report.get('timestamp',''))} &nbsp;|&nbsp; {_esc(meta.get('scanned_path',''))}</p>
  </div>
  <div class="container">

    <div class="cards">
      <div class="card">
        <div class="value" style="color:{risk_color};">{risk}</div>
        <div class="label">Risk Score (0-100)</div>
      </div>
      <div class="card">
        <div class="value" style="color:#2563eb;">{comp:.0f}%</div>
        <div class="label">CIS Compliance</div>
      </div>
      <div class="card">
        <div class="value" style="color:#dc2626;">{by_sev.get('CRITICAL',0)}</div>
        <div class="label">Critical</div>
      </div>
      <div class="card">
        <div class="value" style="color:#ea580c;">{by_sev.get('HIGH',0)}</div>
        <div class="label">High</div>
      </div>
      <div class="card">
        <div class="value" style="color:#d97706;">{by_sev.get('MEDIUM',0)}</div>
        <div class="label">Medium</div>
      </div>
      <div class="card">
        <div class="value" style="color:#65a30d;">{by_sev.get('LOW',0)}</div>
        <div class="label">Low</div>
      </div>
      <div class="card">
        <div class="value">{total}</div>
        <div class="label">Total Findings</div>
      </div>
    </div>

    {df_table}
    {cf_table}
    {sec_table}
    {sc_table}
    {comp_table}

  </div>
</body>
</html>"""
