# -*- coding: utf-8 -*-
"""
report_html.py
---------------
Renders a diagnostic_engine.DiagnosticReport as a single self-contained
HTML file — no JS framework, no CDN, no third-party dependency, so it
opens on any machine including an isolated server with no internet
egress. Pure string templating, stdlib only, Python 3.6.8 compatible.
"""

import html as _html_escape_module  # stdlib 'html' module (3.2+, fine on 3.6)

_SEVERITY_COLORS = {
    "CRITICAL": "#7a0d0d",
    "HIGH": "#b3401f",
    "MEDIUM": "#b8860b",
    "LOW": "#3b6ea5",
    "INFO": "#5a5a5a",
}

_RISK_COLORS = {
    "SAFE": "#1e7d32",
    "LOW": "#3b6ea5",
    "MEDIUM": "#b8860b",
    "HIGH": "#b3401f",
}

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
       max-width: 980px; margin: 0 auto; padding: 24px; color: #1a1a1a;
       background: #fafafa; }
h1 { font-size: 22px; margin-bottom: 4px; }
.subtitle { color: #666; margin-bottom: 24px; font-size: 13px; }
.summary { display: flex; gap: 10px; margin-bottom: 28px; flex-wrap: wrap; }
.summary-chip { padding: 6px 12px; border-radius: 6px; color: #fff;
                font-size: 12px; font-weight: 600; }
.finding { background: #fff; border: 1px solid #e0e0e0; border-left: 5px solid;
           border-radius: 6px; padding: 16px 18px; margin-bottom: 14px; }
.finding-title { font-size: 15px; font-weight: 600; margin: 0 0 4px 0; }
.finding-meta { font-size: 11px; color: #888; margin-bottom: 10px;
                 text-transform: uppercase; letter-spacing: 0.03em; }
.finding-explanation { font-size: 13.5px; line-height: 1.55; color: #333;
                        margin-bottom: 10px; }
.evidence-block { background: #f5f5f5; border-radius: 4px; padding: 8px 10px;
                   font-size: 12px; font-family: SFMono-Regular, Consolas,
                   monospace; margin-bottom: 6px; color: #444; }
.rec-block { border-top: 1px dashed #ddd; padding-top: 10px; margin-top: 10px; }
.rec { margin-bottom: 10px; }
.rec-action { font-weight: 600; font-size: 13px; }
.rec-risk { display: inline-block; padding: 2px 8px; border-radius: 10px;
            color: #fff; font-size: 10px; font-weight: 700; margin-left: 8px; }
.rec-syntax { display: block; background: #1e1e1e; color: #d4d4d4;
              font-family: SFMono-Regular, Consolas, monospace; font-size: 12px;
              padding: 8px 10px; border-radius: 4px; margin: 6px 0;
              white-space: pre-wrap; word-break: break-word; }
.rec-rationale { font-size: 12.5px; color: #555; }
.plan-ref { font-size: 11px; color: #999; margin-top: 6px; }
.no-findings { color: #1e7d32; font-weight: 600; padding: 20px; background: #fff;
               border-radius: 6px; border: 1px solid #cde8cf; }
"""


def _esc(text):
    if text is None:
        return ""
    return _html_escape_module.escape(str(text))


def render_report_html(report, database_context=None):
    """report: a diagnostic_engine.DiagnosticReport instance.
    database_context: optional dict from OracleForensicConnection
        .get_database_context(), shown in the subtitle for traceability."""
    parts = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append("<title>SQL Forensic Report — {0}</title>".format(_esc(report.sql_id)))
    parts.append("<style>{0}</style></head><body>".format(_CSS))

    parts.append("<h1>SQL Forensic Diagnosis — {0}</h1>".format(_esc(report.sql_id)))
    subtitle_bits = ["{0} finding(s)".format(len(report.findings))]
    if database_context:
        subtitle_bits.append(_esc(database_context.get("banner", "")))
        subtitle_bits.append("container: {0}".format(_esc(database_context.get("con_name", ""))))
    parts.append("<div class='subtitle'>{0}</div>".format(" &middot; ".join(b for b in subtitle_bits if b)))

    counts = report.to_dict()["findings_by_severity"]
    parts.append("<div class='summary'>")
    for sev, color in _SEVERITY_COLORS.items():
        count = counts.get(sev, 0)
        if count:
            parts.append(
                "<span class='summary-chip' style='background:{0}'>{1}: {2}</span>".format(
                    color, sev, count))
    parts.append("</div>")

    if not report.findings:
        parts.append(
            "<div class='no-findings'>No findings raised by any diagnostic module against "
            "the collected data. Either the SQL is performing within expectations, or the "
            "collected bundle lacked the data a module needed (check collection_errors in "
            "the JSON bundle).</div>"
        )

    for f in report.findings:
        color = _SEVERITY_COLORS.get(f.to_dict()["severity"], "#666")
        parts.append("<div class='finding' style='border-left-color:{0}'>".format(color))
        parts.append("<div class='finding-title'>{0}</div>".format(_esc(f.title)))
        parts.append(
            "<div class='finding-meta'>{0} &middot; {1}</div>".format(
                f.to_dict()["severity"], _esc(f.module)))
        parts.append("<div class='finding-explanation'>{0}</div>".format(_esc(f.explanation)))

        for e in f.evidence:
            parts.append(
                "<div class='evidence-block'>[{0}] {1}</div>".format(_esc(e.source), _esc(e.detail)))

        if f.recommendations:
            parts.append("<div class='rec-block'>")
            for r in f.recommendations:
                risk_color = _RISK_COLORS.get(r.risk, "#666")
                parts.append("<div class='rec'>")
                parts.append(
                    "<span class='rec-action'>{0}</span>"
                    "<span class='rec-risk' style='background:{1}'>{2} RISK</span>".format(
                        _esc(r.action), risk_color, _esc(r.risk)))
                parts.append("<code class='rec-syntax'>{0}</code>".format(_esc(r.syntax)))
                parts.append("<div class='rec-rationale'>{0}</div>".format(_esc(r.rationale)))
                parts.append("</div>")
            parts.append("</div>")

        if f.plan_step_ref:
            parts.append("<div class='plan-ref'>Ref: {0}</div>".format(_esc(f.plan_step_ref)))

        parts.append("</div>")  # .finding

    parts.append("</body></html>")
    return "".join(parts)


def write_report_html(report, out_path, database_context=None):
    html_text = render_report_html(report, database_context=database_context)
    with open(out_path, "w") as fh:
        fh.write(html_text)
    return out_path
