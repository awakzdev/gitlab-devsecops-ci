#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, html, sys
from pathlib import Path
from datetime import datetime

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}

def load_json(p: Path) -> dict:
    if not p or not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def norm_location(loc: dict | None, kind: str) -> str:
    if not loc:
        return ""

    # DAST locations have hostname/path/method/param
    if kind == "DAST":
        host = loc.get("hostname") or ""
        path = loc.get("path") or ""
        method = (loc.get("method") or "").upper()
        param = loc.get("param") or ""
        url = f"{host}{path}" if (host or path) else ""
        extra = f" ({param})" if param else ""
        return " ".join(x for x in [method, url + extra] if x)

    # SAST / Secrets: file + line
    f = loc.get("file") or ""
    line = loc.get("start_line") or loc.get("line") or ""
    return f"{f}:{line}" if f else ""

def extract_cwe(vuln: dict) -> tuple[str, str]:
    for ident in (vuln.get("identifiers") or []):
        name = (ident.get("name") or "").strip()
        typ = (ident.get("type") or "").lower()
        url = ident.get("url") or ""
        if name.upper().startswith("CWE-") or typ == "cwe":
            return name, url
    desc = (vuln.get("description") or "")
    for token in desc.split():
        if token.upper().startswith("CWE-"):
            return token, ""
    return "", ""

def extract_solution(vuln: dict, max_len: int = 180) -> str:
    sol = (vuln.get("solution") or "").strip()
    if not sol:
        sol = (vuln.get("details") or "").strip()
    if not sol:
        return ""
    sol = " ".join(sol.split())
    if len(sol) > max_len:
        sol = sol[: max_len - 1].rstrip() + "…"
    return sol

def extract_rows(report: dict, kind: str):
    rows = []
    for v in report.get("vulnerabilities", []) or []:
        cwe_text, cwe_url = extract_cwe(v)
        rows.append({
            "type": kind,
            "severity": (v.get("severity") or "Unknown").title(),
            "title": v.get("name") or kind,
            "location": norm_location(v.get("location"), kind),
            "ref": (v.get("links") or [{}])[0].get("url", ""),
            "cwe": cwe_text,
            "cwe_url": cwe_url,
            "remediation": extract_solution(v),
        })
    return rows

def sev_key(s: str) -> int:
    return SEV_ORDER.get(s, 5)

def counts_by_sev(rows):
    out = {k: 0 for k in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]}
    for r in rows:
        out[r["severity"]] = out.get(r["severity"], 0) + 1
    return out

def badge(sev: str) -> str:
    colors = {
        "Critical": "#8B0000", "High": "#C0392B", "Medium": "#D68910",
        "Low": "#2471A3", "Info": "#7D3C98", "Unknown": "#7F8C8D",
    }
    c = colors.get(sev, "#7F8C8D")
    return (
        f"<span style='background:{c};color:#fff;padding:2px 8px;"
        f"border-radius:999px;font:12px/18px system-ui'>{html.escape(sev)}</span>"
    )

def table(rows):
    if not rows:
        return "<p style='color:#666'>No findings.</p>"
    head = (
        "<tr>"
        "<th align='left'>Type</th>"
        "<th align='left'>Severity</th>"
        "<th align='left'>Title</th>"
        "<th align='left'>CWE</th>"
        "<th align='left'>Remediation</th>"
        "<th align='left'>Location</th>"
        "<th align='left'>Ref</th>"
        "</tr>"
    )
    body = []
    for r in rows:
        if r["cwe"] and r["cwe_url"]:
            cwe_cell = (
                f"<a href='{html.escape(r['cwe_url'])}' target='_blank' "
                f"rel='noopener'>{html.escape(r['cwe'])}</a>"
            )
        else:
            cwe_cell = html.escape(r["cwe"])
        ref = (
            f"<a href='{html.escape(r['ref'])}' target='_blank' "
            f"rel='noopener'>link</a>"
            if r["ref"] else ""
        )
        body.append(
            "<tr>"
            f"<td>{html.escape(r['type'])}</td>"
            f"<td>{badge(r['severity'])}</td>"
            f"<td>{html.escape(r['title'])}</td>"
            f"<td>{cwe_cell}</td>"
            f"<td style='max-width:520px'>{html.escape(r['remediation'])}</td>"
            f"<td><code>{html.escape(r['location'])}</code></td>"
            f"<td>{ref}</td>"
            "</tr>"
        )
    return (
        "<table style='border-collapse:collapse;width:100%'>"
        "<thead style='border-bottom:1px solid #f5f5f5'>" + head + "</thead>"
        "<tbody>" + "".join(body) + "</tbody>"
        "</table>"
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sast", default="gl-sast-report.json")
    ap.add_argument("--secrets", default="gl-secret-detection-report.json")
    ap.add_argument("--dast", default="gl-dast-report.json")
    ap.add_argument("--out", default="security-report.html")
    ap.add_argument("--project", default="")
    ap.add_argument("--commit", default="")
    args = ap.parse_args()

    sast = load_json(Path(args.sast))
    secd = load_json(Path(args.secrets))
    dast = load_json(Path(args.dast))

    rows = (
        extract_rows(sast, "SAST")
        + extract_rows(secd, "Secrets")
        + extract_rows(dast, "DAST")
    )
    rows.sort(key=lambda r: (r["type"], sev_key(r["severity"]), r["title"]))
    counts = counts_by_sev(rows)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    subtitle_parts = [f"Generated {now}"]
    if args.project:
        subtitle_parts.append(args.project)
    if args.commit:
        subtitle_parts.append(f"@ {args.commit}")

    # DAST crawl graph (optional)
    crawl_graph_html = ""
    crawl_graph_path = Path("gl-dast-crawl-graph.svg")
    if crawl_graph_path.exists():
        crawl_graph_html = (
            "<h2 style='margin:24px 0 8px'>DAST Crawl Graph</h2>"
            "<p style='color:#666'>Graph of URLs discovered during the DAST crawl.</p>"
            "<div style='border:1px solid #eee;padding:12px;border-radius:8px;"
            "background:#fafafa;overflow:auto'>"
            "<img src='gl-dast-crawl-graph.svg' "
            "style='max-width:100%;height:auto' alt='DAST crawl graph'/>"
            "</div>"
        )

    html_out = f"""<!doctype html>
<meta charset="utf-8">
<title>Security Report</title>
<style>
 body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin:24px; }}
 h1 {{ margin: 0 0 4px 0; }}
 .sub {{ color:#666; margin-bottom: 18px; }}
 .pill {{ display:inline-block; margin-right:8px; }}
 .sum {{ margin: 8px 0 24px 0; }}
 table td, table th {{ padding:8px; border-bottom:1px solid #f5f5f5; vertical-align: top; }}
 code {{ background:#f6f8fa; padding:2px 4px; border-radius:4px; }}
</style>
<h1>Security Report</h1>
<div class="sub">{html.escape(" · ".join(subtitle_parts))}</div>

<div class="sum">
  <span class="pill">{badge("Critical")} {counts.get("Critical",0)}</span>
  <span class="pill">{badge("High")} {counts.get("High",0)}</span>
  <span class="pill">{badge("Medium")} {counts.get("Medium",0)}</span>
  <span class="pill">{badge("Low")} {counts.get("Low",0)}</span>
  <span class="pill">{badge("Info")} {counts.get("Info",0)}</span>
</div>

{crawl_graph_html}

<h2 style="margin:24px 0 8px">Findings (SAST, Secrets, DAST)</h2>
{table(rows)}

<hr style="margin-top:24px"/>
<p>Raw inputs:
  <code>{html.escape(args.sast)}</code>,
  <code>{html.escape(args.secrets)}</code>,
  <code>{html.escape(args.dast)}</code>
</p>
"""
    Path(args.out).write_text(html_out, encoding="utf-8")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    sys.exit(main())
