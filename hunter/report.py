"""Report generation: Markdown + self-contained HTML investigative report."""
from __future__ import annotations

import html
import os
import time
from collections import Counter

from .core import Severity
from . import __version__

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEV_COLORS = {
    "CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#b45309",
    "LOW": "#1d4ed8", "INFO": "#374151",
}


def _risk_score(findings) -> float:
    weights = Counter({s.value: 0 for s in SEV_ORDER})
    for f in findings:
        weights[f.severity.value] += 1
    return round(weights["CRITICAL"] * 10 + weights["HIGH"] * 5 +
                 weights["MEDIUM"] * 2 + weights["LOW"] * 0.5, 1)


def dedupe(findings) -> list:
    seen = set()
    out = []
    for f in sorted(findings, key=lambda f: -f.severity.rank):
        key = (f.title, f.url.split("?")[0], f.param)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def build_markdown(target, asset, findings, started) -> str:
    findings = dedupe(findings)
    counts = Counter(f.severity.value for f in findings)
    lines = [
        f"# Bug Hunter Report — {target}",
        "",
        f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(started))} "
        f"(agent v{__version__})",
        f"- **Scan duration:** {time.time() - started:.0f}s",
        f"- **Risk score:** {_risk_score(findings)} / 100",
        f"- **Findings:** {len(findings)} total — "
        + ", ".join(f"{counts[s.value]} {s.value}" for s in SEV_ORDER if counts[s.value]),
        "",
        "## Executive Summary",
        "",
    ]
    crit = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if crit:
        lines.append(f"The agent identified **{len(crit)} high-impact issue(s)**, "
                     f"including {counts['CRITICAL']} critical and {counts['HIGH']} high severity. "
                     "Prioritize remediation in the order listed below.")
    else:
        lines.append("No critical or high severity issues were identified in this pass. "
                     "Lower-severity hardening items are listed below.")
    lines += ["", "## Attack Surface", ""]
    lines.append(f"- Host: `{asset.host}` → IPs: {', '.join(asset.ips) or 'unresolved'}")
    lines.append(f"- Open ports: {', '.join(f'{p} ({s})' for p, s in asset.open_ports) or 'none of the probed set'}")
    lines.append(f"- Technologies: {', '.join(f'{k}: {v}' for k, v in asset.technologies.items()) or 'unknown'}")
    if asset.interesting_paths:
        lines.append(f"- Notable paths: {', '.join(f'`{p}` ({c})' for p, c, _ in asset.interesting_paths[:15])}")
    if asset.emails:
        lines.append(f"- Contacts found: {', '.join(asset.emails[:10])}")
    for note in asset.notes[:10]:
        lines.append(f"- Note: {note}")

    lines += ["", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f.severity.value}] {f.title}",
            "",
            f"- **URL:** {f.url}",
            (f"- **Parameter:** `{f.param}`" if f.param else ""),
            f"- **Confidence:** {f.confidence}" + (f" — CWE {f.cwe}" if f.cwe else ""),
            f"- **Category:** {f.category}",
            "",
            "**Evidence**",
            "",
            "```",
            f.evidence[:1200],
            "```",
            "",
            f"**Description.** {f.description}",
            "",
            f"**Impact.** {f.impact}",
            "",
            f"**Remediation.** {f.remediation}",
            "",
            "---",
            "",
        ]
    lines += ["## Methodology", "",
              "Recon (CT logs, DNS, ports, tech fingerprinting) → crawl (pages, forms, "
              "params, JS endpoints) → passive checks → active injection & access-control "
              "probes → report. All active payloads are non-destructive."]
    return "\n".join(lines)


def build_html(target, asset, findings, started) -> str:
    findings = dedupe(findings)
    counts = Counter(f.severity.value for f in findings)
    e = html.escape

    def finding_html(i, f):
        return f"""
        <div class="finding">
          <div class="fhead">
            <span class="badge" style="background:{SEV_COLORS[f.severity.value]}">{e(f.severity.value)}</span>
            <h3>{i}. {e(f.title)}</h3>
          </div>
          <table>
            <tr><th>URL</th><td><code>{e(f.url)}</code></td></tr>
            {f'<tr><th>Parameter</th><td><code>{e(f.param)}</code></td></tr>' if f.param else ''}
            <tr><th>Confidence</th><td>{e(f.confidence)}{(' — CWE ' + e(f.cwe)) if f.cwe else ''}</td></tr>
            <tr><th>Category</th><td>{e(f.category)}</td></tr>
          </table>
          <h4>Evidence</h4><pre>{e(f.evidence[:1500])}</pre>
          <h4>Description</h4><p>{e(f.description)}</p>
          <h4>Impact</h4><p>{e(f.impact)}</p>
          <h4>Remediation</h4><p>{e(f.remediation)}</p>
        </div>"""

    sev_row = " ".join(
        f'<div class="stat" style="border-color:{SEV_COLORS[s.value]}">'
        f'<div class="num">{counts.get(s.value, 0)}</div><div class="lbl">{s.value}</div></div>'
        for s in SEV_ORDER)
    ports = ", ".join(f"{p} ({s})" for p, s in asset.open_ports) or "none of the probed set"
    techs = ", ".join(f"{e(k)}: {e(v)}" for k, v in asset.technologies.items()) or "unknown"
    paths = ", ".join(f"<code>{e(p)}</code> ({c})" for p, c, _ in asset.interesting_paths[:15])

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Bug Hunter Report — {e(target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111827;line-height:1.55}}
 h1{{border-bottom:3px solid #111827;padding-bottom:.4rem}}
 .stat{{display:inline-block;border:2px solid;border-radius:8px;padding:.5rem 1.2rem;margin-right:.5rem;text-align:center}}
 .num{{font-size:1.6rem;font-weight:700}}
 .badge{{color:#fff;border-radius:4px;padding:.15rem .6rem;font-size:.75rem;font-weight:700;letter-spacing:.05em}}
 .finding{{border:1px solid #d1d5db;border-radius:8px;padding:1rem;margin:1.2rem 0;break-inside:avoid}}
 .fhead{{display:flex;align-items:center;gap:.7rem}}
 table{{border-collapse:collapse;margin:.6rem 0}}
 th,td{{border:1px solid #e5e7eb;padding:.3rem .6rem;font-size:.9rem;text-align:left}}
 th{{background:#f3f4f6;width:130px}}
 pre{{background:#0b1020;color:#e2e8f0;padding:.8rem;border-radius:6px;overflow-x:auto;font-size:.8rem}}
 code{{background:#f3f4f6;padding:.1rem .3rem;border-radius:3px;font-size:.85em}}
 h4{{margin:.8rem 0 .2rem}}
 @media print{{.finding{{page-break-inside:avoid}}}}
</style></head><body>
<h1>🐞 Bug Hunter Report</h1>
<p><b>Target:</b> {e(target)} &nbsp;|&nbsp; <b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp;
<b>Risk score:</b> {_risk_score(findings)}/100 &nbsp;|&nbsp; agent v{__version__}</p>
<div>{sev_row}</div>
<h2>Attack Surface</h2>
<table>
<tr><th>Host</th><td>{e(asset.host)} → {e(', '.join(asset.ips) or 'unresolved')}</td></tr>
<tr><th>Open ports</th><td>{e(ports)}</td></tr>
<tr><th>Technologies</th><td>{techs}</td></tr>
<tr><th>Notable paths</th><td>{paths or '—'}</td></tr>
</table>
<h2>Findings ({len(findings)})</h2>
{''.join(finding_html(i, f) for i, f in enumerate(findings, 1)) or '<p>No findings in this pass.</p>'}
<hr><p style="color:#6b7280;font-size:.85rem">Methodology: recon → crawl → passive checks → active non-destructive probes.
Verify Tentative findings manually before reporting to a program.</p>
</body></html>"""


def write_reports(target, asset, findings, out_dir: str, started: float) -> tuple:
    os.makedirs(out_dir, exist_ok=True)
    slug = target.replace("https://", "").replace("http://", "").replace("/", "_")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    md_path = os.path.join(out_dir, f"report-{slug}-{stamp}.md")
    html_path = os.path.join(out_dir, f"report-{slug}-{stamp}.html")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(target, asset, findings, started))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(target, asset, findings, started))
    return md_path, html_path
