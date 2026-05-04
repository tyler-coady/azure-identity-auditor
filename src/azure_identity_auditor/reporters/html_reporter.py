"""Self-contained HTML reporter (no external template dependencies)."""

from __future__ import annotations

import html as html_lib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from string import Template

from ..models import Finding, ScanResult, Severity

_SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}

_HTML_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Managed Identity Audit Report</title>
<style>
  :root{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#e2e8f0;--dim:#94a3b8}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:2rem}
  h1{font-size:1.5rem;margin-bottom:.25rem}
  .meta{color:var(--dim);font-size:.85rem;margin-bottom:2rem}
  .summary{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:.5rem;padding:1rem 1.5rem;min-width:120px;text-align:center}
  .card .count{font-size:2rem;font-weight:700}
  .card .label{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
  table{width:100%;border-collapse:collapse;font-size:.875rem}
  th{text-align:left;padding:.75rem 1rem;background:var(--surface);color:var(--dim);font-weight:500;border-bottom:2px solid var(--border);cursor:pointer;user-select:none}
  th:hover{color:var(--text)}
  td{padding:.75rem 1rem;border-bottom:1px solid var(--border);vertical-align:top}
  tr:hover td{background:var(--surface)}
  .badge{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.75rem;font-weight:600;color:#fff}
  .detail-row td{background:var(--surface);font-size:.8rem;color:var(--dim);padding:.5rem 1rem 1rem 3rem}
  .detail-row pre{white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:.8rem;margin-top:.5rem;background:var(--bg);padding:.75rem;border-radius:.25rem;border:1px solid var(--border)}
  .expand-btn{background:none;border:none;color:var(--dim);cursor:pointer;font-size:.75rem;padding:0;margin-left:.5rem}
  .expand-btn:hover{color:var(--text)}
  .filters{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}
  .filter-btn{padding:.25rem .75rem;border-radius:1rem;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;font-size:.8rem}
  .filter-btn.active{border-color:#60a5fa;color:#60a5fa}
  input[type=search]{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.35rem .75rem;border-radius:.375rem;font-size:.875rem;width:280px}
  input[type=search]::placeholder{color:var(--dim)}
  .toolbar{display:flex;align-items:center;gap:1rem;margin-bottom:.75rem;flex-wrap:wrap}
</style>
</head>
<body>
<h1>Azure Managed Identity Audit Report</h1>
<div class="meta">Generated $generated_at&nbsp;&nbsp;·&nbsp;&nbsp;$total_findings finding(s)$sub_note</div>

<div class="summary">
$summary_cards
</div>

<div class="toolbar">
  <input type="search" id="search" placeholder="Filter by resource, rule, title…" oninput="filterTable()">
  <div class="filters" id="sev-filters">
    <button class="filter-btn active" onclick="toggleSev(this,'ALL')">All</button>
$sev_filter_buttons
  </div>
</div>

<table id="findings-table">
<thead>
<tr>
  <th onclick="sortTable(0)">ID ⇅</th>
  <th onclick="sortTable(1)">Severity ⇅</th>
  <th onclick="sortTable(2)">Rule</th>
  <th onclick="sortTable(3)">Resource</th>
  <th>Title</th>
  <th>Source</th>
</tr>
</thead>
<tbody>
$table_rows
</tbody>
</table>

<script>
const SEV_WEIGHT={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};
let activeSev='ALL';
let sortCol=-1,sortAsc=true;

function badge(sev){
  const colors={CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#2563eb',INFO:'#6b7280'};
  return '<span class="badge" style="background:' + (colors[sev]||'#6b7280') + '">' + sev + '</span>';
}

function toggleSev(btn,sev){
  document.querySelectorAll('#sev-filters .filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  activeSev=sev;
  filterTable();
}

function filterTable(){
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#findings-table tbody tr.data-row').forEach(row=>{
    const sev=row.dataset.sev;
    const text=row.textContent.toLowerCase();
    const sevMatch=activeSev==='ALL'||sev===activeSev;
    const txtMatch=!q||text.includes(q);
    const detail=document.getElementById('detail-'+row.dataset.id);
    row.style.display=sevMatch&&txtMatch?'':'none';
    if(detail)detail.style.display='none';
  });
}

function toggleDetail(id){
  const row=document.getElementById('detail-'+id);
  row.style.display=row.style.display==='none'?'':'none';
}

function sortTable(col){
  const tbody=document.querySelector('#findings-table tbody');
  const rows=[...tbody.querySelectorAll('tr.data-row')];
  if(sortCol===col){sortAsc=!sortAsc;}else{sortCol=col;sortAsc=true;}
  rows.sort((a,b)=>{
    let va=a.cells[col].textContent.trim();
    let vb=b.cells[col].textContent.trim();
    if(col===1){va=SEV_WEIGHT[va]||0;vb=SEV_WEIGHT[vb]||0;return sortAsc?vb-va:va-vb;}
    return sortAsc?va.localeCompare(vb):vb.localeCompare(va);
  });
  rows.forEach(r=>{
    tbody.appendChild(r);
    const d=document.getElementById('detail-'+r.dataset.id);
    if(d)tbody.appendChild(d);
  });
}
</script>
</body>
</html>"""
)


class HtmlReporter:
    def write(self, result: ScanResult, output_dir: Path | None = None) -> str:
        findings = sorted(result.findings, key=lambda f: f.severity.weight, reverse=True)
        counts = Counter(f.severity.value for f in findings)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        summary_cards = "\n".join(
            f'  <div class="card"><div class="count" style="color:{_SEVERITY_COLOR[sev]}">'
            f'{counts.get(sev, 0)}</div><div class="label">{sev}</div></div>'
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )

        sev_buttons = "\n".join(
            f'    <button class="filter-btn" onclick="toggleSev(this,\'{sev}\')">{sev}</button>'
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if counts.get(sev, 0) > 0
        )

        rows: list[str] = []
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity.value, "#6b7280")
            resource_short = html_lib.escape(f.resource_id.split("/")[-1] or f.resource_id)
            details_html = _build_details(f)
            rows.append(
                f'<tr class="data-row" data-sev="{f.severity.value}" data-id="{f.id}">'
                f'<td><code>{f.id}</code></td>'
                f'<td><span class="badge" style="background:{color}">{f.severity.value}</span></td>'
                f'<td><code>{f.rule_id}</code></td>'
                f'<td title="{html_lib.escape(f.resource_id)}">{resource_short}</td>'
                f'<td>{html_lib.escape(f.title)}'
                f'<button class="expand-btn" onclick="toggleDetail(\'{f.id}\')" title="details">▾</button>'
                f'</td>'
                f'<td>{f.source.value}</td>'
                f'</tr>'
                f'<tr class="detail-row" id="detail-{f.id}" style="display:none">'
                f'<td colspan="6">{details_html}</td>'
                f'</tr>'
            )

        sub_note = f"&nbsp;&nbsp;·&nbsp;&nbsp;{result.subscription_id}" if result.subscription_id else ""

        html_output = _HTML_TEMPLATE.substitute(
            generated_at=now,
            total_findings=len(findings),
            sub_note=sub_note,
            summary_cards=summary_cards,
            sev_filter_buttons=sev_buttons,
            table_rows="\n".join(rows) if rows else "<tr><td colspan='6' style='text-align:center;color:#6b7280'>No findings</td></tr>",
        )

        if output_dir is not None:
            out_path = output_dir / "report.html"
            out_path.write_text(html_output)

        return html_output


def _build_details(f: Finding) -> str:
    parts = [
        f"<strong>Description:</strong> {html_lib.escape(f.description)}<br>",
        f"<strong>Remediation:</strong> {html_lib.escape(f.remediation)}<br>",
    ]
    if f.resource_id:
        parts.append(f"<strong>Resource ID:</strong> <code>{html_lib.escape(f.resource_id)}</code><br>")
    if f.details:
        kv = "\n".join(f"{k}: {v}" for k, v in f.details.items())
        parts.append(f"<strong>Details:</strong><pre>{html_lib.escape(kv)}</pre>")
    return "\n".join(parts)
