"""Publisher: a public-safe, tamper-evident compliance status page built from live ClickHouse data.

Redaction: account id is masked, no resource ARNs or actor identities leave this module. The evidence bundle is hashed (SHA-256)
and embedded, so anyone holding the page can verify the numbers have not been edited after publication."""
import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import compliance, db, frameworks, insights

STATIC = Path(__file__).parent / "static"


def _mask(account: str) -> str:
    return "••••••••" + account[-4:]


def build(account: str, framework: str) -> dict:
    fw = frameworks.display(framework)
    reqs = compliance.posture(account, framework)
    score = compliance.score(reqs)
    cov = compliance.coverage(account).get(framework, {"total": 0, "scanned": 0})
    sim = insights.simulate(account, framework)
    acts = db.query("""SELECT ts, kind, status, check_id, summary FROM actions FINAL WHERE account_id={a:String} AND kind IN ('self-fix','pr')
                       AND status IN ('fixed-verified','pr-opened','pr-ready','reverted') ORDER BY ts DESC LIMIT 15""", {"a": account})
    dets = db.query("SELECT event_time, severity, title, status FROM detections FINAL WHERE account_id={a:String} ORDER BY event_time DESC LIMIT 15", {"a": account})
    failing = []
    for r in reqs:
        if r["status"] == "FAIL":
            failing.append({"req": r["req_id"], "section": r["section"], "description": r["description"][:220],
                            "checks": [{"id": c, "title": frameworks.check_metadata(c).get("CheckTitle", c), "severity": frameworks.check_metadata(c).get("Severity", "")} for c in r["failing_checks"]]})
    evidence = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "framework": {"id": framework, "name": fw["name"], "version": fw["version"]},
        "account": _mask(account), "region": "us-east-1",
        "score": score, "coverage": cov,
        "projection": [{"step": s["label"], "pct": s["pct"]} for s in sim["scenarios"]],
        "actions": [{"time": a["ts"].isoformat() + "Z", "kind": a["kind"], "status": a["status"], "check": a["check_id"],
                     "title": frameworks.check_metadata(a["check_id"]).get("CheckTitle", a["check_id"])} for a in acts],
        "detections": [{"time": d["event_time"].isoformat() + "Z", "severity": d["severity"], "title": d["title"], "verdict": d["status"]} for d in dets],
        "failing_requirements": failing,
    }
    body = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    evidence["sha256"] = hashlib.sha256(body.encode()).hexdigest()
    return evidence


def render(ev: dict, artifact: bool = False) -> str:
    e = html.escape
    s = ev["score"]
    pct = s["pct"] or 0
    colour = "var(--ok)" if pct >= 80 else "var(--warn)" if pct >= 50 else "var(--bad)"
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = ""
    for r in ev["failing_requirements"]:
        for c in sorted(r["checks"], key=lambda c: sev_order.get(c["severity"], 9)):
            rows += (f'<tr><td><b>{e(r["req"])}</b></td><td>{e(c["title"])}<div class="m">{e(r["description"][:110])}</div></td>'
                     f'<td><span class="chip {e(c["severity"])}">{e(c["severity"] or "n/a")}</span></td>'
                     f'<td><a href="https://hub.prowler.com/check/{e(c["id"])}" rel="noopener">{e(c["id"])}</a></td></tr>')
    acts = "".join(f'<li><span class="chip ok">{e("AWS fix" if a["kind"] == "self-fix" else "Code PR")}</span> {e(a["title"])} <span class="m">· {e(a["status"])} · {e(a["time"][:16].replace("T", " "))} UTC</span></li>' for a in ev["actions"]) \
        or '<li class="m">No automated actions recorded yet.</li>'
    proj = "".join(f'<div class="step"><b>{e(p["step"])}</b><span>{p["pct"]}%</span></div>' for p in ev["projection"])
    blob = e(json.dumps(ev, indent=1))
    light = "--bg:#fdfdfd;--card:#fff;--line:#e5e5e5;--fg:#020617;--mut:#6b7280;--acc:#047857;--ok:#15803d;--warn:#c2410c;--bad:#be123c;color-scheme:light"
    css = f"""
:root{{--bg:#000;--card:#0c0a09;--line:#27272a;--fg:#fff;--mut:#a1a1aa;--acc:#6ee7b7;--ok:#4ade80;--warn:#fb923c;--bad:#f43f5e;--font:Inter,-apple-system,"Segoe UI",sans-serif;--mono:"Fira Code",ui-monospace,Menlo,monospace;color-scheme:dark}}
@media (prefers-color-scheme: light){{:root:not([data-theme="dark"]){{{light}}}}}
:root[data-theme="light"]{{{light}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 var(--font)}}
main{{max-width:960px;margin:0 auto;padding-block:32px 64px;padding-inline:20px}}.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:16px;min-width:0}}
h1{{font-size:26px;margin:4px 0 2px;letter-spacing:-.01em;text-wrap:balance}}h2{{font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:.08em;margin:0 0 12px;font-weight:600}}
.m{{color:var(--mut);font-size:13px}}.hero{{display:flex;gap:28px;align-items:center;flex-wrap:wrap}}.big{{font-size:64px;font-weight:700;line-height:1;color:{colour};font-variant-numeric:tabular-nums}}
.chip{{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid var(--line)}}.chip.ok{{color:var(--ok)}}.chip.critical{{color:var(--bad)}}.chip.high{{color:var(--warn)}}.chip.medium{{color:var(--mut)}}
.tw{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:13.5px}}td,th{{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--mut);font-weight:500;font-size:12px}}
ul{{list-style:none;padding:0;margin:0}}li{{padding:7px 0;border-bottom:1px solid var(--line)}}a{{color:var(--acc)}}a:focus-visible,summary:focus-visible{{outline:2px solid var(--acc);outline-offset:2px}}
.steps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}}.step{{border:1px solid var(--line);border-radius:10px;padding:10px 12px}}.step b{{display:block;font-size:12px;color:var(--mut);font-weight:600}}.step span{{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}}
pre{{white-space:pre-wrap;word-break:break-all;font:12px/1.5 var(--mono);color:var(--mut);max-height:260px;overflow:auto;margin:0}}details summary{{cursor:pointer;color:var(--acc)}}.hash{{font:13px var(--mono);word-break:break-all;margin:6px 0 10px}}
"""
    fonts = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400&family=Inter:wght@400;500;600;700&display=swap">'
    head = (f'<title>Prowler Warden Status</title>{fonts}<style>{css}</style>' if artifact else
            f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Prowler Warden Status</title>{fonts}<style>{css}</style></head><body>')
    tail = "" if artifact else "</body></html>"
    return f"""{head}<main>
<div class="m">Prowler Warden · continuous compliance</div><h1>{e(ev["framework"]["name"])}</h1>
<div class="m">AWS account {e(ev["account"])} · {e(ev["region"])} · updated {e(ev["generated_at"].replace("T", " "))} UTC</div>
<div class="card hero"><div class="big">{pct}%</div><div><div><b>{s["pass"]}</b> of <b>{s["graded"]}</b> graded requirements passing</div>
<div class="m">{s["fail"]} failing · {s["no_data"]} without results · {ev["coverage"]["scanned"]} of {ev["coverage"]["total"]} automated checks evaluated</div>
<div class="m">Source: Prowler OSS scans plus AWS CloudTrail. Requirements without results are not graded.</div></div></div>
<div class="card"><h2>What Warden did</h2><ul>{acts}</ul></div>
<div class="card"><h2>Where fixes can take this</h2><div class="steps">{proj}</div><div class="m" style="margin-top:8px">Projection from the current failing checks: self-fix, then pull requests to code, then tasks that need a person.</div></div>
<div class="card"><h2>Open findings ({len(ev["failing_requirements"])} requirements)</h2><div class="tw"><table><thead><tr><th>Req</th><th>Finding</th><th>Severity</th><th>Check</th></tr></thead><tbody>{rows}</tbody></table></div></div>
<div class="card"><h2>Integrity</h2><div class="m">SHA-256 of the evidence bundle (canonical JSON, hash field excluded):</div><div class="hash">{e(ev["sha256"])}</div>
<details><summary>Show the evidence bundle</summary><pre>{blob}</pre></details>
<div class="m" style="margin-top:10px">Resource identifiers and actor identities are intentionally omitted from this page.</div></div>
</main>{tail}"""


def publish(account: str, framework: str, out: Path) -> dict:
    ev = build(account, framework)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(render(ev))
    (out / "artifact.html").write_text(render(ev, artifact=True))
    (out / "evidence.json").write_text(json.dumps(ev, indent=2, sort_keys=True))
    return {"path": str(out / "index.html"), "sha256": ev["sha256"], "score": ev["score"]["pct"]}
