import subprocess
import time

import typer
from rich.console import Console
from rich.table import Table

from . import agent, compliance, config, db, frameworks, policy, runner, synth

app = typer.Typer(help="Prowler Warden: always-on AWS compliance agent on Prowler OSS + ClickHouse")
console = Console()


@app.command()
def frameworks_list():
    """List the AWS compliance frameworks Prowler OSS supports."""
    for f in frameworks.list_frameworks():
        console.print(f)


@app.command()
def scan(framework: str = config.DEFAULT_FRAMEWORK, profile: str = typer.Option(None), region: list[str] = typer.Option(None),
         check: list[str] = typer.Option(None)):
    """Run Prowler against AWS now and ingest into ClickHouse."""
    console.print(f"scan_id={runner.scan(framework, profile, region, check)}")


@app.command()
def watch(framework: str = config.DEFAULT_FRAMEWORK, profile: str = typer.Option(None), region: list[str] = typer.Option(None),
          interval: int = 3600, review: bool = True):
    """Continuous loop: scan, then have the agent review drift."""
    while True:
        sid = runner.scan(framework, profile, region, None)
        console.print(f"[green]scanned[/] {sid}")
        if review:
            acct = db.query("SELECT account_id FROM scans WHERE scan_id={s:String}", {"s": sid})[0]["account_id"]
            console.print(agent.run("Review drift since the previous scan and propose remediations.", acct, framework))
        time.sleep(interval)


@app.command()
def demo(framework: str = config.DEFAULT_FRAMEWORK, resources: int = 2000, scans: int = 24):
    """Load a synthetic history (resources x checks x scans rows) generated inside ClickHouse."""
    t = time.time()
    r = synth.generate(framework, resources_per_check=resources, scans=scans)
    console.print(f"{r['rows']:,} findings loaded in {time.time() - t:.1f}s; account {r['account']}")


@app.command()
def status(account: str, framework: str = config.DEFAULT_FRAMEWORK):
    """Print compliance posture and drift."""
    reqs = compliance.requirements(account, framework)
    console.print(compliance.score(reqs))
    d = compliance.drift(account, framework, 15)
    t = Table("severity", "check", "resource", "requirements", title=f"{len(d['regressions'])}+ regressions")
    for r in d["regressions"]:
        t.add_row(r["severity"], r["check_id"], r["resource_uid"], ",".join(r["reqs"]))
    console.print(t)


@app.command()
def review(account: str, framework: str = config.DEFAULT_FRAMEWORK, prompt: str = "Review drift since the previous scan and propose remediations."):
    """Ask the agent to review an account."""
    console.print(agent.run(prompt, account, framework, on_event=lambda n, i: console.print(f"[dim]tool: {n} {i}[/]")))


@app.command()
def proposals():
    """List remediation proposals."""
    t = Table("id", "status", "check", "summary", "command")
    for a in db.query("SELECT id, status, check_id, summary, command FROM actions FINAL ORDER BY ts DESC LIMIT 50"):
        t.add_row(str(a["id"])[:8], a["status"], a["check_id"], a["summary"], a["command"])
    console.print(t)


@app.command()
def approve(prefix: str, execute: bool = False):
    """Approve a proposal by id prefix; --execute runs its command (otherwise dry-run print)."""
    rows = db.query("SELECT * FROM actions FINAL WHERE startsWith(toString(id), {p:String})", {"p": prefix})
    if len(rows) != 1:
        raise typer.Exit(f"{len(rows)} matches")
    a = rows[0]
    console.print(f"[bold]{a['summary']}[/]\n$ {a['command']}")
    if not execute or not a["command"]:
        console.print("[yellow]dry-run (pass --execute to run)[/]")
        return
    if not typer.confirm("Run this against your AWS account?"):
        return
    rc = subprocess.run(a["command"], shell=True).returncode
    db.client().command("INSERT INTO actions (id, account_id, framework, kind, check_id, resource_uid, summary, command, status) "
                        "VALUES (%(i)s,%(a)s,%(f)s,%(k)s,%(c)s,%(r)s,%(s)s,%(cmd)s,%(st)s)",
                        parameters={"i": a["id"], "a": a["account_id"], "f": a["framework"], "k": a["kind"], "c": a["check_id"],
                                    "r": a["resource_uid"], "s": a["summary"], "cmd": a["command"], "st": "applied" if rc == 0 else "failed"})


@app.command()
def serve(port: int = 8765):
    """Start the dashboard."""
    import uvicorn
    uvicorn.run("warden.api:app", host="127.0.0.1", port=port)


@app.command()
def fix(account: str, repo: str, framework: str = config.DEFAULT_FRAMEWORK, file: str = "main.tf",
        branch: str = "warden/remediate", open_pr: bool = False):
    """Fixer agent: patch Terraform for failing checks, gate with Semgrep, optionally open a PR."""
    from pathlib import Path
    from . import fixer
    out = fixer.propose(Path(repo), account, framework, file)
    res = fixer.apply(Path(repo), out, branch, open_pr)
    console.print(res)


@app.command()
def ct_watch(account: str, framework: str = config.DEFAULT_FRAMEWORK, profile: str = typer.Option(None), region: str = "us-east-1",
             every: int = 60, once: bool = False):
    """Real-time loop: pull CloudTrail events into ClickHouse, detect compliance-breaking changes, verify with Prowler."""
    from . import cloudtrail
    if once:
        console.print(cloudtrail.cycle(account, framework, profile, region))
    else:
        cloudtrail.watch(account, framework, profile, region, every, on_cycle=console.print)


@app.command()
def detections(limit: int = 30):
    """Show recent detections and their Prowler verification result."""
    t = Table("time", "sev", "rule", "actor", "reqs", "status", "note")
    for d in db.query(f"SELECT * FROM detections FINAL ORDER BY event_time DESC LIMIT {int(limit)}"):
        t.add_row(str(d["event_time"]), d["severity"], d["rule_id"], d["actor"][-30:], ",".join(d["req_ids"]), d["status"], d["note"][:60])
    console.print(t)


mode_app = typer.Typer(help="Runtime remediation policy (prowler-warden mode ...)")
app.add_typer(mode_app, name="mode")


@mode_app.command("show")
def mode_show():
    console.print(policy.get())


@mode_app.command("set")
def mode_set(mode: str):
    """monitor | pr (human reviews a PR) | auto (agent fixes AWS directly)."""
    console.print(policy.set_("mode", mode))


@mode_app.command("config")
def mode_config(key: str, value: str):
    """Set a policy key, e.g. dry_run false, auto_min_severity high, auto_deny_checks '["rds_instance_no_public_access"]'."""
    import json
    v = {"true": True, "false": False}.get(value.lower()) if value.lower() in ("true", "false") else (json.loads(value) if value[:1] in "[{" else value)
    console.print(policy.set_(key, v))


@app.command()
def costs(account: str, framework: str = config.DEFAULT_FRAMEWORK, profile: str = typer.Option(None), fetch: bool = True):
    """Pull Cost Explorer into ClickHouse and rank failing checks by exploitability signals (cost + CloudTrail)."""
    from . import signals
    if fetch:
        console.print(f"{signals.fetch_costs(account, profile)} cost rows loaded")
    console.print(signals.cost_anomalies(account))
    t = Table("score", "verdict", "sev", "check", "res", "evidence")
    for p in signals.prioritize(account, framework, 15):
        t.add_row(str(p["score"]), p["verdict"], p["severity"], p["check_id"], str(p["resources"]), "; ".join(p["evidence"])[:70])
    console.print(t)


live_app = typer.Typer(help="Safe live demo on throwaway warden-demo-tagged resources")
app.add_typer(live_app, name="live")


@live_app.command("status")
def live_status():
    from . import live_demo
    console.print(live_demo.status())


@live_app.command("start")
def live_start():
    """Open port 22 to the internet on the throwaway demo security group (what Warden should catch)."""
    from . import live_demo
    console.print(live_demo.start())


@live_app.command("reset")
def live_reset():
    """Delete the demo VPC + security group so the demo can run again."""
    from . import live_demo
    console.print(live_demo.reset())


@app.command()
def publish(account: str = typer.Argument(None), framework: str = config.DEFAULT_FRAMEWORK, out: str = "site"):
    """Publisher: write a redacted, hash-stamped compliance status page (site/index.html + evidence.json)."""
    from pathlib import Path
    from . import publisher
    console.print(publisher.publish(account or config.ACCOUNT, framework, Path(out)))


@app.command()
def preflight():
    """Check everything the live demo needs and print what to fix."""
    import os
    import boto3
    from . import live_demo, policy, signals
    ok = lambda b, t, hint="": console.print(("[green]ok[/]   " if b else "[red]FAIL[/] ") + t + ("" if b else f"  -> {hint}"))
    try:
        db.client().command("SELECT 1"); ok(True, "ClickHouse reachable")
    except Exception as e:
        ok(False, "ClickHouse reachable", str(e)[:80])
    try:
        ident = boto3.Session(profile_name=config.PROFILE).client("sts").get_caller_identity()["Account"]
        ok(ident == config.ACCOUNT, f"AWS session valid for {config.ACCOUNT}", "aws sso login --profile " + str(config.PROFILE))
    except Exception:
        ok(False, "AWS session valid", "aws sso login --profile " + str(config.PROFILE))
    p = policy.get()
    ok(True, f"mode={p['mode']} dry_run={p['dry_run']} open_pr={p['open_pr']} repo={'set' if p['repo'] else 'missing'}")
    ok(all(os.getenv(k) for k in ("GUILD_API_URL", "GUILD_TRIGGER_KEY_ID", "GUILD_TRIGGER_KEY_SECRET", "GUILD_SLACK_CHANNEL")), "Guild to Slack alerts configured", "fill GUILD_* in .env")
    ok(bool(os.getenv("ANTHROPIC_API_KEY")), "ANTHROPIC_API_KEY set", "add it to .env")
    try:
        console.print(f"      demo resources: {live_demo.status()}  cost overlay: {'on' if signals.demo_active(config.ACCOUNT) else 'off'}")
    except Exception as e:
        ok(False, "demo status", str(e)[:80])


@app.command()
def teleprompter(port: int = 8800):
    """Serve ONLY the teleprompter page on your Wi-Fi so a phone can show the script while you record on the laptop."""
    import socket
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from pathlib import Path
    static = Path(__file__).parent / "static"
    files = {"/": ("teleprompter.html", "text/html"), "/teleprompter": ("teleprompter.html", "text/html"),
             "/static/script.json": ("script.json", "application/json"), "/static/favicon.png": ("favicon.png", "image/png")}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # nothing else is exposed: no dashboard, no API, no AWS controls
            f = files.get(self.path.split("?")[0])
            if not f:
                self.send_error(404)
                return
            body = (static / f[0]).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", f[1])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        ip = "127.0.0.1"
    console.print(f"Teleprompter for your phone (same Wi-Fi): [bold]http://{ip}:{port}[/]   (Ctrl+C to stop)")
    HTTPServer(("0.0.0.0", port), H).serve_forever()
