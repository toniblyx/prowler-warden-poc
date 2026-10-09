import subprocess
import time

import typer
from rich.console import Console
from rich.table import Table

from . import agent, compliance, config, db, frameworks, runner, synth

app = typer.Typer(help="Warden: always-on AWS compliance agent on Prowler OSS + ClickHouse")
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
