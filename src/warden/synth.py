"""Synthetic history at scale, generated inside ClickHouse (INSERT ... SELECT FROM numbers()).

Resource state is a pure function of (check, resource) so it persists across scans; the last scan injects
regressions (new failures) and fixes so the drift agent has something to find.
"""
import uuid
from datetime import datetime, timedelta

from . import db, frameworks, runner


def generate(framework: str, account: str = "123456789012", resources_per_check: int = 2000, scans: int = 24,
             interval_hours: int = 1) -> dict:
    c = db.init()
    runner.load_framework(framework)
    checks = sorted({r[4] for r in frameworks.rows(framework) if r[4]})
    sev = {ck: (frameworks.check_metadata(ck).get("Severity") or "medium") for ck in checks}
    c.command("DROP TABLE IF EXISTS _synth_checks")
    c.command("CREATE TABLE _synth_checks (check_id String, severity String) ENGINE=Memory")
    c.insert("_synth_checks", [[k, v] for k, v in sev.items()], column_names=["check_id", "severity"])
    for t in ("findings", "scans"):
        c.command(f"ALTER TABLE {t} DELETE WHERE account_id = %(a)s SETTINGS mutations_sync=1", parameters={"a": account})
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    total = 0
    for k in range(scans):
        t = now - timedelta(hours=interval_hours * (scans - 1 - k))
        sid = uuid.uuid4().hex[:12]
        last = k == scans - 1
        # baseline failure rate drifts down slowly (team is improving); last scan adds regressions and fixes
        base_fail = "(cityHash64(c.check_id) % 100 < 30 AND cityHash64(c.check_id, n) % 100 < 20)"
        late = f"(cityHash64(c.check_id, n, 'r') % 2500 = 0)" if last else "0"
        fixed = f"(cityHash64(c.check_id, n, 'f') % 400 = 0)" if last else "0"
        c.command(f"""
        INSERT INTO findings
        SELECT '{sid}', toDateTime('{t:%Y-%m-%d %H:%M:%S}'), '{account}',
               arrayElement(['us-east-1','us-west-2','eu-west-1','ap-southeast-1'], 1 + n % 4), c.check_id,
               splitByChar('_', c.check_id)[1], c.severity,
               if(({base_fail} OR {late}) AND NOT {fixed}, 'FAIL', 'PASS'),
               concat('arn:aws:', splitByChar('_', c.check_id)[1], ':', arrayElement(['us-east-1','us-west-2','eu-west-1','ap-southeast-1'], 1 + n % 4),
                      ':{account}:resource/', toString(n)),
               concat('res-', toString(n)), '', '', '', ''
        FROM _synth_checks AS c CROSS JOIN numbers({int(resources_per_check)}) AS nn
        ARRAY JOIN [nn.number] AS n""")
        n = len(checks) * resources_per_check
        c.insert("scans", [[sid, t, account, framework, "synthetic", n]],
                 column_names=["scan_id", "scan_time", "account_id", "framework", "source", "findings"])
        total += n
    return {"account": account, "framework": framework, "checks": len(checks), "scans": scans, "rows": total}
