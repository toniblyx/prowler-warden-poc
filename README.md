# Warden — an always-on AWS compliance agent

Warden keeps an AWS account continuously compliant with a chosen framework (CIS, PCI, HIPAA, NIST, SOC2, ...).
**Prowler OSS** scans and supplies the framework mappings, check metadata and remediations. **ClickHouse** stores every
scan and computes posture and drift in milliseconds. A **Claude agent** reads the drift, explains the risk and
proposes fixes that a human approves.

```
Prowler OSS ──ocsf──▶ ClickHouse ──SQL tools──▶ Claude agent ──▶ proposals ──approve──▶ aws cli
 (scan, frameworks)   (findings, drift)          (triage, explain)   (human gate)
```

## Run
```
docker run -d --name warden-ch -p 8123:8123 -e CLICKHOUSE_USER=default -e CLICKHOUSE_PASSWORD=warden clickhouse/clickhouse-server
uv venv --python 3.12 && uv pip install -e . && uv pip install -e /path/to/prowler   # Prowler OSS
warden demo                       # 3.4M synthetic findings across 24 scans, generated inside ClickHouse
warden serve --port 8799          # dashboard
export ANTHROPIC_API_KEY=...; warden review 123456789012
warden scan --profile myprofile   # real AWS scan via Prowler
warden watch --interval 3600      # continuous: scan, then agent reviews drift
warden proposals; warden approve <id> [--execute]
```
Fixes are never applied silently: `approve` prints a dry run unless `--execute` and a confirmation.
