"""The Warden agent: watches compliance drift, explains it, and proposes (never silently applies) fixes."""
import json

import anthropic

from . import compliance, config, db, frameworks

SYSTEM = """You are Warden, an always-on AWS compliance agent. You keep an AWS account continuously compliant with a
compliance framework (e.g. CIS, PCI, HIPAA). Facts come from Prowler OSS scans stored in ClickHouse.

Workflow when asked to review an account: 1) get_posture, 2) get_drift to see what regressed since the previous scan,
3) for the worst regressions call get_check_info to understand risk and the official remediation, 4) call
propose_remediation for fixes you recommend. Rank by severity and by how many framework requirements a failure breaks.
Never invent resource ids, requirement ids or CLI commands: use only data returned by tools. Fixes are PROPOSALS
requiring human approval; say so. Finish with a short report: score and trend, what changed, top actions."""

TOOLS = [
    {"name": "get_posture", "description": "Compliance score and per-requirement status (failing requirements listed) for the latest scan.",
     "input_schema": {"type": "object", "properties": {"account": {"type": "string"}, "framework": {"type": "string"}}, "required": ["account", "framework"]}},
    {"name": "get_trend", "description": "Compliance percentage for the last N scans.",
     "input_schema": {"type": "object", "properties": {"account": {"type": "string"}, "framework": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["account", "framework"]}},
    {"name": "get_drift", "description": "Resources that newly FAIL (regressions) or were fixed (resolved) between the previous and latest scan, with the framework requirements affected.",
     "input_schema": {"type": "object", "properties": {"account": {"type": "string"}, "framework": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["account", "framework"]}},
    {"name": "get_top_failing_checks", "description": "Failing checks in the latest scan ordered by severity then number of resources.",
     "input_schema": {"type": "object", "properties": {"account": {"type": "string"}, "framework": {"type": "string"}}, "required": ["account", "framework"]}},
    {"name": "get_check_info", "description": "Prowler metadata for a check: risk, official remediation (CLI, Terraform, console), and whether Prowler ships an auto-fixer.",
     "input_schema": {"type": "object", "properties": {"check_id": {"type": "string"}}, "required": ["check_id"]}},
    {"name": "run_sql", "description": "Read-only SQL (SELECT/WITH) over ClickHouse tables: findings, scans, framework_map, actions. Use for ad-hoc questions.",
     "input_schema": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]}},
    {"name": "propose_remediation", "description": "Record a remediation proposal for human approval. Include the exact command from get_check_info.",
     "input_schema": {"type": "object", "properties": {
         "account": {"type": "string"}, "framework": {"type": "string"}, "check_id": {"type": "string"},
         "resource_uid": {"type": "string"}, "summary": {"type": "string"}, "command": {"type": "string"}},
         "required": ["account", "framework", "check_id", "summary"]}},
]


def _json(o):
    return json.dumps(o, default=str)[:30000]


def call_tool(name: str, a: dict):
    if name == "get_posture":
        reqs = compliance.requirements(a["account"], a["framework"])
        failing = [{k: r[k] for k in ("req_id", "section", "description", "failing_checks")} for r in reqs if r["status"] == "FAIL"]
        return {"score": compliance.score(reqs), "failing_requirements": failing}
    if name == "get_trend":
        return compliance.trend(a["account"], a["framework"], a.get("limit", 12))
    if name == "get_drift":
        d = compliance.drift(a["account"], a["framework"], a.get("limit", 40))
        return {"regressions": d["regressions"], "resolved_count": len(d["resolved"]), "resolved_sample": d["resolved"][:5]}
    if name == "get_top_failing_checks":
        return compliance.top_failing_checks(a["account"], a["framework"])
    if name == "get_check_info":
        m = frameworks.check_metadata(a["check_id"])
        if not m:
            return {"error": "unknown check"}
        rem = m.get("Remediation", {})
        return {"title": m.get("CheckTitle"), "severity": m.get("Severity"), "risk": m.get("Risk"),
                "remediation": rem, "has_prowler_fixer": frameworks.has_fixer(a["check_id"])}
    if name == "run_sql":
        sql = a["sql"].strip().rstrip(";")
        if not sql.lower().startswith(("select", "with")):
            return {"error": "read-only: SELECT/WITH only"}
        r = db.client().query(sql, settings={"readonly": 1, "max_execution_time": 20, "max_result_rows": 200, "result_overflow_mode": "break"})
        return [dict(zip(r.column_names, row)) for row in r.result_rows]
    if name == "propose_remediation":
        db.client().insert("actions", [[a["account"], a["framework"], "remediation", a["check_id"], a.get("resource_uid", ""),
                                        a["summary"], a.get("command", ""), "proposed"]],
                           column_names=["account_id", "framework", "kind", "check_id", "resource_uid", "summary", "command", "status"])
        return {"recorded": True, "status": "proposed - awaiting human approval"}
    return {"error": f"unknown tool {name}"}


def run(prompt: str, account: str, framework: str, on_event=None, max_turns: int = 12) -> str:
    cl = anthropic.Anthropic()
    msgs = [{"role": "user", "content": f"Account: {account}\nFramework: {framework}\n\n{prompt}"}]
    for _ in range(max_turns):
        resp = cl.messages.create(model=config.MODEL, max_tokens=4096, system=SYSTEM, tools=TOOLS, messages=msgs)
        msgs.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                if on_event:
                    on_event(b.name, b.input)
                try:
                    out = _json(call_tool(b.name, b.input))
                except Exception as e:  # surface tool errors to the model instead of crashing the loop
                    out = _json({"error": str(e)})
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out})
        msgs.append({"role": "user", "content": results})
    return "(stopped: max turns reached)"
