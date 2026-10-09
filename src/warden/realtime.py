"""Prowler real-time: event-driven Prowler checks.

Every risky API call reaches Prowler within seconds and triggers a targeted Prowler check; Prowler decides if it is a violation and
ClickHouse only stores the evidence. Feed: EventBridge -> SQS (in your account) -> Warden long-poll.

LookupEvents lags by several minutes. EventBridge receives the same API calls from CloudTrail within seconds, and an SQS
queue means Warden needs no public endpoint. Both feeds go through cloudtrail.process_events, which dedupes by event id."""
import json
import os
import time
from pathlib import Path

import boto3

from . import cloudtrail, config

STACK = "warden-realtime"
TEMPLATE = Path(__file__).resolve().parents[2] / "infra" / "realtime.yaml"


def _sess(profile=None, region=None):
    return boto3.Session(profile_name=profile if profile is not None else config.PROFILE, region_name=region or config.REGION)


def deploy(profile=None, region=None) -> str:
    cf = _sess(profile, region).client("cloudformation")
    body = TEMPLATE.read_text()
    try:
        cf.create_stack(StackName=STACK, TemplateBody=body, Tags=[{"Key": "warden", "Value": "realtime"}])
        cf.get_waiter("stack_create_complete").wait(StackName=STACK, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
    except cf.exceptions.AlreadyExistsException:
        try:
            cf.update_stack(StackName=STACK, TemplateBody=body)
            cf.get_waiter("stack_update_complete").wait(StackName=STACK)
        except Exception as e:
            if "No updates are to be performed" not in str(e):
                raise
    return queue_url_from_stack(profile, region)


def queue_url_from_stack(profile=None, region=None) -> str:
    cf = _sess(profile, region).client("cloudformation")
    outs = cf.describe_stacks(StackName=STACK)["Stacks"][0].get("Outputs", [])
    return next(o["OutputValue"] for o in outs if o["OutputKey"] == "QueueUrl")


def destroy(profile=None, region=None):
    cf = _sess(profile, region).client("cloudformation")
    cf.delete_stack(StackName=STACK)
    cf.get_waiter("stack_delete_complete").wait(StackName=STACK)


def receive(url: str, profile=None, region=None, wait: int = 20) -> tuple[list[dict], list[dict]]:
    sqs = _sess(profile, region).client("sqs")
    r = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    events, handles = [], []
    for m in r.get("Messages", []):
        handles.append({"Id": m["MessageId"], "ReceiptHandle": m["ReceiptHandle"]})
        try:
            detail = json.loads(m["Body"]).get("detail")
            if detail and detail.get("eventID"):
                events.append(cloudtrail.normalize(detail))
        except Exception:
            pass  # a malformed message is dropped, never blocks the queue
    return events, handles


def poll_once(url: str, framework: str, profile=None, region=None, wait: int = 20) -> dict:
    events, handles = receive(url, profile, region, wait)
    out = {"messages": len(handles), "events": 0, "detections": 0, "remediation": []}
    if events:
        t = time.time()
        res = cloudtrail.process_events(events, framework, profile)
        out.update(events=res["events"], detections=res["detections"], remediation=res["remediation"], seconds=round(time.time() - t, 1))
    if handles:
        _sess(profile, region).client("sqs").delete_message_batch(QueueUrl=url, Entries=handles)
    return out


def url() -> str:
    return os.getenv("WARDEN_SQS_URL", "")
